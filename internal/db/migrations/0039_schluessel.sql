-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 32: Schlüssel und Signaturen (Befunde M5, M7).
--
-- 1. Geheimtexte im Format 2 tragen ein Kennzeichen des Schlüssels (8 Byte
--    mehr). Die Obergrenzen der verschlüsselten Spalten wachsen um 8 Byte,
--    damit ein Geheimnis, das im alten Format genau an der Grenze lag, beim
--    Schlüsselwechsel nicht abgelehnt wird.
-- 2. Agent-CA: bis zu drei CAs nebeneinander (aktiv, neu, alt) für einen
--    geordneten Wechsel. Die aktive stellt aus; neue und alte gelten für
--    Client-Zertifikate und werden an die Agents verteilt.
-- 3. Update-Schlüssel: Widerrufe aus signierten Updates; Pakete, die mit
--    einem widerrufenen Schlüssel signiert sind, werden nicht mehr angeboten.

-- --- 1. Platz für das Kennzeichen -------------------------------------------------

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_secret_enc_check,
    ADD CONSTRAINT snmp_sources_secret_enc_check CHECK (octet_length(secret_enc) BETWEEN 29 AND 2056);
ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_trap_secret_enc_check,
    ADD CONSTRAINT snmp_sources_trap_secret_enc_check CHECK (octet_length(trap_secret_enc) BETWEEN 29 AND 2056);
ALTER TABLE openwacht.settings DROP CONSTRAINT settings_deadman_enc_check,
    ADD CONSTRAINT settings_deadman_enc_check CHECK (octet_length(deadman_enc) <= 2056);
ALTER TABLE openwacht.settings DROP CONSTRAINT settings_smtp_pass_enc_check,
    ADD CONSTRAINT settings_smtp_pass_enc_check CHECK (octet_length(smtp_pass_enc) BETWEEN 29 AND 1032);
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_secret_enc_check,
    ADD CONSTRAINT alert_channels_secret_enc_check CHECK (octet_length(secret_enc) BETWEEN 29 AND 1032);
ALTER TABLE openwacht.alert_channels DROP CONSTRAINT alert_channels_token_enc_check,
    ADD CONSTRAINT alert_channels_token_enc_check CHECK (octet_length(token_enc) BETWEEN 29 AND 4104);
ALTER TABLE openwacht.https_material DROP CONSTRAINT https_material_key_enc_check,
    ADD CONSTRAINT https_material_key_enc_check CHECK (octet_length(key_enc) BETWEEN 29 AND 16392);
ALTER TABLE openwacht.https_material DROP CONSTRAINT https_material_ca_key_enc_check,
    ADD CONSTRAINT https_material_ca_key_enc_check CHECK (octet_length(ca_key_enc) <= 16392);
ALTER TABLE openwacht.directories DROP CONSTRAINT directories_bind_pass_enc_check,
    ADD CONSTRAINT directories_bind_pass_enc_check CHECK (octet_length(bind_pass_enc) BETWEEN 29 AND 2056);
ALTER TABLE openwacht.snmp_profiles DROP CONSTRAINT snmp_profiles_secret_enc_check,
    ADD CONSTRAINT snmp_profiles_secret_enc_check CHECK (octet_length(secret_enc) BETWEEN 29 AND 2056);

-- --- 2. Agent-CA-Wechsel ----------------------------------------------------------

ALTER TABLE openwacht.agent_ca DROP CONSTRAINT agent_ca_id_check,
    ADD CONSTRAINT agent_ca_id_check CHECK (id BETWEEN 1 AND 32000),
    ADD COLUMN state text NOT NULL DEFAULT 'aktiv' CHECK (state IN ('aktiv', 'neu', 'alt')),
    ADD COLUMN changed_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE openwacht.agent_ca ALTER COLUMN id DROP DEFAULT;
-- je Zustand höchstens eine CA, also höchstens drei
CREATE UNIQUE INDEX agent_ca_state ON openwacht.agent_ca (state);

-- Beim ersten Start: CA anlegen, wenn es keine gibt; liefert die aktive.
CREATE OR REPLACE FUNCTION openwacht.agent_ca_init(p_cert text, p_key bytea)
    RETURNS TABLE (cert_pem text, key_enc bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    INSERT INTO openwacht.agent_ca (id, cert_pem, key_enc, state)
    SELECT 1, p_cert, p_key, 'aktiv' WHERE NOT EXISTS (SELECT 1 FROM openwacht.agent_ca)
    ON CONFLICT DO NOTHING;
    RETURN QUERY SELECT a.cert_pem, a.key_enc FROM openwacht.agent_ca a WHERE a.state = 'aktiv';
END
$$;

-- Alle CAs für die Zentrale (ohne Schlüssel; den der aktiven liefert agent_ca_init).
CREATE FUNCTION openwacht.agent_ca_list()
    RETURNS TABLE (id smallint, state text, cert_pem text, changed_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.id, a.state, a.cert_pem, a.changed_at FROM openwacht.agent_ca a
     ORDER BY CASE a.state WHEN 'aktiv' THEN 0 WHEN 'neu' THEN 1 ELSE 2 END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_ca_list() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_ca_list() TO openwacht_app;

-- --- 3. Widerrufene Update-Schlüssel ------------------------------------------------

CREATE TABLE openwacht.update_key_revocations (
    key_id      text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{16}$'),
    -- Schlüssel und Version des Updates, das den Widerruf trug
    revoked_by  text NOT NULL CHECK (revoked_by ~ '^[0-9a-f]{16}$' AND revoked_by <> key_id),
    version     text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE openwacht.update_key_revocations ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT ON openwacht.update_key_revocations TO openwacht_app;
CREATE POLICY update_key_revocations_select ON openwacht.update_key_revocations FOR SELECT TO openwacht_app
    USING (openwacht.current_user_id() IS NOT NULL);
CREATE POLICY update_key_revocations_insert ON openwacht.update_key_revocations FOR INSERT TO openwacht_app
    WITH CHECK (openwacht.is_platform_operator() AND created_by = openwacht.current_user_id());

-- Kennung des Signaturschlüssels je Paket (aus der Signaturdatei).
ALTER TABLE openwacht.agent_updates ADD COLUMN key_id text CHECK (key_id ~ '^[0-9a-f]{16}$');
UPDATE openwacht.agent_updates SET key_id = signature::jsonb->>'schluessel';
ALTER TABLE openwacht.agent_updates ALTER COLUMN key_id SET NOT NULL;
GRANT SELECT (key_id) ON openwacht.agent_updates TO openwacht_app;

-- Für Widerrufe ohne Benutzerkontext (Agent-Port): Kennungen aller Widerrufe.
CREATE FUNCTION openwacht.update_revoked_keys() RETURNS text[]
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce(array_agg(key_id ORDER BY key_id), '{}') FROM openwacht.update_key_revocations
$$;

CREATE OR REPLACE FUNCTION openwacht.agent_update_offer(p_agent uuid, p_os text, p_arch text)
    RETURNS TABLE (version text, sha256 text, signature text, size bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.version, u.sha256, u.signature, u.size
      FROM openwacht.agent_update_releases r
      JOIN openwacht.agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
      JOIN openwacht.agent_updates u ON u.version = r.version AND u.os = p_os AND u.arch = p_arch
     WHERE r.agent_id = p_agent
       AND NOT EXISTS (SELECT 1 FROM openwacht.update_key_revocations k WHERE k.key_id = u.key_id)
$$;

CREATE OR REPLACE FUNCTION openwacht.agent_update_data(p_agent uuid, p_os text, p_arch text, p_version text) RETURNS bytea
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.data
      FROM openwacht.agent_update_releases r
      JOIN openwacht.agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
      JOIN openwacht.agent_updates u ON u.version = r.version AND u.os = p_os AND u.arch = p_arch
     WHERE r.agent_id = p_agent AND r.version = p_version
       AND NOT EXISTS (SELECT 1 FROM openwacht.update_key_revocations k WHERE k.key_id = u.key_id)
$$;

REVOKE ALL ON FUNCTION openwacht.update_revoked_keys() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.update_revoked_keys() TO openwacht_app;
