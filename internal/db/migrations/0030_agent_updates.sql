-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 23: signierte Agent-Updates (Leitprinzip 4).
--
-- Entscheidung (22.11.2026): nur per Klick in der Oberfläche freigegeben, je
-- Gerät. Pakete lädt der Betreiber hoch; Zentrale und Agent prüfen die
-- Offline-Signatur (Ed25519). Die Zentrale kann ein Update nur anbieten, nie
-- erzwingen oder fälschen.

CREATE TABLE openwacht.agent_updates (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version      text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'),
    os           text NOT NULL CHECK (os IN ('linux', 'windows')),
    arch         text NOT NULL CHECK (arch IN ('amd64', 'arm64')),
    sha256       text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size         bigint NOT NULL CHECK (size BETWEEN 1 AND 67108864),
    -- Signaturdatei (JSON), geprüft beim Hochladen
    signature    text NOT NULL CHECK (char_length(signature) <= 4096),
    data         bytea NOT NULL CHECK (octet_length(data) = size),
    uploaded_by  uuid,
    uploaded_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (version, os, arch)
);
ALTER TABLE openwacht.agent_updates ENABLE ROW LEVEL SECURITY;
-- Liste ohne Daten für alle Angemeldeten (Admins wählen daraus die Version)
GRANT SELECT (id, version, os, arch, sha256, size, uploaded_by, uploaded_at) ON openwacht.agent_updates TO openwacht_app;
GRANT INSERT, DELETE ON openwacht.agent_updates TO openwacht_app;
CREATE POLICY agent_updates_select ON openwacht.agent_updates FOR SELECT TO openwacht_app
    USING (openwacht.current_user_id() IS NOT NULL);
CREATE POLICY agent_updates_insert ON openwacht.agent_updates FOR INSERT TO openwacht_app
    WITH CHECK (openwacht.is_platform_operator());
CREATE POLICY agent_updates_delete ON openwacht.agent_updates FOR DELETE TO openwacht_app
    USING (openwacht.is_platform_operator());

-- Freigabe je Agent. Der Mandant kommt aus dem Agent (Trigger), nie aus der Anfrage.
CREATE TABLE openwacht.agent_update_releases (
    agent_id     uuid PRIMARY KEY REFERENCES openwacht.agents (id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    version      text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'),
    released_by  uuid,
    released_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_update_releases_tenant ON openwacht.agent_update_releases (tenant_id);

CREATE FUNCTION openwacht.agent_update_releases_tenant() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    SELECT a.tenant_id INTO NEW.tenant_id FROM openwacht.agents a WHERE a.id = NEW.agent_id AND a.revoked_at IS NULL;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Agent unbekannt oder gesperrt.' USING ERRCODE = '23503';
    END IF;
    NEW.released_by := openwacht.current_user_id();
    NEW.released_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER agent_update_releases_tenant BEFORE INSERT OR UPDATE ON openwacht.agent_update_releases
    FOR EACH ROW EXECUTE FUNCTION openwacht.agent_update_releases_tenant();

ALTER TABLE openwacht.agent_update_releases ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON openwacht.agent_update_releases TO openwacht_app;
CREATE POLICY agent_update_releases_select ON openwacht.agent_update_releases FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY agent_update_releases_write ON openwacht.agent_update_releases FOR ALL TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants())) WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));

-- Für den Agent-Port (ohne Benutzerkontext): Angebot und Daten nur für
-- freigegebene Agents.
CREATE FUNCTION openwacht.agent_update_offer(p_agent uuid, p_os text, p_arch text)
    RETURNS TABLE (version text, sha256 text, signature text, size bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.version, u.sha256, u.signature, u.size
      FROM openwacht.agent_update_releases r
      JOIN openwacht.agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
      JOIN openwacht.agent_updates u ON u.version = r.version AND u.os = p_os AND u.arch = p_arch
     WHERE r.agent_id = p_agent
$$;

CREATE FUNCTION openwacht.agent_update_data(p_agent uuid, p_os text, p_arch text, p_version text) RETURNS bytea
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT u.data
      FROM openwacht.agent_update_releases r
      JOIN openwacht.agents a ON a.id = r.agent_id AND a.revoked_at IS NULL
      JOIN openwacht.agent_updates u ON u.version = r.version AND u.os = p_os AND u.arch = p_arch
     WHERE r.agent_id = p_agent AND r.version = p_version
$$;

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['agent_update_offer(uuid, text, text)', 'agent_update_data(uuid, text, text, text)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;
