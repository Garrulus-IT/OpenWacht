-- SPDX-License-Identifier: AGPL-3.0-only

-- 0004: Agents – eigene CA, Registrierungs-Token, Agents und ihre Messwerte.
--
-- Der Agent-Port der Zentrale hat keinen Benutzerkontext. Alles, was ein
-- Agent auslöst, läuft über SECURITY-DEFINER-Funktionen, die den Mandanten
-- selbst aus Token bzw. Agent-Tabelle ableiten (Leitprinzip 2): Die Zentrale
-- reicht nur Agent-ID und Zertifikats-Seriennummer durch, nie einen Mandanten.

-- Operator oder Admin: Wer Agents hinzufügen und sperren darf.
CREATE FUNCTION openwacht.operator_tenants() RETURNS SETOF uuid
    LANGUAGE sql STABLE AS $$
    SELECT openwacht.tenants_with_role(ARRAY['admin', 'operator'])
$$;

-- ---------------------------------------------------------------------------
-- Agent-CA (genau eine je Installation)
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.agent_ca (
    id         smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    cert_pem   text NOT NULL,
    -- privater Schlüssel (PKCS#8), mit dem Hauptschlüssel der Zentrale verschlüsselt
    key_enc    bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE openwacht.agent_ca ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.agent_ca FROM PUBLIC, openwacht_app;

-- Legt die CA an, falls es noch keine gibt, und liefert die gültige zurück
-- (bei zwei gleichzeitig startenden Zentralen gewinnt die erste).
CREATE FUNCTION openwacht.agent_ca_init(p_cert text, p_key bytea)
    RETURNS TABLE (cert_pem text, key_enc bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    INSERT INTO openwacht.agent_ca (id, cert_pem, key_enc) VALUES (1, p_cert, p_key)
    ON CONFLICT (id) DO NOTHING;
    RETURN QUERY SELECT a.cert_pem, a.key_enc FROM openwacht.agent_ca a WHERE a.id = 1;
END
$$;

-- ---------------------------------------------------------------------------
-- Registrierungs-Token
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.agent_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    note       text NOT NULL DEFAULT '' CHECK (char_length(note) <= 100 AND note !~ '[[:cntrl:]]'),
    uses_left  integer NOT NULL CHECK (uses_left BETWEEN 0 AND 1000),
    expires_at timestamptz NOT NULL,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_tokens_tenant ON openwacht.agent_tokens (tenant_id);

CREATE FUNCTION openwacht.agent_tokens_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.created_by := openwacht.current_user_id();
    RETURN NEW;
END
$$;
CREATE TRIGGER agent_tokens_before_insert BEFORE INSERT ON openwacht.agent_tokens
    FOR EACH ROW EXECUTE FUNCTION openwacht.agent_tokens_before_insert();

ALTER TABLE openwacht.agent_tokens ENABLE ROW LEVEL SECURITY;
-- Der Hash ist für die Anwendung nicht lesbar.
GRANT SELECT (id, tenant_id, note, uses_left, expires_at, created_by, created_at),
      INSERT (token_hash, tenant_id, note, uses_left, expires_at), DELETE
    ON openwacht.agent_tokens TO openwacht_app;
CREATE POLICY agent_tokens_select ON openwacht.agent_tokens FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));
-- Höchstens 7 Tage gültig.
CREATE POLICY agent_tokens_insert ON openwacht.agent_tokens FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants())
                AND expires_at <= now() + interval '7 days' AND uses_left >= 1);
CREATE POLICY agent_tokens_delete ON openwacht.agent_tokens FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- ---------------------------------------------------------------------------
-- Agents
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.agents (
    -- vergibt die Zentrale; steht im Client-Zertifikat
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    hostname         text NOT NULL CHECK (char_length(hostname) BETWEEN 1 AND 253),
    -- gültige Seriennummer; die vorige bleibt gültig, bis der Agent die neue
    -- benutzt (falls die Antwort einer Erneuerung unterwegs verloren geht)
    cert_serial      text NOT NULL,
    cert_serial_prev text,
    cert_not_after   timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz,
    revoked_at       timestamptz,
    snapshot         jsonb CHECK (snapshot IS NULL OR octet_length(snapshot::text) <= 65536)
);
CREATE INDEX agents_tenant ON openwacht.agents (tenant_id);

-- Eine Sperre ist endgültig.
CREATE FUNCTION openwacht.agents_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'Ein gesperrter Agent kann nicht entsperrt werden.';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant eines Agents sind unveränderlich.';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER agents_before_update BEFORE UPDATE ON openwacht.agents
    FOR EACH ROW EXECUTE FUNCTION openwacht.agents_before_update();

ALTER TABLE openwacht.agents ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, hostname, cert_not_after, created_at, last_seen, revoked_at, snapshot),
      UPDATE (revoked_at)
    ON openwacht.agents TO openwacht_app;
CREATE POLICY agents_select ON openwacht.agents FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY agents_update ON openwacht.agents FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()) AND revoked_at IS NOT NULL);

-- ---------------------------------------------------------------------------
-- Funktionen für den Agent-Port (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Token einlösen und Agent anlegen. Mandant kommt aus dem Token.
CREATE FUNCTION openwacht.agent_enroll(p_token_hash bytea, p_agent uuid, p_hostname text,
                                      p_serial text, p_not_after timestamptz) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    t openwacht.agent_tokens;
BEGIN
    SELECT * INTO t FROM openwacht.agent_tokens WHERE token_hash = p_token_hash FOR UPDATE;
    IF NOT FOUND OR t.expires_at <= now() OR t.uses_left < 1 THEN
        RAISE EXCEPTION 'Token ungültig, abgelaufen oder verbraucht' USING ERRCODE = '28000';
    END IF;
    IF t.uses_left = 1 THEN
        DELETE FROM openwacht.agent_tokens WHERE id = t.id;
    ELSE
        UPDATE openwacht.agent_tokens SET uses_left = uses_left - 1 WHERE id = t.id;
    END IF;
    INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after)
    VALUES (p_agent, t.tenant_id, p_hostname, p_serial, p_not_after);
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (t.tenant_id, 'agent.registriert',
            jsonb_build_object('agent', p_agent, 'hostname', p_hostname, 'token', t.id));
    RETURN t.tenant_id;
END
$$;

-- Ist das Zertifikat (Agent-ID + Seriennummer) gültig und der Agent nicht gesperrt?
CREATE FUNCTION openwacht.agent_check(p_agent uuid, p_serial text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1 FROM openwacht.agents a
         WHERE a.id = p_agent AND a.revoked_at IS NULL
           AND p_serial IN (a.cert_serial, a.cert_serial_prev))
$$;

-- Messwerte speichern. Benutzt der Agent die neue Seriennummer, verfällt die vorige.
CREATE FUNCTION openwacht.agent_report(p_agent uuid, p_serial text, p_hostname text, p_snapshot jsonb)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.agents
       SET last_seen = now(), hostname = p_hostname, snapshot = p_snapshot,
           cert_serial_prev = CASE WHEN p_serial = cert_serial THEN NULL ELSE cert_serial_prev END
     WHERE id = p_agent AND revoked_at IS NULL
       AND p_serial IN (cert_serial, cert_serial_prev);
    RETURN FOUND;
END
$$;

-- Zertifikat erneuern: neue Seriennummer gilt, die bisher benutzte bleibt als vorige gültig.
CREATE FUNCTION openwacht.agent_renew(p_agent uuid, p_old_serial text, p_new_serial text, p_not_after timestamptz)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    UPDATE openwacht.agents
       SET cert_serial_prev = p_old_serial, cert_serial = p_new_serial, cert_not_after = p_not_after
     WHERE id = p_agent AND revoked_at IS NULL
       AND p_old_serial IN (cert_serial, cert_serial_prev);
    RETURN FOUND;
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openwacht FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    openwacht.operator_tenants(),
    openwacht.agent_ca_init(text, bytea),
    openwacht.agent_enroll(bytea, uuid, text, text, timestamptz),
    openwacht.agent_check(uuid, text),
    openwacht.agent_report(uuid, text, text, jsonb),
    openwacht.agent_renew(uuid, text, text, timestamptz)
TO openwacht_app;
