-- SPDX-License-Identifier: AGPL-3.0-only

-- 0012: Gerätemodell.
--
-- Ein Gerät (Host) ist das, was überwacht wird. Agent und Checks sind Arten,
-- es zu überwachen, auch zusammen. Jeder Agent und jeder Check gehört zu genau
-- einem Gerät desselben Mandanten; das erzwingt ein zusammengesetzter
-- Fremdschlüssel (device_id, tenant_id). Ein Gerät hat höchstens einen aktiven
-- Agent. Die Adresse eines Geräts ist optional und nur ein Vorschlag für neue
-- Checks: Die Zentrale verbindet sich nie mit ihr (kein neuer Netzweg), und
-- das Ziel eines Checks darf davon abweichen.
--
-- Zuordnung bestehender Daten: Jeder Agent bekommt ein Gerät mit seinem
-- Hostnamen. Ein Check kommt zu dem Agent-Gerät im selben Mandanten, dessen
-- Hostname zum Ziel passt (ganzer Name oder erstes Label); sonst bekommt jedes
-- Ziel ein eigenes Gerät ohne Agent.
--
-- Wartung gibt es je Check und je Gerät; die Gerätewartung gilt für den Agent
-- und alle Checks des Geräts. Laufende Wartungen eines Agents werden zur
-- Wartung seines Geräts.
--
-- Neu gespeichert wird die Adresse, von der sich ein Agent zuletzt gemeldet
-- hat (eigene Hosts, keine Personendaten). Sie dient nur dem Vorschlag, ein
-- Gerät ohne Agent mit einem Agent zusammenzuführen; verknüpft wird nie
-- automatisch, weil hinter einem NAT viele Agents dieselbe Adresse haben.

CREATE TABLE openwacht.devices (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    -- Hostname oder IP-Adresse (geprüft von der Zentrale), ohne Protokoll und Port
    address    text CHECK (address IS NULL OR (char_length(address) BETWEEN 1 AND 253
                                               AND address ~ '^[A-Za-z0-9.:-]+$')),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id)
);
CREATE INDEX devices_tenant ON openwacht.devices (tenant_id);

-- ---------------------------------------------------------------------------
-- Bestehende Daten zuordnen (vor Triggern und Pflichtspalten)
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.agents ADD COLUMN device_id uuid, ADD COLUMN last_addr inet;
UPDATE openwacht.agents SET device_id = gen_random_uuid();
INSERT INTO openwacht.devices (id, tenant_id, name, created_at)
SELECT a.device_id, a.tenant_id, left(a.hostname, 100), a.created_at FROM openwacht.agents a;

ALTER TABLE openwacht.checks ADD COLUMN device_id uuid;

-- Zielname je Check: host, sonst der Host der URL (IPv6 ohne Klammern).
CREATE TABLE openwacht.mig_check_host AS
SELECT c.id, c.tenant_id, c.created_at,
       nullif(lower(btrim(coalesce(nullif(c.target ->> 'host', ''),
                                    substring(c.target ->> 'url' FROM '^[A-Za-z][A-Za-z0-9+.-]*://(\[[^]]+\]|[^/:?#]+)')),
                           '[]')), '') AS host
  FROM openwacht.checks c;

-- Passendes Agent-Gerät: aktive Agents vor gesperrten, dann der zuletzt gesehene.
UPDATE openwacht.checks c
   SET device_id = (
       SELECT a.device_id FROM openwacht.agents a
        WHERE a.tenant_id = h.tenant_id
          AND (lower(a.hostname) = h.host
               OR (h.host !~ '^[0-9.]+$' AND h.host !~ ':' AND lower(a.hostname) = split_part(h.host, '.', 1)))
        ORDER BY a.revoked_at IS NOT NULL, a.last_seen DESC NULLS LAST, a.id
        LIMIT 1)
  FROM openwacht.mig_check_host h
 WHERE h.id = c.id AND h.host IS NOT NULL;

-- Übrige: ein Gerät je Mandant und Ziel.
CREATE TABLE openwacht.mig_new_device AS
SELECT gen_random_uuid() AS id, g.tenant_id, g.host, g.created_at
  FROM (SELECT h.tenant_id, coalesce(h.host, '') AS host, min(h.created_at) AS created_at
          FROM openwacht.mig_check_host h JOIN openwacht.checks c ON c.id = h.id
         WHERE c.device_id IS NULL
         GROUP BY h.tenant_id, coalesce(h.host, '')) g;
INSERT INTO openwacht.devices (id, tenant_id, name, address, created_at)
SELECT n.id, n.tenant_id, CASE WHEN n.host = '' THEN 'Ohne Ziel' ELSE left(n.host, 100) END,
       CASE WHEN n.host ~ '^[a-z0-9.:-]+$' AND char_length(n.host) <= 253 THEN n.host END, n.created_at
  FROM openwacht.mig_new_device n;
UPDATE openwacht.checks c SET device_id = n.id
  FROM openwacht.mig_check_host h JOIN openwacht.mig_new_device n ON n.tenant_id = h.tenant_id AND n.host = coalesce(h.host, '')
 WHERE h.id = c.id AND c.device_id IS NULL;

ALTER TABLE openwacht.agents ALTER COLUMN device_id SET NOT NULL,
    ADD CONSTRAINT agents_device_fk FOREIGN KEY (device_id, tenant_id)
        REFERENCES openwacht.devices (id, tenant_id) ON DELETE RESTRICT;
DROP TABLE openwacht.mig_check_host, openwacht.mig_new_device;

CREATE UNIQUE INDEX agents_device_active ON openwacht.agents (device_id) WHERE revoked_at IS NULL;
CREATE INDEX agents_device ON openwacht.agents (device_id);

ALTER TABLE openwacht.checks ALTER COLUMN device_id SET NOT NULL,
    ADD CONSTRAINT checks_device_fk FOREIGN KEY (device_id, tenant_id)
        REFERENCES openwacht.devices (id, tenant_id) ON DELETE RESTRICT;
CREATE INDEX checks_device ON openwacht.checks (device_id);

-- ---------------------------------------------------------------------------
-- Geräte: Trigger und Rechte
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.devices_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM openwacht.devices WHERE tenant_id = NEW.tenant_id) >= 2000 THEN
        RAISE EXCEPTION 'Höchstens 2000 Geräte je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.created_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER devices_before_insert BEFORE INSERT ON openwacht.devices
    FOR EACH ROW EXECUTE FUNCTION openwacht.devices_before_insert();

CREATE FUNCTION openwacht.devices_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant eines Geräts sind unveränderlich.';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER devices_before_update BEFORE UPDATE ON openwacht.devices
    FOR EACH ROW EXECUTE FUNCTION openwacht.devices_before_update();

ALTER TABLE openwacht.devices ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, name, address, created_at),
      INSERT (tenant_id, name, address),
      UPDATE (name, address),
      DELETE
    ON openwacht.devices TO openwacht_app;
CREATE POLICY devices_select ON openwacht.devices FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY devices_insert ON openwacht.devices FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY devices_update ON openwacht.devices FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY devices_delete ON openwacht.devices FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- ---------------------------------------------------------------------------
-- Agents: Gerät beim Anlegen, Adresse beim Melden
-- ---------------------------------------------------------------------------

-- Ohne Gerät angelegt (Registrierung mit einem allgemeinen Token): eigenes
-- Gerät mit dem Hostnamen. Agents legt nur agent_enroll an (ohne Benutzer).
CREATE FUNCTION openwacht.agents_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.device_id IS NULL THEN
        INSERT INTO openwacht.devices (tenant_id, name) VALUES (NEW.tenant_id, left(NEW.hostname, 100))
        RETURNING id INTO NEW.device_id;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER agents_before_insert BEFORE INSERT ON openwacht.agents
    FOR EACH ROW EXECUTE FUNCTION openwacht.agents_before_insert();

-- Gerät und Adresse eines Agents ändert die Anwendung nicht.
GRANT SELECT (device_id, last_addr) ON openwacht.agents TO openwacht_app;

-- Ein Token kann an ein Gerät gebunden sein (Agent für ein bestehendes Gerät);
-- dann gilt es für genau einen Rechner. Den Mandanten setzt die Datenbank aus
-- dem Gerät; was der Aufrufer nicht sieht, findet sie nicht.
ALTER TABLE openwacht.agent_tokens ADD COLUMN device_id uuid,
    ADD CONSTRAINT agent_tokens_device_fk FOREIGN KEY (device_id, tenant_id)
        REFERENCES openwacht.devices (id, tenant_id) ON DELETE CASCADE,
    ADD CONSTRAINT agent_tokens_device_single CHECK (device_id IS NULL OR uses_left <= 1);
CREATE OR REPLACE FUNCTION openwacht.agent_tokens_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.device_id IS NOT NULL THEN
        NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'Token: Gerät nicht gefunden.' USING ERRCODE = '23503';
        END IF;
    END IF;
    NEW.created_by := openwacht.current_user_id();
    RETURN NEW;
END
$$;
GRANT SELECT (device_id), INSERT (device_id) ON openwacht.agent_tokens TO openwacht_app;

-- Token einlösen: Gerät aus dem Token, wenn es noch keinen aktiven Agent hat,
-- sonst ein neues (der Trigger oben).
CREATE OR REPLACE FUNCTION openwacht.agent_enroll(p_token_hash bytea, p_agent uuid, p_hostname text,
                                                 p_serial text, p_not_after timestamptz) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    t        openwacht.agent_tokens;
    v_device uuid;
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
    IF t.device_id IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM openwacht.agents a WHERE a.device_id = t.device_id AND a.revoked_at IS NULL) THEN
        v_device := t.device_id;
    END IF;
    INSERT INTO openwacht.agents (id, tenant_id, hostname, cert_serial, cert_not_after, device_id)
    VALUES (p_agent, t.tenant_id, p_hostname, p_serial, p_not_after, v_device)
    RETURNING device_id INTO v_device;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (t.tenant_id, 'agent.registriert',
            jsonb_build_object('agent', p_agent, 'hostname', p_hostname, 'token', t.id, 'geraet', v_device));
    RETURN t.tenant_id;
END
$$;

-- Messwerte speichern wie bisher, dazu die Absenderadresse.
DROP FUNCTION openwacht.agent_report(uuid, text, text, jsonb, text[], double precision[]);
CREATE FUNCTION openwacht.agent_report(p_agent uuid, p_serial text, p_hostname text, p_snapshot jsonb,
                                      p_series text[], p_values double precision[], p_addr inet)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
BEGIN
    IF cardinality(p_series) IS DISTINCT FROM cardinality(p_values) OR cardinality(p_series) > 100 THEN
        RAISE EXCEPTION 'agent_report: Reihen ungültig' USING ERRCODE = '22023';
    END IF;
    UPDATE openwacht.agents
       SET last_seen = now(), hostname = p_hostname, snapshot = p_snapshot,
           last_addr = coalesce(p_addr, last_addr),
           cert_serial_prev = CASE WHEN p_serial = cert_serial THEN NULL ELSE cert_serial_prev END
     WHERE id = p_agent AND revoked_at IS NULL
       AND p_serial IN (cert_serial, cert_serial_prev)
    RETURNING tenant_id INTO v_tenant;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    BEGIN
        INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
        SELECT DISTINCT ON (x.series) v_tenant, p_agent, now(), x.series, x.value
          FROM unnest(p_series, p_values) AS x(series, value);
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'Verlauf: Messwerte von Agent % nicht gespeichert: %', p_agent, SQLERRM;
    END;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_report(uuid, text, text, jsonb, text[], double precision[], inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_report(uuid, text, text, jsonb, text[], double precision[], inet) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Checks: Mandant aus dem Gerät
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.checks_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    -- Mit den Rechten des Aufrufers: ein Gerät, das er nicht sieht, gibt es nicht.
    NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Check: Gerät nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    IF (SELECT count(*) FROM openwacht.checks WHERE tenant_id = NEW.tenant_id) >= 500 THEN
        RAISE EXCEPTION 'Höchstens 500 Checks je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.revision := 1;
    NEW.next_run := now();
    NEW.status := NULL; NEW.message := NULL; NEW.metric := NULL; NEW.since := NULL;
    NEW.fails := 0; NEW.last_run := NULL;
    RETURN NEW;
END
$$;
-- Ein Check kann zu einem anderen Gerät desselben Mandanten wechseln
-- (Fremdschlüssel mit tenant_id, der Mandant ist unveränderlich).
REVOKE INSERT (tenant_id) ON openwacht.checks FROM openwacht_app;
GRANT SELECT (device_id), INSERT (device_id), UPDATE (device_id) ON openwacht.checks TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Wartung je Gerät statt je Agent
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.maintenance ADD COLUMN device_id uuid REFERENCES openwacht.devices (id) ON DELETE CASCADE;
UPDATE openwacht.maintenance m SET device_id = a.device_id
  FROM openwacht.agents a WHERE a.id = m.agent_id;
ALTER TABLE openwacht.maintenance DROP COLUMN agent_id;
ALTER TABLE openwacht.maintenance ADD CHECK ((check_id IS NULL) <> (device_id IS NULL));
CREATE UNIQUE INDEX maintenance_device ON openwacht.maintenance (device_id) WHERE device_id IS NOT NULL;
GRANT INSERT (device_id) ON openwacht.maintenance TO openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.maintenance_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF NEW.check_id IS NOT NULL THEN
        NEW.tenant_id := (SELECT c.tenant_id FROM openwacht.checks c WHERE c.id = NEW.check_id);
    ELSE
        NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
    END IF;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Wartung: Check oder Gerät nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    NEW.starts_at := now();
    NEW.created_by := uid;
    NEW.created_by_name := (SELECT u.display_name FROM openwacht.users u WHERE u.id = uid);
    RETURN NEW;
END
$$;

-- Für die Zentrale: laufende Wartungen, aufgelöst auf Checks und Agents. Ein
-- Check ist in Wartung, wenn er selbst oder sein Gerät es ist; ein Agent, wenn
-- sein Gerät es ist.
DROP FUNCTION openwacht.maintenance_active();
CREATE FUNCTION openwacht.maintenance_active()
    RETURNS TABLE (check_id uuid, agent_id uuid, ends_at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.maintenance m WHERE m.ends_at <= now();
    RETURN QUERY
        SELECT m.check_id, NULL::uuid, m.ends_at FROM openwacht.maintenance m WHERE m.check_id IS NOT NULL
        UNION ALL
        SELECT c.id, NULL::uuid, m.ends_at FROM openwacht.maintenance m JOIN openwacht.checks c ON c.device_id = m.device_id
        UNION ALL
        SELECT NULL::uuid, a.id, m.ends_at FROM openwacht.maintenance m JOIN openwacht.agents a ON a.device_id = m.device_id
        LIMIT 200000;
END
$$;
REVOKE ALL ON FUNCTION openwacht.maintenance_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.maintenance_active() TO openwacht_app;
