-- SPDX-License-Identifier: AGPL-3.0-only

-- 0010: Wartungsmodus und CPU-Alarm.
--
-- Wartung: je Host (Agent) oder je Check höchstens eine laufende Wartung mit
-- festem Ende (höchstens 7 Tage). Messungen laufen weiter; die Zentrale
-- meldet in der Zeit keine neuen Probleme und keine Erinnerungen und eröffnet
-- keine neuen Alarme im Protokoll. Entwarnungen gehen weiter raus. Besteht das
-- Problem nach dem Ende, meldet der nächste Alarmdurchlauf es sofort.
--
-- Den Mandanten, die Startzeit und die Person setzt die Datenbank selbst
-- (Leitprinzip 2): Der Mandant ergibt sich aus Check bzw. Agent, nicht aus der
-- Anfrage. Setzen und beenden dürfen Admins und Operatoren (RLS), sehen alle
-- im sichtbaren Teilbaum. Eine Wartung lässt sich nicht ändern, nur beenden
-- und neu setzen. Abgelaufene Einträge räumt die Zentrale ab; die Geschichte
-- steht im Audit-Log.
--
-- CPU: Mittelwert der CPU-Auslastung über 15 Minuten aus metrics_host_raw.
-- Bewertet wird erst, wenn die Werte mindestens 10 Minuten zurückreichen, damit
-- ein frisch gestarteter Agent nicht mit einem einzelnen Wert alarmiert.

CREATE TABLE openwacht.maintenance (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    check_id        uuid REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    agent_id        uuid REFERENCES openwacht.agents (id) ON DELETE CASCADE,
    starts_at       timestamptz NOT NULL DEFAULT now(),
    ends_at         timestamptz NOT NULL,
    reason          text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 200 AND reason !~ '[[:cntrl:]]'),
    created_by      uuid REFERENCES openwacht.users (id) ON DELETE SET NULL,
    created_by_name text CHECK (char_length(created_by_name) <= 100),
    CHECK ((check_id IS NULL) <> (agent_id IS NULL)),
    CHECK (ends_at > starts_at AND ends_at <= starts_at + interval '7 days')
);
CREATE UNIQUE INDEX maintenance_check ON openwacht.maintenance (check_id) WHERE check_id IS NOT NULL;
CREATE UNIQUE INDEX maintenance_agent ON openwacht.maintenance (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX maintenance_tenant ON openwacht.maintenance (tenant_id);

-- Mandant, Start und Person aus der Datenbank. Die Abfrage auf Check bzw.
-- Agent läuft mit den Rechten des Aufrufers: Was er nicht sieht, findet sie
-- nicht, und der Eintrag scheitert.
CREATE FUNCTION openwacht.maintenance_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF NEW.check_id IS NOT NULL THEN
        NEW.tenant_id := (SELECT c.tenant_id FROM openwacht.checks c WHERE c.id = NEW.check_id);
    ELSE
        NEW.tenant_id := (SELECT a.tenant_id FROM openwacht.agents a WHERE a.id = NEW.agent_id AND a.revoked_at IS NULL);
    END IF;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Wartung: Check oder Host nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    NEW.starts_at := now();
    NEW.created_by := uid;
    NEW.created_by_name := (SELECT u.display_name FROM openwacht.users u WHERE u.id = uid);
    RETURN NEW;
END
$$;
CREATE TRIGGER maintenance_before_insert BEFORE INSERT ON openwacht.maintenance
    FOR EACH ROW EXECUTE FUNCTION openwacht.maintenance_before_insert();

ALTER TABLE openwacht.maintenance ENABLE ROW LEVEL SECURITY;
GRANT SELECT, DELETE ON openwacht.maintenance TO openwacht_app;
GRANT INSERT (check_id, agent_id, ends_at, reason) ON openwacht.maintenance TO openwacht_app;
CREATE POLICY maintenance_select ON openwacht.maintenance FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY maintenance_insert ON openwacht.maintenance FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY maintenance_delete ON openwacht.maintenance FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- Für die Zentrale (ohne Benutzerkontext): laufende Wartungen; abgelaufene
-- werden dabei gelöscht.
CREATE FUNCTION openwacht.maintenance_active()
    RETURNS TABLE (check_id uuid, agent_id uuid, ends_at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.maintenance m WHERE m.ends_at <= now();
    RETURN QUERY SELECT m.check_id, m.agent_id, m.ends_at FROM openwacht.maintenance m ORDER BY m.id LIMIT 200000;
END
$$;
REVOKE ALL ON FUNCTION openwacht.maintenance_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.maintenance_active() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- CPU
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.alert_state_agents DROP CONSTRAINT alert_state_agents_subject_check;
ALTER TABLE openwacht.alert_state_agents ADD CONSTRAINT alert_state_agents_subject_check
    CHECK (char_length(subject) <= 300 AND subject !~ '[[:cntrl:]]'
           AND (subject IN ('stumm', 'speicher', 'cpu') OR subject ~ '^platte:.'));
ALTER TABLE openwacht.alarms DROP CONSTRAINT alarms_subject_check;
ALTER TABLE openwacht.alarms ADD CONSTRAINT alarms_subject_check
    CHECK (char_length(subject) <= 300 AND subject !~ '[[:cntrl:]]'
           AND (subject IN ('check', 'stumm', 'speicher', 'cpu') OR subject ~ '^platte:.'));

-- Mittel der CPU-Auslastung der letzten 15 Minuten, NULL ohne ausreichende
-- Werte. Mit den Rechten des Aufrufers (RLS auf metrics_host_raw).
CREATE FUNCTION openwacht.agent_cpu15(p_agent uuid) RETURNS double precision
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT avg(r.value)
      FROM openwacht.metrics_host_raw r
     WHERE r.agent_id = p_agent AND r.series = 'cpu' AND r.ts > now() - interval '15 minutes'
    HAVING min(r.ts) <= now() - interval '10 minutes'
$$;

-- Messwerte für die Alarme: wie bisher Speicher und Platten, dazu cpu15.
CREATE FUNCTION openwacht.agent_alarm_metrics(p_agent uuid, p_snapshot jsonb) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE WHEN p_snapshot IS NULL THEN NULL
                ELSE jsonb_build_object('speicher', p_snapshot -> 'speicher', 'platten', p_snapshot -> 'platten',
                                        'cpu15', openwacht.agent_cpu15(p_agent)) END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_cpu15(uuid), openwacht.agent_alarm_metrics(uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_cpu15(uuid), openwacht.agent_alarm_metrics(uuid, jsonb) TO openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.alert_host_candidates()
    RETURNS TABLE (agent_id uuid, agent_tenant uuid, tenant_name text, hostname text, revoked boolean,
                   silent_s double precision, metrics jsonb, channels uuid[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.id, a.tenant_id, t.name, a.hostname, a.revoked_at IS NOT NULL,
           extract(epoch FROM now() - coalesce(a.last_seen, a.created_at))::double precision,
           openwacht.agent_alarm_metrics(a.id, a.snapshot),
           array_agg(ch.id ORDER BY ch.id)
      FROM openwacht.agents a
      JOIN openwacht.tenants t ON t.id = a.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = a.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
     WHERE a.revoked_at IS NULL
        OR EXISTS (SELECT 1 FROM openwacht.alert_state_agents s WHERE s.agent_id = a.id)
     GROUP BY a.id, t.name
     ORDER BY a.id
     LIMIT 20000
$$;

CREATE OR REPLACE FUNCTION openwacht.alarm_host_sources()
    RETURNS TABLE (agent_id uuid, hostname text, silent_s double precision, metrics jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.id, a.hostname,
           extract(epoch FROM now() - coalesce(a.last_seen, a.created_at))::double precision,
           openwacht.agent_alarm_metrics(a.id, a.snapshot)
      FROM openwacht.agents a
     WHERE a.revoked_at IS NULL
     ORDER BY a.id
     LIMIT 20000
$$;
