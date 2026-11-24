-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 24: Abhängigkeiten zwischen Geräten, Eskalation und Bereitschaft.
--
-- Entscheidungen (22.11.2026):
-- - Ein Gerät kann von einem Elterngerät abhängen (gleicher Mandant, keine
--   Zyklen). Ist das Elterngerät nicht erreichbar (offener kritischer Alarm:
--   Ping-Check, Agent stumm oder Abfragequelle stumm), gehen für die Geräte
--   darunter keine neuen Alarme raus; die Oberfläche zeigt „nicht erreichbar
--   wegen …“.
-- - Eskalation je Kanal: unbestätigt nach N Minuten zusätzlich an einen
--   weiteren Kanal desselben Mandanten.
-- - Bereitschaft je Kanal: Wochentage und Uhrzeit (Zeitzone der Installation);
--   außerhalb wartet der Kanal, bis sein Zeitfenster beginnt.

-- --- Abhängigkeiten -----------------------------------------------------------------

ALTER TABLE openwacht.devices ADD COLUMN parent_id uuid;
ALTER TABLE openwacht.devices ADD CONSTRAINT devices_parent_fk FOREIGN KEY (parent_id, tenant_id)
    REFERENCES openwacht.devices (id, tenant_id) ON DELETE SET NULL (parent_id);
ALTER TABLE openwacht.devices ADD CONSTRAINT devices_parent_self CHECK (parent_id IS NULL OR parent_id <> id);
CREATE INDEX devices_parent ON openwacht.devices (parent_id) WHERE parent_id IS NOT NULL;
GRANT SELECT (parent_id), INSERT (parent_id), UPDATE (parent_id) ON openwacht.devices TO openwacht_app;

CREATE FUNCTION openwacht.devices_parent_check() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE cur uuid := NEW.parent_id; n int := 0;
BEGIN
    WHILE cur IS NOT NULL LOOP
        IF cur = NEW.id THEN
            RAISE EXCEPTION 'Diese Abhängigkeit ergäbe einen Kreis.' USING ERRCODE = '23514';
        END IF;
        n := n + 1;
        IF n > 20 THEN
            RAISE EXCEPTION 'Höchstens 20 Ebenen von Abhängigkeiten.' USING ERRCODE = '23514';
        END IF;
        SELECT d.parent_id INTO cur FROM openwacht.devices d WHERE d.id = cur;
    END LOOP;
    RETURN NEW;
END
$$;
CREATE TRIGGER devices_parent_check BEFORE INSERT OR UPDATE OF parent_id ON openwacht.devices
    FOR EACH ROW WHEN (NEW.parent_id IS NOT NULL) EXECUTE FUNCTION openwacht.devices_parent_check();

-- Nicht erreichbare Geräte: offener kritischer Alarm zur Erreichbarkeit.
CREATE FUNCTION openwacht.devices_down() RETURNS TABLE (device_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.device_id FROM openwacht.alarms a JOIN openwacht.checks c ON c.id = a.check_id
     WHERE a.ended_at IS NULL AND a.status = 'crit' AND c.kind = 'ping' AND c.device_id IS NOT NULL
    UNION
    SELECT g.device_id FROM openwacht.alarms a JOIN openwacht.agents g ON g.id = a.agent_id
     WHERE a.ended_at IS NULL AND a.status = 'crit' AND a.subject = 'stumm' AND g.device_id IS NOT NULL
    UNION
    SELECT s.device_id FROM openwacht.alarms a JOIN openwacht.snmp_sources s ON s.id = a.snmp_id
     WHERE a.ended_at IS NULL AND a.status = 'crit' AND a.subject = 'stumm' AND s.device_id IS NOT NULL
$$;

-- Geräte unter einem nicht erreichbaren Gerät, mit dem obersten Ausfall.
CREATE FUNCTION openwacht.devices_blocked() RETURNS TABLE (device_id uuid, blocker_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH RECURSIVE down AS (SELECT device_id FROM openwacht.devices_down()),
    walk AS (
        SELECT d.id AS device_id, d.parent_id AS blocker_id, 1 AS depth
          FROM openwacht.devices d JOIN down ON down.device_id = d.parent_id
        UNION
        SELECT d.id, w.blocker_id, w.depth + 1
          FROM openwacht.devices d JOIN walk w ON d.parent_id = w.device_id
         WHERE w.depth < 20
    )
    SELECT DISTINCT ON (device_id) device_id, blocker_id FROM walk ORDER BY device_id, depth DESC
$$;

-- Für den Alarmdurchlauf: Checks, Agents und Quellen gesperrter Geräte.
CREATE FUNCTION openwacht.dependency_suppressed() RETURNS TABLE (check_id uuid, agent_id uuid, snmp_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, NULL::uuid, NULL::uuid FROM openwacht.checks c JOIN openwacht.devices_blocked() b ON b.device_id = c.device_id
    UNION ALL
    SELECT NULL, g.id, NULL FROM openwacht.agents g JOIN openwacht.devices_blocked() b ON b.device_id = g.device_id
    UNION ALL
    SELECT NULL, NULL, s.id FROM openwacht.snmp_sources s JOIN openwacht.devices_blocked() b ON b.device_id = s.device_id
$$;

-- --- Eskalation und Bereitschaft -------------------------------------------------------

ALTER TABLE openwacht.alert_channels
    ADD COLUMN escalate_after_min integer CHECK (escalate_after_min BETWEEN 5 AND 1440),
    ADD COLUMN escalate_channel_id uuid,
    -- Bereitschaft: {"tage":[1..7], "von":"HH:MM", "bis":"HH:MM"}; NULL = immer
    ADD COLUMN active_hours jsonb CHECK (active_hours IS NULL OR (jsonb_typeof(active_hours) = 'object'
                                          AND octet_length(active_hours::text) <= 200)),
    ADD CONSTRAINT alert_channels_escalation CHECK ((escalate_after_min IS NULL) = (escalate_channel_id IS NULL)),
    ADD CONSTRAINT alert_channels_escalate_self CHECK (escalate_channel_id IS NULL OR escalate_channel_id <> id);
ALTER TABLE openwacht.alert_channels ADD CONSTRAINT alert_channels_escalate_fk FOREIGN KEY (escalate_channel_id, tenant_id)
    REFERENCES openwacht.alert_channels (id, tenant_id) ON DELETE SET NULL (escalate_channel_id);
GRANT SELECT (escalate_after_min, escalate_channel_id, active_hours),
      INSERT (escalate_after_min, escalate_channel_id, active_hours),
      UPDATE (escalate_after_min, escalate_channel_id, active_hours) ON openwacht.alert_channels TO openwacht_app;

-- Wird der Zielkanal gelöscht, entfällt auch die Wartezeit (CHECK oben).
CREATE FUNCTION openwacht.alert_channels_escalation_clear() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.escalate_channel_id IS NULL THEN
        NEW.escalate_after_min := NULL;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER alert_channels_escalation_clear BEFORE UPDATE OF escalate_channel_id ON openwacht.alert_channels
    FOR EACH ROW EXECUTE FUNCTION openwacht.alert_channels_escalation_clear();

CREATE TABLE openwacht.alarm_escalations (
    alarm_id   uuid NOT NULL REFERENCES openwacht.alarms (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES openwacht.alert_channels (id) ON DELETE CASCADE,
    sent_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (alarm_id, channel_id)
);
ALTER TABLE openwacht.alarm_escalations ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON openwacht.alarm_escalations TO openwacht_app;
CREATE POLICY alarm_escalations_select ON openwacht.alarm_escalations FOR SELECT TO openwacht_app
    USING (EXISTS (SELECT 1 FROM openwacht.alert_channels c WHERE c.id = channel_id));

-- Fällige Eskalationen (ohne Benutzerkontext, im Alarmdurchlauf).
CREATE FUNCTION openwacht.escalation_candidates()
    RETURNS TABLE (alarm_id uuid, channel_id uuid, from_channel text, tenant_name text, name text, status text,
                   message text, started_at timestamptz, check_id uuid, agent_id uuid, snmp_id uuid, subject text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT DISTINCT ON (a.id, e.id) a.id, e.id, c.name, t.name, a.name, a.status, a.message, a.started_at,
           a.check_id, a.agent_id, a.snmp_id, a.subject
      FROM openwacht.alarms a
      JOIN openwacht.tenants t ON t.id = a.tenant_id
      JOIN openwacht.alert_channels c ON c.escalate_channel_id IS NOT NULL AND c.enabled
      JOIN openwacht.alert_channels e ON e.id = c.escalate_channel_id AND e.enabled
     WHERE a.ended_at IS NULL AND a.ack_at IS NULL AND a.status IN ('crit', 'unknown', 'warn')
       AND a.started_at < now() - make_interval(mins => c.escalate_after_min)
       AND ((a.check_id IS NOT NULL AND EXISTS (SELECT 1 FROM openwacht.alert_state s
                 WHERE s.check_id = a.check_id AND s.channel_id = c.id AND s.alerted <> 'ok'))
         OR (a.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM openwacht.alert_state_agents s
                 WHERE s.agent_id = a.agent_id AND s.subject = a.subject AND s.channel_id = c.id))
         OR (a.snmp_id IS NOT NULL AND EXISTS (SELECT 1 FROM openwacht.alert_state_snmp s
                 WHERE s.snmp_id = a.snmp_id AND s.subject = a.subject AND s.channel_id = c.id)))
       AND NOT EXISTS (SELECT 1 FROM openwacht.alarm_escalations x WHERE x.alarm_id = a.id AND x.channel_id = e.id)
     ORDER BY a.id, e.id, c.name
$$;

CREATE FUNCTION openwacht.escalation_sent(p_alarms uuid[], p_channel uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    INSERT INTO openwacht.alarm_escalations (alarm_id, channel_id)
    SELECT x, p_channel FROM unnest(p_alarms) x ON CONFLICT DO NOTHING
$$;

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['devices_down()', 'devices_blocked()', 'dependency_suppressed()',
        'escalation_candidates()', 'escalation_sent(uuid[], uuid)'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION openwacht.%s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION openwacht.%s TO openwacht_app', f);
    END LOOP;
END $$;

-- Bereitschaft der Kanäle für den Alarmdurchlauf (ohne Benutzerkontext).
CREATE FUNCTION openwacht.alert_channel_hours(p_ids uuid[]) RETURNS TABLE (id uuid, active_hours jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.active_hours FROM openwacht.alert_channels c WHERE c.id = ANY (p_ids) AND c.active_hours IS NOT NULL
$$;
REVOKE ALL ON FUNCTION openwacht.alert_channel_hours(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_channel_hours(uuid[]) TO openwacht_app;
