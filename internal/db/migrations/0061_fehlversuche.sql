-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Fehlversuche je Sensor. Ein Sensor meldet „kritisch“ bzw.
-- „unbekannt“ erst nach so vielen Fehlschlägen in Folge (1 bis 10); leer
-- heißt Standard der Zentrale (ab 1.0.6: 3, vorher 2). Warnungen gehen wie
-- bisher sofort raus. Eigene Sensor-Vorlagen tragen den Wert mit, beim
-- Anwenden geht er an den Sensor.

ALTER TABLE openwacht.checks ADD COLUMN fail_threshold smallint
    CHECK (fail_threshold BETWEEN 1 AND 10);
GRANT SELECT (fail_threshold), INSERT (fail_threshold), UPDATE (fail_threshold)
    ON openwacht.checks TO openwacht_app;

ALTER TABLE openwacht.sensor_templates ADD COLUMN fail_threshold smallint
    CHECK (fail_threshold BETWEEN 1 AND 10);
GRANT INSERT (fail_threshold), UPDATE (fail_threshold)
    ON openwacht.sensor_templates TO openwacht_app;

-- Wie 0022, dazu die Schwelle des Sensors (NULL = Standard).
DROP FUNCTION openwacht.alert_candidates();
CREATE FUNCTION openwacht.alert_candidates()
    RETURNS TABLE (check_id uuid, check_tenant uuid, tenant_name text, check_name text, status text,
                   message text, fails integer, channel_id uuid, alerted text, alerted_at timestamptz,
                   fail_threshold integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.tenant_id, t.name, openwacht.check_label(d.name, c.name), c.status, coalesce(c.message, ''), c.fails,
           ch.id, s.alerted, s.alerted_at, c.fail_threshold
      FROM openwacht.checks c
      JOIN openwacht.tenants t ON t.id = c.tenant_id
      LEFT JOIN openwacht.devices d ON d.id = c.device_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = c.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
      LEFT JOIN openwacht.alert_state s ON s.check_id = c.id AND s.channel_id = ch.id
     WHERE c.enabled AND c.status IS NOT NULL
       AND NOT (c.status = 'ok' AND s.alerted IS NOT DISTINCT FROM 'ok')
       AND NOT (c.status = 'ok' AND s.alerted IS NULL)
       AND NOT (c.status = 'warn' AND s.alerted IS NOT DISTINCT FROM 'warn')
     ORDER BY ch.id, c.id
     LIMIT 20000
$$;
REVOKE ALL ON FUNCTION openwacht.alert_candidates() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_candidates() TO openwacht_app;

-- Wie 0022, dazu die Schwelle des Sensors (Alarmprotokoll).
DROP FUNCTION openwacht.alarm_check_sources();
CREATE FUNCTION openwacht.alarm_check_sources()
    RETURNS TABLE (check_id uuid, name text, status text, message text, fails integer, fail_threshold integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, openwacht.check_label(d.name, c.name), c.status, coalesce(c.message, ''), c.fails, c.fail_threshold
      FROM openwacht.checks c
      LEFT JOIN openwacht.devices d ON d.id = c.device_id
     WHERE c.enabled AND c.status IS NOT NULL AND c.status <> 'ok'
     ORDER BY c.id
     LIMIT 20000
$$;
REVOKE ALL ON FUNCTION openwacht.alarm_check_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alarm_check_sources() TO openwacht_app;
