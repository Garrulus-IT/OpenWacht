-- SPDX-License-Identifier: AGPL-3.0-only

-- Ausgenommene Gegenstände ganz aus der Oberfläche entfernen.
--
-- Anlass: alte SnapMirror-Beziehungen einer NetApp. Ausgenommen melden sie
-- keine Alarme mehr, stehen aber weiter grau in jeder Liste. Löschen lässt
-- sich ein solcher Wert nicht, weil die Quelle ihn bei jeder Abfrage wieder
-- meldet. „Entfernt“ ist deshalb eine Ausnahme, die zusätzlich ausgeblendet
-- wird: kein Alarm, keine Zeile bei den Sensoren, im Dashboard und auf
-- Wandanzeigen. Am Gerät bleibt eine Liste der entfernten Werte mit
-- Begründung, von dort kommen sie zurück.
--
-- Rechte wie bei den Ausnahmen (0048).

ALTER TABLE openwacht.snmp_exclusions ADD COLUMN hidden boolean NOT NULL DEFAULT false;
GRANT INSERT (hidden), UPDATE (hidden) ON openwacht.snmp_exclusions TO openwacht_app;

-- Für Sensorlisten ohne Leserecht auf die Tabelle (Wandanzeigen): nur Quelle
-- und Gegenstand, wie snmp_exclusions_all().
CREATE FUNCTION openwacht.snmp_hidden_all() RETURNS TABLE (snmp_id uuid, subject text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT e.snmp_id, e.subject FROM openwacht.snmp_exclusions e
     WHERE e.hidden
       AND ((openwacht.current_user_id() IS NULL AND openwacht.current_display_id() IS NULL)
            OR e.tenant_id IN (SELECT openwacht.visible_tenants())
            OR e.tenant_id IN (SELECT openwacht.display_tenants()))
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_hidden_all() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_hidden_all() TO openwacht_app;
