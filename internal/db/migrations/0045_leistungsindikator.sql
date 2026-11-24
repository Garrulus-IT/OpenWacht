-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.44.0: Sensorart „leistungsindikator“ am Windows-Agent (SwyxWare,
-- IQ4docs, IIS-Anwendungspools). Der Agent liest einen Windows-
-- Leistungsindikator nur aus Objekten, die am Rechner freigegeben sind
-- (openwacht-agent sensoren -indikatoren …); die Zentrale schickt nur Namen
-- als Daten (Leitprinzip 1). Mit Instanz „*“ meldet er nur eine Zahl,
-- nie Namen von Instanzen (Leitprinzip 5).
--
-- Keine neue Tabelle: Sensoren liegen wie alle Agent-Arten in
-- openwacht.checks (RLS unverändert); nur die Liste der Arten wächst.

CREATE OR REPLACE FUNCTION openwacht.is_agent_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('dienst', 'prozess', 'datei', 'docker', 'hyperv', 'leistungsindikator')
$$;

ALTER TABLE openwacht.checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE openwacht.checks ADD CONSTRAINT checks_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker', 'hyperv', 'leistungsindikator'));
ALTER TABLE openwacht.sensor_templates DROP CONSTRAINT sensor_templates_kind_check;
ALTER TABLE openwacht.sensor_templates ADD CONSTRAINT sensor_templates_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker', 'hyperv', 'leistungsindikator'));
