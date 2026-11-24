-- SPDX-License-Identifier: AGPL-3.0-only

-- 0021: weitere Sensorarten (Etappe 18b).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * tcp_banner: erste Zeile eines Dienstes (SMTP, IMAP, SSH, FTP), im
--     Klartext oder mit direktem TLS; der Text wird nur verglichen.
--   * ntp: Abweichung zur Uhr der Zentrale und Stratum.
--   * snmp_oid: Wert einer eigenen OID. Gelesen mit der normalen SNMP-Abfrage
--     des Geräts (Zentrale oder Sammler), deshalb führt der Planer der Checks
--     sie nicht aus. Texte speichert die Abfrage nur als Hash.
--   * docker (Agent): Container läuft, nur über einen lokalen, nur-lesenden
--     Socket-Proxy, den der Admin des Rechners freigibt.

CREATE OR REPLACE FUNCTION openwacht.is_agent_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('dienst', 'prozess', 'datei', 'docker')
$$;

ALTER TABLE openwacht.checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE openwacht.checks ADD CONSTRAINT checks_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker'));
ALTER TABLE openwacht.sensor_templates DROP CONSTRAINT sensor_templates_kind_check;
ALTER TABLE openwacht.sensor_templates ADD CONSTRAINT sensor_templates_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker'));

-- snmp_oid nur an Geräten mit SNMP-Abfrage (nicht Proxmox), höchstens 32 je
-- Gerät (so viele OIDs liest eine Abfrage zusätzlich). Mit den Rechten des
-- Aufrufers wie checks_zz_agent_device.
CREATE FUNCTION openwacht.checks_zz_snmp_device() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind <> 'snmp_oid' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM openwacht.snmp_sources s
                    WHERE s.device_id = NEW.device_id AND s.tenant_id = NEW.tenant_id AND s.version IN ('1', '2c', '3')) THEN
        RAISE EXCEPTION 'SNMP-Sensoren brauchen ein Gerät mit SNMP-Abfrage.' USING ERRCODE = '23514';
    END IF;
    IF (SELECT count(*) FROM openwacht.checks c
         WHERE c.device_id = NEW.device_id AND c.kind = 'snmp_oid' AND c.id <> NEW.id) >= 32 THEN
        RAISE EXCEPTION 'Höchstens 32 SNMP-Sensoren je Gerät.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER checks_zz_snmp_device BEFORE INSERT OR UPDATE OF kind, device_id ON openwacht.checks
    FOR EACH ROW EXECUTE FUNCTION openwacht.checks_zz_snmp_device();

-- Planer der Zentrale: weder Agent- noch SNMP-Sensoren.
CREATE OR REPLACE FUNCTION openwacht.checks_claim(p_limit integer)
    RETURNS TABLE (id uuid, kind text, target jsonb, revision integer)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.checks c SET next_run = now() + interval '2 minutes'
     WHERE c.id IN (SELECT d.id FROM openwacht.checks d
                     WHERE d.enabled AND d.next_run <= now() AND NOT openwacht.is_agent_kind(d.kind)
                       AND d.kind <> 'snmp_oid'
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING c.id, c.kind, c.target, c.revision
$$;

-- OID-Sensoren der Geräte dieser Quellen (für die Abfrage durch Zentrale oder
-- Sammler, ohne Benutzerkontext). Nur Gerät und Mandant der Quelle.
CREATE FUNCTION openwacht.snmp_oid_checks(p_sources uuid[])
    RETURNS TABLE (source_id uuid, id uuid, revision integer, target jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, c.id, c.revision, c.target
      FROM openwacht.snmp_sources s
      JOIN openwacht.checks c ON c.device_id = s.device_id AND c.tenant_id = s.tenant_id
     WHERE s.id = ANY (p_sources) AND s.version IN ('1', '2c', '3')
       AND c.kind = 'snmp_oid' AND c.enabled
     ORDER BY s.id, c.created_at, c.id
     LIMIT 16000
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_oid_checks(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_oid_checks(uuid[]) TO openwacht_app;
