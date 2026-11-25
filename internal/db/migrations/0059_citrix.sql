-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.6: Citrix Monitor Service (OData v4) als Abfragequelle (version =
-- 'citrix'), aufgebaut wie XenServer (0043): Benutzer, Passwort und
-- Fingerabdruck des Controllers verschlüsselt in secret_enc, keine CA, keine
-- Traps, kein Sammler (die bestehenden CHECKs erlauben beides nur für SNMP).
-- Wechsel der Art verwirft die Zugangsdaten (Trigger wie 0043/0058).
--
-- Neue Gegenstände für Alarme: 'citrixvda' (nicht registrierte VDAs) und
-- 'citrixfehler' (fehlgeschlagene Verbindungen der letzten Stunde).

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_version_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_version_check
    CHECK (version IN ('1', '2c', '3', 'pve', 'tr064', 'vcenter', 'ontap', 'xapi', 'citrix'));

CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064'
                            WHEN 'vcenter' THEN 'vcenter' WHEN 'ontap' THEN 'ontap' WHEN 'xapi' THEN 'xapi' WHEN 'citrix' THEN 'citrix' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064'
                            WHEN 'vcenter' THEN 'vcenter' WHEN 'ontap' THEN 'ontap' WHEN 'xapi' THEN 'xapi' WHEN 'citrix' THEN 'citrix' ELSE 'v1' END;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.device_id IS DISTINCT FROM OLD.device_id
       OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id AND NOT openwacht.moving()) THEN
        RAISE EXCEPTION 'ID, Gerät und Mandant einer SNMP-Quelle sind unveränderlich.';
    END IF;
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
        OR v_kind_new IS DISTINCT FROM v_kind_old
        OR NEW.v3_auth IS DISTINCT FROM OLD.v3_auth OR NEW.v3_priv IS DISTINCT FROM OLD.v3_priv
        OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem)
       AND NEW.secret_enc IS NOT DISTINCT FROM OLD.secret_enc THEN
        NEW.secret_enc := NULL;
    END IF;
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
        OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc)
       AND NEW.trap_secret_enc IS NOT DISTINCT FROM OLD.trap_secret_enc THEN
        NEW.trap_secret_enc := NULL;
    END IF;
    IF NOT NEW.traps OR NEW.secret_enc IS NULL THEN
        NEW.trap_secret_enc := NULL;
    END IF;
    IF NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
       OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc
       OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem OR NEW.collector_id IS DISTINCT FROM OLD.collector_id THEN
        NEW.revision := OLD.revision + 1;
        NEW.changed_at := now(); NEW.next_run := now();
        NEW.last_try := NULL; NEW.last_ok := NULL; NEW.last_error := NULL;
        NEW.snapshot := NULL; NEW.rebooted_at := NULL; NEW.poll_requested_at := NULL;
    ELSIF NEW.enabled AND NOT OLD.enabled THEN
        NEW.next_run := now(); NEW.changed_at := now();
    ELSIF NEW.interval_s < OLD.interval_s THEN
        NEW.next_run := least(NEW.next_run, now() + make_interval(secs => NEW.interval_s));
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.valid_snmp_subject(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('stumm', 'speicher', 'cpu', 'neustart', 'system', 'temperatur', 'usv', 'wan', 'platten',
                      'xenha', 'xenupdates', 'citrixvda', 'citrixfehler')
                OR s ~ '^(platte|if|laufwerk|raid|toner|meta|pvespeicher):.'
                OR s ~ '^(knoten|aggregat|volume|shelf|snapmirror|ems):.'
                OR s ~ '^(xenhost|xencpu|xenram|xensr):.'
                OR s ~ '^xenvm:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                OR s ~ '^(gast|backup):[1-9][0-9]{2,8}$'
                OR s ~ '^trap:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(:.+)?$')
$$;
