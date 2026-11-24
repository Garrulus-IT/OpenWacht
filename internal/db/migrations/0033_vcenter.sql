-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 26: vCenter als Abfragequelle (version = 'vcenter'), aufgebaut wie
-- Proxmox. Wechsel der Art verwirft die Zugangsdaten (Trigger wie 0022).

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_version_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_version_check
    CHECK (version IN ('1', '2c', '3', 'pve', 'tr064', 'vcenter'));
-- eigene CA wie bei Proxmox
ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_ca_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_ca_check CHECK (
    ca_pem IS NULL OR (version IN ('pve', 'vcenter') AND octet_length(ca_pem) BETWEEN 64 AND 16384
                       AND ca_pem ~ '^-----BEGIN CERTIFICATE-----' AND ca_pem !~ 'PRIVATE KEY'));
-- vCenter fragt nur die Zentrale ab, nie ein Sammler
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_vcenter_collector
    CHECK (version <> 'vcenter' OR collector_id IS NULL);

CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064' WHEN 'vcenter' THEN 'vcenter' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064' WHEN 'vcenter' THEN 'vcenter' ELSE 'v1' END;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id THEN
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

-- Hyper-V-Sensor am Windows-Agent (Art hyperv): nur Name und Zustand der VMs.
CREATE OR REPLACE FUNCTION openwacht.is_agent_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('dienst', 'prozess', 'datei', 'docker', 'hyperv')
$$;

ALTER TABLE openwacht.checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE openwacht.checks ADD CONSTRAINT checks_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker', 'hyperv'));
ALTER TABLE openwacht.sensor_templates DROP CONSTRAINT sensor_templates_kind_check;
ALTER TABLE openwacht.sensor_templates ADD CONSTRAINT sensor_templates_kind_check
    CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                    'dienst', 'prozess', 'datei', 'docker', 'hyperv'));
