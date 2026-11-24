-- SPDX-License-Identifier: AGPL-3.0-only

-- 0014: Proxmox VE als zweite Art einer Abfragequelle.
--
-- Eine Proxmox-Quelle ist eine Zeile in snmp_sources mit version = 'pve'.
-- So gelten Mandant, RLS, Rechte (nur Admins pflegen), Planer, Verlauf,
-- Alarme, Alarmprotokoll und Wartung unverändert auch für Proxmox. Je Gerät
-- gibt es weiterhin höchstens eine Abfragequelle.
--
-- Das API-Token (USER@REALM!TOKENID=UUID) liegt wie die Community
-- verschlüsselt in secret_enc, gebunden an Quelle, Mandant, Adresse, Port und
-- die hinterlegte CA. ca_pem ist das öffentliche CA-Zertifikat des Hosts
-- (/etc/pve/pve-root-ca.pem); NULL = System-CAs. Ändert sich Art, Adresse,
-- Port oder CA ohne neues Token, wird das alte verworfen: Sonst ließe es sich
-- an ein fremdes Ziel umleiten.
--
-- Neue Gegenstände: 'gast:<vmid>' (läuft nicht), 'backup:<vmid>' (Alter des
-- letzten Backups), 'meta:<vg>/<lv>' (Metadaten eines Thin-Pools),
-- 'pvespeicher:<name>' (Speicher nicht verfügbar). Speicherbelegung kommt
-- als 'platte:<name>', neue Verlaufsreihe 'meta:<vg>/<lv>'.

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_version_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_version_check CHECK (version IN ('1', '2c', 'pve'));
ALTER TABLE openwacht.snmp_sources ADD COLUMN ca_pem text;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_ca_check CHECK (
    ca_pem IS NULL OR (version = 'pve' AND octet_length(ca_pem) BETWEEN 64 AND 16384
                       AND ca_pem ~ '^-----BEGIN CERTIFICATE-----' AND ca_pem !~ 'PRIVATE KEY'));

GRANT SELECT (ca_pem), INSERT (ca_pem), UPDATE (ca_pem) ON openwacht.snmp_sources TO openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id THEN
        RAISE EXCEPTION 'ID, Gerät und Mandant einer SNMP-Quelle sind unveränderlich.';
    END IF;
    -- Zugangsdaten gelten nur für Art, Adresse, Port und CA, für die sie
    -- eingegeben wurden.
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
        OR (NEW.version = 'pve') IS DISTINCT FROM (OLD.version = 'pve')
        OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem)
       AND NEW.secret_enc IS NOT DISTINCT FROM OLD.secret_enc THEN
        NEW.secret_enc := NULL;
    END IF;
    IF NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
       OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc
       OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem THEN
        NEW.revision := OLD.revision + 1;
        NEW.changed_at := now(); NEW.next_run := now();
        NEW.last_try := NULL; NEW.last_ok := NULL; NEW.last_error := NULL;
        NEW.snapshot := NULL; NEW.rebooted_at := NULL;
    ELSIF NEW.enabled AND NOT OLD.enabled THEN
        NEW.next_run := now(); NEW.changed_at := now();
    ELSIF NEW.interval_s < OLD.interval_s THEN
        NEW.next_run := least(NEW.next_run, now() + make_interval(secs => NEW.interval_s));
    END IF;
    RETURN NEW;
END
$$;

-- Planer: zusätzlich die CA.
DROP FUNCTION openwacht.snmp_claim(integer);
CREATE FUNCTION openwacht.snmp_claim(p_limit integer)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, host text, port integer, secret_enc bytea,
                   revision integer, snapshot jsonb, ca_pem text)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.snmp_sources s SET next_run = now() + interval '2 minutes'
     WHERE s.id IN (SELECT d.id FROM openwacht.snmp_sources d
                     WHERE d.enabled AND d.next_run <= now()
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING s.id, s.tenant_id, s.version, s.host, s.port, s.secret_enc, s.revision, s.snapshot, s.ca_pem
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_claim(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_claim(integer) TO openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.valid_snmp_series(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('cpu', 'speicher', 'temperatur', 'usv_ladung') OR s ~ '^(platte|if_ein|if_aus|toner|meta):.')
$$;

CREATE OR REPLACE FUNCTION openwacht.valid_snmp_subject(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('stumm', 'speicher', 'cpu', 'neustart', 'system', 'temperatur', 'usv')
                OR s ~ '^(platte|if|laufwerk|raid|toner|meta|pvespeicher):.'
                OR s ~ '^(gast|backup):[1-9][0-9]{2,8}$')
$$;

-- Alarme und Alarmprotokoll: zusätzlich die Art der Quelle (für die Texte).
DROP FUNCTION openwacht.alert_snmp_candidates();
CREATE FUNCTION openwacht.alert_snmp_candidates()
    RETURNS TABLE (snmp_id uuid, tenant_name text, name text, disabled boolean, silent_s double precision,
                   interval_s integer, last_error text, snapshot jsonb, cpu15 double precision,
                   rebooted_s double precision, watched text[], channels uuid[], version text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, t.name, d.name, NOT s.enabled,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched,
           array_agg(ch.id ORDER BY ch.id), s.version
      FROM openwacht.snmp_sources s
      JOIN openwacht.devices d ON d.id = s.device_id
      JOIN openwacht.tenants t ON t.id = s.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = s.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
     WHERE s.enabled OR EXISTS (SELECT 1 FROM openwacht.alert_state_snmp x WHERE x.snmp_id = s.id)
     GROUP BY s.id, t.name, d.name
     ORDER BY s.id
     LIMIT 20000
$$;

DROP FUNCTION openwacht.alarm_snmp_sources();
CREATE FUNCTION openwacht.alarm_snmp_sources()
    RETURNS TABLE (snmp_id uuid, name text, silent_s double precision, interval_s integer, last_error text,
                   snapshot jsonb, cpu15 double precision, rebooted_s double precision, watched text[], version text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, d.name,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched, s.version
      FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
     WHERE s.enabled
     ORDER BY s.id
     LIMIT 20000
$$;

REVOKE ALL ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() TO openwacht_app;
