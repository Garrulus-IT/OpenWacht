-- SPDX-License-Identifier: AGPL-3.0-only

-- 0022: Namen je Gerät und FRITZ!Box über TR-064 (Etappe 18c).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * Der Name eines Checks bzw. Sensors ist nicht mehr Pflicht. Bleibt er
--     leer, bildet die Zentrale ihn aus Art und Ziel („Ping“, „TCP 53“) und
--     hängt bei Bedarf eine Nummer an („Ping 2“). Ein selbst eingetippter
--     Name, den es am Gerät schon gibt, wird abgelehnt (409).
--   * Eindeutig ist der Name je Gerät statt je Mandant. Alarme, ntfy und das
--     Alarmprotokoll zeigen deshalb „Gerät · Sensor“ (check_label).
--   * Vorlagen legen den Sensor unter dem Namen der Vorlage an („Ping“ statt
--     „pve-1 Ping“). Bestehende Namen dieser Form werden hier gekürzt, wenn der
--     kurze Name am Gerät frei ist.
--   * FRITZ!Box: Abfragequelle mit version = 'tr064' (wie Proxmox als 'pve').
--     Benutzer, Passwort und der Fingerabdruck des TLS-Zertifikats liegen
--     verschlüsselt in secret_enc, gebunden an Quelle, Mandant, Adresse und
--     Port. Die Zentrale ruft nur eine feste Liste lesender Aktionen auf.
--   * Neuer Gegenstand 'wan' (Internetverbindung getrennt), neue
--     Verlaufsreihen 'dsl_ab' und 'dsl_auf' (Synchronrate in bit/s).

-- ---------------------------------------------------------------------------
-- Namen je Gerät
-- ---------------------------------------------------------------------------

-- Vorher je Mandant eindeutig, also auch je Gerät: Der neue Index entsteht
-- immer ohne Konflikt.
CREATE UNIQUE INDEX checks_device_name ON openwacht.checks (device_id, lower(name));
DROP INDEX openwacht.checks_name;

-- „<Gerät> <Vorlage>“ → „<Vorlage>“, wenn der kurze Name am Gerät frei ist.
-- Zwei Sensoren eines Geräts mit derselben Vorlage können nicht beide so
-- heißen (die Namen waren eindeutig), deshalb kollidiert die Änderung nicht.
UPDATE openwacht.checks c
   SET name = c.origin
  FROM openwacht.devices d
 WHERE d.id = c.device_id AND c.origin IS NOT NULL
   AND char_length(c.origin) BETWEEN 1 AND 100
   AND lower(c.name) = lower(left(d.name || ' ' || c.origin, 100))
   AND NOT EXISTS (SELECT 1 FROM openwacht.checks o
                    WHERE o.device_id = c.device_id AND o.id <> c.id AND lower(o.name) = lower(c.origin));

-- Anzeigename für Alarme: „Gerät · Sensor“, ohne den Gerätenamen zu doppeln,
-- wenn der Name schon damit beginnt (ältere Namen wie „pve-1 Ping“).
CREATE FUNCTION openwacht.check_label(p_device text, p_check text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT CASE
        WHEN coalesce(p_device, '') = '' THEN p_check
        WHEN lower(p_check) = lower(p_device) THEN p_check
        WHEN lower(left(p_check, char_length(p_device) + 1)) = lower(p_device) || ' ' THEN p_check
        ELSE p_device || ' · ' || p_check
    END
$$;

-- Wie 0006, aber mit check_label als Name.
CREATE OR REPLACE FUNCTION openwacht.alert_candidates()
    RETURNS TABLE (check_id uuid, check_tenant uuid, tenant_name text, check_name text, status text,
                   message text, fails integer, channel_id uuid, alerted text, alerted_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.tenant_id, t.name, openwacht.check_label(d.name, c.name), c.status, coalesce(c.message, ''), c.fails,
           ch.id, s.alerted, s.alerted_at
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

-- Wie 0009, aber mit check_label als Name (Alarmprotokoll).
CREATE OR REPLACE FUNCTION openwacht.alarm_check_sources()
    RETURNS TABLE (check_id uuid, name text, status text, message text, fails integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, openwacht.check_label(d.name, c.name), c.status, coalesce(c.message, ''), c.fails
      FROM openwacht.checks c
      LEFT JOIN openwacht.devices d ON d.id = c.device_id
     WHERE c.enabled AND c.status IS NOT NULL AND c.status <> 'ok'
     ORDER BY c.id
     LIMIT 20000
$$;

-- ---------------------------------------------------------------------------
-- FRITZ!Box (TR-064)
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.snmp_sources DROP CONSTRAINT snmp_sources_version_check;
ALTER TABLE openwacht.snmp_sources ADD CONSTRAINT snmp_sources_version_check
    CHECK (version IN ('1', '2c', '3', 'pve', 'tr064'));

-- Wie 0018, mit 'tr064' als eigener Art: Wechsel zwischen SNMP, Proxmox und
-- FRITZ!Box verwirft die Zugangsdaten.
CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' WHEN 'tr064' THEN 'tr064' ELSE 'v1' END;
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

CREATE OR REPLACE FUNCTION openwacht.valid_snmp_subject(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('stumm', 'speicher', 'cpu', 'neustart', 'system', 'temperatur', 'usv', 'wan')
                OR s ~ '^(platte|if|laufwerk|raid|toner|meta|pvespeicher):.'
                OR s ~ '^(gast|backup):[1-9][0-9]{2,8}$'
                OR s ~ '^trap:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(:.+)?$')
$$;

CREATE OR REPLACE FUNCTION openwacht.valid_snmp_series(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('cpu', 'speicher', 'temperatur', 'usv_ladung', 'dsl_ab', 'dsl_auf')
                OR s ~ '^(platte|if_ein|if_aus|toner|meta):.')
$$;
