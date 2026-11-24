-- SPDX-License-Identifier: AGPL-3.0-only

-- 0018: Agent als Sammler (Etappe 15).
--
-- Ein Agent kann SNMP-Geräte in seinem Netz abfragen (Außenstelle,
-- Fertigung), die die Zentrale nicht erreicht. Entscheidungen (
-- 20.11.2026):
--   * Der Agent sammelt nur nach lokaler Freigabe auf dem Rechner selbst
--     (openwacht-agent sammler -netze …). Die Netze meldet er mit seinen
--     Messwerten (snapshot -> 'sammler'); die Zentrale kann sie nicht ändern.
--   * Nur Geräte des eigenen Mandanten (zusammengesetzter Fremdschlüssel).
--   * Fällt der Sammler aus, werden seine Geräte grau, und es gibt genau einen
--     Alarm am Sammler, keine Einzelalarme. Die Zentrale übernimmt nicht.
--   * Nur SNMP (v1, v2c, v3), kein Proxmox, keine Traps über den Sammler.
--
-- Leitprinzip 1 bleibt gewahrt: Der Agent holt Geräteliste und Zugangsdaten
-- ab (Daten, kein Code) und schickt Ergebnisse; er öffnet keinen Port.

-- ---------------------------------------------------------------------------
-- Spalten
-- ---------------------------------------------------------------------------

-- collector_seen_at: letzter Abruf der Geräteliste. collector_since: Beginn
-- des aktuellen ununterbrochenen Abrufs (nach einem Ausfall neu); ab dann
-- zählt „antwortet nicht“ für seine Geräte neu.
ALTER TABLE openwacht.agents
    ADD COLUMN collector_seen_at timestamptz,
    ADD COLUMN collector_since   timestamptz,
    ADD CONSTRAINT agents_id_tenant UNIQUE (id, tenant_id);
GRANT SELECT (collector_seen_at, collector_since, device_id) ON openwacht.agents TO openwacht_app;

-- collector_id: Agent, der die Quelle abfragt; NULL = die Zentrale.
-- poll_requested_at: „jetzt abfragen“ für den Sammler (die Zentrale nutzt
-- dafür weiter next_run).
ALTER TABLE openwacht.snmp_sources
    ADD COLUMN collector_id uuid,
    ADD COLUMN poll_requested_at timestamptz,
    ADD CONSTRAINT snmp_sources_collector_fk FOREIGN KEY (collector_id, tenant_id)
        REFERENCES openwacht.agents (id, tenant_id) ON DELETE RESTRICT,
    -- Proxmox nicht über den Sammler; Traps ordnet der Trap-Dienst über die
    -- Absenderadresse zu, die in fremden Netzen nicht eindeutig ist.
    ADD CONSTRAINT snmp_sources_collector_check CHECK (collector_id IS NULL OR (version IN ('1', '2c', '3') AND NOT traps));
CREATE INDEX snmp_sources_collector ON openwacht.snmp_sources (collector_id) WHERE collector_id IS NOT NULL;
GRANT SELECT (collector_id), INSERT (collector_id), UPDATE (collector_id) ON openwacht.snmp_sources TO openwacht_app;

-- Zuordnung prüfen: Agent nicht gesperrt, höchstens 500 Geräte je Sammler.
-- Mit den Rechten des Aufrufers (Admin des Mandanten, sieht dessen Agents).
CREATE FUNCTION openwacht.snmp_sources_collector() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.collector_id IS NULL OR (TG_OP = 'UPDATE' AND NEW.collector_id IS NOT DISTINCT FROM OLD.collector_id) THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM openwacht.agents a
                    WHERE a.id = NEW.collector_id AND a.tenant_id = NEW.tenant_id AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Sammler nicht gefunden oder gesperrt.' USING ERRCODE = '23503';
    END IF;
    IF (SELECT count(*) FROM openwacht.snmp_sources s WHERE s.collector_id = NEW.collector_id AND s.id <> NEW.id) >= 500 THEN
        RAISE EXCEPTION 'Höchstens 500 Geräte je Sammler.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_sources_collector BEFORE INSERT OR UPDATE OF collector_id ON openwacht.snmp_sources
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_sources_collector();

-- Wie 0017, zusätzlich: Wechsel des Sammlers setzt den Zustand zurück wie
-- ein neues Ziel (anderer Standort, andere Sicht). Die Zugangsdaten bleiben,
-- sie hängen an Adresse und Port, nicht am Sammler.
CREATE OR REPLACE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_kind_old text := CASE OLD.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' ELSE 'v1' END;
    v_kind_new text := CASE NEW.version WHEN '3' THEN 'v3' WHEN 'pve' THEN 'pve' ELSE 'v1' END;
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

-- ---------------------------------------------------------------------------
-- Planer der Zentrale: Quellen mit Sammler fragt sie nicht ab
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.snmp_claim(p_limit integer)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, host text, port integer, secret_enc bytea,
                   revision integer, snapshot jsonb, ca_pem text)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.snmp_sources s SET next_run = now() + interval '2 minutes'
     WHERE s.id IN (SELECT d.id FROM openwacht.snmp_sources d
                     WHERE d.enabled AND d.collector_id IS NULL AND d.next_run <= now()
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING s.id, s.tenant_id, s.version, s.host, s.port, s.secret_enc, s.revision, s.snapshot, s.ca_pem
$$;

-- „Jetzt abfragen“: beim Sammler über poll_requested_at (er holt es beim
-- nächsten Abgleich ab), sonst wie bisher über next_run.
CREATE OR REPLACE FUNCTION openwacht.snmp_poll_now(p_id uuid) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
    v_recent boolean;
    v_enabled boolean;
BEGIN
    SELECT s.tenant_id, coalesce(s.last_try > now() - interval '10 seconds', false), s.enabled
      INTO v_tenant, v_recent, v_enabled
      FROM openwacht.snmp_sources s WHERE s.id = p_id;
    IF v_tenant IS NULL OR v_tenant NOT IN (SELECT openwacht.visible_tenants()) THEN
        RETURN 'fehlt';
    END IF;
    IF v_tenant NOT IN (SELECT openwacht.operator_tenants()) THEN
        RETURN 'verboten';
    END IF;
    IF NOT v_enabled THEN
        RETURN 'aus';
    END IF;
    IF v_recent THEN
        RETURN 'gerade';
    END IF;
    UPDATE openwacht.snmp_sources
       SET next_run = now(), poll_requested_at = CASE WHEN collector_id IS NOT NULL THEN now() END
     WHERE id = p_id;
    RETURN 'ok';
END
$$;

-- ---------------------------------------------------------------------------
-- Funktionen für den Agent-Port (Identität aus dem Client-Zertifikat)
-- ---------------------------------------------------------------------------

-- Geräteliste eines Sammlers. Nur für einen gültigen Agent, der sich mit
-- Netzen als Sammler gemeldet hat; vermerkt den Abruf. p_gap_s: Ab dieser
-- Lücke gilt der Abruf als neu begonnen (collector_since).
CREATE FUNCTION openwacht.collector_jobs(p_agent uuid, p_serial text, p_gap_s double precision)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, host text, port integer, secret_enc bytea, revision integer,
                   interval_s integer, due boolean, last_try_s double precision, nets jsonb)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
#variable_conflict use_column
DECLARE
    v_nets jsonb;
BEGIN
    UPDATE openwacht.agents a
       SET collector_since = CASE WHEN a.collector_seen_at IS NULL OR a.collector_seen_at < now() - make_interval(secs => p_gap_s)
                                  THEN now() ELSE a.collector_since END,
           collector_seen_at = now()
     WHERE a.id = p_agent AND a.revoked_at IS NULL AND p_serial IN (a.cert_serial, a.cert_serial_prev)
       AND jsonb_typeof(a.snapshot -> 'sammler' -> 'netze') = 'array'
    RETURNING a.snapshot -> 'sammler' -> 'netze' INTO v_nets;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT s.id, s.tenant_id, s.version, s.host, s.port, s.secret_enc, s.revision, s.interval_s,
           coalesce(s.poll_requested_at > coalesce(s.last_try, '-infinity'::timestamptz), false),
           extract(epoch FROM now() - s.last_try)::double precision, v_nets
      FROM openwacht.snmp_sources s
     WHERE s.collector_id = p_agent AND s.enabled
     ORDER BY s.id
     LIMIT 500;
END
$$;

-- Vorige Messwerte einer Quelle für die Raten, nur für ihren Sammler.
CREATE FUNCTION openwacht.collector_source(p_agent uuid, p_serial text, p_id uuid)
    RETURNS TABLE (tenant_id uuid, revision integer, snapshot jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.tenant_id, s.revision, s.snapshot
      FROM openwacht.snmp_sources s
      JOIN openwacht.agents a ON a.id = s.collector_id AND a.tenant_id = s.tenant_id
     WHERE s.id = p_id AND s.collector_id = p_agent AND s.enabled
       AND a.revoked_at IS NULL AND p_serial IN (a.cert_serial, a.cert_serial_prev)
$$;

-- Ergebnis eines Sammlers speichern: nur für seine eigenen Quellen und den
-- aktuellen Stand (revision), sonst wie die Zentrale (snmp_record).
CREATE FUNCTION openwacht.collector_record(p_agent uuid, p_serial text, p_id uuid, p_revision integer, p_ok boolean,
                                          p_error text, p_snapshot jsonb, p_rebooted boolean, p_series text[],
                                          p_values double precision[])
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM openwacht.snmp_sources s
                     JOIN openwacht.agents a ON a.id = s.collector_id AND a.tenant_id = s.tenant_id
                    WHERE s.id = p_id AND s.collector_id = p_agent
                      AND a.revoked_at IS NULL AND p_serial IN (a.cert_serial, a.cert_serial_prev)) THEN
        RETURN false;
    END IF;
    RETURN openwacht.snmp_record(p_id, p_revision, p_ok, p_error, p_snapshot, p_rebooted, p_series, p_values);
END
$$;

REVOKE ALL ON FUNCTION openwacht.collector_jobs(uuid, text, double precision),
    openwacht.collector_source(uuid, text, uuid),
    openwacht.collector_record(uuid, text, uuid, integer, boolean, text, jsonb, boolean, text[], double precision[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.collector_jobs(uuid, text, double precision),
    openwacht.collector_source(uuid, text, uuid),
    openwacht.collector_record(uuid, text, uuid, integer, boolean, text, jsonb, boolean, text[], double precision[]) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Alarme und Sensoren
-- ---------------------------------------------------------------------------

-- Neuer Gegenstand 'sammler' am Agent: ein Alarm für alle Geräte eines
-- ausgefallenen Sammlers.
ALTER TABLE openwacht.alert_state_agents DROP CONSTRAINT alert_state_agents_subject_check;
ALTER TABLE openwacht.alert_state_agents ADD CONSTRAINT alert_state_agents_subject_check
    CHECK (char_length(subject) <= 300 AND subject !~ '[[:cntrl:]]'
           AND (subject IN ('stumm', 'speicher', 'cpu', 'sammler') OR subject ~ '^platte:.'));
ALTER TABLE openwacht.alarms DROP CONSTRAINT alarms_subject_check;
ALTER TABLE openwacht.alarms ADD CONSTRAINT alarms_subject_check
    CHECK (subject IN ('check', 'sammler') OR openwacht.valid_snmp_subject(subject));

-- Messwerte für die Bewertung eines Agents, dazu sein Zustand als Sammler
-- (nur wenn ihm Geräte zugewiesen sind): Anzahl, lokal an, seit wann kein Abruf.
CREATE OR REPLACE FUNCTION openwacht.agent_alarm_metrics(p_agent uuid, p_snapshot jsonb) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE WHEN p_snapshot IS NULL THEN NULL
                ELSE jsonb_build_object('speicher', p_snapshot -> 'speicher', 'platten', p_snapshot -> 'platten',
                                        'cpu15', openwacht.agent_cpu15(p_agent),
                                        'sammler', (SELECT jsonb_build_object(
                                                        'geraete', count(*),
                                                        'aktiv', jsonb_typeof(p_snapshot -> 'sammler' -> 'netze') = 'array',
                                                        'abgeholt_vor_s', (SELECT extract(epoch FROM now() - a.collector_seen_at)
                                                                             FROM openwacht.agents a WHERE a.id = p_agent))
                                                      FROM openwacht.snmp_sources s
                                                     WHERE s.collector_id = p_agent AND s.enabled
                                                    HAVING count(*) > 0)) END
$$;

-- Zustand des Sammlers einer SNMP-Quelle; NULL-Spalten = die Zentrale fragt ab.
-- „antwortet nicht“ zählt bei Sammlern erst ab dem Beginn des aktuellen
-- Abrufs (collector_since), damit nach einem Ausfall des Sammlers nicht
-- sofort alle Geräte alarmieren.
DROP FUNCTION openwacht.alert_snmp_candidates();
CREATE FUNCTION openwacht.alert_snmp_candidates()
    RETURNS TABLE (snmp_id uuid, tenant_name text, name text, disabled boolean, silent_s double precision,
                   interval_s integer, last_error text, snapshot jsonb, cpu15 double precision,
                   rebooted_s double precision, watched text[], channels uuid[], version text, traps jsonb,
                   collector text, collector_on boolean, collector_revoked boolean, collector_seen_s double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, t.name, d.name, NOT s.enabled,
           extract(epoch FROM now() - greatest(coalesce(s.last_ok, s.changed_at), a.collector_since))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched,
           array_agg(ch.id ORDER BY ch.id), s.version, openwacht.snmp_trap_states_json(s.id),
           (SELECT cd.name FROM openwacht.devices cd WHERE cd.id = a.device_id),
           jsonb_typeof(a.snapshot -> 'sammler' -> 'netze') = 'array', a.revoked_at IS NOT NULL,
           extract(epoch FROM now() - a.collector_seen_at)::double precision
      FROM openwacht.snmp_sources s
      JOIN openwacht.devices d ON d.id = s.device_id
      JOIN openwacht.tenants t ON t.id = s.tenant_id
      JOIN openwacht.tenant_closure tc ON tc.descendant = s.tenant_id
      JOIN openwacht.alert_channels ch ON ch.tenant_id = tc.ancestor AND ch.enabled
                                     AND (tc.depth = 0 OR ch.include_children)
      LEFT JOIN openwacht.agents a ON a.id = s.collector_id
     WHERE s.enabled OR EXISTS (SELECT 1 FROM openwacht.alert_state_snmp x WHERE x.snmp_id = s.id)
     GROUP BY s.id, t.name, d.name, a.id
     ORDER BY s.id
     LIMIT 20000
$$;

DROP FUNCTION openwacht.alarm_snmp_sources();
CREATE FUNCTION openwacht.alarm_snmp_sources()
    RETURNS TABLE (snmp_id uuid, name text, silent_s double precision, interval_s integer, last_error text,
                   snapshot jsonb, cpu15 double precision, rebooted_s double precision, watched text[], version text,
                   traps jsonb, collector text, collector_on boolean, collector_revoked boolean,
                   collector_seen_s double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, d.name,
           extract(epoch FROM now() - greatest(coalesce(s.last_ok, s.changed_at), a.collector_since))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched, s.version,
           openwacht.snmp_trap_states_json(s.id),
           (SELECT cd.name FROM openwacht.devices cd WHERE cd.id = a.device_id),
           jsonb_typeof(a.snapshot -> 'sammler' -> 'netze') = 'array', a.revoked_at IS NOT NULL,
           extract(epoch FROM now() - a.collector_seen_at)::double precision
      FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
      LEFT JOIN openwacht.agents a ON a.id = s.collector_id
     WHERE s.enabled
     ORDER BY s.id
     LIMIT 20000
$$;

REVOKE ALL ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alert_snmp_candidates(), openwacht.alarm_snmp_sources() TO openwacht_app;
