-- SPDX-License-Identifier: AGPL-3.0-only

-- 0013: SNMP-Abfragen (v1, v2c) als dritte Art, ein Gerät zu überwachen.
--
-- Je Gerät höchstens eine SNMP-Quelle. Sie gehört zum Mandanten des Geräts
-- (zusammengesetzter Fremdschlüssel wie bei Agents und Checks); den Mandanten
-- setzt die Datenbank aus dem Gerät, nie aus der Anfrage (Leitprinzip 2).
--
-- Zugangsdaten (Community; später v3-Schlüssel) liegen verschlüsselt in
-- secret_enc (AES-256-GCM mit dem Hauptschlüssel der Zentrale, gebunden an
-- Quelle, Mandant, Adresse und Port). Die Anwendung darf secret_enc schreiben,
-- aber nie lesen; den Klartext sieht nur der Planer der Zentrale. Ändert sich
-- Adresse oder Port ohne neue Zugangsdaten, werden die alten verworfen:
-- Sonst ließe sich die Community an ein beliebiges Ziel umleiten.
--
-- Anlegen, ändern und löschen dürfen nur Admins (Sicherheitskonzept:
-- Zugangsdaten nur für Admins des Knotens), „jetzt abfragen“ auch Operatoren.
-- Welche Netze erreichbar sind, entscheidet der Betreiber (-check-netze).
--
-- Den Zustand schreibt nur der Planer über SECURITY-DEFINER-Funktionen.
-- Verlauf, Alarme, Alarmprotokoll und Wartung kennen SNMP-Quellen wie Agents:
-- Gegenstände (subject) sind 'stumm', 'speicher', 'cpu', 'platte:…' und
-- zusätzlich 'neustart', 'system', 'temperatur', 'usv', 'if:…', 'laufwerk:…',
-- 'raid:…', 'toner:…'.

CREATE FUNCTION openwacht.valid_watched(w text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT cardinality(w) <= 64
       AND NOT EXISTS (SELECT 1 FROM unnest(w) x WHERE x IS NULL OR char_length(x) NOT BETWEEN 1 AND 200 OR x ~ '[[:cntrl:]]')
$$;

CREATE TABLE openwacht.snmp_sources (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE RESTRICT,
    device_id   uuid NOT NULL UNIQUE,
    version     text NOT NULL CHECK (version IN ('1', '2c')),
    -- Hostname oder IP-Adresse (geprüft von der Zentrale)
    host        text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253 AND host ~ '^[A-Za-z0-9.:-]+$'),
    port        integer NOT NULL DEFAULT 161 CHECK (port BETWEEN 1 AND 65535),
    secret_enc  bytea CHECK (octet_length(secret_enc) BETWEEN 29 AND 2048),
    has_secret  boolean GENERATED ALWAYS AS (secret_enc IS NOT NULL) STORED,
    interval_s  integer NOT NULL DEFAULT 60 CHECK (interval_s BETWEEN 30 AND 3600),
    enabled     boolean NOT NULL DEFAULT true,
    -- überwachte Schnittstellen (Namen): Alarm, wenn nicht verbunden
    watched     text[] NOT NULL DEFAULT '{}' CHECK (openwacht.valid_watched(watched)),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- letzte Änderung von Ziel oder Zugangsdaten (Bezug für „antwortet nicht“)
    changed_at  timestamptz NOT NULL DEFAULT now(),
    revision    integer NOT NULL DEFAULT 1,
    next_run    timestamptz NOT NULL DEFAULT now(),
    -- Zustand (nur über snmp_record)
    last_try    timestamptz,
    last_ok     timestamptz,
    last_error  text CHECK (char_length(last_error) <= 300 AND last_error !~ '[[:cntrl:]]'),
    snapshot    jsonb CHECK (jsonb_typeof(snapshot) = 'object' AND octet_length(snapshot::text) <= 524288),
    rebooted_at timestamptz,
    FOREIGN KEY (device_id, tenant_id) REFERENCES openwacht.devices (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX snmp_sources_tenant ON openwacht.snmp_sources (tenant_id);
CREATE INDEX snmp_sources_due ON openwacht.snmp_sources (next_run) WHERE enabled;

CREATE FUNCTION openwacht.snmp_sources_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    -- Mit den Rechten des Aufrufers: ein Gerät, das er nicht sieht, gibt es nicht.
    NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'SNMP: Gerät nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    IF (SELECT count(*) FROM openwacht.snmp_sources WHERE tenant_id = NEW.tenant_id) >= 2000 THEN
        RAISE EXCEPTION 'Höchstens 2000 SNMP-Geräte je Mandant.' USING ERRCODE = '23514';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.created_at := now(); NEW.changed_at := now();
    NEW.revision := 1; NEW.next_run := now();
    NEW.last_try := NULL; NEW.last_ok := NULL; NEW.last_error := NULL;
    NEW.snapshot := NULL; NEW.rebooted_at := NULL;
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_sources_before_insert BEFORE INSERT ON openwacht.snmp_sources
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_sources_before_insert();

-- Neues Ziel oder neue Zugangsdaten: alter Zustand gilt nicht mehr, sofort
-- neu abfragen. Neue Adresse ohne neue Zugangsdaten: alte verwerfen.
CREATE FUNCTION openwacht.snmp_sources_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id THEN
        RAISE EXCEPTION 'ID, Gerät und Mandant einer SNMP-Quelle sind unveränderlich.';
    END IF;
    IF (NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port)
       AND NEW.secret_enc IS NOT DISTINCT FROM OLD.secret_enc THEN
        NEW.secret_enc := NULL;
    END IF;
    IF NEW.host IS DISTINCT FROM OLD.host OR NEW.port IS DISTINCT FROM OLD.port
       OR NEW.version IS DISTINCT FROM OLD.version OR NEW.secret_enc IS DISTINCT FROM OLD.secret_enc THEN
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
CREATE TRIGGER snmp_sources_before_update BEFORE UPDATE ON openwacht.snmp_sources
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_sources_before_update();

ALTER TABLE openwacht.snmp_sources ENABLE ROW LEVEL SECURITY;
-- secret_enc: schreibbar, nie lesbar. Zustand: nur lesbar.
GRANT SELECT (id, tenant_id, device_id, version, host, port, has_secret, interval_s, enabled, watched, created_at,
              changed_at, next_run, last_try, last_ok, last_error, snapshot, rebooted_at),
      INSERT (id, device_id, version, host, port, secret_enc, interval_s, enabled, watched),
      UPDATE (version, host, port, secret_enc, interval_s, enabled, watched),
      DELETE
    ON openwacht.snmp_sources TO openwacht_app;
CREATE POLICY snmp_sources_select ON openwacht.snmp_sources FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY snmp_sources_insert ON openwacht.snmp_sources FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_sources_update ON openwacht.snmp_sources FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.admin_tenants()));
CREATE POLICY snmp_sources_delete ON openwacht.snmp_sources FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.admin_tenants()));

-- „Jetzt abfragen“: Admins und Operatoren, höchstens alle 10 Sekunden.
-- Liefert false, wenn die Quelle nicht sichtbar, nicht erlaubt oder gerade erst
-- abgefragt ist.
CREATE FUNCTION openwacht.snmp_poll_now(p_id uuid) RETURNS text
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
    UPDATE openwacht.snmp_sources SET next_run = now() WHERE id = p_id;
    RETURN 'ok';
END
$$;

-- „Verbindung prüfen“ ohne neue Community: die gespeicherte, aber nur für
-- Admins und nur für dieselbe Adresse und denselben Port.
CREATE FUNCTION openwacht.snmp_secret_for_probe(p_device uuid, p_host text, p_port integer)
    RETURNS TABLE (id uuid, secret_enc bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, s.secret_enc FROM openwacht.snmp_sources s
     WHERE s.device_id = p_device AND s.host = p_host AND s.port = p_port
       AND s.tenant_id IN (SELECT openwacht.admin_tenants())
$$;

-- ---------------------------------------------------------------------------
-- Planer (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.snmp_claim(p_limit integer)
    RETURNS TABLE (id uuid, tenant_id uuid, version text, host text, port integer, secret_enc bytea,
                   revision integer, snapshot jsonb)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.snmp_sources s SET next_run = now() + interval '2 minutes'
     WHERE s.id IN (SELECT d.id FROM openwacht.snmp_sources d
                     WHERE d.enabled AND d.next_run <= now()
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING s.id, s.tenant_id, s.version, s.host, s.port, s.secret_enc, s.revision, s.snapshot
$$;

-- Reihen des Verlaufs: wie beim Agent, dazu Schnittstellen (Bit/s),
-- Temperatur, USV-Ladung und Verbrauchsmaterial.
CREATE FUNCTION openwacht.valid_snmp_series(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('cpu', 'speicher', 'temperatur', 'usv_ladung') OR s ~ '^(platte|if_ein|if_aus|toner):.')
$$;

CREATE TABLE openwacht.metrics_snmp_raw (
    tenant_id uuid NOT NULL,
    snmp_id   uuid NOT NULL REFERENCES openwacht.snmp_sources (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    series    text NOT NULL CHECK (openwacht.valid_snmp_series(series)),
    value     double precision NOT NULL CHECK (value BETWEEN -1000 AND 1e13)
) PARTITION BY RANGE (ts);
CREATE INDEX metrics_snmp_raw_source ON openwacht.metrics_snmp_raw (snmp_id, ts);

CREATE TABLE openwacht.metrics_snmp_5m (
    tenant_id uuid NOT NULL,
    snmp_id   uuid NOT NULL REFERENCES openwacht.snmp_sources (id) ON DELETE CASCADE,
    bucket    timestamptz NOT NULL,
    series    text NOT NULL CHECK (openwacht.valid_snmp_series(series)),
    avg       double precision NOT NULL,
    min       double precision NOT NULL,
    max       double precision NOT NULL,
    n         integer NOT NULL CHECK (n > 0),
    PRIMARY KEY (snmp_id, bucket, series)
);
CREATE INDEX metrics_snmp_5m_bucket ON openwacht.metrics_snmp_5m (bucket);
CREATE TABLE openwacht.metrics_snmp_1h (LIKE openwacht.metrics_snmp_5m INCLUDING ALL);
ALTER TABLE openwacht.metrics_snmp_1h
    ADD FOREIGN KEY (snmp_id) REFERENCES openwacht.snmp_sources (id) ON DELETE CASCADE;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['metrics_snmp_raw', 'metrics_snmp_5m', 'metrics_snmp_1h'] LOOP
        EXECUTE format('ALTER TABLE openwacht.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON openwacht.%I FROM PUBLIC', t);
        EXECUTE format('GRANT SELECT ON openwacht.%I TO openwacht_app', t);
        EXECUTE format('CREATE POLICY %I ON openwacht.%I FOR SELECT TO openwacht_app
                        USING (tenant_id IN (SELECT openwacht.visible_tenants()))', t || '_select', t);
    END LOOP;
END
$$;

-- Ergebnis speichern. Stimmt die Revision nicht mehr (Ziel geändert), wird
-- es verworfen. Fehlt die Tagespartition, gehen nur die Verlaufswerte verloren.
CREATE FUNCTION openwacht.snmp_record(p_id uuid, p_revision integer, p_ok boolean, p_error text, p_snapshot jsonb,
                                     p_rebooted boolean, p_series text[], p_values double precision[])
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
BEGIN
    IF cardinality(p_series) IS DISTINCT FROM cardinality(p_values) OR cardinality(p_series) > 200 THEN
        RAISE EXCEPTION 'snmp_record: Reihen ungültig' USING ERRCODE = '22023';
    END IF;
    UPDATE openwacht.snmp_sources s
       SET last_try    = now(),
           next_run    = now() + make_interval(secs => s.interval_s),
           last_ok     = CASE WHEN p_ok THEN now() ELSE s.last_ok END,
           last_error  = CASE WHEN p_ok THEN NULL ELSE left(openwacht.alarm_clean(p_error), 300) END,
           snapshot    = CASE WHEN p_ok THEN p_snapshot ELSE s.snapshot END,
           rebooted_at = CASE WHEN p_ok AND p_rebooted THEN now() ELSE s.rebooted_at END
     WHERE s.id = p_id AND s.revision = p_revision AND s.enabled
    RETURNING s.tenant_id INTO v_tenant;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF p_ok AND cardinality(p_series) > 0 THEN
        BEGIN
            INSERT INTO openwacht.metrics_snmp_raw (tenant_id, snmp_id, ts, series, value)
            SELECT DISTINCT ON (x.series) v_tenant, p_id, now(), x.series, x.value
              FROM unnest(p_series, p_values) AS x(series, value);
        EXCEPTION WHEN check_violation THEN
            RAISE WARNING 'Verlauf: Messwerte von SNMP-Quelle % nicht gespeichert: %', p_id, SQLERRM;
        END;
    END IF;
    RETURN true;
END
$$;

-- Mittel der CPU-Auslastung der letzten 15 Minuten (wie agent_cpu15).
CREATE FUNCTION openwacht.snmp_cpu15(p_id uuid) RETURNS double precision
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT avg(r.value)
      FROM openwacht.metrics_snmp_raw r
     WHERE r.snmp_id = p_id AND r.series = 'cpu' AND r.ts > now() - interval '15 minutes'
    HAVING min(r.ts) <= now() - interval '10 minutes'
$$;

REVOKE ALL ON FUNCTION openwacht.snmp_poll_now(uuid), openwacht.snmp_secret_for_probe(uuid, text, integer), openwacht.snmp_claim(integer),
    openwacht.snmp_record(uuid, integer, boolean, text, jsonb, boolean, text[], double precision[]),
    openwacht.snmp_cpu15(uuid), openwacht.valid_snmp_series(text), openwacht.valid_watched(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_poll_now(uuid), openwacht.snmp_secret_for_probe(uuid, text, integer), openwacht.snmp_claim(integer),
    openwacht.snmp_record(uuid, integer, boolean, text, jsonb, boolean, text[], double precision[]),
    openwacht.snmp_cpu15(uuid), openwacht.valid_snmp_series(text), openwacht.valid_watched(text[]) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Verlauf: Partitionen, Verdichtung, Aufräumen (wie 0008, dazu SNMP)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION openwacht.metrics_maintain() RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, openwacht SET TimeZone = 'UTC' AS $$
DECLARE
    d        date;
    tbl      text;
    part     record;
    v_from   timestamptz;
    v_to     timestamptz;
    v_blocks integer := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtext('openwacht.metrics_maintain')) THEN
        RETURN 0;
    END IF;

    FOR d IN SELECT generate_series(current_date - 1, current_date + 2, interval '1 day')::date LOOP
        FOREACH tbl IN ARRAY ARRAY['metrics_host_raw', 'metrics_check_raw', 'metrics_snmp_raw'] LOOP
            IF to_regclass(format('openwacht.%I', tbl || '_' || to_char(d, 'YYYYMMDD'))) IS NULL THEN
                EXECUTE format('CREATE TABLE openwacht.%I PARTITION OF openwacht.%I FOR VALUES FROM (%L) TO (%L)',
                               tbl || '_' || to_char(d, 'YYYYMMDD'), tbl,
                               d::timestamptz, (d + 1)::timestamptz);
            END IF;
        END LOOP;
    END LOOP;

    SELECT done_until INTO v_from FROM openwacht.metrics_rollup_state WHERE tier = '5m' FOR UPDATE;
    v_to := date_bin('5 minutes', now() - interval '1 minute', timestamptz 'epoch');
    IF v_to > v_from THEN
        INSERT INTO openwacht.metrics_host_5m (tenant_id, agent_id, bucket, series, avg, min, max, n)
        SELECT r.tenant_id, r.agent_id, date_bin('5 minutes', r.ts, timestamptz 'epoch'), r.series,
               avg(r.value), min(r.value), max(r.value), count(*)
          FROM openwacht.metrics_host_raw r
         WHERE r.ts >= v_from AND r.ts < v_to
         GROUP BY 1, 2, 3, 4
        ON CONFLICT (agent_id, bucket, series) DO UPDATE
           SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, n = EXCLUDED.n;
        INSERT INTO openwacht.metrics_snmp_5m (tenant_id, snmp_id, bucket, series, avg, min, max, n)
        SELECT r.tenant_id, r.snmp_id, date_bin('5 minutes', r.ts, timestamptz 'epoch'), r.series,
               avg(r.value), min(r.value), max(r.value), count(*)
          FROM openwacht.metrics_snmp_raw r
         WHERE r.ts >= v_from AND r.ts < v_to
         GROUP BY 1, 2, 3, 4
        ON CONFLICT (snmp_id, bucket, series) DO UPDATE
           SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, n = EXCLUDED.n;
        INSERT INTO openwacht.metrics_check_5m (tenant_id, check_id, bucket, n, n_ok, worst, ms_n, ms_avg, ms_min, ms_max)
        SELECT r.tenant_id, r.check_id, date_bin('5 minutes', r.ts, timestamptz 'epoch'),
               count(*), count(*) FILTER (WHERE r.status = 'ok'),
               (array_agg(r.status ORDER BY openwacht.status_rank(r.status) DESC))[1],
               count(r.ms), avg(r.ms), min(r.ms), max(r.ms)
          FROM openwacht.metrics_check_raw r
         WHERE r.ts >= v_from AND r.ts < v_to
         GROUP BY 1, 2, 3
        ON CONFLICT (check_id, bucket) DO UPDATE
           SET n = EXCLUDED.n, n_ok = EXCLUDED.n_ok, worst = EXCLUDED.worst, ms_n = EXCLUDED.ms_n,
               ms_avg = EXCLUDED.ms_avg, ms_min = EXCLUDED.ms_min, ms_max = EXCLUDED.ms_max;
        v_blocks := ((extract(epoch FROM v_to - v_from)) / 300)::integer;
        UPDATE openwacht.metrics_rollup_state SET done_until = v_to WHERE tier = '5m';
    END IF;

    SELECT done_until INTO v_from FROM openwacht.metrics_rollup_state WHERE tier = '1h' FOR UPDATE;
    SELECT date_bin('1 hour', done_until, timestamptz 'epoch') INTO v_to
      FROM openwacht.metrics_rollup_state WHERE tier = '5m';
    IF v_to > v_from THEN
        INSERT INTO openwacht.metrics_host_1h (tenant_id, agent_id, bucket, series, avg, min, max, n)
        SELECT m.tenant_id, m.agent_id, date_bin('1 hour', m.bucket, timestamptz 'epoch'), m.series,
               sum(m.avg * m.n) / sum(m.n), min(m.min), max(m.max), sum(m.n)
          FROM openwacht.metrics_host_5m m
         WHERE m.bucket >= v_from AND m.bucket < v_to
         GROUP BY 1, 2, 3, 4
        ON CONFLICT (agent_id, bucket, series) DO UPDATE
           SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, n = EXCLUDED.n;
        INSERT INTO openwacht.metrics_snmp_1h (tenant_id, snmp_id, bucket, series, avg, min, max, n)
        SELECT m.tenant_id, m.snmp_id, date_bin('1 hour', m.bucket, timestamptz 'epoch'), m.series,
               sum(m.avg * m.n) / sum(m.n), min(m.min), max(m.max), sum(m.n)
          FROM openwacht.metrics_snmp_5m m
         WHERE m.bucket >= v_from AND m.bucket < v_to
         GROUP BY 1, 2, 3, 4
        ON CONFLICT (snmp_id, bucket, series) DO UPDATE
           SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, n = EXCLUDED.n;
        INSERT INTO openwacht.metrics_check_1h (tenant_id, check_id, bucket, n, n_ok, worst, ms_n, ms_avg, ms_min, ms_max)
        SELECT m.tenant_id, m.check_id, date_bin('1 hour', m.bucket, timestamptz 'epoch'),
               sum(m.n), sum(m.n_ok),
               (array_agg(m.worst ORDER BY openwacht.status_rank(m.worst) DESC))[1],
               sum(m.ms_n), sum(m.ms_avg * m.ms_n) / nullif(sum(m.ms_n), 0), min(m.ms_min), max(m.ms_max)
          FROM openwacht.metrics_check_5m m
         WHERE m.bucket >= v_from AND m.bucket < v_to
         GROUP BY 1, 2, 3
        ON CONFLICT (check_id, bucket) DO UPDATE
           SET n = EXCLUDED.n, n_ok = EXCLUDED.n_ok, worst = EXCLUDED.worst, ms_n = EXCLUDED.ms_n,
               ms_avg = EXCLUDED.ms_avg, ms_min = EXCLUDED.ms_min, ms_max = EXCLUDED.ms_max;
        UPDATE openwacht.metrics_rollup_state SET done_until = v_to WHERE tier = '1h';
    END IF;

    FOR part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
          JOIN pg_namespace n ON n.oid = p.relnamespace
         WHERE n.nspname = 'openwacht' AND p.relname IN ('metrics_host_raw', 'metrics_check_raw', 'metrics_snmp_raw')
           AND c.relname ~ '_[0-9]{8}$'
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1 <= (now() - interval '48 hours')::date
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1
               <= (SELECT done_until FROM openwacht.metrics_rollup_state WHERE tier = '5m')::date
    LOOP
        EXECUTE format('DROP TABLE openwacht.%I', part.relname);
    END LOOP;
    DELETE FROM openwacht.metrics_host_5m WHERE bucket < now() - interval '30 days';
    DELETE FROM openwacht.metrics_snmp_5m WHERE bucket < now() - interval '30 days';
    DELETE FROM openwacht.metrics_check_5m WHERE bucket < now() - interval '30 days';
    DELETE FROM openwacht.metrics_host_1h WHERE bucket < now() - interval '365 days';
    DELETE FROM openwacht.metrics_snmp_1h WHERE bucket < now() - interval '365 days';
    DELETE FROM openwacht.metrics_check_1h WHERE bucket < now() - interval '365 days';
    DELETE FROM openwacht.check_transitions WHERE ts < now() - interval '30 days';
    RETURN v_blocks;
END
$$;

SELECT openwacht.metrics_maintain();

-- ---------------------------------------------------------------------------
-- Alarme: Meldezustand je Quelle, Kanal und Gegenstand
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.valid_snmp_subject(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('stumm', 'speicher', 'cpu', 'neustart', 'system', 'temperatur', 'usv')
                OR s ~ '^(platte|if|laufwerk|raid|toner):.')
$$;

CREATE TABLE openwacht.alert_state_snmp (
    snmp_id    uuid NOT NULL REFERENCES openwacht.snmp_sources (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES openwacht.alert_channels (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    subject    text NOT NULL CHECK (openwacht.valid_snmp_subject(subject)),
    alerted    text NOT NULL CHECK (alerted IN ('warn', 'crit', 'unknown')),
    alerted_at timestamptz NOT NULL,
    PRIMARY KEY (snmp_id, channel_id, subject)
);
CREATE INDEX alert_state_snmp_channel ON openwacht.alert_state_snmp (channel_id);
ALTER TABLE openwacht.alert_state_snmp ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.alert_state_snmp FROM PUBLIC, openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.alert_channels_before_update() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant eines Alarmkanals sind unveränderlich.';
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server AND NEW.token_enc IS NOT DISTINCT FROM OLD.token_enc THEN
        NEW.token_enc := NULL;
    END IF;
    IF NEW.server IS DISTINCT FROM OLD.server OR NEW.topic IS DISTINCT FROM OLD.topic THEN
        DELETE FROM openwacht.alert_state WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_agents WHERE channel_id = OLD.id;
        DELETE FROM openwacht.alert_state_snmp WHERE channel_id = OLD.id;
        NEW.last_ok := NULL; NEW.last_error := NULL; NEW.last_error_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

-- Je SNMP-Quelle mit zuständigem aktivem Kanal: was die Bewertung braucht.
-- Ausgeschaltete Quellen nur, solange ein Problem gemeldet ist (letzte
-- Entwarnung).
CREATE FUNCTION openwacht.alert_snmp_candidates()
    RETURNS TABLE (snmp_id uuid, tenant_name text, name text, disabled boolean, silent_s double precision,
                   interval_s integer, last_error text, snapshot jsonb, cpu15 double precision,
                   rebooted_s double precision, watched text[], channels uuid[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, t.name, d.name, NOT s.enabled,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched,
           array_agg(ch.id ORDER BY ch.id)
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

CREATE FUNCTION openwacht.alert_snmp_states()
    RETURNS TABLE (snmp_id uuid, channel_id uuid, subject text, alerted text, alerted_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.snmp_id, s.channel_id, s.subject, s.alerted, s.alerted_at
      FROM openwacht.alert_state_snmp s
     ORDER BY s.channel_id, s.snmp_id, s.subject
     LIMIT 200000
$$;

CREATE FUNCTION openwacht.alert_snmp_commit(p_channel uuid, p_sources uuid[], p_subjects text[], p_status text[])
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF cardinality(p_sources) IS DISTINCT FROM cardinality(p_subjects)
       OR cardinality(p_sources) IS DISTINCT FROM cardinality(p_status) THEN
        RAISE EXCEPTION 'alert_snmp_commit: Listen unterschiedlich lang';
    END IF;
    DELETE FROM openwacht.alert_state_snmp s
     USING unnest(p_sources, p_subjects, p_status) AS x(snmp_id, subject, status)
     WHERE x.status = 'ok' AND s.channel_id = p_channel AND s.snmp_id = x.snmp_id AND s.subject = x.subject;
    INSERT INTO openwacht.alert_state_snmp (snmp_id, channel_id, tenant_id, subject, alerted, alerted_at)
    SELECT q.id, ch.id, q.tenant_id, x.subject, x.status, now()
      FROM unnest(p_sources, p_subjects, p_status) AS x(snmp_id, subject, status)
      JOIN openwacht.snmp_sources q ON q.id = x.snmp_id
      JOIN openwacht.alert_channels ch ON ch.id = p_channel
      JOIN openwacht.tenant_closure tc ON tc.ancestor = ch.tenant_id AND tc.descendant = q.tenant_id
     WHERE x.status <> 'ok' AND (tc.depth = 0 OR ch.include_children)
    ON CONFLICT (snmp_id, channel_id, subject) DO UPDATE SET alerted = EXCLUDED.alerted, alerted_at = EXCLUDED.alerted_at;
    UPDATE openwacht.alert_channels SET last_ok = now(), last_error = NULL, last_error_at = NULL
     WHERE id = p_channel;
END
$$;

REVOKE ALL ON FUNCTION openwacht.valid_snmp_subject(text), openwacht.alert_snmp_candidates(), openwacht.alert_snmp_states(),
    openwacht.alert_snmp_commit(uuid, uuid[], text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.valid_snmp_subject(text), openwacht.alert_snmp_candidates(), openwacht.alert_snmp_states(),
    openwacht.alert_snmp_commit(uuid, uuid[], text[], text[]) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Alarmprotokoll
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.alarms ADD COLUMN snmp_id uuid REFERENCES openwacht.snmp_sources (id) ON DELETE SET NULL;
CREATE UNIQUE INDEX alarms_open_snmp ON openwacht.alarms (snmp_id, subject) WHERE ended_at IS NULL AND snmp_id IS NOT NULL;
ALTER TABLE openwacht.alarms DROP CONSTRAINT alarms_subject_check;
ALTER TABLE openwacht.alarms ADD CONSTRAINT alarms_subject_check
    CHECK (subject = 'check' OR openwacht.valid_snmp_subject(subject));

CREATE FUNCTION openwacht.alarm_snmp_sources()
    RETURNS TABLE (snmp_id uuid, name text, silent_s double precision, interval_s integer, last_error text,
                   snapshot jsonb, cpu15 double precision, rebooted_s double precision, watched text[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.id, d.name,
           extract(epoch FROM now() - coalesce(s.last_ok, s.changed_at))::double precision,
           s.interval_s, coalesce(s.last_error, ''), s.snapshot, openwacht.snmp_cpu15(s.id),
           extract(epoch FROM now() - s.rebooted_at)::double precision, s.watched
      FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
     WHERE s.enabled
     ORDER BY s.id
     LIMIT 20000
$$;

DROP FUNCTION openwacht.alarm_open();
CREATE FUNCTION openwacht.alarm_open()
    RETURNS TABLE (check_id uuid, agent_id uuid, snmp_id uuid, subject text, name text, status text, message text,
                   acknowledged boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.check_id, a.agent_id, a.snmp_id, a.subject, a.name, a.status, a.message, a.ack_at IS NOT NULL
      FROM openwacht.alarms a
     WHERE a.ended_at IS NULL
     ORDER BY a.started_at
     LIMIT 200000
$$;

DROP FUNCTION openwacht.alarm_sync(uuid[], uuid[], text[], text[], text[], text[]);
DROP FUNCTION openwacht.alarm_input(uuid[], uuid[], text[], text[], text[], text[]);

-- Je Eintrag genau eine Quelle: Check (Gegenstand 'check'), Agent oder
-- SNMP-Quelle (Gegenstand nicht 'check').
CREATE FUNCTION openwacht.alarm_input(p_checks uuid[], p_agents uuid[], p_snmp uuid[], p_subjects text[], p_names text[],
                                     p_status text[], p_messages text[])
    RETURNS TABLE (check_id uuid, agent_id uuid, snmp_id uuid, subject text, name text, status text, message text)
    LANGUAGE sql IMMUTABLE AS $$
    SELECT x.c, x.g, x.q, x.s, left(openwacht.alarm_clean(x.n), 300), x.st, left(openwacht.alarm_clean(x.m), 300)
      FROM unnest(p_checks, p_agents, p_snmp, p_subjects, p_names, p_status, p_messages) AS x(c, g, q, s, n, st, m)
     WHERE x.st IN ('warn', 'crit', 'unknown')
       AND ((x.c IS NOT NULL AND x.g IS NULL AND x.q IS NULL AND x.s = 'check')
            OR (x.c IS NULL AND x.g IS NOT NULL AND x.q IS NULL AND x.s IS DISTINCT FROM 'check')
            OR (x.c IS NULL AND x.g IS NULL AND x.q IS NOT NULL AND x.s IS DISTINCT FROM 'check'))
$$;

CREATE FUNCTION openwacht.alarm_sync(p_checks uuid[], p_agents uuid[], p_snmp uuid[], p_subjects text[], p_names text[],
                                    p_status text[], p_messages text[]) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    n integer := coalesce(cardinality(p_checks), 0);
BEGIN
    IF coalesce(cardinality(p_agents), 0) <> n OR coalesce(cardinality(p_snmp), 0) <> n
       OR coalesce(cardinality(p_subjects), 0) <> n
       OR coalesce(cardinality(p_names), 0) <> n OR coalesce(cardinality(p_status), 0) <> n
       OR coalesce(cardinality(p_messages), 0) <> n THEN
        RAISE EXCEPTION 'alarm_sync: Listen unterschiedlich lang';
    END IF;

    UPDATE openwacht.alarms a SET ended_at = now()
     WHERE a.ended_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM openwacht.alarm_input(p_checks, p_agents, p_snmp, p_subjects, p_names, p_status, p_messages) x
                        WHERE (x.check_id IS NOT NULL AND x.check_id = a.check_id)
                           OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject)
                           OR (x.snmp_id IS NOT NULL AND x.snmp_id = a.snmp_id AND x.subject = a.subject));

    UPDATE openwacht.alarms a
       SET status      = x.status,
           message     = x.message,
           name        = coalesce(nullif(x.name, ''), a.name),
           worst       = CASE WHEN openwacht.alarm_rank(x.status) > openwacht.alarm_rank(a.worst) THEN x.status ELSE a.worst END,
           changed_at  = CASE WHEN x.status <> a.status THEN now() ELSE a.changed_at END,
           ack_at      = CASE WHEN openwacht.alarm_rank(x.status) > openwacht.alarm_rank(a.status) THEN NULL ELSE a.ack_at END,
           ack_by      = CASE WHEN openwacht.alarm_rank(x.status) > openwacht.alarm_rank(a.status) THEN NULL ELSE a.ack_by END,
           ack_by_name = CASE WHEN openwacht.alarm_rank(x.status) > openwacht.alarm_rank(a.status) THEN NULL ELSE a.ack_by_name END,
           ack_comment = CASE WHEN openwacht.alarm_rank(x.status) > openwacht.alarm_rank(a.status) THEN NULL ELSE a.ack_comment END
      FROM openwacht.alarm_input(p_checks, p_agents, p_snmp, p_subjects, p_names, p_status, p_messages) x
     WHERE a.ended_at IS NULL
       AND ((x.check_id IS NOT NULL AND x.check_id = a.check_id)
            OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject)
            OR (x.snmp_id IS NOT NULL AND x.snmp_id = a.snmp_id AND x.subject = a.subject))
       AND (a.status, a.message, a.name) IS DISTINCT FROM (x.status, x.message, coalesce(nullif(x.name, ''), a.name));

    -- Neu: Mandant aus Check, Agent bzw. SNMP-Quelle, nie aus den Eingaben.
    INSERT INTO openwacht.alarms (tenant_id, check_id, agent_id, snmp_id, subject, name, status, worst, message,
                                 started_at, changed_at)
    SELECT coalesce(c.tenant_id, g.tenant_id, q.tenant_id), x.check_id, x.agent_id, x.snmp_id, x.subject,
           coalesce(nullif(x.name, ''), c.name, g.hostname, qd.name), x.status, x.status, x.message, now(), now()
      FROM openwacht.alarm_input(p_checks, p_agents, p_snmp, p_subjects, p_names, p_status, p_messages) x
      LEFT JOIN openwacht.checks c ON c.id = x.check_id
      LEFT JOIN openwacht.agents g ON g.id = x.agent_id AND g.revoked_at IS NULL
      LEFT JOIN openwacht.snmp_sources q ON q.id = x.snmp_id AND q.enabled
      LEFT JOIN openwacht.devices qd ON qd.id = q.device_id
     WHERE coalesce(c.tenant_id, g.tenant_id, q.tenant_id) IS NOT NULL
       AND (x.snmp_id IS NULL OR openwacht.valid_snmp_subject(x.subject))
       AND NOT EXISTS (SELECT 1 FROM openwacht.alarms a
                        WHERE a.ended_at IS NULL
                          AND ((x.check_id IS NOT NULL AND x.check_id = a.check_id)
                               OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject)
                               OR (x.snmp_id IS NOT NULL AND x.snmp_id = a.snmp_id AND x.subject = a.subject)));

    DELETE FROM openwacht.alarms WHERE ended_at < now() - interval '90 days';
END
$$;

REVOKE ALL ON FUNCTION openwacht.alarm_snmp_sources(), openwacht.alarm_open(),
    openwacht.alarm_input(uuid[], uuid[], uuid[], text[], text[], text[], text[]),
    openwacht.alarm_sync(uuid[], uuid[], uuid[], text[], text[], text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alarm_snmp_sources(), openwacht.alarm_open(),
    openwacht.alarm_input(uuid[], uuid[], uuid[], text[], text[], text[], text[]),
    openwacht.alarm_sync(uuid[], uuid[], uuid[], text[], text[], text[], text[]) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Wartung: Die Gerätewartung gilt auch für die SNMP-Quelle des Geräts.
-- ---------------------------------------------------------------------------

DROP FUNCTION openwacht.maintenance_active();
CREATE FUNCTION openwacht.maintenance_active()
    RETURNS TABLE (check_id uuid, agent_id uuid, snmp_id uuid, ends_at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.maintenance m WHERE m.ends_at <= now();
    RETURN QUERY
        SELECT m.check_id, NULL::uuid, NULL::uuid, m.ends_at FROM openwacht.maintenance m WHERE m.check_id IS NOT NULL
        UNION ALL
        SELECT c.id, NULL::uuid, NULL::uuid, m.ends_at FROM openwacht.maintenance m JOIN openwacht.checks c ON c.device_id = m.device_id
        UNION ALL
        SELECT NULL::uuid, a.id, NULL::uuid, m.ends_at FROM openwacht.maintenance m JOIN openwacht.agents a ON a.device_id = m.device_id
        UNION ALL
        SELECT NULL::uuid, NULL::uuid, s.id, m.ends_at FROM openwacht.maintenance m JOIN openwacht.snmp_sources s ON s.device_id = m.device_id
        LIMIT 200000;
END
$$;
REVOKE ALL ON FUNCTION openwacht.maintenance_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.maintenance_active() TO openwacht_app;
