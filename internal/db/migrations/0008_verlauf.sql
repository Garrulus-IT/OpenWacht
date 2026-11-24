-- SPDX-License-Identifier: AGPL-3.0-only

-- 0008: Verlauf der Messwerte von Hosts und Checks, mit Verdichtung.
--
-- Drei Stufen (Entscheidung 19.11.2026):
--   Rohwerte          48 Stunden   metrics_host_raw, metrics_check_raw
--   5-Minuten-Mittel  30 Tage      metrics_host_5m,  metrics_check_5m
--   Stundenmittel     1 Jahr       metrics_host_1h,  metrics_check_1h
-- Zustandswechsel der Checks (check_transitions) bleiben 30 Tage; für längere
-- Zeiträume zeigt der schlechteste Zustand je Stunde, was los war. Einzelne
-- Wechsel ein Jahr lang zu halten, würde bei einem flatternden Check (alle
-- 30 s ein Wechsel) auf eine Million Zeilen je Check und Jahr wachsen.
--
-- Die Rohwerte liegen in Tagespartitionen (UTC): Alte Tage werden als Ganzes
-- entfernt statt Zeile für Zeile gelöscht. Partitionen anlegen, verdichten und
-- aufräumen erledigt metrics_maintain(), das die Zentrale regelmäßig aufruft.
--
-- Schreiben dürfen nur die SECURITY-DEFINER-Funktionen; den Mandanten leiten
-- sie aus Agent bzw. Check ab (Leitprinzip 2). Lesen darf die Anwendung im
-- sichtbaren Teilbaum (RLS wie bei agents und checks).

-- ---------------------------------------------------------------------------
-- Hosts
-- ---------------------------------------------------------------------------

-- Reihen: 'cpu' (Auslastung %), 'last1', 'speicher' und 'swap' (belegt %),
-- 'platte:<Einhängepunkt>' (belegt %).
CREATE FUNCTION openwacht.valid_series(s text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT char_length(s) <= 300 AND s !~ '[[:cntrl:]]'
           AND (s IN ('cpu', 'last1', 'speicher', 'swap') OR s ~ '^platte:.')
$$;

CREATE TABLE openwacht.metrics_host_raw (
    tenant_id uuid NOT NULL,
    agent_id  uuid NOT NULL REFERENCES openwacht.agents (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    series    text NOT NULL CHECK (openwacht.valid_series(series)),
    value     double precision NOT NULL CHECK (value BETWEEN 0 AND 1e6)
) PARTITION BY RANGE (ts);
CREATE INDEX metrics_host_raw_agent ON openwacht.metrics_host_raw (agent_id, ts);

CREATE TABLE openwacht.metrics_host_5m (
    tenant_id uuid NOT NULL,
    agent_id  uuid NOT NULL REFERENCES openwacht.agents (id) ON DELETE CASCADE,
    bucket    timestamptz NOT NULL,
    series    text NOT NULL CHECK (openwacht.valid_series(series)),
    avg       double precision NOT NULL,
    min       double precision NOT NULL,
    max       double precision NOT NULL,
    n         integer NOT NULL CHECK (n > 0),
    PRIMARY KEY (agent_id, bucket, series)
);
CREATE INDEX metrics_host_5m_bucket ON openwacht.metrics_host_5m (bucket);

CREATE TABLE openwacht.metrics_host_1h (LIKE openwacht.metrics_host_5m INCLUDING ALL);
ALTER TABLE openwacht.metrics_host_1h
    ADD FOREIGN KEY (agent_id) REFERENCES openwacht.agents (id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- Checks
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.metrics_check_raw (
    tenant_id uuid NOT NULL,
    check_id  uuid NOT NULL REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    status    text NOT NULL CHECK (status IN ('ok', 'warn', 'crit', 'unknown')),
    -- Antwortzeit in Millisekunden, falls der Check eine misst
    ms        double precision CHECK (ms BETWEEN 0 AND 600000)
) PARTITION BY RANGE (ts);
CREATE INDEX metrics_check_raw_check ON openwacht.metrics_check_raw (check_id, ts);

CREATE TABLE openwacht.metrics_check_5m (
    tenant_id uuid NOT NULL,
    check_id  uuid NOT NULL REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    bucket    timestamptz NOT NULL,
    n         integer NOT NULL CHECK (n > 0),
    n_ok      integer NOT NULL CHECK (n_ok BETWEEN 0 AND n),
    worst     text NOT NULL CHECK (worst IN ('ok', 'warn', 'crit', 'unknown')),
    ms_n      integer NOT NULL CHECK (ms_n BETWEEN 0 AND n),
    ms_avg    double precision,
    ms_min    double precision,
    ms_max    double precision,
    PRIMARY KEY (check_id, bucket)
);
CREATE INDEX metrics_check_5m_bucket ON openwacht.metrics_check_5m (bucket);

CREATE TABLE openwacht.metrics_check_1h (LIKE openwacht.metrics_check_5m INCLUDING ALL);
ALTER TABLE openwacht.metrics_check_1h
    ADD FOREIGN KEY (check_id) REFERENCES openwacht.checks (id) ON DELETE CASCADE;

CREATE TABLE openwacht.check_transitions (
    tenant_id  uuid NOT NULL,
    check_id   uuid NOT NULL REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    ts         timestamptz NOT NULL,
    old_status text CHECK (old_status IN ('ok', 'warn', 'crit', 'unknown')),
    new_status text NOT NULL CHECK (new_status IN ('ok', 'warn', 'crit', 'unknown')),
    message    text CHECK (char_length(message) <= 300)
);
CREATE INDEX check_transitions_check ON openwacht.check_transitions (check_id, ts);
CREATE INDEX check_transitions_ts ON openwacht.check_transitions (ts);

-- Schwere eines Zustands, wie internal/checks (ok < warn < crit < unknown).
CREATE FUNCTION openwacht.status_rank(s text) RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE s WHEN 'ok' THEN 0 WHEN 'warn' THEN 1 WHEN 'crit' THEN 2 WHEN 'unknown' THEN 3 END
$$;

-- ---------------------------------------------------------------------------
-- Rechte: nur lesen, im sichtbaren Teilbaum
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['metrics_host_raw', 'metrics_host_5m', 'metrics_host_1h',
                             'metrics_check_raw', 'metrics_check_5m', 'metrics_check_1h', 'check_transitions'] LOOP
        EXECUTE format('ALTER TABLE openwacht.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON openwacht.%I FROM PUBLIC', t);
        EXECUTE format('GRANT SELECT ON openwacht.%I TO openwacht_app', t);
        EXECUTE format('CREATE POLICY %I ON openwacht.%I FOR SELECT TO openwacht_app
                        USING (tenant_id IN (SELECT openwacht.visible_tenants()))', t || '_select', t);
    END LOOP;
END
$$;

-- Bis wohin verdichtet ist (je Stufe). Ohne Mandantenbezug, für die Anwendung
-- nur über metrics_watermarks() lesbar.
CREATE TABLE openwacht.metrics_rollup_state (
    tier       text PRIMARY KEY CHECK (tier IN ('5m', '1h')),
    done_until timestamptz NOT NULL
);
ALTER TABLE openwacht.metrics_rollup_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.metrics_rollup_state FROM PUBLIC, openwacht_app;
INSERT INTO openwacht.metrics_rollup_state (tier, done_until)
VALUES ('5m', date_bin('5 minutes', now(), timestamptz 'epoch')),
       ('1h', date_bin('1 hour', now(), timestamptz 'epoch'));

CREATE FUNCTION openwacht.metrics_watermarks(OUT done_5m timestamptz, OUT done_1h timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT (SELECT done_until FROM openwacht.metrics_rollup_state WHERE tier = '5m'),
           (SELECT done_until FROM openwacht.metrics_rollup_state WHERE tier = '1h')
$$;

-- ---------------------------------------------------------------------------
-- Schreiben (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Messwerte speichern wie bisher, dazu die Reihen für den Verlauf. Fehlt die
-- Tagespartition (Wartung lief nicht), gehen nur die Verlaufswerte verloren,
-- nicht die Meldung.
DROP FUNCTION openwacht.agent_report(uuid, text, text, jsonb);
CREATE FUNCTION openwacht.agent_report(p_agent uuid, p_serial text, p_hostname text, p_snapshot jsonb,
                                      p_series text[], p_values double precision[])
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
BEGIN
    IF cardinality(p_series) IS DISTINCT FROM cardinality(p_values) OR cardinality(p_series) > 100 THEN
        RAISE EXCEPTION 'agent_report: Reihen ungültig' USING ERRCODE = '22023';
    END IF;
    UPDATE openwacht.agents
       SET last_seen = now(), hostname = p_hostname, snapshot = p_snapshot,
           cert_serial_prev = CASE WHEN p_serial = cert_serial THEN NULL ELSE cert_serial_prev END
     WHERE id = p_agent AND revoked_at IS NULL
       AND p_serial IN (cert_serial, cert_serial_prev)
    RETURNING tenant_id INTO v_tenant;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    BEGIN
        INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
        SELECT DISTINCT ON (x.series) v_tenant, p_agent, now(), x.series, x.value
          FROM unnest(p_series, p_values) AS x(series, value);
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'Verlauf: Messwerte von Agent % nicht gespeichert: %', p_agent, SQLERRM;
    END;
    RETURN true;
END
$$;

-- Ergebnis eines Checks speichern wie bisher, dazu Rohwert und Zustandswechsel.
DROP FUNCTION openwacht.check_record(uuid, integer, text, text, text);
CREATE FUNCTION openwacht.check_record(p_id uuid, p_revision integer, p_status text,
                                      p_message text, p_metric text, p_ms double precision) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
    v_old    text;
BEGIN
    SELECT c.tenant_id, c.status INTO v_tenant, v_old
      FROM openwacht.checks c WHERE c.id = p_id AND c.revision = p_revision FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE openwacht.checks c
       SET since    = CASE WHEN c.status IS DISTINCT FROM p_status THEN now() ELSE c.since END,
           status   = p_status,
           message  = p_message,
           metric   = nullif(p_metric, ''),
           fails    = CASE WHEN p_status = 'ok' THEN 0 ELSE c.fails + 1 END,
           last_run = now(),
           next_run = now() + make_interval(secs => c.interval_s)
     WHERE c.id = p_id;
    IF v_old IS DISTINCT FROM p_status THEN
        INSERT INTO openwacht.check_transitions (tenant_id, check_id, ts, old_status, new_status, message)
        VALUES (v_tenant, p_id, now(), v_old, p_status, p_message);
    END IF;
    BEGIN
        INSERT INTO openwacht.metrics_check_raw (tenant_id, check_id, ts, status, ms)
        VALUES (v_tenant, p_id, now(), p_status, CASE WHEN p_ms BETWEEN 0 AND 600000 THEN p_ms END);
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'Verlauf: Ergebnis von Check % nicht gespeichert: %', p_id, SQLERRM;
    END;
    RETURN true;
END
$$;

-- ---------------------------------------------------------------------------
-- Wartung: Partitionen, Verdichtung, Aufräumen
-- ---------------------------------------------------------------------------

-- Läuft bei mehreren Zentralen nur einmal gleichzeitig (die anderen kehren
-- sofort zurück). Verdichtet wird nur, was mindestens eine Minute zurückliegt,
-- damit keine noch offene Transaktion einen Rohwert in einen fertigen Block
-- nachreicht. Liefert die Zahl der neu verdichteten 5-Minuten-Blöcke.
CREATE FUNCTION openwacht.metrics_maintain() RETURNS integer
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

    -- Partitionen für gestern bis übermorgen
    FOR d IN SELECT generate_series(current_date - 1, current_date + 2, interval '1 day')::date LOOP
        FOREACH tbl IN ARRAY ARRAY['metrics_host_raw', 'metrics_check_raw'] LOOP
            IF to_regclass(format('openwacht.%I', tbl || '_' || to_char(d, 'YYYYMMDD'))) IS NULL THEN
                EXECUTE format('CREATE TABLE openwacht.%I PARTITION OF openwacht.%I FOR VALUES FROM (%L) TO (%L)',
                               tbl || '_' || to_char(d, 'YYYYMMDD'), tbl,
                               d::timestamptz, (d + 1)::timestamptz);
            END IF;
        END LOOP;
    END LOOP;

    -- 5-Minuten-Blöcke aus Rohwerten
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

    -- Stundenblöcke aus 5-Minuten-Blöcken (gewichtet nach Anzahl)
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

    -- Aufräumen: Rohwerte-Tage, deren Ende mehr als 48 Stunden zurückliegt
    -- (erst nach der Verdichtung, damit nichts unverdichtet verschwindet)
    FOR part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
          JOIN pg_namespace n ON n.oid = p.relnamespace
         WHERE n.nspname = 'openwacht' AND p.relname IN ('metrics_host_raw', 'metrics_check_raw')
           AND c.relname ~ '_[0-9]{8}$'
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1 <= (now() - interval '48 hours')::date
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1
               <= (SELECT done_until FROM openwacht.metrics_rollup_state WHERE tier = '5m')::date
    LOOP
        EXECUTE format('DROP TABLE openwacht.%I', part.relname);
    END LOOP;
    DELETE FROM openwacht.metrics_host_5m WHERE bucket < now() - interval '30 days';
    DELETE FROM openwacht.metrics_check_5m WHERE bucket < now() - interval '30 days';
    DELETE FROM openwacht.metrics_host_1h WHERE bucket < now() - interval '365 days';
    DELETE FROM openwacht.metrics_check_1h WHERE bucket < now() - interval '365 days';
    DELETE FROM openwacht.check_transitions WHERE ts < now() - interval '30 days';
    RETURN v_blocks;
END
$$;

-- Partitionen für heute und die nächsten Tage sofort anlegen.
SELECT openwacht.metrics_maintain();

REVOKE ALL ON FUNCTION openwacht.valid_series(text), openwacht.status_rank(text), openwacht.metrics_watermarks(),
    openwacht.agent_report(uuid, text, text, jsonb, text[], double precision[]),
    openwacht.check_record(uuid, integer, text, text, text, double precision),
    openwacht.metrics_maintain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.valid_series(text), openwacht.status_rank(text), openwacht.metrics_watermarks(),
    openwacht.agent_report(uuid, text, text, jsonb, text[], double precision[]),
    openwacht.check_record(uuid, integer, text, text, text, double precision),
    openwacht.metrics_maintain() TO openwacht_app;
