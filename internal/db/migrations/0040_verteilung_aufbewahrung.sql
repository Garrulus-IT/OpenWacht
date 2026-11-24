-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappen 34 und 35: Agent-Verteilung und Betrieb.
--
-- 1. Download des Agents von der Zentrale (Entscheidung 22.11.2026:
--    nur mit Prüfung der Offline-Signatur auf dem Zielrechner). Wer ein
--    gültiges Registrierungs-Token hat, darf das neueste signierte Paket
--    seiner Plattform holen; das Token wird dabei nicht verbraucht. Welche
--    Signatur noch gilt (Widerrufe), prüft die Zentrale in Go.
-- 2. Aufbewahrung der Messwerte: global einstellbar (Betreiber) und je
--    Mandant für die 5-Minuten- und Stundenwerte (erbt vom nächsten
--    Mandanten darüber). Rohwerte liegen in Tagespartitionen für alle
--    Mandanten gemeinsam, deshalb nur global.

-- --- 1. Download ---------------------------------------------------------------------

CREATE FUNCTION openwacht.agent_token_usable(p_token_hash bytea) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (SELECT 1 FROM openwacht.agent_tokens t
                    WHERE t.token_hash = p_token_hash AND t.expires_at > now() AND t.uses_left >= 1)
$$;
REVOKE ALL ON FUNCTION openwacht.agent_token_usable(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_token_usable(bytea) TO openwacht_app;

-- Die neuesten Pakete der Plattform (ohne Daten), neueste zuerst.
CREATE FUNCTION openwacht.agent_download_list(p_token_hash bytea, p_os text, p_arch text)
    RETURNS TABLE (version text, sha256 text, size bigint, signature text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.agent_token_usable(p_token_hash) THEN
        RAISE EXCEPTION 'Token ungültig, abgelaufen oder verbraucht' USING ERRCODE = '28000';
    END IF;
    RETURN QUERY SELECT u.version, u.sha256, u.size, u.signature FROM openwacht.agent_updates u
      WHERE u.os = p_os AND u.arch = p_arch
      ORDER BY string_to_array(u.version, '.')::int[] DESC LIMIT 10;
END
$$;

CREATE FUNCTION openwacht.agent_download_data(p_token_hash bytea, p_os text, p_arch text, p_version text) RETURNS bytea
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    d bytea;
BEGIN
    IF NOT openwacht.agent_token_usable(p_token_hash) THEN
        RAISE EXCEPTION 'Token ungültig, abgelaufen oder verbraucht' USING ERRCODE = '28000';
    END IF;
    SELECT u.data INTO d FROM openwacht.agent_updates u WHERE u.os = p_os AND u.arch = p_arch AND u.version = p_version;
    RETURN d;
END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_download_list(bytea, text, text), openwacht.agent_download_data(bytea, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_download_list(bytea, text, text), openwacht.agent_download_data(bytea, text, text, text)
    TO openwacht_app;

-- --- 2. Aufbewahrung -----------------------------------------------------------------

-- NULL = Standard (Rohwerte 2 Tage, 5-Minuten-Werte 30 Tage, Stundenwerte 365 Tage).
ALTER TABLE openwacht.settings
    ADD COLUMN keep_raw_days integer CHECK (keep_raw_days BETWEEN 2 AND 7),
    ADD COLUMN keep_5m_days integer CHECK (keep_5m_days BETWEEN 30 AND 400),
    ADD COLUMN keep_1h_days integer CHECK (keep_1h_days BETWEEN 90 AND 1830);
GRANT UPDATE (keep_raw_days, keep_5m_days, keep_1h_days) ON openwacht.settings TO openwacht_app;

-- NULL = vom nächsten Mandanten darüber bzw. global
ALTER TABLE openwacht.tenant_settings
    ADD COLUMN keep_5m_days integer CHECK (keep_5m_days BETWEEN 30 AND 400),
    ADD COLUMN keep_1h_days integer CHECK (keep_1h_days BETWEEN 90 AND 1830);
GRANT UPDATE (keep_5m_days, keep_1h_days) ON openwacht.tenant_settings TO openwacht_app;

-- Audit der Aufbewahrung (die allgemeinen Trigger kennen die neuen Spalten nicht).
CREATE FUNCTION openwacht.retention_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_tenant uuid;
    v_old    jsonb;
    v_new    jsonb;
BEGIN
    IF TG_TABLE_NAME = 'settings' THEN
        v_old := jsonb_build_object('roh_tage', OLD.keep_raw_days, 'fuenf_min_tage', OLD.keep_5m_days, 'stunden_tage', OLD.keep_1h_days);
        v_new := jsonb_build_object('roh_tage', NEW.keep_raw_days, 'fuenf_min_tage', NEW.keep_5m_days, 'stunden_tage', NEW.keep_1h_days);
    ELSE
        v_tenant := coalesce(NEW.tenant_id, OLD.tenant_id);
        IF TG_OP = 'INSERT' THEN
            v_old := jsonb_build_object('fuenf_min_tage', NULL, 'stunden_tage', NULL);
        ELSE
            v_old := jsonb_build_object('fuenf_min_tage', OLD.keep_5m_days, 'stunden_tage', OLD.keep_1h_days);
        END IF;
        IF TG_OP = 'DELETE' THEN
            v_new := jsonb_build_object('fuenf_min_tage', NULL, 'stunden_tage', NULL);
        ELSE
            v_new := jsonb_build_object('fuenf_min_tage', NEW.keep_5m_days, 'stunden_tage', NEW.keep_1h_days);
        END IF;
    END IF;
    IF v_old IS DISTINCT FROM v_new THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (v_tenant, 'einstellungen.aufbewahrung', jsonb_build_object('alt', v_old, 'neu', v_new));
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER settings_retention_audit AFTER UPDATE ON openwacht.settings
    FOR EACH ROW EXECUTE FUNCTION openwacht.retention_audit();
CREATE TRIGGER tenant_settings_retention_audit AFTER INSERT OR UPDATE OR DELETE ON openwacht.tenant_settings
    FOR EACH ROW EXECUTE FUNCTION openwacht.retention_audit();

-- Wirksame Aufbewahrung je Mandant: eigener Wert, sonst der des nächsten
-- Mandanten darüber, sonst global, sonst Standard. Nur für die Wartung und
-- den Betreiber (Seite Einstellungen).
CREATE FUNCTION openwacht.metrics_retention()
    RETURNS TABLE (tenant_id uuid, days_5m integer, days_1h integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT t.id,
        coalesce((SELECT ts.keep_5m_days FROM openwacht.tenant_closure c
                    JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor
                   WHERE c.descendant = t.id AND ts.keep_5m_days IS NOT NULL ORDER BY c.depth LIMIT 1),
                 (SELECT s.keep_5m_days FROM openwacht.settings s), 30),
        coalesce((SELECT ts.keep_1h_days FROM openwacht.tenant_closure c
                    JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor
                   WHERE c.descendant = t.id AND ts.keep_1h_days IS NOT NULL ORDER BY c.depth LIMIT 1),
                 (SELECT s.keep_1h_days FROM openwacht.settings s), 365)
      FROM openwacht.tenants t
$$;
REVOKE ALL ON FUNCTION openwacht.metrics_retention() FROM PUBLIC;

CREATE FUNCTION openwacht.settings_retention()
    RETURNS TABLE (tenant_id uuid, days_5m integer, days_1h integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT * FROM openwacht.metrics_retention();
END
$$;
REVOKE ALL ON FUNCTION openwacht.settings_retention() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.settings_retention() TO openwacht_app;

-- Größe der Messwert-Tabellen (Betreiber, Seite Einstellungen und Lasttest).
CREATE FUNCTION openwacht.metrics_sizes() RETURNS TABLE (tier text, bytes bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT 'roh'::text, coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint
      FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
      JOIN pg_namespace n ON n.oid = p.relnamespace
     WHERE n.nspname = 'openwacht' AND p.relname IN ('metrics_host_raw', 'metrics_check_raw', 'metrics_snmp_raw')
    UNION ALL
    SELECT '5m', (pg_total_relation_size('openwacht.metrics_host_5m') + pg_total_relation_size('openwacht.metrics_snmp_5m')
                  + pg_total_relation_size('openwacht.metrics_check_5m') + pg_total_relation_size('openwacht.check_transitions'))::bigint
    UNION ALL
    SELECT '1h', (pg_total_relation_size('openwacht.metrics_host_1h') + pg_total_relation_size('openwacht.metrics_snmp_1h')
                  + pg_total_relation_size('openwacht.metrics_check_1h'))::bigint;
END
$$;
REVOKE ALL ON FUNCTION openwacht.metrics_sizes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.metrics_sizes() TO openwacht_app;

-- Wartung wie in 0013, nur das Aufräumen folgt der Aufbewahrung.
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
    v_raw    integer;
    v_min5   integer;
    v_min1   integer;
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

    -- Rohwerte: ganze Tagespartitionen, frühestens nach der Verdichtung.
    SELECT coalesce(s.keep_raw_days, 2) INTO v_raw FROM openwacht.settings s;
    v_raw := coalesce(v_raw, 2);
    FOR part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
          JOIN pg_namespace n ON n.oid = p.relnamespace
         WHERE n.nspname = 'openwacht' AND p.relname IN ('metrics_host_raw', 'metrics_check_raw', 'metrics_snmp_raw')
           AND c.relname ~ '_[0-9]{8}$'
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1 <= (now() - make_interval(days => v_raw))::date
           AND to_date(right(c.relname, 8), 'YYYYMMDD') + 1
               <= (SELECT done_until FROM openwacht.metrics_rollup_state WHERE tier = '5m')::date
    LOOP
        EXECUTE format('DROP TABLE openwacht.%I', part.relname);
    END LOOP;

    -- Verdichtete Werte je Mandant. Die Vorauswahl über den kürzesten Wert
    -- nutzt den Index auf bucket; ohne passende Zeile kostet das nichts.
    SELECT coalesce(min(r.days_5m), 30), coalesce(min(r.days_1h), 365) INTO v_min5, v_min1 FROM openwacht.metrics_retention() r;
    DELETE FROM openwacht.metrics_host_5m m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min5) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_5m);
    DELETE FROM openwacht.metrics_snmp_5m m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min5) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_5m);
    DELETE FROM openwacht.metrics_check_5m m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min5) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_5m);
    DELETE FROM openwacht.check_transitions m USING openwacht.metrics_retention() k
     WHERE m.ts < now() - make_interval(days => v_min5) AND k.tenant_id = m.tenant_id
       AND m.ts < now() - make_interval(days => k.days_5m);
    DELETE FROM openwacht.metrics_host_1h m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min1) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_1h);
    DELETE FROM openwacht.metrics_snmp_1h m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min1) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_1h);
    DELETE FROM openwacht.metrics_check_1h m USING openwacht.metrics_retention() k
     WHERE m.bucket < now() - make_interval(days => v_min1) AND k.tenant_id = m.tenant_id
       AND m.bucket < now() - make_interval(days => k.days_1h);
    -- Werte eines gelöschten Mandanten (ohne Zeile in keep) verschwinden mit dem Mandanten.
    RETURN v_blocks;
END
$$;

-- Für die Oberfläche: Kandidaten für den Download-Befehl (jeder Angemeldete,
-- wie die Liste der Pakete; die Signatur ist nicht geheim).
CREATE FUNCTION openwacht.agent_download_candidates(p_os text, p_arch text)
    RETURNS TABLE (version text, sha256 text, size bigint, signature text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF openwacht.current_user_id() IS NULL THEN
        RAISE EXCEPTION 'nicht angemeldet' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT u.version, u.sha256, u.size, u.signature FROM openwacht.agent_updates u
      WHERE u.os = p_os AND u.arch = p_arch
      ORDER BY string_to_array(u.version, '.')::int[] DESC LIMIT 10;
END
$$;
REVOKE ALL ON FUNCTION openwacht.agent_download_candidates(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.agent_download_candidates(text, text) TO openwacht_app;
