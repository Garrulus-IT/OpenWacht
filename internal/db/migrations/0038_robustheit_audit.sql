-- SPDX-License-Identifier: AGPL-3.0-only

-- Etappe 31: Robustheit und Audit (Befunde M6, N2 und Selbstüberwachung).
--
-- 1. Audit-Kette: täglicher Prüflauf mit Ergebnis (audit_checks), Anker für
--    die Aufbewahrung (audit_anchor), Löschen nur am Anfang der Kette und nur
--    nach erfolgreicher Prüfung (audit_prune), Export mit Folgenummer und Hash
--    (audit_export_rows, Stand je Ziel in audit_export_state).
-- 2. Hinweise (notices): Meldungen der Zentrale über sich selbst an den
--    Betreiber (tenant_id NULL) und Hinweise an Mandanten (N2: Alarme seit
--    7 Tagen durch eine Abhängigkeit unterdrückt). Versand an die Alarmkanäle
--    des Mandanten bzw. des Hauptmandanten.
-- 3. Lebenszeichen des Trap-Dienstes für /api/v1/gesund.
--
-- Die Funktionen ohne Benutzerprüfung („System“) ruft nur die Zentrale selbst
-- auf (Hintergrundläufe, wie runtime_settings); RLS schützt nicht gegen eine
-- übernommene Zentrale (Befund I1).

-- --- 1. Audit-Kette ------------------------------------------------------------

-- Anker: erste noch vorhandene Folgenummer und Hash des letzten gelöschten
-- Eintrags. Fehlt die Zeile, beginnt die Kette bei 1 ohne Vorgänger.
CREATE TABLE openwacht.audit_anchor (
    id           boolean PRIMARY KEY DEFAULT true CHECK (id),
    first_seq    bigint NOT NULL CHECK (first_seq > 1),
    prev_hash    bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    pruned_at    timestamptz NOT NULL,
    pruned_total bigint NOT NULL CHECK (pruned_total > 0)
);
ALTER TABLE openwacht.audit_anchor ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.audit_anchor FROM PUBLIC, openwacht_app;

-- Prüfung ab dem Anker (sonst wie bisher ab 1).
CREATE OR REPLACE FUNCTION openwacht.audit_verify() RETURNS bigint
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    e        openwacht.audit_log;
    expected bigint := 1;
    prev     bytea := NULL;
BEGIN
    SELECT a.first_seq, a.prev_hash INTO expected, prev FROM openwacht.audit_anchor a;
    IF NOT FOUND THEN
        expected := 1;
        prev := NULL;
    END IF;
    FOR e IN SELECT * FROM openwacht.audit_log ORDER BY chain_seq LOOP
        IF e.chain_seq <> expected
           OR e.prev_hash IS DISTINCT FROM prev
           OR e.hash <> openwacht.audit_entry_hash(e) THEN
            RETURN e.chain_seq;
        END IF;
        prev := e.hash;
        expected := expected + 1;
    END LOOP;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openwacht.audit_verify() FROM PUBLIC;

-- Löschen nur über audit_prune (setzt die lokale Einstellung in seiner
-- Transaktion). Die App-Rolle hat ohnehin kein DELETE-Recht.
CREATE OR REPLACE FUNCTION openwacht.audit_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('openwacht.audit_prune', true) = 'an' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Das Audit-Log ist unveränderlich.';
END
$$;

-- Ergebnisse der Prüfläufe (für Oberfläche, Alarm und Befehl audit-pruefen).
CREATE TABLE openwacht.audit_checks (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    ok         boolean NOT NULL,
    broken_seq bigint,
    entries    bigint NOT NULL,
    first_seq  bigint,
    last_seq   bigint,
    last_hash  bytea,
    CHECK (ok = (broken_seq IS NULL))
);
CREATE INDEX audit_checks_at ON openwacht.audit_checks (at DESC);
ALTER TABLE openwacht.audit_checks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.audit_checks FROM PUBLIC, openwacht_app;

-- System: Prüflauf. Ein Bruch wird zusätzlich ins Audit-Log geschrieben
-- (ans Ende der Kette, die Prüfung danach meldet weiter dieselbe Stelle).
CREATE FUNCTION openwacht.audit_check_run()
    RETURNS TABLE (ok boolean, broken_seq bigint, entries bigint, first_seq bigint, last_seq bigint, last_hash bytea)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_broken bigint;
    v_n bigint;
    v_first bigint;
    v_last bigint;
    v_hash bytea;
BEGIN
    v_broken := openwacht.audit_verify();
    SELECT count(*), min(a.chain_seq), max(a.chain_seq) INTO v_n, v_first, v_last FROM openwacht.audit_log a;
    SELECT a.hash INTO v_hash FROM openwacht.audit_log a WHERE a.chain_seq = v_last;
    INSERT INTO openwacht.audit_checks (ok, broken_seq, entries, first_seq, last_seq, last_hash)
    VALUES (v_broken IS NULL, v_broken, v_n, v_first, v_last, v_hash);
    DELETE FROM openwacht.audit_checks c WHERE c.at < now() - interval '400 days';
    IF v_broken IS NOT NULL THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NULL, 'audit.kette_gebrochen', jsonb_build_object('stelle', v_broken));
    END IF;
    RETURN QUERY SELECT v_broken IS NULL, v_broken, v_n, v_first, v_last, v_hash;
END
$$;
REVOKE ALL ON FUNCTION openwacht.audit_check_run() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_check_run() TO openwacht_app;

-- System: letzter Prüflauf (Planung des täglichen Laufs, Alarm).
CREATE FUNCTION openwacht.audit_check_last()
    RETURNS TABLE (at timestamptz, ok boolean, broken_seq bigint, entries bigint, first_seq bigint, last_seq bigint, last_hash bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.at, c.ok, c.broken_seq, c.entries, c.first_seq, c.last_seq, c.last_hash
      FROM openwacht.audit_checks c ORDER BY c.at DESC, c.id DESC LIMIT 1
$$;
REVOKE ALL ON FUNCTION openwacht.audit_check_last() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_check_last() TO openwacht_app;

-- Aufbewahrung in Tagen (NULL = unbegrenzt), nur der Betreiber stellt sie ein.
ALTER TABLE openwacht.settings ADD COLUMN audit_days integer CHECK (audit_days BETWEEN 365 AND 3650);
GRANT UPDATE (audit_days) ON openwacht.settings TO openwacht_app;

CREATE FUNCTION openwacht.runtime_audit_days() RETURNS integer
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.audit_days FROM openwacht.settings s
$$;
REVOKE ALL ON FUNCTION openwacht.runtime_audit_days() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.runtime_audit_days() TO openwacht_app;

-- Stand des fortlaufenden Exports je Ziel (letzte geschriebene Folgenummer).
CREATE TABLE openwacht.audit_export_state (
    target     text PRIMARY KEY CHECK (target IN ('datei', 'syslog')),
    last_seq   bigint NOT NULL CHECK (last_seq >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    error      text CHECK (char_length(error) <= 300),
    error_at   timestamptz
);
ALTER TABLE openwacht.audit_export_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.audit_export_state FROM PUBLIC, openwacht_app;

-- System: Stand eines Ziels; beim ersten Mal 0 (alles exportieren).
CREATE FUNCTION openwacht.audit_export_cursor(p_target text) RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce((SELECT e.last_seq FROM openwacht.audit_export_state e WHERE e.target = p_target), 0)
$$;
REVOKE ALL ON FUNCTION openwacht.audit_export_cursor(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_export_cursor(text) TO openwacht_app;

-- System: Stand fortschreiben (nur vorwärts) oder einen Fehler vermerken.
CREATE FUNCTION openwacht.audit_export_done(p_target text, p_seq bigint, p_error text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF p_target NOT IN ('datei', 'syslog') THEN
        RAISE EXCEPTION 'unbekanntes Ziel' USING ERRCODE = '22023';
    END IF;
    INSERT INTO openwacht.audit_export_state AS e (target, last_seq, updated_at, error, error_at)
    VALUES (p_target, greatest(coalesce(p_seq, 0), 0), now(), left(p_error, 300), CASE WHEN p_error IS NOT NULL THEN now() END)
    ON CONFLICT (target) DO UPDATE SET
        last_seq = greatest(e.last_seq, coalesce(p_seq, e.last_seq)),
        updated_at = CASE WHEN p_error IS NULL THEN now() ELSE e.updated_at END,
        error = left(p_error, 300),
        error_at = CASE WHEN p_error IS NULL THEN NULL ELSE coalesce(e.error_at, now()) END;
END
$$;
REVOKE ALL ON FUNCTION openwacht.audit_export_done(text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_export_done(text, bigint, text) TO openwacht_app;

-- System: Einträge nach p_after für den fortlaufenden Export.
CREATE FUNCTION openwacht.audit_export_rows(p_after bigint, p_limit integer)
    RETURNS TABLE (chain_seq bigint, at timestamptz, tenant_id uuid, tenant_name text, actor_id uuid, actor_email text,
                   action text, details jsonb, prev_hash bytea, hash bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.chain_seq, a.at, a.tenant_id, t.name, a.actor_user_id, u.email, a.action, a.details, a.prev_hash, a.hash
      FROM openwacht.audit_log a
      LEFT JOIN openwacht.tenants t ON t.id = a.tenant_id
      LEFT JOIN openwacht.users u ON u.id = a.actor_user_id
     WHERE a.chain_seq > p_after
     ORDER BY a.chain_seq LIMIT least(greatest(p_limit, 1), 1000)
$$;
REVOKE ALL ON FUNCTION openwacht.audit_export_rows(bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_export_rows(bigint, integer) TO openwacht_app;

-- System: Aufbewahrung. Löscht nur am Anfang der Kette, nie den jüngsten
-- Eintrag, nie über p_max_seq hinaus (noch nicht exportiert) und nur, wenn
-- die Kette vorher heil ist. Danach steht der Anker in audit_anchor und als
-- Eintrag „audit.gekuerzt“ in der Kette.
CREATE FUNCTION openwacht.audit_prune(p_days integer, p_max_seq bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    v_cut bigint;
    v_last bigint;
    v_hash bytea;
    v_n bigint;
BEGIN
    IF p_days IS NULL OR p_days < 365 OR p_days > 3650 THEN
        RAISE EXCEPTION 'Aufbewahrung 365 bis 3650 Tage' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('openwacht.audit_log'));
    IF openwacht.audit_verify() IS NOT NULL THEN
        RAISE EXCEPTION 'Audit-Kette gebrochen, es wird nichts gelöscht' USING ERRCODE = '55000';
    END IF;
    SELECT max(a.chain_seq) INTO v_last FROM openwacht.audit_log a;
    -- bis vor den ersten Eintrag, der noch aufbewahrt wird
    SELECT coalesce(min(a.chain_seq), v_last + 1) - 1 INTO v_cut
      FROM openwacht.audit_log a WHERE a.at >= now() - p_days * interval '1 day';
    v_cut := least(v_cut, v_last - 1, coalesce(p_max_seq, v_cut));
    IF v_cut IS NULL OR NOT EXISTS (SELECT 1 FROM openwacht.audit_log a WHERE a.chain_seq <= v_cut) THEN
        RETURN 0;
    END IF;
    SELECT a.hash INTO v_hash FROM openwacht.audit_log a WHERE a.chain_seq = v_cut;
    PERFORM set_config('openwacht.audit_prune', 'an', true);
    DELETE FROM openwacht.audit_log a WHERE a.chain_seq <= v_cut;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    PERFORM set_config('openwacht.audit_prune', '', true);
    INSERT INTO openwacht.audit_anchor AS x (first_seq, prev_hash, pruned_at, pruned_total)
    VALUES (v_cut + 1, v_hash, now(), v_n)
    ON CONFLICT (id) DO UPDATE SET first_seq = EXCLUDED.first_seq, prev_hash = EXCLUDED.prev_hash,
        pruned_at = EXCLUDED.pruned_at, pruned_total = x.pruned_total + EXCLUDED.pruned_total;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (NULL, 'audit.gekuerzt', jsonb_build_object('bis', v_cut, 'anzahl', v_n, 'anker', encode(v_hash, 'hex'),
        'tage', p_days));
    RETURN v_n;
END
$$;
REVOKE ALL ON FUNCTION openwacht.audit_prune(integer, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_prune(integer, bigint) TO openwacht_app;

-- Betreiber: Zustand für die Seite Einstellungen.
CREATE FUNCTION openwacht.audit_status()
    RETURNS TABLE (checked_at timestamptz, ok boolean, broken_seq bigint, entries bigint, first_seq bigint,
                   last_seq bigint, last_hash bytea, audit_days integer, pruned_at timestamptz, pruned_total bigint,
                   file_seq bigint, file_error text, file_error_at timestamptz,
                   syslog_seq bigint, syslog_error text, syslog_error_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'nur für Betreiber' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT c.at, c.ok, c.broken_seq, c.entries, c.first_seq, c.last_seq, c.last_hash,
        (SELECT s.audit_days FROM openwacht.settings s), x.pruned_at, x.pruned_total,
        f.last_seq, f.error, f.error_at, y.last_seq, y.error, y.error_at
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (SELECT * FROM openwacht.audit_check_last()) c ON true
      LEFT JOIN openwacht.audit_anchor x ON true
      LEFT JOIN openwacht.audit_export_state f ON f.target = 'datei'
      LEFT JOIN openwacht.audit_export_state y ON y.target = 'syslog';
END
$$;
REVOKE ALL ON FUNCTION openwacht.audit_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.audit_status() TO openwacht_app;

-- --- 2. Hinweise -------------------------------------------------------------------

-- Schlüssel „bereich:name“, z. B. zentrale:sicherung, unterdrueckt:<Gerät>.
-- sent_status: zuletzt verschickter Zustand (NULL = noch nichts).
CREATE TABLE openwacht.notices (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z]{1,20}:[A-Za-z0-9._-]{1,100}$'),
    tenant_id   uuid REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    status      text NOT NULL CHECK (status IN ('warn', 'crit', 'ok')),
    title       text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200 AND title !~ '[[:cntrl:]]'),
    message     text NOT NULL CHECK (char_length(message) <= 1000),
    since       timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    sent_status text CHECK (sent_status IN ('warn', 'crit', 'ok')),
    sent_at     timestamptz,
    CHECK ((ended_at IS NULL) = (status <> 'ok'))
);
CREATE INDEX notices_tenant ON openwacht.notices (tenant_id) WHERE ended_at IS NULL;
ALTER TABLE openwacht.notices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.notices FROM PUBLIC, openwacht_app;

-- System: Stand eines Bereichs setzen. p_items: [{key, mandant, status, titel,
-- text, seit}]; Einträge des Bereichs, die fehlen, sind erledigt.
CREATE FUNCTION openwacht.notice_put(p_scope text, p_items jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    i jsonb;
    keys text[] := '{}';
BEGIN
    IF p_scope !~ '^[a-z]{1,20}$' OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 1000 THEN
        RAISE EXCEPTION 'ungültige Hinweise' USING ERRCODE = '22023';
    END IF;
    FOR i IN SELECT * FROM jsonb_array_elements(p_items) LOOP
        IF split_part(i->>'key', ':', 1) <> p_scope OR i->>'status' NOT IN ('warn', 'crit') THEN
            RAISE EXCEPTION 'ungültiger Hinweis' USING ERRCODE = '22023';
        END IF;
        keys := keys || (i->>'key');
        INSERT INTO openwacht.notices AS n (key, tenant_id, status, title, message, since)
        VALUES (i->>'key', (i->>'mandant')::uuid, i->>'status', left(i->>'titel', 200), left(coalesce(i->>'text', ''), 1000),
                coalesce((i->>'seit')::timestamptz, now()))
        ON CONFLICT (key) DO UPDATE SET
            tenant_id = EXCLUDED.tenant_id, status = EXCLUDED.status, title = EXCLUDED.title, message = EXCLUDED.message,
            since = CASE WHEN n.ended_at IS NULL THEN n.since ELSE EXCLUDED.since END,
            ended_at = NULL, updated_at = now(),
            -- nach einer Entwarnung beginnt der Hinweis neu
            sent_status = CASE WHEN n.ended_at IS NULL THEN n.sent_status END;
    END LOOP;
    UPDATE openwacht.notices n SET status = 'ok', ended_at = now(), updated_at = now()
     WHERE split_part(n.key, ':', 1) = p_scope AND n.ended_at IS NULL AND NOT (n.key = ANY (keys));
    DELETE FROM openwacht.notices n WHERE n.ended_at < now() - interval '30 days';
END
$$;
REVOKE ALL ON FUNCTION openwacht.notice_put(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.notice_put(text, jsonb) TO openwacht_app;

-- System: zu verschickende Hinweise (neu, Zustand geändert, Entwarnung nach
-- einer verschickten Meldung) mit den Alarmkanälen ihres Mandanten bzw. des
-- Hauptmandanten.
CREATE FUNCTION openwacht.notice_due()
    RETURNS TABLE (key text, tenant_id uuid, status text, title text, message text, since timestamptz, channels uuid[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT n.key, n.tenant_id, n.status, n.title, n.message, n.since,
           coalesce((SELECT array_agg(c.id ORDER BY c.id) FROM openwacht.alert_channels c
                      WHERE c.tenant_id = coalesce(n.tenant_id, (SELECT t.id FROM openwacht.tenants t WHERE t.parent_id IS NULL))),
                    '{}')
      FROM openwacht.notices n
     WHERE n.sent_status IS DISTINCT FROM n.status AND NOT (n.status = 'ok' AND n.sent_status IS NULL)
     ORDER BY n.since
$$;
REVOKE ALL ON FUNCTION openwacht.notice_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.notice_due() TO openwacht_app;

CREATE FUNCTION openwacht.notice_sent(p_key text, p_status text) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.notices SET sent_status = p_status, sent_at = now() WHERE key = p_key AND status = p_status
$$;
REVOKE ALL ON FUNCTION openwacht.notice_sent(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.notice_sent(text, text) TO openwacht_app;

-- Benutzer: offene Hinweise der sichtbaren Mandanten; die der Zentrale nur
-- für den Betreiber.
CREATE FUNCTION openwacht.notice_list()
    RETURNS TABLE (key text, tenant_id uuid, status text, title text, message text, since timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT n.key, n.tenant_id, n.status, n.title, n.message, n.since FROM openwacht.notices n
     WHERE n.ended_at IS NULL
       AND (n.tenant_id IN (SELECT openwacht.visible_tenants())
            OR (n.tenant_id IS NULL AND openwacht.is_platform_operator()))
     ORDER BY n.status = 'crit' DESC, n.since
$$;
REVOKE ALL ON FUNCTION openwacht.notice_list() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.notice_list() TO openwacht_app;

-- System: letzte Sicherung (Alarm bei Fehler oder Überfälligkeit).
CREATE FUNCTION openwacht.backup_last()
    RETURNS TABLE (started_at timestamptz, ok boolean, message text, last_ok_at timestamptz, runs bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT b.started_at, b.ok, b.message,
           (SELECT max(o.started_at) FROM openwacht.backup_log o WHERE o.ok),
           (SELECT count(*) FROM openwacht.backup_log)
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (SELECT * FROM openwacht.backup_log x ORDER BY x.started_at DESC LIMIT 1) b ON true
$$;
REVOKE ALL ON FUNCTION openwacht.backup_last() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.backup_last() TO openwacht_app;

-- N2: Geräte, deren Alarme wegen eines ausgefallenen Elterngeräts ruhen, je
-- auslösendem Gerät mit dem Beginn seines Ausfalls.
CREATE FUNCTION openwacht.device_down_since(p_device uuid) RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT min(x.started_at) FROM (
        SELECT a.started_at FROM openwacht.alarms a JOIN openwacht.checks c ON c.id = a.check_id
         WHERE a.ended_at IS NULL AND a.status = 'crit' AND c.kind = 'ping' AND c.device_id = p_device
        UNION ALL
        SELECT a.started_at FROM openwacht.alarms a JOIN openwacht.agents g ON g.id = a.agent_id
         WHERE a.ended_at IS NULL AND a.status = 'crit' AND a.subject = 'stumm' AND g.device_id = p_device
        UNION ALL
        SELECT a.started_at FROM openwacht.alarms a JOIN openwacht.snmp_sources s ON s.id = a.snmp_id
         WHERE a.ended_at IS NULL AND a.status = 'crit' AND a.subject = 'stumm' AND s.device_id = p_device) x
$$;
REVOKE ALL ON FUNCTION openwacht.device_down_since(uuid) FROM PUBLIC;

CREATE FUNCTION openwacht.dependency_suppression()
    RETURNS TABLE (tenant_id uuid, blocker_id uuid, blocker_name text, since timestamptz, devices bigint, names text[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.tenant_id, b.blocker_id, bd.name, openwacht.device_down_since(b.blocker_id), count(*),
           (array_agg(d.name ORDER BY lower(d.name), d.id))[1:20]
      FROM openwacht.devices_blocked() b
      JOIN openwacht.devices d ON d.id = b.device_id
      JOIN openwacht.devices bd ON bd.id = b.blocker_id
     GROUP BY d.tenant_id, b.blocker_id, bd.name
$$;
REVOKE ALL ON FUNCTION openwacht.dependency_suppression() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.dependency_suppression() TO openwacht_app;

-- --- 3. Lebenszeichen des Trap-Dienstes ---------------------------------------------

CREATE TABLE openwacht.trap_service_state (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    seen_at timestamptz NOT NULL
);
ALTER TABLE openwacht.trap_service_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.trap_service_state FROM PUBLIC, openwacht_app, openwacht_traps;

CREATE FUNCTION openwacht.traps_heartbeat() RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    INSERT INTO openwacht.trap_service_state (seen_at) VALUES (now())
    ON CONFLICT (id) DO UPDATE SET seen_at = EXCLUDED.seen_at
$$;
REVOKE ALL ON FUNCTION openwacht.traps_heartbeat() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.traps_heartbeat() TO openwacht_traps;

CREATE FUNCTION openwacht.trap_service_seen() RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT seen_at FROM openwacht.trap_service_state
$$;
REVOKE ALL ON FUNCTION openwacht.trap_service_seen() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.trap_service_seen() TO openwacht_app;
