-- SPDX-License-Identifier: AGPL-3.0-only

-- 0009: Alarmprotokoll und Bestätigen.
--
-- Ein Alarm ist ein Problemabschnitt eines Sensors: ein Check oder ein
-- Gegenstand eines Agents ('stumm', 'speicher', 'platte:<Einhängepunkt>').
-- Er beginnt, wenn der Sensor zum Problem wird (Checks mit Fehler erst nach
-- der Zahl der Fehlschläge, ab der auch gemeldet wird), und endet mit der
-- Erholung. Das Protokoll entsteht unabhängig von Alarmkanälen: Auch wer
-- keinen Kanal hat, sieht in der Übersicht, was los war.
--
-- Schreiben darf nur die Zentrale über alarm_sync() (ohne Benutzerkontext);
-- den Mandanten leitet die Funktion aus Check bzw. Agent ab (Leitprinzip 2).
-- Die Anwendung darf im sichtbaren Teilbaum lesen und als Admin oder
-- Operator bestätigen. Ein bestätigter Alarm bekommt keine Erinnerungen mehr;
-- wird er schlimmer (Warnung → Fehler), verfällt die Bestätigung.
--
-- Abgeschlossene Alarme bleiben 90 Tage.

CREATE TABLE openwacht.alarms (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    -- Quelle; wird sie gelöscht, bleibt der Eintrag im Protokoll stehen.
    check_id     uuid REFERENCES openwacht.checks (id) ON DELETE SET NULL,
    agent_id     uuid REFERENCES openwacht.agents (id) ON DELETE SET NULL,
    subject      text NOT NULL CHECK (char_length(subject) <= 300 AND subject !~ '[[:cntrl:]]'
                                      AND (subject IN ('check', 'stumm', 'speicher') OR subject ~ '^platte:.')),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 300 AND name !~ '[[:cntrl:]]'),
    status       text NOT NULL CHECK (status IN ('warn', 'crit', 'unknown')),
    worst        text NOT NULL CHECK (worst IN ('warn', 'crit', 'unknown')),
    message      text NOT NULL DEFAULT '' CHECK (char_length(message) <= 300),
    started_at   timestamptz NOT NULL,
    changed_at   timestamptz NOT NULL,
    ended_at     timestamptz,
    ack_at       timestamptz,
    ack_by       uuid REFERENCES openwacht.users (id) ON DELETE SET NULL,
    ack_by_name  text CHECK (char_length(ack_by_name) <= 100),
    ack_comment  text CHECK (char_length(ack_comment) <= 300 AND ack_comment !~ '[[:cntrl:]]'),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);
-- Je Quelle höchstens ein offener Alarm.
CREATE UNIQUE INDEX alarms_open_check ON openwacht.alarms (check_id) WHERE ended_at IS NULL AND check_id IS NOT NULL;
CREATE UNIQUE INDEX alarms_open_agent ON openwacht.alarms (agent_id, subject) WHERE ended_at IS NULL AND agent_id IS NOT NULL;
CREATE INDEX alarms_tenant_started ON openwacht.alarms (tenant_id, started_at DESC);
CREATE INDEX alarms_ended ON openwacht.alarms (ended_at) WHERE ended_at IS NOT NULL;

-- Rang wie alarm.rank in Go: Warnung < Unbekannt < Fehler.
CREATE FUNCTION openwacht.alarm_rank(s text) RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(array_position(ARRAY['warn', 'unknown', 'crit'], s), 0)
$$;

-- Bestätigen: Zeitpunkt und Person setzt die Datenbank selbst, nicht die
-- Anwendung. Nur offene, noch nicht bestätigte Alarme; eine Bestätigung
-- lässt sich über die Anwendung nicht zurücknehmen oder ändern.
CREATE FUNCTION openwacht.alarms_before_update() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    -- Ohne Benutzerkontext (alarm_sync) und bei Änderungen, die nicht die
    -- Bestätigung betreffen (Quelle gelöscht: ON DELETE SET NULL), nichts tun.
    IF uid IS NULL OR (NEW.ack_at IS NOT DISTINCT FROM OLD.ack_at AND NEW.ack_comment IS NOT DISTINCT FROM OLD.ack_comment) THEN
        RETURN NEW;
    END IF;
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'Der Alarm ist schon beendet.' USING ERRCODE = '23514';
    END IF;
    IF OLD.ack_at IS NOT NULL OR NEW.ack_at IS NULL THEN
        RAISE EXCEPTION 'Der Alarm ist schon bestätigt.' USING ERRCODE = '23514';
    END IF;
    NEW.ack_at := now();
    NEW.ack_by := uid;
    NEW.ack_by_name := (SELECT u.display_name FROM openwacht.users u WHERE u.id = uid);
    RETURN NEW;
END
$$;
CREATE TRIGGER alarms_before_update BEFORE UPDATE ON openwacht.alarms
    FOR EACH ROW EXECUTE FUNCTION openwacht.alarms_before_update();

ALTER TABLE openwacht.alarms ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON openwacht.alarms TO openwacht_app;
GRANT UPDATE (ack_at, ack_comment) ON openwacht.alarms TO openwacht_app;
CREATE POLICY alarms_select ON openwacht.alarms FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY alarms_update ON openwacht.alarms FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()) AND ended_at IS NULL)
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));

-- ---------------------------------------------------------------------------
-- Funktionen der Zentrale (ohne Benutzerkontext)
-- ---------------------------------------------------------------------------

-- Was die Zentrale zum Bewerten braucht: Checks mit Problemzustand und alle
-- nicht gesperrten Agents (Messwerte wie in alert_host_candidates).
CREATE FUNCTION openwacht.alarm_check_sources()
    RETURNS TABLE (check_id uuid, name text, status text, message text, fails integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.id, c.name, c.status, coalesce(c.message, ''), c.fails
      FROM openwacht.checks c
     WHERE c.enabled AND c.status IS NOT NULL AND c.status <> 'ok'
     ORDER BY c.id
     LIMIT 20000
$$;

CREATE FUNCTION openwacht.alarm_host_sources()
    RETURNS TABLE (agent_id uuid, hostname text, silent_s double precision, metrics jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.id, a.hostname,
           extract(epoch FROM now() - coalesce(a.last_seen, a.created_at))::double precision,
           CASE WHEN a.snapshot IS NULL THEN NULL
                ELSE jsonb_build_object('speicher', a.snapshot -> 'speicher', 'platten', a.snapshot -> 'platten') END
      FROM openwacht.agents a
     WHERE a.revoked_at IS NULL
     ORDER BY a.id
     LIMIT 20000
$$;

-- Offene Alarme: für Hysterese und Bestätigungen.
CREATE FUNCTION openwacht.alarm_open()
    RETURNS TABLE (check_id uuid, agent_id uuid, subject text, name text, status text, message text, acknowledged boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT a.check_id, a.agent_id, a.subject, a.name, a.status, a.message, a.ack_at IS NOT NULL
      FROM openwacht.alarms a
     WHERE a.ended_at IS NULL
     ORDER BY a.started_at
     LIMIT 200000
$$;

-- Fremdtext auf eine Zeile ohne Steuerzeichen bringen (die CHECKs verlangen das).
CREATE FUNCTION openwacht.alarm_clean(s text) RETURNS text
    LANGUAGE sql IMMUTABLE AS $$
    SELECT btrim(regexp_replace(coalesce(s, ''), '[[:cntrl:]]+', ' ', 'g'))
$$;

-- Eingaben von alarm_sync als Tabelle, bereinigt; Einträge, die weder
-- eindeutig Check noch Agent-Gegenstand sind, fallen weg.
CREATE FUNCTION openwacht.alarm_input(p_checks uuid[], p_agents uuid[], p_subjects text[], p_names text[],
                                     p_status text[], p_messages text[])
    RETURNS TABLE (check_id uuid, agent_id uuid, subject text, name text, status text, message text)
    LANGUAGE sql IMMUTABLE AS $$
    SELECT x.c, x.g, x.s, left(openwacht.alarm_clean(x.n), 300), x.st, left(openwacht.alarm_clean(x.m), 300)
      FROM unnest(p_checks, p_agents, p_subjects, p_names, p_status, p_messages) AS x(c, g, s, n, st, m)
     WHERE x.st IN ('warn', 'crit', 'unknown')
       AND ((x.c IS NOT NULL AND x.g IS NULL AND x.s = 'check')
            OR (x.c IS NULL AND x.g IS NOT NULL AND x.s IS DISTINCT FROM 'check'))
$$;

-- Abgleich: Die Listen beschreiben alle Probleme, die jetzt bestehen. Je
-- Eintrag entweder p_checks[i] (dann p_subjects[i] = 'check') oder
-- p_agents[i] mit Gegenstand. Neue Probleme eröffnen einen Alarm, bestehende
-- werden fortgeschrieben, alles andere Offene endet.
CREATE FUNCTION openwacht.alarm_sync(p_checks uuid[], p_agents uuid[], p_subjects text[], p_names text[],
                                    p_status text[], p_messages text[]) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    n integer := coalesce(cardinality(p_checks), 0);
BEGIN
    IF coalesce(cardinality(p_agents), 0) <> n OR coalesce(cardinality(p_subjects), 0) <> n
       OR coalesce(cardinality(p_names), 0) <> n OR coalesce(cardinality(p_status), 0) <> n
       OR coalesce(cardinality(p_messages), 0) <> n THEN
        RAISE EXCEPTION 'alarm_sync: Listen unterschiedlich lang';
    END IF;

    -- Beendet: offen, aber nicht mehr in der Liste (auch gelöschte Quellen).
    UPDATE openwacht.alarms a SET ended_at = now()
     WHERE a.ended_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM openwacht.alarm_input(p_checks, p_agents, p_subjects, p_names, p_status, p_messages) x
                        WHERE (x.check_id IS NOT NULL AND x.check_id = a.check_id)
                           OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject));

    -- Fortschreiben; wird es schlimmer, verfällt die Bestätigung.
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
      FROM openwacht.alarm_input(p_checks, p_agents, p_subjects, p_names, p_status, p_messages) x
     WHERE a.ended_at IS NULL
       AND ((x.check_id IS NOT NULL AND x.check_id = a.check_id)
            OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject))
       AND (a.status, a.message, a.name) IS DISTINCT FROM (x.status, x.message, coalesce(nullif(x.name, ''), a.name));

    -- Neu: Mandant aus Check bzw. Agent, nie aus den Eingaben.
    INSERT INTO openwacht.alarms (tenant_id, check_id, agent_id, subject, name, status, worst, message, started_at, changed_at)
    SELECT coalesce(c.tenant_id, g.tenant_id), x.check_id, x.agent_id, x.subject,
           coalesce(nullif(x.name, ''), c.name, g.hostname), x.status, x.status, x.message, now(), now()
      FROM openwacht.alarm_input(p_checks, p_agents, p_subjects, p_names, p_status, p_messages) x
      LEFT JOIN openwacht.checks c ON c.id = x.check_id
      LEFT JOIN openwacht.agents g ON g.id = x.agent_id AND g.revoked_at IS NULL
     WHERE coalesce(c.tenant_id, g.tenant_id) IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM openwacht.alarms a
                        WHERE a.ended_at IS NULL
                          AND ((x.check_id IS NOT NULL AND x.check_id = a.check_id)
                               OR (x.agent_id IS NOT NULL AND x.agent_id = a.agent_id AND x.subject = a.subject)));

    DELETE FROM openwacht.alarms WHERE ended_at < now() - interval '90 days';
END
$$;

REVOKE ALL ON FUNCTION openwacht.alarm_check_sources(), openwacht.alarm_host_sources(), openwacht.alarm_open(),
    openwacht.alarm_sync(uuid[], uuid[], text[], text[], text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.alarm_check_sources(), openwacht.alarm_host_sources(), openwacht.alarm_open(),
    openwacht.alarm_sync(uuid[], uuid[], text[], text[], text[], text[]) TO openwacht_app;
