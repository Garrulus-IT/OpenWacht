-- SPDX-License-Identifier: AGPL-3.0-only

-- 0025: Wartungsfenster und Alarm „Platte voll in < N Tagen“ (Etappe 20b).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * Wartungsfenster einmalig (auch in der Zukunft), wöchentlich (Wochentage,
--     Uhrzeit, Dauer) oder monatlich am n-ten Wochentag mit Versatz in Tagen
--     (Patchday: 2. Dienstag + n Tage). Ziel: ein Gerät, ein Sensor oder eine
--     Gruppe (mit Untergruppen), dynamisch: Geräte, die später in die Gruppe
--     kommen, sind mit drin. Zeitzone je Fenster (Standard Europe/Berlin),
--     Sommerzeit wird beachtet. Pflegen dürfen Admins und Operatoren, ein
--     Fenster dauert höchstens 7 Tage.
--   * „Platte voll in < N Tagen“: Warnung, wenn die Prognose (Etappe 10)
--     weniger als N Tage ergibt; keine kritische Stufe. N global, je Mandant
--     und je Gerät, 0 = aus (Standard 14).
--
-- Umsetzung: Die Zentrale rechnet die Termine in Go aus und schreibt
-- ein laufendes Fenster in jedem Alarmdurchlauf als gewöhnliche Wartung in
-- openwacht.maintenance (mit window_id). Alarme, Hosts, Wandanzeige und
-- Dashboard zeigen die Wartung damit ohne Sonderfall. Wird eine solche
-- Wartung vorzeitig beendet, merkt sich maintenance_window_done das für
-- dieses Vorkommen, damit sie nicht gleich wieder angelegt wird.

-- ---------------------------------------------------------------------------
-- Schwelle „Platte voll in < N Tagen“
-- ---------------------------------------------------------------------------

CREATE FUNCTION openwacht.valid_days(v double precision) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$ SELECT v IS NULL OR v BETWEEN 0 AND 365 AND v = trunc(v) $$;

ALTER TABLE openwacht.settings ADD COLUMN disk_days double precision CHECK (openwacht.valid_days(disk_days));
ALTER TABLE openwacht.tenant_settings ADD COLUMN disk_days double precision CHECK (openwacht.valid_days(disk_days));
ALTER TABLE openwacht.device_limits ADD COLUMN disk_days double precision CHECK (openwacht.valid_days(disk_days));
GRANT UPDATE (disk_days) ON openwacht.settings TO openwacht_app;
GRANT UPDATE (disk_days) ON openwacht.tenant_settings TO openwacht_app;
GRANT INSERT (disk_days), UPDATE (disk_days) ON openwacht.device_limits TO openwacht_app;

-- Audit wie 0024, Schwellen mit „platte_tage“.
CREATE OR REPLACE FUNCTION openwacht.settings_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    d jsonb := '{}'::jsonb;
BEGIN
    NEW.updated_at := now();
    IF NEW.check_nets IS DISTINCT FROM OLD.check_nets THEN
        d := d || jsonb_build_object('netze_alt', OLD.check_nets::text[], 'netze', NEW.check_nets::text[]);
    END IF;
    IF NEW.alert_targets IS DISTINCT FROM OLD.alert_targets THEN
        d := d || jsonb_build_object('alarmziele_alt', OLD.alert_targets, 'alarmziele', NEW.alert_targets);
    END IF;
    IF NEW.deadman_enc IS DISTINCT FROM OLD.deadman_enc THEN
        d := d || jsonb_build_object('totmann', CASE WHEN coalesce(octet_length(NEW.deadman_enc), 0) = 0 THEN 'aus' ELSE 'gesetzt' END);
    END IF;
    IF (NEW.silent_s, NEW.disk_warn, NEW.disk_crit, NEW.mem_warn, NEW.mem_crit, NEW.cpu_warn, NEW.cpu_crit, NEW.disk_days)
       IS DISTINCT FROM (OLD.silent_s, OLD.disk_warn, OLD.disk_crit, OLD.mem_warn, OLD.mem_crit, OLD.cpu_warn, OLD.cpu_crit, OLD.disk_days) THEN
        d := d || jsonb_build_object('schwellen', jsonb_build_object('stumm_s', NEW.silent_s,
            'platte', jsonb_build_array(NEW.disk_warn, NEW.disk_crit), 'speicher', jsonb_build_array(NEW.mem_warn, NEW.mem_crit),
            'cpu', jsonb_build_array(NEW.cpu_warn, NEW.cpu_crit), 'platte_tage', NEW.disk_days));
    END IF;
    IF (NEW.smtp_host, NEW.smtp_port, NEW.smtp_tls, NEW.smtp_from, NEW.smtp_user, NEW.smtp_pass_enc, NEW.smtp_ca)
       IS DISTINCT FROM (OLD.smtp_host, OLD.smtp_port, OLD.smtp_tls, OLD.smtp_from, OLD.smtp_user, OLD.smtp_pass_enc, OLD.smtp_ca) THEN
        d := d || jsonb_build_object('mail', jsonb_build_object('server', NEW.smtp_host, 'port', NEW.smtp_port,
            'tls', NEW.smtp_tls, 'absender', NEW.smtp_from, 'benutzer', NEW.smtp_user IS NOT NULL,
            'passwort', CASE WHEN NEW.smtp_pass_enc IS NULL THEN 'aus'
                             WHEN NEW.smtp_pass_enc IS DISTINCT FROM OLD.smtp_pass_enc THEN 'geändert' ELSE 'gesetzt' END,
            'eigene_ca', NEW.smtp_ca IS NOT NULL));
    END IF;
    IF d <> '{}'::jsonb THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NULL, CASE WHEN openwacht.current_user_id() IS NULL THEN 'einstellungen.uebernommen' ELSE 'einstellungen.geaendert' END, d);
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openwacht.tenant_settings_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    r openwacht.tenant_settings;
BEGIN
    IF TG_OP = 'DELETE' THEN
        r := OLD;
    ELSE
        r := NEW;
    END IF;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (r.tenant_id, CASE WHEN TG_OP = 'DELETE' THEN 'einstellungen.mandant_zurueckgesetzt' ELSE 'einstellungen.mandant' END,
            CASE WHEN TG_OP = 'DELETE' THEN '{}'::jsonb ELSE jsonb_build_object('netze', r.check_nets::text[],
                'stumm_s', r.silent_s, 'platte', jsonb_build_array(r.disk_warn, r.disk_crit),
                'speicher', jsonb_build_array(r.mem_warn, r.mem_crit), 'cpu', jsonb_build_array(r.cpu_warn, r.cpu_crit),
                'platte_tage', r.disk_days) END);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;

DROP FUNCTION openwacht.runtime_settings();
CREATE FUNCTION openwacht.runtime_settings()
    RETURNS TABLE (check_nets cidr[], alert_targets text[], deadman_enc bytea, silent_s integer,
                   disk_warn double precision, disk_crit double precision, mem_warn double precision,
                   mem_crit double precision, cpu_warn double precision, cpu_crit double precision,
                   disk_days double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.check_nets, s.alert_targets, s.deadman_enc, s.silent_s, s.disk_warn, s.disk_crit,
           s.mem_warn, s.mem_crit, s.cpu_warn, s.cpu_crit, s.disk_days
      FROM openwacht.settings s
$$;
REVOKE ALL ON FUNCTION openwacht.runtime_settings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.runtime_settings() TO openwacht_app;

DROP FUNCTION openwacht.device_limits_inherited(uuid);
CREATE FUNCTION openwacht.device_limits_inherited(p_device uuid)
    RETURNS TABLE (silent_s integer, disk_warn double precision, disk_crit double precision,
                   mem_warn double precision, mem_crit double precision, cpu_warn double precision,
                   cpu_crit double precision, disk_days double precision, tenant_name text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH d AS (SELECT d.tenant_id FROM openwacht.devices d
                WHERE d.id = p_device AND d.tenant_id IN (SELECT openwacht.visible_tenants())),
         k AS (SELECT ts.*, c.depth FROM d JOIN openwacht.tenant_closure c ON c.descendant = d.tenant_id
                 JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor)
    SELECT (SELECT k.silent_s FROM k WHERE k.silent_s IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.disk_warn FROM k WHERE k.disk_warn IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.disk_crit FROM k WHERE k.disk_crit IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.mem_warn FROM k WHERE k.mem_warn IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.mem_crit FROM k WHERE k.mem_crit IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.cpu_warn FROM k WHERE k.cpu_warn IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.cpu_crit FROM k WHERE k.cpu_crit IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT k.disk_days FROM k WHERE k.disk_days IS NOT NULL ORDER BY k.depth LIMIT 1),
           (SELECT t.name FROM d JOIN openwacht.tenants t ON t.id = d.tenant_id)
      FROM d
$$;
REVOKE ALL ON FUNCTION openwacht.device_limits_inherited(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.device_limits_inherited(uuid) TO openwacht_app;

DROP FUNCTION openwacht.limit_overrides();
CREATE FUNCTION openwacht.limit_overrides()
    RETURNS TABLE (kind text, id uuid, silent_s integer, disk_warn double precision, disk_crit double precision,
                   mem_warn double precision, mem_crit double precision, cpu_warn double precision,
                   cpu_crit double precision, disk_days double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH src AS (
        SELECT 'agent'::text AS kind, a.id, a.device_id, a.tenant_id FROM openwacht.agents a
        UNION ALL
        SELECT 'snmp', s.id, s.device_id, s.tenant_id FROM openwacht.snmp_sources s
    ), k AS (
        SELECT c.descendant AS tenant_id, c.depth, ts.silent_s, ts.disk_warn, ts.disk_crit, ts.mem_warn,
               ts.mem_crit, ts.cpu_warn, ts.cpu_crit, ts.disk_days FROM openwacht.tenant_closure c
          JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor
    ), r AS (
        SELECT src.kind, src.id,
            coalesce(dl.silent_s, (SELECT k.silent_s FROM k WHERE k.tenant_id = src.tenant_id AND k.silent_s IS NOT NULL ORDER BY k.depth LIMIT 1)) AS silent_s,
            coalesce(dl.disk_warn, (SELECT k.disk_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.disk_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS disk_warn,
            coalesce(dl.disk_crit, (SELECT k.disk_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.disk_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS disk_crit,
            coalesce(dl.mem_warn, (SELECT k.mem_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.mem_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS mem_warn,
            coalesce(dl.mem_crit, (SELECT k.mem_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.mem_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS mem_crit,
            coalesce(dl.cpu_warn, (SELECT k.cpu_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.cpu_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS cpu_warn,
            coalesce(dl.cpu_crit, (SELECT k.cpu_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.cpu_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS cpu_crit,
            coalesce(dl.disk_days, (SELECT k.disk_days FROM k WHERE k.tenant_id = src.tenant_id AND k.disk_days IS NOT NULL ORDER BY k.depth LIMIT 1)) AS disk_days
          FROM src LEFT JOIN openwacht.device_limits dl ON dl.device_id = src.device_id
    )
    SELECT * FROM r
     WHERE coalesce(r.silent_s::double precision, r.disk_warn, r.disk_crit, r.mem_warn, r.mem_crit, r.cpu_warn, r.cpu_crit,
                    r.disk_days) IS NOT NULL
$$;
REVOKE ALL ON FUNCTION openwacht.limit_overrides() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.limit_overrides() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Wartungsfenster
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.maintenance_windows (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name           text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
    reason         text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 200 AND reason !~ '[[:cntrl:]]'),
    -- Ziel: genau eins von Gerät, Sensor, Gruppe
    device_id      uuid,
    check_id       uuid REFERENCES openwacht.checks (id) ON DELETE CASCADE,
    group_id       uuid,
    with_subgroups boolean NOT NULL DEFAULT true,
    repeat         text NOT NULL CHECK (repeat IN ('einmalig', 'woechentlich', 'monatlich')),
    -- einmalig
    starts_at      timestamptz,
    ends_at        timestamptz,
    -- wöchentlich: Bit 0 = Montag … Bit 6 = Sonntag
    weekdays       smallint CHECK (weekdays BETWEEN 1 AND 127),
    -- monatlich: n-ter (1–4, -1 = letzter) Wochentag (1 = Montag … 7 = Sonntag) plus Versatz in Tagen
    nth            smallint CHECK (nth IN (1, 2, 3, 4, -1)),
    weekday        smallint CHECK (weekday BETWEEN 1 AND 7),
    offset_days    smallint CHECK (offset_days BETWEEN 0 AND 27),
    -- wöchentlich und monatlich: Beginn (Ortszeit) und Dauer
    start_time     time CHECK (start_time = date_trunc('minute', start_time)),
    duration_min   integer CHECK (duration_min BETWEEN 1 AND 10080),
    tz             text NOT NULL DEFAULT 'Europe/Berlin'
                   CHECK (char_length(tz) <= 64 AND tz ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$'),
    enabled        boolean NOT NULL DEFAULT true,
    created_by     uuid REFERENCES openwacht.users (id) ON DELETE SET NULL,
    created_by_name text CHECK (char_length(created_by_name) <= 100),
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES openwacht.devices (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES openwacht.device_groups (tenant_id, id) ON DELETE CASCADE,
    CHECK (num_nonnulls(device_id, check_id, group_id) = 1),
    CHECK (CASE repeat
        WHEN 'einmalig' THEN starts_at IS NOT NULL AND ends_at > starts_at AND ends_at <= starts_at + interval '7 days'
            AND num_nulls(weekdays, nth, weekday, offset_days, start_time, duration_min) = 6
        WHEN 'woechentlich' THEN weekdays IS NOT NULL AND start_time IS NOT NULL AND duration_min IS NOT NULL
            AND num_nulls(starts_at, ends_at, nth, weekday, offset_days) = 5
        WHEN 'monatlich' THEN nth IS NOT NULL AND weekday IS NOT NULL AND offset_days IS NOT NULL
            AND start_time IS NOT NULL AND duration_min IS NOT NULL AND num_nulls(starts_at, ends_at, weekdays) = 3
    END)
);
CREATE INDEX maintenance_windows_tenant ON openwacht.maintenance_windows (tenant_id);
CREATE INDEX maintenance_windows_device ON openwacht.maintenance_windows (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX maintenance_windows_check ON openwacht.maintenance_windows (check_id) WHERE check_id IS NOT NULL;

-- Mandant aus dem Ziel, mit den Rechten des Aufrufers (Leitprinzip 2): Was
-- er nicht sieht, findet die Abfrage nicht, und der Eintrag scheitert.
CREATE FUNCTION openwacht.maintenance_windows_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    NEW.tenant_id := CASE
        WHEN NEW.device_id IS NOT NULL THEN (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id)
        WHEN NEW.check_id IS NOT NULL THEN (SELECT c.tenant_id FROM openwacht.checks c WHERE c.id = NEW.check_id)
        ELSE (SELECT g.tenant_id FROM openwacht.device_groups g WHERE g.id = NEW.group_id) END;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Wartungsfenster: Ziel nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.maintenance_windows WHERE tenant_id = NEW.tenant_id) >= 200 THEN
            RAISE EXCEPTION 'Höchstens 200 Wartungsfenster je Mandant.' USING ERRCODE = '23514';
        END IF;
        NEW.created_by := uid;
        NEW.created_by_name := (SELECT u.display_name FROM openwacht.users u WHERE u.id = uid);
        NEW.created_at := now();
    ELSE
        NEW.id := OLD.id;
        NEW.created_by := OLD.created_by;
        NEW.created_by_name := OLD.created_by_name;
        NEW.created_at := OLD.created_at;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER maintenance_windows_before BEFORE INSERT OR UPDATE ON openwacht.maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION openwacht.maintenance_windows_before();

ALTER TABLE openwacht.maintenance_windows ENABLE ROW LEVEL SECURITY;
GRANT SELECT, DELETE ON openwacht.maintenance_windows TO openwacht_app;
GRANT INSERT (name, reason, device_id, check_id, group_id, with_subgroups, repeat, starts_at, ends_at, weekdays,
              nth, weekday, offset_days, start_time, duration_min, tz, enabled),
      UPDATE (name, reason, device_id, check_id, group_id, with_subgroups, repeat, starts_at, ends_at, weekdays,
              nth, weekday, offset_days, start_time, duration_min, tz, enabled)
    ON openwacht.maintenance_windows TO openwacht_app;
CREATE POLICY maintenance_windows_select ON openwacht.maintenance_windows FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY maintenance_windows_insert ON openwacht.maintenance_windows FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY maintenance_windows_update ON openwacht.maintenance_windows FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY maintenance_windows_delete ON openwacht.maintenance_windows FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- Wartungen aus einem Fenster. Die Anwendung kann window_id nicht setzen
-- (keine Spaltenrechte); das tut nur maintenance_window_apply.
ALTER TABLE openwacht.maintenance ADD COLUMN window_id uuid REFERENCES openwacht.maintenance_windows (id) ON DELETE CASCADE;
GRANT SELECT (window_id) ON openwacht.maintenance TO openwacht_app;

-- Vorzeitig beendete Vorkommen (je Fenster, Ziel und Ende), damit die Zentrale
-- sie nicht gleich wieder anlegt. Nur für die Funktionen der Zentrale.
CREATE TABLE openwacht.maintenance_window_done (
    window_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    device_id uuid,
    check_id  uuid,
    until     timestamptz NOT NULL
);
CREATE INDEX maintenance_window_done_window ON openwacht.maintenance_window_done (window_id, until);
ALTER TABLE openwacht.maintenance_window_done ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.maintenance_window_done FROM PUBLIC, openwacht_app;

-- Wie 0012, aber eine Wartung aus einem Fenster behält ihren Namen
-- („Wartungsfenster …“) statt der Person.
CREATE OR REPLACE FUNCTION openwacht.maintenance_before_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF NEW.check_id IS NOT NULL THEN
        NEW.tenant_id := (SELECT c.tenant_id FROM openwacht.checks c WHERE c.id = NEW.check_id);
    ELSE
        NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
    END IF;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'Wartung: Check oder Gerät nicht gefunden.' USING ERRCODE = '23503';
    END IF;
    NEW.starts_at := now();
    NEW.created_by := uid;
    IF NEW.window_id IS NULL THEN
        NEW.created_by_name := (SELECT u.display_name FROM openwacht.users u WHERE u.id = uid);
    END IF;
    RETURN NEW;
END
$$;

-- Vorzeitig beendet (von Hand, nicht abgelaufen): Vorkommen merken.
CREATE FUNCTION openwacht.maintenance_after_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF OLD.window_id IS NOT NULL AND OLD.ends_at > now() THEN
        INSERT INTO openwacht.maintenance_window_done (window_id, tenant_id, device_id, check_id, until)
        VALUES (OLD.window_id, OLD.tenant_id, OLD.device_id, OLD.check_id, OLD.ends_at);
    END IF;
    RETURN OLD;
END
$$;
CREATE TRIGGER maintenance_after_delete AFTER DELETE ON openwacht.maintenance
    FOR EACH ROW EXECUTE FUNCTION openwacht.maintenance_after_delete();

-- Geändertes oder pausiertes Fenster: laufende Wartungen daraus enden, der
-- nächste Durchlauf legt sie nach dem neuen Plan an.
CREATE FUNCTION openwacht.maintenance_windows_after_update() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.maintenance WHERE window_id = NEW.id;
    DELETE FROM openwacht.maintenance_window_done WHERE window_id = NEW.id;
    RETURN NULL;
END
$$;
CREATE TRIGGER maintenance_windows_after_update AFTER UPDATE ON openwacht.maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION openwacht.maintenance_windows_after_update();

-- Für die Zentrale: alle eingeschalteten Fenster (ohne Benutzerkontext).
CREATE FUNCTION openwacht.maintenance_windows_all()
    RETURNS TABLE (id uuid, repeat text, starts_at timestamptz, ends_at timestamptz, weekdays smallint, nth smallint,
                   weekday smallint, offset_days smallint, start_time time, duration_min integer, tz text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT w.id, w.repeat, w.starts_at, w.ends_at, w.weekdays, w.nth, w.weekday, w.offset_days, w.start_time,
           w.duration_min, w.tz
      FROM openwacht.maintenance_windows w WHERE w.enabled ORDER BY w.id LIMIT 100000
$$;

-- Ein laufendes Vorkommen anwenden: Wartung für jedes Ziel ohne laufende
-- Wartung und ohne vorzeitiges Ende dieses Vorkommens. Eine Gruppe meint
-- ihre Geräte (mit Untergruppen, wenn gewählt), zum Zeitpunkt des Aufrufs.
-- Liefert die Zahl der neu angelegten Wartungen.
CREATE FUNCTION openwacht.maintenance_window_apply(p_window uuid, p_end timestamptz) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    w openwacht.maintenance_windows;
    n integer;
BEGIN
    SELECT * INTO w FROM openwacht.maintenance_windows mw WHERE mw.id = p_window AND mw.enabled;
    IF NOT FOUND OR p_end <= now() OR p_end > now() + interval '7 days' THEN
        RETURN 0;
    END IF;
    WITH RECURSIVE g AS (
        SELECT dg.id FROM openwacht.device_groups dg WHERE dg.id = w.group_id AND dg.tenant_id = w.tenant_id
        UNION ALL
        SELECT dg.id FROM openwacht.device_groups dg JOIN g ON dg.parent_id = g.id
         WHERE w.with_subgroups AND dg.tenant_id = w.tenant_id
    ), t AS (
        SELECT w.device_id AS device_id, NULL::uuid AS check_id WHERE w.device_id IS NOT NULL
        UNION ALL
        SELECT NULL::uuid, w.check_id WHERE w.check_id IS NOT NULL
        UNION ALL
        SELECT d.id, NULL::uuid FROM openwacht.devices d
         WHERE w.group_id IS NOT NULL AND d.tenant_id = w.tenant_id AND d.group_id IN (SELECT g.id FROM g)
    ), ins AS (
        INSERT INTO openwacht.maintenance (device_id, check_id, ends_at, reason, window_id, created_by_name)
        SELECT t.device_id, t.check_id, p_end, left(CASE WHEN w.reason <> '' THEN w.reason ELSE w.name END, 200), w.id,
               left('Wartungsfenster „' || w.name || '“', 100)
          FROM t
         WHERE NOT EXISTS (SELECT 1 FROM openwacht.maintenance m
                            WHERE m.device_id = t.device_id OR m.check_id = t.check_id)
           AND NOT EXISTS (SELECT 1 FROM openwacht.maintenance_window_done x
                            WHERE x.window_id = w.id AND x.until = p_end
                              AND (x.device_id = t.device_id OR x.check_id = t.check_id))
        ON CONFLICT DO NOTHING
        RETURNING 1
    )
    SELECT count(*) INTO n FROM ins;
    RETURN n;
END
$$;

-- Wie 0013, dazu: abgelaufene Merker vorzeitig beendeter Vorkommen löschen.
DROP FUNCTION openwacht.maintenance_active();
CREATE FUNCTION openwacht.maintenance_active()
    RETURNS TABLE (check_id uuid, agent_id uuid, snmp_id uuid, ends_at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    DELETE FROM openwacht.maintenance m WHERE m.ends_at <= now();
    DELETE FROM openwacht.maintenance_window_done x WHERE x.until <= now();
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

REVOKE ALL ON FUNCTION openwacht.maintenance_windows_all(), openwacht.maintenance_window_apply(uuid, timestamptz),
    openwacht.maintenance_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.maintenance_windows_all(), openwacht.maintenance_window_apply(uuid, timestamptz),
    openwacht.maintenance_active() TO openwacht_app;
