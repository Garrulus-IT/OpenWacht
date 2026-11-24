-- SPDX-License-Identifier: AGPL-3.0-only

-- 0023: Einstellungen in der Oberfläche, Gerät mit Inhalt löschen (Etappe 19).
--
-- Entscheidungen (Entscheidung, 21.11.2026):
--   * Einstellungen der ganzen Installation pflegt nur der Betreiber: ein
--     Kennzeichen am Benutzer, das nur per Shell vergeben wird
--     (openwacht-zentrale betreiber), nur für Benutzer des Hauptmandanten und
--     nur mit eingerichteter Zwei-Faktor-Anmeldung. Ein Admin des
--     Hauptmandanten ist nicht automatisch Betreiber (Sicherheitskonzept).
--   * Startoptionen gewinnen: Die Zentrale übernimmt gesetzte Startoptionen
--     einmalig in die Datenbank (nur Felder ohne Wert). Solange eine Option
--     in der Unit steht, gilt sie und das Feld ist in der Oberfläche gesperrt.
--   * Netzfreigabe und Schwellen auch je Mandant (nur der Betreiber) und
--     Schwellen je Gerät (Admins und Operatoren des Geräts). NULL = erbt.
--     Netze eines Mandanten grenzen nur ein: Eine Adresse muss global UND in
--     jedem Mandanten der Kette mit eigener Liste freigegeben sein.
--   * Gerät mit Inhalt löschen: Admins und Operatoren, nach Eintippen des
--     Namens; Agent wird gesperrt und gelöscht, Verlauf geht mit, das
--     Alarmprotokoll bleibt; Trap-Regeln nur für dieses Gerät gehen mit; ist
--     der Agent Sammler anderer Geräte, bleibt das Löschen gesperrt.
--
-- Ausnahme vom Grundsatz „jede fachliche Tabelle hat tenant_id“: settings
-- gilt für die ganze Installation (eine Zeile). Lesen und schreiben darf nur
-- der Betreiber; die Zentrale liest sie über runtime_settings().

-- ---------------------------------------------------------------------------
-- Betreiber
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.users ADD COLUMN platform_operator boolean NOT NULL DEFAULT false;
GRANT SELECT (platform_operator) ON openwacht.users TO openwacht_app;

-- Ist der aktuelle Benutzer Betreiber? Kennzeichen, aktiv, Zwei-Faktor
-- eingerichtet und Benutzer des Hauptmandanten.
CREATE FUNCTION openwacht.is_platform_operator() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1 FROM openwacht.users u JOIN openwacht.tenants t ON t.id = u.tenant_id
         WHERE u.id = openwacht.current_user_id() AND u.platform_operator
           AND NOT u.disabled AND u.totp_enabled AND t.parent_id IS NULL)
$$;
REVOKE ALL ON FUNCTION openwacht.is_platform_operator() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.is_platform_operator() TO openwacht_app;

-- Das Kennzeichen setzt nur der Eigentümer (Befehl betreiber). Der Trigger
-- schreibt den Audit-Eintrag, auch wenn jemand es von Hand in der DB ändert.
CREATE FUNCTION openwacht.users_operator_audit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NEW.platform_operator IS DISTINCT FROM OLD.platform_operator THEN
        IF NEW.platform_operator AND (SELECT t.parent_id FROM openwacht.tenants t WHERE t.id = NEW.tenant_id) IS NOT NULL THEN
            RAISE EXCEPTION 'Betreiber können nur Benutzer des Hauptmandanten sein.' USING ERRCODE = '23514';
        END IF;
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NEW.tenant_id, CASE WHEN NEW.platform_operator THEN 'betreiber.vergeben' ELSE 'betreiber.entzogen' END,
                jsonb_build_object('benutzer', NEW.id, 'email', NEW.email));
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER users_operator_audit AFTER UPDATE OF platform_operator ON openwacht.users
    FOR EACH ROW EXECUTE FUNCTION openwacht.users_operator_audit();

-- ---------------------------------------------------------------------------
-- Prüfungen für Schwellen
-- ---------------------------------------------------------------------------

-- Prozentwert: NULL = erbt bzw. Standard, 0 = aus, sonst 1–100.
CREATE FUNCTION openwacht.valid_pct(v double precision) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT v IS NULL OR (v = 0 OR v >= 1) AND v <= 100 AND v = v
$$;
-- Warn unter Krit, wenn beide gesetzt und an.
CREATE FUNCTION openwacht.valid_pair(w double precision, c double precision) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT w IS NULL OR c IS NULL OR w = 0 OR c = 0 OR w < c
$$;
-- Netzliste: höchstens 64 Einträge, keine leeren Einträge.
CREATE FUNCTION openwacht.valid_nets(n cidr[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT n IS NULL OR (cardinality(n) <= 64 AND array_position(n, NULL) IS NULL)
$$;

-- ---------------------------------------------------------------------------
-- Einstellungen der Installation (eine Zeile)
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.settings (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    -- NULL = nie gesetzt (Standard: keine Netze, keine Alarmziele, Totmann aus)
    check_nets    cidr[] CHECK (openwacht.valid_nets(check_nets)),
    alert_targets text[] CHECK (alert_targets IS NULL OR cardinality(alert_targets) <= 32
                                AND array_position(alert_targets, NULL) IS NULL),
    -- Ping-Adresse des Totmannschalters, verschlüsselt (AAD „openwacht totmann v1“);
    -- leeres bytea = ausdrücklich aus
    deadman_enc   bytea CHECK (octet_length(deadman_enc) <= 2048),
    silent_s      integer CHECK (silent_s BETWEEN 120 AND 86400),
    disk_warn     double precision CHECK (openwacht.valid_pct(disk_warn)),
    disk_crit     double precision CHECK (openwacht.valid_pct(disk_crit)),
    mem_warn      double precision CHECK (openwacht.valid_pct(mem_warn)),
    mem_crit      double precision CHECK (openwacht.valid_pct(mem_crit)),
    cpu_warn      double precision CHECK (openwacht.valid_pct(cpu_warn)),
    cpu_crit      double precision CHECK (openwacht.valid_pct(cpu_crit)),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (openwacht.valid_pair(disk_warn, disk_crit) AND openwacht.valid_pair(mem_warn, mem_crit)
           AND openwacht.valid_pair(cpu_warn, cpu_crit))
);
INSERT INTO openwacht.settings DEFAULT VALUES;
ALTER TABLE openwacht.settings ENABLE ROW LEVEL SECURITY;
GRANT SELECT, UPDATE (check_nets, alert_targets, deadman_enc, silent_s, disk_warn, disk_crit,
                      mem_warn, mem_crit, cpu_warn, cpu_crit) ON openwacht.settings TO openwacht_app;
CREATE POLICY settings_select ON openwacht.settings FOR SELECT TO openwacht_app
    USING (openwacht.is_platform_operator());
CREATE POLICY settings_update ON openwacht.settings FOR UPDATE TO openwacht_app
    USING (openwacht.is_platform_operator()) WITH CHECK (openwacht.is_platform_operator());

-- Audit für jede Änderung, auch ohne Benutzer (Übernahme der Startoptionen).
-- Die Ping-Adresse erscheint nie im Klartext.
CREATE FUNCTION openwacht.settings_audit() RETURNS trigger
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
    IF (NEW.silent_s, NEW.disk_warn, NEW.disk_crit, NEW.mem_warn, NEW.mem_crit, NEW.cpu_warn, NEW.cpu_crit)
       IS DISTINCT FROM (OLD.silent_s, OLD.disk_warn, OLD.disk_crit, OLD.mem_warn, OLD.mem_crit, OLD.cpu_warn, OLD.cpu_crit) THEN
        d := d || jsonb_build_object('schwellen', jsonb_build_object('stumm_s', NEW.silent_s,
            'platte', jsonb_build_array(NEW.disk_warn, NEW.disk_crit), 'speicher', jsonb_build_array(NEW.mem_warn, NEW.mem_crit),
            'cpu', jsonb_build_array(NEW.cpu_warn, NEW.cpu_crit)));
    END IF;
    IF d <> '{}'::jsonb THEN
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (NULL, CASE WHEN openwacht.current_user_id() IS NULL THEN 'einstellungen.uebernommen' ELSE 'einstellungen.geaendert' END, d);
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER settings_audit BEFORE UPDATE ON openwacht.settings
    FOR EACH ROW EXECUTE FUNCTION openwacht.settings_audit();

-- Für die Zentrale ohne Benutzerkontext (Planer, Alarme, Start).
CREATE FUNCTION openwacht.runtime_settings()
    RETURNS TABLE (check_nets cidr[], alert_targets text[], deadman_enc bytea, silent_s integer,
                   disk_warn double precision, disk_crit double precision, mem_warn double precision,
                   mem_crit double precision, cpu_warn double precision, cpu_crit double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT s.check_nets, s.alert_targets, s.deadman_enc, s.silent_s, s.disk_warn, s.disk_crit,
           s.mem_warn, s.mem_crit, s.cpu_warn, s.cpu_crit
      FROM openwacht.settings s
$$;
REVOKE ALL ON FUNCTION openwacht.runtime_settings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.runtime_settings() TO openwacht_app;

-- Übernahme der Startoptionen beim Start: setzt nur Felder ohne Wert. Die
-- Zentrale ruft sie ohne Benutzer auf; sie kann nichts Bestehendes ändern.
CREATE FUNCTION openwacht.settings_import(p_nets cidr[], p_targets text[], p_deadman bytea, p_silent integer,
        p_disk_warn double precision, p_disk_crit double precision, p_mem_warn double precision,
        p_mem_crit double precision, p_cpu_warn double precision, p_cpu_crit double precision)
    RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    n integer := 0;
    s openwacht.settings;
BEGIN
    SELECT * INTO s FROM openwacht.settings FOR UPDATE;
    n := (s.check_nets IS NULL AND p_nets IS NOT NULL)::int + (s.alert_targets IS NULL AND p_targets IS NOT NULL)::int
       + (s.deadman_enc IS NULL AND p_deadman IS NOT NULL)::int + (s.silent_s IS NULL AND p_silent IS NOT NULL)::int
       + (s.disk_warn IS NULL AND p_disk_warn IS NOT NULL)::int + (s.disk_crit IS NULL AND p_disk_crit IS NOT NULL)::int
       + (s.mem_warn IS NULL AND p_mem_warn IS NOT NULL)::int + (s.mem_crit IS NULL AND p_mem_crit IS NOT NULL)::int
       + (s.cpu_warn IS NULL AND p_cpu_warn IS NOT NULL)::int + (s.cpu_crit IS NULL AND p_cpu_crit IS NOT NULL)::int;
    IF n = 0 THEN
        RETURN 0;
    END IF;
    UPDATE openwacht.settings SET
        check_nets = coalesce(check_nets, p_nets), alert_targets = coalesce(alert_targets, p_targets),
        deadman_enc = coalesce(deadman_enc, p_deadman), silent_s = coalesce(silent_s, p_silent),
        disk_warn = coalesce(disk_warn, p_disk_warn), disk_crit = coalesce(disk_crit, p_disk_crit),
        mem_warn = coalesce(mem_warn, p_mem_warn), mem_crit = coalesce(mem_crit, p_mem_crit),
        cpu_warn = coalesce(cpu_warn, p_cpu_warn), cpu_crit = coalesce(cpu_crit, p_cpu_crit);
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION openwacht.settings_import(cidr[], text[], bytea, integer, double precision, double precision,
    double precision, double precision, double precision, double precision) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.settings_import(cidr[], text[], bytea, integer, double precision, double precision,
    double precision, double precision, double precision, double precision) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Einstellungen je Mandant (nur Betreiber)
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.tenant_settings (
    tenant_id  uuid PRIMARY KEY REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    -- NULL = keine eigene Eingrenzung; leeres Array = dieser Mandant erreicht nichts
    check_nets cidr[] CHECK (openwacht.valid_nets(check_nets)),
    silent_s   integer CHECK (silent_s BETWEEN 120 AND 86400),
    disk_warn  double precision CHECK (openwacht.valid_pct(disk_warn)),
    disk_crit  double precision CHECK (openwacht.valid_pct(disk_crit)),
    mem_warn   double precision CHECK (openwacht.valid_pct(mem_warn)),
    mem_crit   double precision CHECK (openwacht.valid_pct(mem_crit)),
    cpu_warn   double precision CHECK (openwacht.valid_pct(cpu_warn)),
    cpu_crit   double precision CHECK (openwacht.valid_pct(cpu_crit)),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (openwacht.valid_pair(disk_warn, disk_crit) AND openwacht.valid_pair(mem_warn, mem_crit)
           AND openwacht.valid_pair(cpu_warn, cpu_crit))
);
ALTER TABLE openwacht.tenant_settings ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE (check_nets, silent_s, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit), DELETE
    ON openwacht.tenant_settings TO openwacht_app;
CREATE POLICY tenant_settings_select ON openwacht.tenant_settings FOR SELECT TO openwacht_app
    USING (openwacht.is_platform_operator());
CREATE POLICY tenant_settings_insert ON openwacht.tenant_settings FOR INSERT TO openwacht_app
    WITH CHECK (openwacht.is_platform_operator());
CREATE POLICY tenant_settings_update ON openwacht.tenant_settings FOR UPDATE TO openwacht_app
    USING (openwacht.is_platform_operator()) WITH CHECK (openwacht.is_platform_operator());
CREATE POLICY tenant_settings_delete ON openwacht.tenant_settings FOR DELETE TO openwacht_app
    USING (openwacht.is_platform_operator());

-- Audit je Mandant. Der Betreiber hat nicht unbedingt eine Rolle im Mandanten,
-- deshalb schreibt der Trigger mit den Rechten des Eigentümers.
CREATE FUNCTION openwacht.tenant_settings_audit() RETURNS trigger
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
                'speicher', jsonb_build_array(r.mem_warn, r.mem_crit), 'cpu', jsonb_build_array(r.cpu_warn, r.cpu_crit)) END);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER tenant_settings_audit_iu BEFORE INSERT OR UPDATE ON openwacht.tenant_settings
    FOR EACH ROW EXECUTE FUNCTION openwacht.tenant_settings_audit();
CREATE TRIGGER tenant_settings_audit_d AFTER DELETE ON openwacht.tenant_settings
    FOR EACH ROW EXECUTE FUNCTION openwacht.tenant_settings_audit();

-- Alle Mandanten mit Namen und Elternknoten, für die Seite Einstellungen.
-- Der Betreiber ist Benutzer des Hauptmandanten und darf die Namen sehen,
-- auch ohne Rolle in jedem Mandanten.
CREATE FUNCTION openwacht.settings_tenants()
    RETURNS TABLE (id uuid, parent_id uuid, name text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
BEGIN
    IF NOT openwacht.is_platform_operator() THEN
        RAISE EXCEPTION 'Nur für Betreiber.' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT t.id, t.parent_id, t.name FROM openwacht.tenants t ORDER BY lower(t.name) LIMIT 5000;
END
$$;
REVOKE ALL ON FUNCTION openwacht.settings_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.settings_tenants() TO openwacht_app;

-- Netzketten für die Zentrale: je Mandant alle Vorfahren (einschließlich
-- sich selbst) mit eigener Netzliste. Eine Adresse muss in jeder Liste liegen.
CREATE FUNCTION openwacht.tenant_net_chains()
    RETURNS TABLE (tenant_id uuid, ancestor uuid, nets cidr[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT c.descendant, c.ancestor, ts.check_nets
      FROM openwacht.tenant_closure c
      JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor AND ts.check_nets IS NOT NULL
     ORDER BY c.descendant, c.depth
$$;
REVOKE ALL ON FUNCTION openwacht.tenant_net_chains() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.tenant_net_chains() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Schwellen je Gerät (Admins und Operatoren des Geräts)
-- ---------------------------------------------------------------------------

CREATE TABLE openwacht.device_limits (
    device_id  uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    silent_s   integer CHECK (silent_s BETWEEN 120 AND 86400),
    disk_warn  double precision CHECK (openwacht.valid_pct(disk_warn)),
    disk_crit  double precision CHECK (openwacht.valid_pct(disk_crit)),
    mem_warn   double precision CHECK (openwacht.valid_pct(mem_warn)),
    mem_crit   double precision CHECK (openwacht.valid_pct(mem_crit)),
    cpu_warn   double precision CHECK (openwacht.valid_pct(cpu_warn)),
    cpu_crit   double precision CHECK (openwacht.valid_pct(cpu_crit)),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, tenant_id) REFERENCES openwacht.devices (id, tenant_id) ON DELETE CASCADE,
    CHECK (openwacht.valid_pair(disk_warn, disk_crit) AND openwacht.valid_pair(mem_warn, mem_crit)
           AND openwacht.valid_pair(cpu_warn, cpu_crit))
);
CREATE INDEX device_limits_tenant ON openwacht.device_limits (tenant_id);
ALTER TABLE openwacht.device_limits ENABLE ROW LEVEL SECURITY;

-- Mandant aus dem Gerät, mit den Rechten des Aufrufers (Leitprinzip 2).
CREATE FUNCTION openwacht.device_limits_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.tenant_id := (SELECT d.tenant_id FROM openwacht.devices d WHERE d.id = NEW.device_id);
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'Schwellen: Gerät nicht gefunden.' USING ERRCODE = '23503';
        END IF;
    ELSE
        NEW.device_id := OLD.device_id;
        NEW.tenant_id := OLD.tenant_id;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER device_limits_before BEFORE INSERT OR UPDATE ON openwacht.device_limits
    FOR EACH ROW EXECUTE FUNCTION openwacht.device_limits_before();

GRANT SELECT, INSERT (device_id, silent_s, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit),
      UPDATE (silent_s, disk_warn, disk_crit, mem_warn, mem_crit, cpu_warn, cpu_crit), DELETE
    ON openwacht.device_limits TO openwacht_app;
CREATE POLICY device_limits_select ON openwacht.device_limits FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY device_limits_insert ON openwacht.device_limits FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY device_limits_update ON openwacht.device_limits FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY device_limits_delete ON openwacht.device_limits FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- Geerbte Schwellen eines Geräts: je Feld der nächste Mandant der Kette mit
-- eigenem Wert (NULL = global). Nur für Geräte, die der Aufrufer sieht.
CREATE FUNCTION openwacht.device_limits_inherited(p_device uuid)
    RETURNS TABLE (silent_s integer, disk_warn double precision, disk_crit double precision,
                   mem_warn double precision, mem_crit double precision, cpu_warn double precision,
                   cpu_crit double precision, tenant_name text)
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
           (SELECT t.name FROM d JOIN openwacht.tenants t ON t.id = d.tenant_id)
      FROM d
$$;
REVOKE ALL ON FUNCTION openwacht.device_limits_inherited(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.device_limits_inherited(uuid) TO openwacht_app;

-- Wirksame Abweichungen für die Zentrale (ohne Benutzerkontext): je Agent
-- und je Abfragequelle das Gerät, je Feld zuerst das Gerät, dann der nächste
-- Mandant der Kette. Nur Zeilen mit mindestens einer Abweichung; NULL = global.
CREATE FUNCTION openwacht.limit_overrides()
    RETURNS TABLE (kind text, id uuid, silent_s integer, disk_warn double precision, disk_crit double precision,
                   mem_warn double precision, mem_crit double precision, cpu_warn double precision,
                   cpu_crit double precision)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    WITH src AS (
        SELECT 'agent'::text AS kind, a.id, a.device_id, a.tenant_id FROM openwacht.agents a
        UNION ALL
        SELECT 'snmp', s.id, s.device_id, s.tenant_id FROM openwacht.snmp_sources s
    ), k AS (
        SELECT c.descendant AS tenant_id, c.depth, ts.silent_s, ts.disk_warn, ts.disk_crit, ts.mem_warn,
               ts.mem_crit, ts.cpu_warn, ts.cpu_crit FROM openwacht.tenant_closure c
          JOIN openwacht.tenant_settings ts ON ts.tenant_id = c.ancestor
    ), r AS (
        SELECT src.kind, src.id,
            coalesce(dl.silent_s, (SELECT k.silent_s FROM k WHERE k.tenant_id = src.tenant_id AND k.silent_s IS NOT NULL ORDER BY k.depth LIMIT 1)) AS silent_s,
            coalesce(dl.disk_warn, (SELECT k.disk_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.disk_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS disk_warn,
            coalesce(dl.disk_crit, (SELECT k.disk_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.disk_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS disk_crit,
            coalesce(dl.mem_warn, (SELECT k.mem_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.mem_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS mem_warn,
            coalesce(dl.mem_crit, (SELECT k.mem_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.mem_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS mem_crit,
            coalesce(dl.cpu_warn, (SELECT k.cpu_warn FROM k WHERE k.tenant_id = src.tenant_id AND k.cpu_warn IS NOT NULL ORDER BY k.depth LIMIT 1)) AS cpu_warn,
            coalesce(dl.cpu_crit, (SELECT k.cpu_crit FROM k WHERE k.tenant_id = src.tenant_id AND k.cpu_crit IS NOT NULL ORDER BY k.depth LIMIT 1)) AS cpu_crit
          FROM src LEFT JOIN openwacht.device_limits dl ON dl.device_id = src.device_id
    )
    SELECT * FROM r
     WHERE coalesce(r.silent_s::double precision, r.disk_warn, r.disk_crit, r.mem_warn, r.mem_crit, r.cpu_warn, r.cpu_crit) IS NOT NULL
$$;
REVOKE ALL ON FUNCTION openwacht.limit_overrides() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.limit_overrides() TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Planer: Mandant mitliefern (Netze je Mandant)
-- ---------------------------------------------------------------------------

DROP FUNCTION openwacht.checks_claim(integer);
CREATE FUNCTION openwacht.checks_claim(p_limit integer)
    RETURNS TABLE (id uuid, kind text, target jsonb, revision integer, tenant_id uuid)
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    UPDATE openwacht.checks c SET next_run = now() + interval '2 minutes'
     WHERE c.id IN (SELECT d.id FROM openwacht.checks d
                     WHERE d.enabled AND d.next_run <= now() AND NOT openwacht.is_agent_kind(d.kind)
                       AND d.kind <> 'snmp_oid'
                     ORDER BY d.next_run LIMIT least(greatest(p_limit, 0), 1000)
                     FOR UPDATE SKIP LOCKED)
    RETURNING c.id, c.kind, c.target, c.revision, c.tenant_id
$$;
REVOKE ALL ON FUNCTION openwacht.checks_claim(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.checks_claim(integer) TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Gerät mit Inhalt löschen
-- ---------------------------------------------------------------------------

-- Was am Gerät hängt. p_execute = false: nur zählen (Vorschau); true: nach
-- Prüfung des Namens alles löschen. Admins und Operatoren des Mandanten des
-- Geräts. Läuft als Eigentümer, weil SNMP-Quellen und Trap-Regeln sonst nur
-- Admins löschen dürfen (Entscheidung: Operatoren dürfen hier mitlöschen).
CREATE FUNCTION openwacht.device_delete_all(p_device uuid, p_name text, p_execute boolean)
    RETURNS jsonb
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    d       openwacht.devices;
    can     boolean;
    out     jsonb;
    n_coll  integer;
    n_blk   integer;
    a       record;
BEGIN
    SELECT * INTO d FROM openwacht.devices WHERE id = p_device
       AND tenant_id IN (SELECT openwacht.visible_tenants()) FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Gerät nicht gefunden.' USING ERRCODE = 'P0002';
    END IF;
    can := d.tenant_id IN (SELECT openwacht.operator_tenants());

    -- Geräte, die ein Agent dieses Geräts als Sammler abfragt (außer das eigene)
    SELECT count(*) INTO n_coll FROM openwacht.snmp_sources s
     WHERE s.collector_id IN (SELECT ag.id FROM openwacht.agents ag WHERE ag.device_id = d.id) AND s.device_id <> d.id;
    -- Entwarn-Regeln anderer Geltung, die eine Regel dieses Geräts beenden
    SELECT count(*) INTO n_blk FROM openwacht.snmp_trap_rules r
     WHERE (r.device_id IS DISTINCT FROM d.id)
       AND r.clears IN (SELECT x.id FROM openwacht.snmp_trap_rules x WHERE x.device_id = d.id);

    out := jsonb_build_object(
        'name', d.name,
        'darf', can,
        'sensoren', (SELECT count(*) FROM openwacht.checks c WHERE c.device_id = d.id),
        'agents', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', ag.id, 'hostname', ag.hostname,
                        'gesperrt', ag.revoked_at IS NOT NULL) ORDER BY ag.created_at), '[]'::jsonb)
                     FROM openwacht.agents ag WHERE ag.device_id = d.id),
        'quellen', (SELECT coalesce(jsonb_agg(s.version ORDER BY s.created_at), '[]'::jsonb)
                      FROM openwacht.snmp_sources s WHERE s.device_id = d.id),
        'trap_regeln', (SELECT coalesce(jsonb_agg(r.name ORDER BY r.position, r.name), '[]'::jsonb)
                          FROM openwacht.snmp_trap_rules r WHERE r.device_id = d.id),
        'wartung', EXISTS (SELECT 1 FROM openwacht.maintenance m WHERE m.device_id = d.id),
        'sammler_fuer', n_coll,
        'regeln_blockiert', n_blk);
    IF NOT p_execute THEN
        RETURN out;
    END IF;

    IF NOT can THEN
        RAISE EXCEPTION 'Löschen dürfen nur Admins und Operatoren.' USING ERRCODE = '42501';
    END IF;
    IF lower(btrim(coalesce(p_name, ''))) <> lower(d.name) THEN
        RAISE EXCEPTION 'Zur Bestätigung bitte den Namen des Geräts genau eintippen.' USING ERRCODE = '22023';
    END IF;
    IF n_coll > 0 THEN
        RAISE EXCEPTION 'Der Agent dieses Geräts ist Sammler für % weitere(s) Gerät(e). Bitte dort zuerst unter „Abgefragt von“ einen anderen Sammler oder die Zentrale wählen.', n_coll
            USING ERRCODE = '55006';
    END IF;
    IF n_blk > 0 THEN
        RAISE EXCEPTION 'Eine Trap-Regel außerhalb dieses Geräts beendet eine Regel des Geräts. Bitte diese Entwarn-Regel zuerst ändern oder löschen.'
            USING ERRCODE = '55006';
    END IF;

    -- Agents: erst sperren (Zertifikat sofort ungültig), dann löschen.
    FOR a IN SELECT ag.id, ag.hostname, ag.revoked_at FROM openwacht.agents ag WHERE ag.device_id = d.id LOOP
        IF a.revoked_at IS NULL THEN
            UPDATE openwacht.agents SET revoked_at = now() WHERE id = a.id;
            INSERT INTO openwacht.audit_log (tenant_id, action, details)
            VALUES (d.tenant_id, 'agent.gesperrt', jsonb_build_object('agent', a.id, 'hostname', a.hostname, 'grund', 'Gerät gelöscht'));
        END IF;
    END LOOP;
    DELETE FROM openwacht.snmp_trap_rules WHERE device_id = d.id AND clears IS NOT NULL;
    DELETE FROM openwacht.snmp_trap_rules WHERE device_id = d.id;
    DELETE FROM openwacht.checks WHERE device_id = d.id;
    DELETE FROM openwacht.snmp_sources WHERE device_id = d.id;
    FOR a IN DELETE FROM openwacht.agents WHERE device_id = d.id RETURNING id, hostname LOOP
        INSERT INTO openwacht.audit_log (tenant_id, action, details)
        VALUES (d.tenant_id, 'agent.geloescht', jsonb_build_object('agent', a.id, 'hostname', a.hostname, 'grund', 'Gerät gelöscht'));
    END LOOP;
    DELETE FROM openwacht.devices WHERE id = d.id;
    INSERT INTO openwacht.audit_log (tenant_id, action, details)
    VALUES (d.tenant_id, 'geraet.geloescht', jsonb_build_object('id', d.id, 'name', d.name, 'mit_inhalt', true,
        'sensoren', out->'sensoren', 'agents', jsonb_array_length(out->'agents'), 'quellen', out->'quellen',
        'trap_regeln', jsonb_array_length(out->'trap_regeln')));
    RETURN out;
END
$$;
REVOKE ALL ON FUNCTION openwacht.device_delete_all(uuid, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.device_delete_all(uuid, text, boolean) TO openwacht_app;
