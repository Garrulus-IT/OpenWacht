-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.99.2: Kennfarben (24.11.2026).
--
-- Eine Kennfarbe ist ein Name mit einer frei gewählten Farbe je Mandant, z. B.
-- „Neustart verpasst“ in Pink. Ist ein Sensor mit Kennfarbe nicht OK, zeigt
-- die Oberfläche ihn in dieser Farbe statt in Gelb bzw. Rot; Form und Text
-- der Schwere bleiben, ebenso die Schwere für Benachrichtigungen. Bei gleicher
-- Schwere gewinnt immer der Sensor ohne Kennfarbe (Entscheidung 24.11.2026).
--
-- Zuordnen lässt sich eine Kennfarbe
--   - Sensoren der Zentrale und der Agents (checks.kennfarbe_id),
--   - eingebauten Gegenständen von Agents und SNMP-Quellen (Speicher,
--     Platten, Schnittstellen …) über sensor_kennfarben,
--   - Trap-Regeln (snmp_trap_rules.kennfarbe_id); deren Zustände und
--     Protokolleinträge erben sie.
--
-- Rechte wie bei eigenen Vorlagen: pflegen Operatoren und Admins des
-- Mandanten. Sehen dürfen Kennfarben alle, die den Mandanten oder einen
-- Mandanten darunter sehen (auch Wandanzeigen), damit eine Kennfarbe der IT
-- an Sensoren eines Untermandanten dort auch erscheint. Geschwister sehen
-- nichts. Zuordnen lässt sich eine Kennfarbe nur im eigenen Mandanten oder
-- darunter. Die Farbe prüft die Zentrale zusätzlich auf Kontrast
-- (internal/kennfarbe), die Datenbank nur auf die Form.

CREATE TABLE openwacht.kennfarben (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 40 AND name !~ '[[:cntrl:]]' AND name = btrim(name)),
    color      text NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX kennfarben_name ON openwacht.kennfarben (tenant_id, lower(name));

CREATE FUNCTION openwacht.kennfarben_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.kennfarben WHERE tenant_id = NEW.tenant_id) >= 50 THEN
            RAISE EXCEPTION 'Höchstens 50 Kennfarben je Mandant.' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := now();
    ELSIF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
          OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'ID und Mandant einer Kennfarbe sind unveränderlich.';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER kennfarben_before BEFORE INSERT OR UPDATE ON openwacht.kennfarben
    FOR EACH ROW EXECUTE FUNCTION openwacht.kennfarben_before();

-- Mandanten, deren Kennfarben der aktuelle Benutzer bzw. die aktuelle
-- Anzeige sieht: jeder sichtbare Mandant und alle seine Vorfahren.
CREATE FUNCTION openwacht.kennfarben_tenants() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT DISTINCT c.ancestor
      FROM openwacht.tenant_closure c
     WHERE c.descendant IN (SELECT openwacht.visible_tenants())
        OR c.descendant IN (SELECT openwacht.display_tenants())
$$;

-- Darf eine Kennfarbe an etwas im Mandanten p_tenant hängen? Nur, wenn sie
-- zum Mandanten selbst oder einem Vorfahren gehört. Bewusst ohne RLS (der
-- Aufrufer ist ein Trigger); ob jemand die Zuordnung schreiben darf, prüfen
-- die Policies der jeweiligen Tabelle.
CREATE FUNCTION openwacht.kennfarbe_allowed(p_kennfarbe uuid, p_tenant uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT EXISTS (
        SELECT 1 FROM openwacht.kennfarben k
          JOIN openwacht.tenant_closure c ON c.ancestor = k.tenant_id AND c.descendant = p_tenant
         WHERE k.id = p_kennfarbe)
$$;
REVOKE ALL ON FUNCTION openwacht.kennfarben_tenants(), openwacht.kennfarbe_allowed(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.kennfarben_tenants(), openwacht.kennfarbe_allowed(uuid, uuid) TO openwacht_app;

ALTER TABLE openwacht.kennfarben ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.kennfarben FROM PUBLIC;
GRANT SELECT, INSERT (tenant_id, name, color), UPDATE (name, color), DELETE ON openwacht.kennfarben TO openwacht_app;
CREATE POLICY kennfarben_select ON openwacht.kennfarben FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.kennfarben_tenants()));
CREATE POLICY kennfarben_insert ON openwacht.kennfarben FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY kennfarben_update ON openwacht.kennfarben FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY kennfarben_delete ON openwacht.kennfarben FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- Gemeinsamer Trigger: Kennfarbe nur aus dem eigenen Mandanten oder darüber.
CREATE FUNCTION openwacht.kennfarbe_ref_check() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kennfarbe_id IS NOT NULL
       AND (TG_OP = 'INSERT' OR NEW.kennfarbe_id IS DISTINCT FROM OLD.kennfarbe_id)
       AND NOT openwacht.kennfarbe_allowed(NEW.kennfarbe_id, NEW.tenant_id) THEN
        RAISE EXCEPTION 'Die Kennfarbe gehört nicht zu diesem Mandanten oder einem übergeordneten.'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- --- Sensoren ----------------------------------------------------------------

ALTER TABLE openwacht.checks
    ADD COLUMN kennfarbe_id uuid REFERENCES openwacht.kennfarben (id) ON DELETE SET NULL;
CREATE INDEX checks_kennfarbe ON openwacht.checks (kennfarbe_id) WHERE kennfarbe_id IS NOT NULL;
GRANT SELECT (kennfarbe_id), UPDATE (kennfarbe_id) ON openwacht.checks TO openwacht_app;
CREATE TRIGGER checks_kennfarbe BEFORE INSERT OR UPDATE OF kennfarbe_id ON openwacht.checks
    FOR EACH ROW EXECUTE FUNCTION openwacht.kennfarbe_ref_check();

-- --- Eingebaute Gegenstände von Agents und SNMP-Quellen -------------------------

CREATE TABLE openwacht.sensor_kennfarben (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL,
    agent_id     uuid,
    snmp_id      uuid,
    -- Gegenstand wie im Alarmprotokoll (speicher, platte:/, if:3, trap:<Regel> …)
    subject      text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300 AND subject !~ '[[:cntrl:]]'),
    kennfarbe_id uuid NOT NULL REFERENCES openwacht.kennfarben (id) ON DELETE CASCADE,
    CHECK ((agent_id IS NULL) <> (snmp_id IS NULL)),
    FOREIGN KEY (agent_id, tenant_id) REFERENCES openwacht.agents (id, tenant_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (snmp_id, tenant_id) REFERENCES openwacht.snmp_sources (id, tenant_id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX sensor_kennfarben_agent ON openwacht.sensor_kennfarben (agent_id, subject) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX sensor_kennfarben_snmp ON openwacht.sensor_kennfarben (snmp_id, subject) WHERE snmp_id IS NOT NULL;
CREATE INDEX sensor_kennfarben_kennfarbe ON openwacht.sensor_kennfarben (kennfarbe_id);

CREATE FUNCTION openwacht.sensor_kennfarben_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
            OR NEW.snmp_id IS DISTINCT FROM OLD.snmp_id OR NEW.subject IS DISTINCT FROM OLD.subject) THEN
        RAISE EXCEPTION 'Nur die Kennfarbe einer Zuordnung ist änderbar.';
    END IF;
    IF TG_OP = 'INSERT' AND (SELECT count(*) FROM openwacht.sensor_kennfarben
                              WHERE tenant_id = NEW.tenant_id) >= 5000 THEN
        RAISE EXCEPTION 'Höchstens 5000 Kennfarben-Zuordnungen je Mandant.' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER sensor_kennfarben_before BEFORE INSERT OR UPDATE ON openwacht.sensor_kennfarben
    FOR EACH ROW EXECUTE FUNCTION openwacht.sensor_kennfarben_before();
CREATE TRIGGER sensor_kennfarben_ref BEFORE INSERT OR UPDATE OF kennfarbe_id ON openwacht.sensor_kennfarben
    FOR EACH ROW EXECUTE FUNCTION openwacht.kennfarbe_ref_check();

ALTER TABLE openwacht.sensor_kennfarben ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.sensor_kennfarben FROM PUBLIC;
GRANT SELECT, INSERT (tenant_id, agent_id, snmp_id, subject, kennfarbe_id), UPDATE (kennfarbe_id), DELETE
    ON openwacht.sensor_kennfarben TO openwacht_app;
CREATE POLICY sensor_kennfarben_select ON openwacht.sensor_kennfarben FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
CREATE POLICY sensor_kennfarben_insert ON openwacht.sensor_kennfarben FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_kennfarben_update ON openwacht.sensor_kennfarben FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_kennfarben_delete ON openwacht.sensor_kennfarben FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- --- Trap-Regeln -----------------------------------------------------------------

ALTER TABLE openwacht.snmp_trap_rules
    ADD COLUMN kennfarbe_id uuid REFERENCES openwacht.kennfarben (id) ON DELETE SET NULL;
GRANT INSERT (kennfarbe_id), UPDATE (kennfarbe_id) ON openwacht.snmp_trap_rules TO openwacht_app;
CREATE TRIGGER snmp_trap_rules_kennfarbe BEFORE INSERT OR UPDATE OF kennfarbe_id ON openwacht.snmp_trap_rules
    FOR EACH ROW EXECUTE FUNCTION openwacht.kennfarbe_ref_check();

-- --- Auflösung ----------------------------------------------------------------------

-- Kennfarbe einer Trap-Regel. SECURITY DEFINER, weil Wandanzeigen die
-- Regeln selbst nicht lesen dürfen; geliefert wird nur die ID der Kennfarbe,
-- und nur für Regeln in Mandanten, die Benutzer oder Anzeige sehen.
CREATE FUNCTION openwacht.trap_rule_kennfarbe(p_rule uuid) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT r.kennfarbe_id FROM openwacht.snmp_trap_rules r
     WHERE r.id = p_rule
       AND (r.tenant_id IN (SELECT openwacht.visible_tenants()) OR r.tenant_id IN (SELECT openwacht.display_tenants()))
$$;
REVOKE ALL ON FUNCTION openwacht.trap_rule_kennfarbe(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.trap_rule_kennfarbe(uuid) TO openwacht_app;

-- Kennfarbe eines Sensors bzw. Alarms. Reihenfolge: eigene Zuordnung, bei
-- Trap-Zuständen sonst die der Regel. Läuft mit den Rechten des Aufrufers
-- (RLS): Eine nicht sichtbare Kennfarbe ergibt NULL, also die Standardfarben.
CREATE FUNCTION openwacht.kennfarbe_of(p_check uuid, p_agent uuid, p_snmp uuid, p_subject text) RETURNS uuid
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT CASE
        WHEN p_check IS NOT NULL THEN (SELECT c.kennfarbe_id FROM openwacht.checks c WHERE c.id = p_check)
        WHEN p_agent IS NOT NULL THEN (SELECT z.kennfarbe_id FROM openwacht.sensor_kennfarben z
                                        WHERE z.agent_id = p_agent AND z.subject = p_subject)
        WHEN p_snmp IS NOT NULL THEN coalesce(
            (SELECT z.kennfarbe_id FROM openwacht.sensor_kennfarben z WHERE z.snmp_id = p_snmp AND z.subject = p_subject),
            CASE WHEN p_subject ~ '^trap:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(:|$)'
                 THEN openwacht.trap_rule_kennfarbe(substr(p_subject, 6, 36)::uuid) END)
    END
$$;

-- Als JSON für die Oberfläche: {id, name, farbe} oder NULL.
CREATE FUNCTION openwacht.kennfarbe_json(p_kennfarbe uuid) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT jsonb_build_object('id', k.id, 'name', k.name, 'farbe', k.color)
      FROM openwacht.kennfarben k WHERE k.id = p_kennfarbe
$$;
REVOKE ALL ON FUNCTION openwacht.kennfarbe_of(uuid, uuid, uuid, text), openwacht.kennfarbe_json(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.kennfarbe_of(uuid, uuid, uuid, text), openwacht.kennfarbe_json(uuid) TO openwacht_app;

-- Trap-Zustände einer Quelle, dazu die Kennfarbe der Regel (sonst wie 0017).
CREATE OR REPLACE FUNCTION openwacht.snmp_trap_states_json(p_source uuid) RETURNS jsonb
    LANGUAGE sql STABLE SET search_path = pg_catalog, openwacht AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'regel', t.rule_id, 'name', t.rule_name, 'instanz', t.instance, 'status', t.status,
               'meldung', t.message, 'bestaetigt', t.authentic, 'seit', t.since, 'zuletzt', t.last_at,
               'anzahl', t.hits, 'bis', t.expires_at,
               'kennfarbe', openwacht.kennfarbe_json(openwacht.trap_rule_kennfarbe(t.rule_id)))
             ORDER BY t.rule_name, t.instance), '[]'::jsonb)
      FROM (SELECT * FROM openwacht.snmp_trap_state x
             WHERE x.source_id = p_source AND (x.expires_at IS NULL OR x.expires_at > now())
             ORDER BY x.rule_name, x.instance LIMIT 200) t
$$;
