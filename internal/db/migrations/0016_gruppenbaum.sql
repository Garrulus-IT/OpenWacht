-- SPDX-License-Identifier: AGPL-3.0-only

-- 0016: Gruppenbaum (Etappe 13).
--
-- Gruppen sind jetzt eigene Einträge je Mandant und bilden einen Baum
-- (höchstens 4 Ebenen). Ein Gerät hängt über group_id an genau einer Gruppe
-- seines Mandanten oder an keiner. Der bisherige Pfad am Gerät (0015,
-- group_path) wird in den Baum übernommen und danach entfernt, damit es nur
-- eine Quelle der Wahrheit gibt.
--
-- Gruppen dienen nur der Darstellung (Hosts-Baum, Wandanzeige); Rechte hängen
-- weiterhin allein am Mandanten. Pflegen dürfen sie Operatoren und Admins,
-- wie die Geräte selbst (Entscheidung, 20.11.2026). Die Reihenfolge unter
-- Geschwistern ist von Hand einstellbar (position).
--
-- Schutz in der Datenbank, nicht nur in der Anwendung:
-- - Eltern-Gruppe und Gerät müssen zum selben Mandanten gehören
--   (zusammengesetzte Fremdschlüssel über (tenant_id, id)).
-- - Kein Zyklus, höchstens 4 Ebenen, auch beim Verschieben ganzer Teilbäume
--   (Trigger; je Mandant serialisiert über eine Advisory-Sperre, damit zwei
--   gleichzeitige Verschiebungen keinen Zyklus bauen).
-- - Mandant und ID einer Gruppe sind unveränderlich.

CREATE TABLE openwacht.device_groups (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    parent_id  uuid,
    name       text NOT NULL CHECK (
                   char_length(name) BETWEEN 1 AND 50
                   AND name !~ '[[:cntrl:]]'
                   AND name = btrim(name)
                   AND position('/' IN name) = 0),
    position   integer NOT NULL DEFAULT 0 CHECK (position BETWEEN 0 AND 100000),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES openwacht.device_groups (tenant_id, id),
    CHECK (parent_id IS DISTINCT FROM id)
);
-- Namen unter Geschwistern eindeutig, ohne Groß/Klein.
CREATE UNIQUE INDEX device_groups_sibling_name ON openwacht.device_groups
    (tenant_id, coalesce(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));
CREATE INDEX device_groups_parent ON openwacht.device_groups (parent_id);

CREATE FUNCTION openwacht.device_groups_before_write() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    lvl    integer := 1;
    height integer := 0;
    cur    uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        RAISE EXCEPTION 'ID und Mandant einer Gruppe sind unveränderlich.' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id THEN
        RETURN NEW; -- nur Name oder Reihenfolge
    END IF;
    -- Änderungen am Baum eines Mandanten nacheinander, sonst könnten zwei
    -- gleichzeitige Verschiebungen (A in B, B in A) einen Zyklus bauen.
    PERFORM pg_advisory_xact_lock(hashtextextended('openwacht.device_groups:' || NEW.tenant_id::text, 0));
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.device_groups WHERE tenant_id = NEW.tenant_id) >= 1000 THEN
            RAISE EXCEPTION 'Höchstens 1000 Gruppen je Mandant.' USING ERRCODE = '23514', CONSTRAINT = 'device_groups_limit';
        END IF;
        NEW.created_at := now();
    END IF;
    -- Ebene der Gruppe an ihrem neuen Platz; dabei auf Zyklen achten.
    cur := NEW.parent_id;
    WHILE cur IS NOT NULL LOOP
        IF cur = NEW.id THEN
            RAISE EXCEPTION 'Eine Gruppe kann nicht in sich selbst oder ihre Untergruppen verschoben werden.'
                USING ERRCODE = '23514', CONSTRAINT = 'device_groups_cycle';
        END IF;
        lvl := lvl + 1;
        IF lvl > 4 THEN
            RAISE EXCEPTION 'Höchstens 4 Ebenen.' USING ERRCODE = '23514', CONSTRAINT = 'device_groups_depth';
        END IF;
        SELECT g.parent_id INTO cur FROM openwacht.device_groups g WHERE g.id = cur;
    END LOOP;
    -- Beim Verschieben zieht der ganze Teilbaum mit.
    IF TG_OP = 'UPDATE' THEN
        WITH RECURSIVE sub(id, h) AS (
            SELECT NEW.id, 0
            UNION ALL
            SELECT g.id, s.h + 1 FROM openwacht.device_groups g JOIN sub s ON g.parent_id = s.id WHERE s.h < 4
        ) SELECT max(h) INTO height FROM sub;
        IF lvl + height > 4 THEN
            RAISE EXCEPTION 'Höchstens 4 Ebenen.' USING ERRCODE = '23514', CONSTRAINT = 'device_groups_depth';
        END IF;
    END IF;
    -- Neu oder verschoben: ans Ende der neuen Geschwister.
    SELECT coalesce(max(g.position) + 1, 0) INTO NEW.position
      FROM openwacht.device_groups g
     WHERE g.tenant_id = NEW.tenant_id AND g.parent_id IS NOT DISTINCT FROM NEW.parent_id AND g.id <> NEW.id;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openwacht.device_groups_before_write() FROM PUBLIC;
CREATE TRIGGER device_groups_before_write BEFORE INSERT OR UPDATE ON openwacht.device_groups
    FOR EACH ROW EXECUTE FUNCTION openwacht.device_groups_before_write();

ALTER TABLE openwacht.device_groups ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, tenant_id, parent_id, name, position, created_at),
      INSERT (tenant_id, parent_id, name),
      UPDATE (parent_id, name, position),
      DELETE
    ON openwacht.device_groups TO openwacht_app;
-- Lesen wie Geräte, auch für Wandanzeigen (Allowlist aus 0015).
CREATE POLICY device_groups_select ON openwacht.device_groups FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()) OR tenant_id IN (SELECT openwacht.display_tenants()));
CREATE POLICY device_groups_insert ON openwacht.device_groups FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY device_groups_update ON openwacht.device_groups FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY device_groups_delete ON openwacht.device_groups FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- ---------------------------------------------------------------------------
-- Gerät → Gruppe
-- ---------------------------------------------------------------------------

ALTER TABLE openwacht.devices ADD COLUMN group_id uuid;
ALTER TABLE openwacht.devices ADD CONSTRAINT devices_group_fk
    FOREIGN KEY (tenant_id, group_id) REFERENCES openwacht.device_groups (tenant_id, id);
CREATE INDEX devices_group ON openwacht.devices (group_id) WHERE group_id IS NOT NULL;
GRANT SELECT (group_id), INSERT (group_id), UPDATE (group_id) ON openwacht.devices TO openwacht_app;

-- ---------------------------------------------------------------------------
-- Vorhandene Pfade übernehmen
-- ---------------------------------------------------------------------------
-- Gleich geschriebene Ebenen (ohne Groß/Klein) werden zu einer Gruppe; der
-- Name kommt vom ersten Gerät in Pfad-Reihenfolge.

DO $$
DECLARE
    r      record;
    part   text;
    parent uuid;
    gid    uuid;
BEGIN
    FOR r IN SELECT d.id, d.tenant_id, string_to_array(d.group_path, '/') AS parts
               FROM openwacht.devices d
              WHERE d.group_path IS NOT NULL
              ORDER BY d.tenant_id, d.group_path, d.id
    LOOP
        parent := NULL;
        FOREACH part IN ARRAY r.parts LOOP
            part := btrim(left(part, 50));
            gid := NULL;
            SELECT g.id INTO gid FROM openwacht.device_groups g
             WHERE g.tenant_id = r.tenant_id AND g.parent_id IS NOT DISTINCT FROM parent AND lower(g.name) = lower(part);
            IF gid IS NULL THEN
                INSERT INTO openwacht.device_groups (tenant_id, parent_id, name)
                VALUES (r.tenant_id, parent, part) RETURNING id INTO gid;
            END IF;
            parent := gid;
        END LOOP;
        UPDATE openwacht.devices SET group_id = parent WHERE id = r.id;
    END LOOP;
    -- Anfangs alphabetisch wie bisher.
    UPDATE openwacht.device_groups g SET position = o.rn - 1
      FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id, parent_id ORDER BY lower(name), name, id) AS rn
              FROM openwacht.device_groups) o
     WHERE o.id = g.id;
END
$$;

ALTER TABLE openwacht.devices DROP COLUMN group_path;
