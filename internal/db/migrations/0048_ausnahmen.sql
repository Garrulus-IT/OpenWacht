-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.99.2: einzelne Gegenstände einer SNMP-Quelle ausnehmen (24.11.2026).
--
-- Anlass: alte SnapMirror-Beziehungen einer NetApp, die dauerhaft rot sind,
-- weil sie niemand mehr pflegt. Bestätigen hilft nicht, der Alarm bliebe
-- offen. Eine Ausnahme gilt für genau einen Gegenstand einer Quelle (z. B.
-- 'snapmirror:svm:vol', 'volume:x', 'if:3'), braucht eine Begründung und
-- steht im Audit-Log. Ausgenommene Gegenstände gelten für Alarme als OK
-- (ein offener Alarm endet) und erscheinen in der Oberfläche grau als
-- „ausgenommen“. Die Erreichbarkeit ('stumm') lässt sich nicht ausnehmen;
-- dafür gibt es „Abfrage ausschalten“.
--
-- Rechte: pflegen Operatoren und Admins des Mandanten der Quelle, sehen alle
-- mit Rolle dort oder darüber.

CREATE TABLE openwacht.snmp_exclusions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL,
    snmp_id     uuid NOT NULL,
    subject     text NOT NULL CHECK (openwacht.valid_snmp_subject(subject) AND subject <> 'stumm'),
    reason      text NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 300 AND reason !~ '[[:cntrl:]]' AND reason = btrim(reason)),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snmp_id, subject),
    FOREIGN KEY (snmp_id, tenant_id) REFERENCES openwacht.snmp_sources (id, tenant_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE FUNCTION openwacht.snmp_exclusions_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.snmp_exclusions WHERE tenant_id = NEW.tenant_id) >= 2000 THEN
            RAISE EXCEPTION 'Höchstens 2000 Ausnahmen je Mandant.' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.id IS DISTINCT FROM OLD.id OR NEW.snmp_id IS DISTINCT FROM OLD.snmp_id
          OR NEW.subject IS DISTINCT FROM OLD.subject THEN
        RAISE EXCEPTION 'Nur die Begründung einer Ausnahme ist änderbar.';
    END IF;
    NEW.created_by := openwacht.current_user_id();
    NEW.created_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER snmp_exclusions_before BEFORE INSERT OR UPDATE ON openwacht.snmp_exclusions
    FOR EACH ROW EXECUTE FUNCTION openwacht.snmp_exclusions_before();

ALTER TABLE openwacht.snmp_exclusions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON openwacht.snmp_exclusions FROM PUBLIC;
GRANT SELECT, INSERT (tenant_id, snmp_id, subject, reason), UPDATE (reason), DELETE ON openwacht.snmp_exclusions TO openwacht_app;
CREATE POLICY snmp_exclusions_select ON openwacht.snmp_exclusions FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY snmp_exclusions_insert ON openwacht.snmp_exclusions FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY snmp_exclusions_update ON openwacht.snmp_exclusions FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY snmp_exclusions_delete ON openwacht.snmp_exclusions FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));

-- Für die Bewertung der Alarme ohne Benutzerkontext (wie alert_snmp_candidates)
-- und für Wandanzeigen: nur Quelle und Gegenstand, keine Begründung.
CREATE FUNCTION openwacht.snmp_exclusions_all() RETURNS TABLE (snmp_id uuid, subject text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT e.snmp_id, e.subject FROM openwacht.snmp_exclusions e
     WHERE (openwacht.current_user_id() IS NULL AND openwacht.current_display_id() IS NULL)
        OR e.tenant_id IN (SELECT openwacht.visible_tenants())
        OR e.tenant_id IN (SELECT openwacht.display_tenants())
$$;
REVOKE ALL ON FUNCTION openwacht.snmp_exclusions_all() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.snmp_exclusions_all() TO openwacht_app;
