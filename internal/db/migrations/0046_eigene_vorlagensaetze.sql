-- SPDX-License-Identifier: AGPL-3.0-only

-- 0.46.0: eigene Vorlagensätze je Mandant (23.11.2026).
--
-- Ein Satz ist eine Liste von Vorlagen (Kopien, keine Verweise): Name, Art,
-- Ziel, Intervall, Notiz je Eintrag. Ändert oder löscht jemand später eine
-- Vorlage, bleibt der Satz unverändert, wie bei angelegten Sensoren auch.
-- Die Zentrale prüft jedes Ziel mit checks.ParseTemplate; die Datenbank
-- prüft zusätzlich Form, Art und Intervall (zweite Schutzschicht).
--
-- Rechte wie bei eigenen Vorlagen (0020): sehen alle mit Rolle im Mandanten
-- oder darüber, pflegen Operatoren und Admins; Geschwister sehen nichts.

CREATE FUNCTION openwacht.valid_template_set_items(items jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(items) = 'array'
       AND jsonb_array_length(items) BETWEEN 1 AND 50
       AND octet_length(items::text) <= 262144
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(items) AS e(x)
            WHERE jsonb_typeof(x) <> 'object'
               OR NOT (x ?& ARRAY['name', 'typ', 'ziel', 'intervall_sekunden', 'notiz'])
               OR (SELECT count(*) FROM jsonb_object_keys(x)) <> 5
               OR jsonb_typeof(x->'name') <> 'string'
               OR char_length(x->>'name') NOT BETWEEN 1 AND 100
               OR x->>'name' ~ '[[:cntrl:]]'
               OR jsonb_typeof(x->'notiz') <> 'string'
               OR char_length(x->>'notiz') > 200
               OR x->>'notiz' ~ '[[:cntrl:]]'
               OR jsonb_typeof(x->'typ') <> 'string'
               OR x->>'typ' NOT IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid',
                                    'dienst', 'prozess', 'datei', 'docker', 'hyperv', 'leistungsindikator')
               OR jsonb_typeof(x->'ziel') <> 'object'
               OR jsonb_typeof(x->'intervall_sekunden') <> 'number'
               OR (x->>'intervall_sekunden') !~ '^[0-9]{1,5}$'
               OR (x->>'intervall_sekunden')::integer NOT BETWEEN 30 AND 86400
               OR (openwacht.is_agent_kind(x->>'typ') AND (x->>'intervall_sekunden')::integer < 60))
       AND (SELECT count(DISTINCT lower(e->>'name')) FROM jsonb_array_elements(items) AS a(e)) = jsonb_array_length(items)
$$;

CREATE TABLE openwacht.sensor_template_sets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES openwacht.tenants (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60 AND name !~ '[[:cntrl:]]'),
    note       text NOT NULL DEFAULT '' CHECK (char_length(note) <= 500 AND note !~ '[[:cntrl:]]'),
    items      jsonb NOT NULL CHECK (openwacht.valid_template_set_items(items)),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sensor_template_sets_name ON openwacht.sensor_template_sets (tenant_id, lower(name));

CREATE FUNCTION openwacht.sensor_template_sets_before() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (SELECT count(*) FROM openwacht.sensor_template_sets WHERE tenant_id = NEW.tenant_id) >= 50 THEN
            RAISE EXCEPTION 'Höchstens 50 Vorlagensätze je Mandant.' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := now();
    ELSIF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'ID und Mandant eines Vorlagensatzes sind unveränderlich.';
    END IF;
    NEW.changed_at := now();
    RETURN NEW;
END
$$;
CREATE TRIGGER sensor_template_sets_before BEFORE INSERT OR UPDATE ON openwacht.sensor_template_sets
    FOR EACH ROW EXECUTE FUNCTION openwacht.sensor_template_sets_before();

ALTER TABLE openwacht.sensor_template_sets ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT (tenant_id, name, note, items), UPDATE (name, note, items), DELETE
    ON openwacht.sensor_template_sets TO openwacht_app;
CREATE POLICY sensor_template_sets_select ON openwacht.sensor_template_sets FOR SELECT TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.visible_tenants()));
CREATE POLICY sensor_template_sets_insert ON openwacht.sensor_template_sets FOR INSERT TO openwacht_app
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_template_sets_update ON openwacht.sensor_template_sets FOR UPDATE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()))
    WITH CHECK (tenant_id IN (SELECT openwacht.operator_tenants()));
CREATE POLICY sensor_template_sets_delete ON openwacht.sensor_template_sets FOR DELETE TO openwacht_app
    USING (tenant_id IN (SELECT openwacht.operator_tenants()));
