-- SPDX-License-Identifier: AGPL-3.0-only

-- 0019: Dashboard-Layout je Benutzer (Etappe 17).
--
-- Übersicht und Dashboard sind eins: Jeder Benutzer stellt sich seine Widgets
-- selbst zusammen. Das Layout gilt für alle Mandanten und folgt dem Benutzer
-- auf jedes Gerät (Entscheidung, 21.11.2026). Ein Widget kann auf einen festen
-- Mandanten oder (Graph) ein Gerät zeigen; das ist nur ein Anzeigefilter, die
-- Daten selbst begrenzt weiterhin RLS über den Mandantenbaum.
--
-- Schutz in der Datenbank, nicht nur in der Anwendung:
-- - Jeder sieht und ändert nur sein eigenes Layout (RLS über app.user_id),
--   auch Admins nicht das anderer Benutzer.
-- - Der Mandant der Zeile ist der des Benutzers (zusammengesetzter
--   Fremdschlüssel); sie verschwindet mit dem Benutzer.
-- - Aufbau, Typen, Größen und Einstellungen prüft eine Funktion im CHECK,
--   dieselben Regeln wie in der API (internal/zentrale/dashboard_layout.go).
--   Ob ein genannter Mandant oder ein Gerät sichtbar ist, prüft die API.

-- Zielspalte für den zusammengesetzten Fremdschlüssel.
ALTER TABLE openwacht.users ADD CONSTRAINT users_id_tenant UNIQUE (id, tenant_id);

CREATE FUNCTION openwacht.dashboard_widgets_valid(w jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    e     jsonb;
    k     text;
    typ   text;
    ids   text[] := '{}';
    typen text[] := '{}';
    uuid_re constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
BEGIN
    IF w IS NULL OR jsonb_typeof(w) <> 'array' OR jsonb_array_length(w) > 30 OR octet_length(w::text) > 8192 THEN
        RETURN false;
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(w) AS t(x) LOOP
        IF jsonb_typeof(e) <> 'object' THEN
            RETURN false;
        END IF;
        FOR k IN SELECT jsonb_object_keys(e) LOOP
            IF k <> ALL (ARRAY['id', 'typ', 'groesse', 'mandant_id', 'geraet_id', 'zeitraum', 'wert']) THEN
                RETURN false;
            END IF;
        END LOOP;
        IF jsonb_typeof(e -> 'id') IS DISTINCT FROM 'string' OR (e ->> 'id') !~ '^[a-z0-9]{4,16}$' OR (e ->> 'id') = ANY (ids) THEN
            RETURN false;
        END IF;
        ids := ids || (e ->> 'id');
        typ := e ->> 'typ';
        IF jsonb_typeof(e -> 'typ') IS DISTINCT FROM 'string' OR typ <> ALL (ARRAY['zustand', 'alarme', 'sensoren', 'auslastung',
                'platten', 'prognose', 'alarme_je_tag', 'verfuegbarkeit', 'graph', 'sonne', 'ereignisse']) THEN
            RETURN false;
        END IF;
        -- Jede Art höchstens einmal, nur Graphen mehrfach.
        IF typ <> 'graph' AND typ = ANY (typen) THEN
            RETURN false;
        END IF;
        typen := typen || typ;
        IF jsonb_typeof(e -> 'groesse') IS DISTINCT FROM 'string' OR (e ->> 'groesse') <> ALL (ARRAY['klein', 'breit', 'hoch']) THEN
            RETURN false;
        END IF;
        IF e ? 'mandant_id' AND jsonb_typeof(e -> 'mandant_id') <> 'null'
           AND (jsonb_typeof(e -> 'mandant_id') <> 'string' OR (e ->> 'mandant_id') !~ uuid_re) THEN
            RETURN false;
        END IF;
        -- Gerät, Zeitraum und Wert nur beim Graphen; ein Gerät bestimmt den Mandanten selbst.
        IF e ? 'geraet_id' AND jsonb_typeof(e -> 'geraet_id') <> 'null' THEN
            IF typ <> 'graph' OR jsonb_typeof(e -> 'geraet_id') <> 'string' OR (e ->> 'geraet_id') !~ uuid_re
               OR (e ? 'mandant_id' AND jsonb_typeof(e -> 'mandant_id') <> 'null') THEN
                RETURN false;
            END IF;
        END IF;
        IF e ? 'zeitraum' AND jsonb_typeof(e -> 'zeitraum') <> 'null'
           AND (typ <> 'graph' OR jsonb_typeof(e -> 'zeitraum') <> 'string' OR (e ->> 'zeitraum') <> ALL (ARRAY['1h', '24h', '7t', '30t'])) THEN
            RETURN false;
        END IF;
        IF e ? 'wert' AND jsonb_typeof(e -> 'wert') <> 'null'
           AND (typ <> 'graph' OR jsonb_typeof(e -> 'wert') <> 'string' OR (e ->> 'wert') <> ALL (ARRAY['cpu', 'speicher'])) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END
$$;

CREATE TABLE openwacht.dashboard_layouts (
    user_id    uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    widgets    jsonb NOT NULL CONSTRAINT dashboard_layouts_widgets CHECK (openwacht.dashboard_widgets_valid(widgets)),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id, tenant_id) REFERENCES openwacht.users (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX dashboard_layouts_tenant ON openwacht.dashboard_layouts (tenant_id);

ALTER TABLE openwacht.dashboard_layouts ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT (user_id, tenant_id, widgets), UPDATE (widgets, updated_at), DELETE
    ON openwacht.dashboard_layouts TO openwacht_app;
CREATE POLICY dashboard_layouts_own ON openwacht.dashboard_layouts FOR ALL TO openwacht_app
    USING (user_id = openwacht.current_user_id())
    WITH CHECK (user_id = openwacht.current_user_id());
