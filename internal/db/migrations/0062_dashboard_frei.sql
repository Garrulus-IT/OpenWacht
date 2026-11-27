-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.7: Dashboard freier anpassbar.
--
-- - Jedes Widget hat eine freie Breite (2 bis 12 Spalten) und Höhe (1 bis 6
--   Reihen) statt nur „klein, breit, hoch“. Alte Layouts mit „groesse“ gelten
--   weiter; die Oberfläche rechnet sie um.
-- - Eigener Titel je Widget, jede Art beliebig oft.
-- - Mehrere Seiten je Benutzer (bis 8, mit Namen); das Widget nennt seine
--   Seite als Zahl ab 0.
-- - Neue Arten: zertifikate, wartung, uhr, notiz (mit Text), sensor (ein
--   Sensor, Schlüssel wie in /api/v1/sensoren).
--
-- Dieselben Regeln prüft die API (internal/zentrale/dashboard_layout.go). Ob
-- ein genannter Mandant oder ein Gerät sichtbar ist, prüft weiter nur die API;
-- der Sensor-Schlüssel ist ein reiner Anzeigefilter über Daten, die der
-- Benutzer ohnehin nur sieht, wenn RLS sie liefert.

CREATE OR REPLACE FUNCTION openwacht.dashboard_widgets_valid(w jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    e     jsonb;
    k     text;
    typ   text;
    ids   text[] := '{}';
    uuid_re constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    hat_groesse boolean;
    hat_mass    boolean;
BEGIN
    IF w IS NULL OR jsonb_typeof(w) <> 'array' OR jsonb_array_length(w) > 60 OR octet_length(w::text) > 32768 THEN
        RETURN false;
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(w) AS t(x) LOOP
        IF jsonb_typeof(e) <> 'object' THEN
            RETURN false;
        END IF;
        FOR k IN SELECT jsonb_object_keys(e) LOOP
            IF k <> ALL (ARRAY['id', 'typ', 'groesse', 'breite', 'hoehe', 'titel', 'seite', 'mandant_id', 'geraet_id',
                               'zeitraum', 'wert', 'text', 'sensor']) THEN
                RETURN false;
            END IF;
        END LOOP;
        IF jsonb_typeof(e -> 'id') IS DISTINCT FROM 'string' OR (e ->> 'id') !~ '^[a-z0-9]{4,16}$' OR (e ->> 'id') = ANY (ids) THEN
            RETURN false;
        END IF;
        ids := ids || (e ->> 'id');
        typ := e ->> 'typ';
        IF jsonb_typeof(e -> 'typ') IS DISTINCT FROM 'string' OR typ <> ALL (ARRAY['zustand', 'alarme', 'sensoren', 'auslastung',
                'platten', 'prognose', 'alarme_je_tag', 'verfuegbarkeit', 'graph', 'sonne', 'ereignisse',
                'zertifikate', 'wartung', 'uhr', 'notiz', 'sensor']) THEN
            RETURN false;
        END IF;
        -- Größe: alt „groesse“ oder neu Breite und Höhe (beide).
        hat_groesse := e ? 'groesse' AND jsonb_typeof(e -> 'groesse') <> 'null';
        hat_mass := (e ? 'breite' AND jsonb_typeof(e -> 'breite') <> 'null') OR (e ? 'hoehe' AND jsonb_typeof(e -> 'hoehe') <> 'null');
        IF hat_groesse AND (jsonb_typeof(e -> 'groesse') <> 'string' OR (e ->> 'groesse') <> ALL (ARRAY['klein', 'breit', 'hoch'])) THEN
            RETURN false;
        END IF;
        IF hat_mass THEN
            IF jsonb_typeof(e -> 'breite') IS DISTINCT FROM 'number' OR jsonb_typeof(e -> 'hoehe') IS DISTINCT FROM 'number'
               OR (e ->> 'breite') !~ '^[0-9]{1,2}$' OR (e ->> 'hoehe') !~ '^[0-9]$'
               OR (e ->> 'breite')::int NOT BETWEEN 2 AND 12 OR (e ->> 'hoehe')::int NOT BETWEEN 1 AND 6 THEN
                RETURN false;
            END IF;
        ELSIF NOT hat_groesse THEN
            RETURN false;
        END IF;
        IF e ? 'titel' AND jsonb_typeof(e -> 'titel') <> 'null'
           AND (jsonb_typeof(e -> 'titel') <> 'string' OR char_length(e ->> 'titel') NOT BETWEEN 1 AND 60
                OR (e ->> 'titel') ~ '[[:cntrl:]]') THEN
            RETURN false;
        END IF;
        IF e ? 'seite' AND jsonb_typeof(e -> 'seite') <> 'null'
           AND (jsonb_typeof(e -> 'seite') <> 'number' OR (e ->> 'seite') !~ '^[0-7]$') THEN
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
        -- Text nur an der Notiz (Zeilenumbrüche erlaubt, sonst keine Steuerzeichen).
        IF e ? 'text' AND jsonb_typeof(e -> 'text') <> 'null'
           AND (typ <> 'notiz' OR jsonb_typeof(e -> 'text') <> 'string' OR char_length(e ->> 'text') > 500
                OR replace(e ->> 'text', E'\n', '') ~ '[[:cntrl:]]') THEN
            RETURN false;
        END IF;
        IF e ? 'sensor' AND jsonb_typeof(e -> 'sensor') <> 'null'
           AND (typ <> 'sensor' OR jsonb_typeof(e -> 'sensor') <> 'string' OR char_length(e ->> 'sensor') NOT BETWEEN 3 AND 200
                OR (e ->> 'sensor') !~ '^[chs]:' OR (e ->> 'sensor') ~ '[[:cntrl:]]') THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END
$$;

-- Namen der Seiten: 0 bis 8 Texte mit 1 bis 40 Zeichen, ohne Steuerzeichen.
CREATE FUNCTION openwacht.dashboard_pages_valid(p jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    e jsonb;
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'array' OR jsonb_array_length(p) > 8 THEN
        RETURN false;
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(p) AS t(x) LOOP
        IF jsonb_typeof(e) <> 'string' OR char_length(e #>> '{}') NOT BETWEEN 1 AND 40 OR (e #>> '{}') ~ '[[:cntrl:]]' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END
$$;

ALTER TABLE openwacht.dashboard_layouts ADD COLUMN pages jsonb NOT NULL DEFAULT '[]'
    CONSTRAINT dashboard_layouts_pages CHECK (openwacht.dashboard_pages_valid(pages));
GRANT INSERT (pages), UPDATE (pages) ON openwacht.dashboard_layouts TO openwacht_app;
