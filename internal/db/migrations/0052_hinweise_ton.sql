-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.2: Hinweise am Rand und Ton bei neuen Ereignissen.
-- Je Benutzer (nur das eigene Konto, über set_alarm_ui) und je Wandanzeige
-- (Admins des Mandanten der Anzeige). Gespeichert als kleines JSON-Objekt mit
-- festen Schlüsseln; die Klänge erzeugt der Browser selbst (keine Dateien).
--   hinweise    boolean   Hinweise am Rand zeigen (nur Benutzer)
--   ton         text      'aus' | 'krit' (nur kritisch) | 'warn' (Warnung und kritisch)
--   klang       text      'bling' | 'gong' | 'doppel'
--   lautstaerke integer   0 … 100
--   entwarnung  boolean   leiser Ton bei Entwarnung

CREATE FUNCTION openwacht.valid_alarm_ui(v jsonb, p_user boolean) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(v) = 'object'
       AND (SELECT count(*) FROM jsonb_object_keys(v)) = CASE WHEN p_user THEN 5 ELSE 4 END
       AND v ?& ARRAY['ton', 'klang', 'lautstaerke', 'entwarnung']
       AND (NOT p_user OR (v ? 'hinweise' AND jsonb_typeof(v->'hinweise') = 'boolean'))
       AND jsonb_typeof(v->'ton') = 'string' AND v->>'ton' IN ('aus', 'krit', 'warn')
       AND jsonb_typeof(v->'klang') = 'string' AND v->>'klang' IN ('bling', 'gong', 'doppel')
       AND jsonb_typeof(v->'lautstaerke') = 'number' AND (v->>'lautstaerke') ~ '^[0-9]{1,3}$'
       AND (v->>'lautstaerke')::integer BETWEEN 0 AND 100
       AND jsonb_typeof(v->'entwarnung') = 'boolean'
$$;

ALTER TABLE openwacht.users ADD COLUMN alarm_ui jsonb NOT NULL
    DEFAULT '{"hinweise": true, "ton": "aus", "klang": "bling", "lautstaerke": 60, "entwarnung": false}'
    CHECK (openwacht.valid_alarm_ui(alarm_ui, true));
GRANT SELECT (alarm_ui) ON openwacht.users TO openwacht_app;

CREATE FUNCTION openwacht.set_alarm_ui(p_value jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
DECLARE
    uid uuid := openwacht.current_user_id();
BEGIN
    IF uid IS NULL OR p_value IS NULL THEN
        RAISE EXCEPTION 'set_alarm_ui: kein Benutzer' USING ERRCODE = '42501';
    END IF;
    UPDATE openwacht.users SET alarm_ui = p_value WHERE id = uid;
END
$$;
REVOKE ALL ON FUNCTION openwacht.set_alarm_ui(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.set_alarm_ui(jsonb) TO openwacht_app;

-- Wandanzeige: ab Werk nur bei kritisch (der Ton klingt erst nach einem
-- Klick am Bildschirm, weil Browser sonst nichts abspielen).
ALTER TABLE openwacht.displays ADD COLUMN sound jsonb NOT NULL
    DEFAULT '{"ton": "krit", "klang": "bling", "lautstaerke": 70, "entwarnung": false}'
    CHECK (openwacht.valid_alarm_ui(sound, false));
GRANT SELECT (sound), UPDATE (sound) ON openwacht.displays TO openwacht_app;

-- Für die Anzeige selbst (ohne Benutzersitzung): nur der eigene Ton, nie der
-- einer anderen Anzeige (die Kennung kommt aus dem Transaktionskontext).
CREATE FUNCTION openwacht.display_sound() RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, openwacht AS $$
    SELECT d.sound FROM openwacht.displays d
     WHERE d.id = openwacht.current_display_id() AND openwacht.current_user_id() IS NULL
$$;
REVOKE ALL ON FUNCTION openwacht.display_sound() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openwacht.display_sound() TO openwacht_app;
