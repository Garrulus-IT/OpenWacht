-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.1: Kennfarben für Vorlagensätze.
-- (A) Ein Eintrag eines eigenen Vorlagensatzes darf eine Kennfarbe tragen
--     (Schlüssel „kennfarbe“, UUID). Beim Anwenden bekommt der neue Sensor
--     die Farbe, wenn sie zum Mandanten des Geräts passt (kennfarbe_allowed).
-- (B) Die Kennfarbe aller Sensoren einer Herkunft lässt sich in einem Schritt
--     setzen; dafür reicht das bestehende UPDATE-Recht auf kennfarbe_id.

GRANT INSERT (kennfarbe_id) ON openwacht.checks TO openwacht_app;

CREATE OR REPLACE FUNCTION openwacht.valid_template_set_items(items jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(items) = 'array'
       AND jsonb_array_length(items) BETWEEN 1 AND 50
       AND octet_length(items::text) <= 262144
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(items) AS e(x)
            WHERE jsonb_typeof(x) <> 'object'
               OR NOT (x ?& ARRAY['name', 'typ', 'ziel', 'intervall_sekunden', 'notiz'])
               OR (SELECT count(*) FROM jsonb_object_keys(x)) <> 5 + (CASE WHEN x ? 'kennfarbe' THEN 1 ELSE 0 END)
               OR (x ? 'kennfarbe' AND (jsonb_typeof(x->'kennfarbe') <> 'string'
                   OR x->>'kennfarbe' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
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
