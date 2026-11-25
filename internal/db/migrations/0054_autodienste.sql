-- SPDX-License-Identifier: AGPL-3.0-only

-- 1.0.5: Sensorart „autodienste“ am Windows-Agent: Alle Dienste mit
-- Starttyp „Automatisch“ laufen. Der Agent meldet nur Namen gestoppter
-- Dienste und ihre Anzahl, kein Dienstkonto und keinen Pfad (Leitprinzip 5).
-- Gemessen wird nur, wenn die Art am Rechner freigegeben ist (Leitprinzip 1).
--
-- Die Liste der Arten steht ab jetzt an einer Stelle (is_check_kind); neue
-- Arten ersetzen künftig nur noch diese Funktion und is_agent_kind.

CREATE OR REPLACE FUNCTION openwacht.is_agent_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('dienst', 'prozess', 'datei', 'docker', 'hyperv', 'leistungsindikator', 'autodienste')
$$;

CREATE FUNCTION openwacht.is_check_kind(k text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT k IN ('ping', 'tcp', 'http', 'tls', 'dns', 'http_json', 'tcp_banner', 'ntp', 'snmp_oid')
        OR openwacht.is_agent_kind(k)
$$;

ALTER TABLE openwacht.checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE openwacht.checks ADD CONSTRAINT checks_kind_check CHECK (openwacht.is_check_kind(kind));
ALTER TABLE openwacht.sensor_templates DROP CONSTRAINT sensor_templates_kind_check;
ALTER TABLE openwacht.sensor_templates ADD CONSTRAINT sensor_templates_kind_check CHECK (openwacht.is_check_kind(kind));

-- Einträge eigener Vorlagensätze: wie 0051, Arten aus is_check_kind.
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
               OR NOT openwacht.is_check_kind(x->>'typ')
               OR jsonb_typeof(x->'ziel') <> 'object'
               OR jsonb_typeof(x->'intervall_sekunden') <> 'number'
               OR (x->>'intervall_sekunden') !~ '^[0-9]{1,5}$'
               OR (x->>'intervall_sekunden')::integer NOT BETWEEN 30 AND 86400
               OR (openwacht.is_agent_kind(x->>'typ') AND (x->>'intervall_sekunden')::integer < 60))
       AND (SELECT count(DISTINCT lower(e->>'name')) FROM jsonb_array_elements(items) AS a(e)) = jsonb_array_length(items)
$$;
