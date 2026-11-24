-- SPDX-License-Identifier: AGPL-3.0-only

-- Lasttest, zweiter Teil (Etappe 35): einen ganzen Tag hochrechnen.
--
-- Voraussetzung: TestLast lief mindestens 30 Minuten unter Last. Dieses
-- Skript (als Eigentümer der Datenbank, nie im Betrieb!) vervielfältigt die
-- Rohwerte der letzten 30 Minuten auf 24 Stunden, die verdichteten Werte auf
-- 30 Tage (5 Minuten) und 365 Tage (Stunden), und misst dann:
--   - Größe einer Tagespartition der Rohwerte und der verdichteten Tabellen
--   - Dauer von metrics_maintain() für einen normalen Lauf und für das
--     Nachholen eines ganzen Tages (z. B. nach einem Ausfall der Zentrale)
--
--   psql "$EIGENTUEMER" -v ON_ERROR_STOP=1 -f tools/lasttest/tag.sql

\timing on
SET search_path = openwacht, pg_catalog;

-- Ausgangslage
SELECT 'roh je Minute' AS was,
       (SELECT count(*) FROM metrics_host_raw WHERE ts > now() - interval '30 minutes') / 30 AS host,
       (SELECT count(*) FROM metrics_snmp_raw WHERE ts > now() - interval '30 minutes') / 30 AS snmp,
       (SELECT count(*) FROM metrics_check_raw WHERE ts > now() - interval '30 minutes') / 30 AS checks;

-- 1. Rohwerte: 30 Minuten 47-mal nach hinten kopieren (= 24 Stunden).
SELECT metrics_maintain();
CREATE TEMP TABLE w AS SELECT now() - interval '30 minutes' AS von, now() AS bis;
INSERT INTO metrics_host_raw (tenant_id, agent_id, ts, series, value)
SELECT r.tenant_id, r.agent_id, r.ts - k * interval '30 minutes', r.series, r.value
  FROM metrics_host_raw r, w, generate_series(1, 47) k WHERE r.ts >= w.von AND r.ts < w.bis;
INSERT INTO metrics_snmp_raw (tenant_id, snmp_id, ts, series, value)
SELECT r.tenant_id, r.snmp_id, r.ts - k * interval '30 minutes', r.series, r.value
  FROM metrics_snmp_raw r, w, generate_series(1, 47) k WHERE r.ts >= w.von AND r.ts < w.bis;

-- 2. Den Tag neu verdichten lassen: Stand zurücksetzen und messen.
DELETE FROM metrics_host_5m WHERE bucket >= now() - interval '25 hours';
DELETE FROM metrics_snmp_5m WHERE bucket >= now() - interval '25 hours';
DELETE FROM metrics_host_1h WHERE bucket >= now() - interval '25 hours';
DELETE FROM metrics_snmp_1h WHERE bucket >= now() - interval '25 hours';
UPDATE metrics_rollup_state SET done_until = date_bin('1 hour', now() - interval '24 hours', timestamptz 'epoch');
SELECT 'Nachholen 24 Std.' AS was, metrics_maintain() AS bloecke;
-- normaler Lauf: die letzten 5 Minuten
UPDATE metrics_rollup_state SET done_until = done_until - interval '5 minutes' WHERE tier = '5m';
SELECT 'normaler Lauf' AS was, metrics_maintain() AS bloecke;

-- 3. Verdichtete Werte für 7 Tage (5 Minuten) und 30 Tage (Stunden); mehr
--    passt nicht in die Testumgebung, die Größen für 30 bzw. 365 Tage rechnet
--    Kapitel 16 linear hoch (die Tabellen wachsen je Tag gleich).
INSERT INTO metrics_host_5m SELECT m.tenant_id, m.agent_id, m.bucket - k * interval '1 day', m.series, m.avg, m.min, m.max, m.n
  FROM metrics_host_5m m, generate_series(1, 6) k WHERE m.bucket > now() - interval '24 hours' ON CONFLICT DO NOTHING;
INSERT INTO metrics_snmp_5m SELECT m.tenant_id, m.snmp_id, m.bucket - k * interval '1 day', m.series, m.avg, m.min, m.max, m.n
  FROM metrics_snmp_5m m, generate_series(1, 6) k WHERE m.bucket > now() - interval '24 hours' ON CONFLICT DO NOTHING;
INSERT INTO metrics_host_1h SELECT m.tenant_id, m.agent_id, m.bucket - k * interval '1 day', m.series, m.avg, m.min, m.max, m.n
  FROM metrics_host_1h m, generate_series(1, 29) k WHERE m.bucket > now() - interval '24 hours' ON CONFLICT DO NOTHING;
INSERT INTO metrics_snmp_1h SELECT m.tenant_id, m.snmp_id, m.bucket - k * interval '1 day', m.series, m.avg, m.min, m.max, m.n
  FROM metrics_snmp_1h m, generate_series(1, 29) k WHERE m.bucket > now() - interval '24 hours' ON CONFLICT DO NOTHING;
VACUUM ANALYZE metrics_host_5m, metrics_snmp_5m, metrics_host_1h, metrics_snmp_1h;

-- normaler Lauf mit vollem Verlauf (Aufräumen über den Index)
UPDATE metrics_rollup_state SET done_until = done_until - interval '5 minutes' WHERE tier = '5m';
SELECT 'normaler Lauf, voller Verlauf' AS was, metrics_maintain() AS bloecke;

-- 4. Größen (je Tag: 5 Minuten / 7, Stunden / 30)
SELECT c.relname AS tabelle, pg_size_pretty(pg_total_relation_size(c.oid)) AS groesse, c.reltuples::bigint AS zeilen_ca
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'openwacht' AND c.relkind IN ('r', 'p') AND c.relname LIKE 'metrics%'
   AND pg_total_relation_size(c.oid) > 1024 * 1024
 ORDER BY pg_total_relation_size(c.oid) DESC;
SELECT pg_size_pretty(pg_database_size(current_database())) AS datenbank;
