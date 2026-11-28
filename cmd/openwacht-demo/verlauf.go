// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Verlauf für die Demo: Wer die Demo öffnet, soll Graphen über Tage sehen,
// nicht nur die Minuten seit dem Start. Fehlt Verlauf (erster Besuch oder
// Wiederkehr nach Tagen), schreibt lueckeFuellen ihn rückwärts aus den
// zuletzt gemeldeten Werten fort: dieselben Reihen, mit Tagesgang und etwas
// Rauschen, Platten mit ihrem Zuwachs. Danach verdichtet die echte Wartung
// (metrics_maintain) ihn wie im Betrieb. Nur die Demo, nie im Betrieb.
//
// Läuft als Eigentümer des Schemas (demo_owner), damit Partitionen und Zeilen
// wie die der Wartung gehören; danach wieder als Rolle des Servers.

// Damit das im Browser schnell geht, entstehen nur so viele Werte, wie die
// Ansichten zeigen, gleich in der Stufe, aus der sie lesen: Rohwerte alle fünf
// Minuten für den letzten Tag (Ansicht 24 Stunden), Fünf-Minuten-Stufe alle
// 30 Minuten für sieben Tage, Stunden-Stufe alle zwei Stunden für 30 Tage.
// Die Wartung macht danach ab „jetzt“ weiter.
const lueckeSQL = `
DO $demo$
DECLARE
    v_jetzt timestamptz := now();
    v_bis5  timestamptz := date_bin('5 minutes', now(), timestamptz 'epoch');
    v_bis1  timestamptz := date_bin('1 hour', now(), timestamptz 'epoch');
    v_von   timestamptz;
    d       date;
    tbl     text;
BEGIN
    -- Ende des bisherigen Verlaufs (Wiederkehr nach einem früheren Besuch);
    -- beim ersten Besuch gibt es nur die Werte der ersten Sekunden.
    SELECT max(ts) INTO v_von FROM openwacht.metrics_host_raw WHERE ts < v_jetzt - interval '10 minutes';
    v_von := coalesce(v_von, v_jetzt - interval '31 days');
    IF v_von >= v_jetzt - interval '15 minutes' THEN
        RETURN;
    END IF;
    FOR d IN SELECT generate_series(greatest(v_von, v_jetzt - interval '1 day')::date - 1, v_jetzt::date + 2, interval '1 day')::date LOOP
        FOREACH tbl IN ARRAY ARRAY['metrics_host_raw', 'metrics_check_raw', 'metrics_snmp_raw'] LOOP
            IF to_regclass(format('openwacht.%I', tbl || '_' || to_char(d, 'YYYYMMDD'))) IS NULL THEN
                EXECUTE format('CREATE TABLE openwacht.%I PARTITION OF openwacht.%I FOR VALUES FROM (%L) TO (%L)',
                               tbl || '_' || to_char(d, 'YYYYMMDD'), tbl, d::timestamptz, (d + 1)::timestamptz);
            END IF;
        END LOOP;
    END LOOP;

    -- Zeitpunkte je Stufe ('h' Stunden-, 'm' Fünf-Minuten-Stufe, 'r' roh)
    CREATE TEMP TABLE demo_zeit ON COMMIT DROP AS
    SELECT 'h'::text AS stufe, t AS ts
      FROM generate_series(date_bin('2 hours', greatest(v_von, v_bis1 - interval '30 days'), timestamptz 'epoch') + interval '2 hours',
                           v_bis1 - interval '1 hour', interval '2 hours') t
    UNION ALL
    SELECT 'm', t
      FROM generate_series(date_bin('30 minutes', greatest(v_von, v_bis5 - interval '7 days'), timestamptz 'epoch') + interval '30 minutes',
                           v_bis5 - interval '5 minutes', interval '30 minutes') t
    UNION ALL
    SELECT 'r', t
      FROM generate_series(date_bin('5 minutes', greatest(v_von, v_jetzt - interval '1 day'), timestamptz 'epoch') + interval '5 minutes',
                           v_jetzt - interval '1 minute', interval '5 minutes') t;
    -- Tagesgang 0 … 1 (nachts wenig, nachmittags viel)
    CREATE TEMP TABLE demo_gang ON COMMIT DROP AS
    SELECT stufe, ts, 0.5 - 0.5 * cos(radians((extract(hour FROM ts AT TIME ZONE 'Europe/Berlin') - 3) * 15)) AS g FROM demo_zeit;

    -- Agents: letzte Werte je Reihe, rückwärts mit Tagesgang
    CREATE TEMP TABLE demo_host ON COMMIT DROP AS
    SELECT l.tenant_id, l.agent_id, z.stufe, z.ts, l.series,
           CASE
             -- Platten wachsen langsam, fast volle (wie D: auf srv-file01) schneller
             WHEN l.series LIKE 'platte:%' THEN greatest(0, l.value - extract(epoch FROM (v_jetzt - z.ts)) / 86400
                    * CASE WHEN l.value > 85 THEN 0.6 ELSE 0.05 END)
             WHEN l.series = 'cpu' THEN least(100, l.value * (0.55 + 0.9 * z.g) * (0.9 + 0.2 * random()))
             WHEN l.series = 'last1' THEN l.value * (0.55 + 0.9 * z.g) * (0.9 + 0.2 * random())
             ELSE least(1e6, l.value * (0.97 + 0.06 * random()))
           END AS value
      FROM (SELECT DISTINCT ON (agent_id, series) tenant_id, agent_id, series, value
              FROM openwacht.metrics_host_raw ORDER BY agent_id, series, ts DESC) l
     CROSS JOIN demo_gang z;
    INSERT INTO openwacht.metrics_host_raw (tenant_id, agent_id, ts, series, value)
    SELECT tenant_id, agent_id, ts, series, value FROM demo_host WHERE stufe = 'r';
    INSERT INTO openwacht.metrics_host_5m (tenant_id, agent_id, bucket, series, avg, min, max, n)
    SELECT tenant_id, agent_id, ts, series, value, value * 0.9, least(1e6, value * 1.1), 5 FROM demo_host WHERE stufe = 'm'
    ON CONFLICT DO NOTHING;
    INSERT INTO openwacht.metrics_host_1h (tenant_id, agent_id, bucket, series, avg, min, max, n)
    SELECT tenant_id, agent_id, ts, series, value, value * 0.8, least(1e6, value * 1.25), 60 FROM demo_host WHERE stufe = 'h'
    ON CONFLICT DO NOTHING;

    -- Sensoren: Zustand wie zuletzt, Antwortzeit mit Rauschen
    CREATE TEMP TABLE demo_check ON COMMIT DROP AS
    SELECT l.tenant_id, l.check_id, z.stufe, z.ts, l.status,
           CASE WHEN l.ms IS NULL THEN NULL ELSE least(600000, l.ms * (0.7 + 0.6 * random())) END AS ms
      FROM (SELECT DISTINCT ON (check_id) tenant_id, check_id, status, ms
              FROM openwacht.metrics_check_raw ORDER BY check_id, ts DESC) l
     CROSS JOIN demo_zeit z;
    INSERT INTO openwacht.metrics_check_raw (tenant_id, check_id, ts, status, ms)
    SELECT tenant_id, check_id, ts, status, ms FROM demo_check WHERE stufe = 'r';
    INSERT INTO openwacht.metrics_check_5m (tenant_id, check_id, bucket, n, n_ok, worst, ms_n, ms_avg, ms_min, ms_max)
    SELECT tenant_id, check_id, ts, 5, CASE WHEN status = 'ok' THEN 5 ELSE 0 END, status,
           CASE WHEN ms IS NULL THEN 0 ELSE 5 END, ms, ms * 0.8, least(600000, ms * 1.3)
      FROM demo_check WHERE stufe = 'm'
    ON CONFLICT DO NOTHING;
    INSERT INTO openwacht.metrics_check_1h (tenant_id, check_id, bucket, n, n_ok, worst, ms_n, ms_avg, ms_min, ms_max)
    SELECT tenant_id, check_id, ts, 60, CASE WHEN status = 'ok' THEN 60 ELSE 0 END, status,
           CASE WHEN ms IS NULL THEN 0 ELSE 60 END, ms, ms * 0.7, least(600000, ms * 1.6)
      FROM demo_check WHERE stufe = 'h'
    ON CONFLICT DO NOTHING;

    -- Abfragequellen (SNMP, Proxmox, FRITZ!Box …)
    CREATE TEMP TABLE demo_snmp ON COMMIT DROP AS
    SELECT l.tenant_id, l.snmp_id, z.stufe, z.ts, l.series,
           least(1e13, CASE
             WHEN l.series LIKE 'if_%' OR l.series IN ('cpu', 'dsl_ab', 'dsl_auf') THEN greatest(0, l.value
                    * (0.35 + 1.1 * z.g) * (0.85 + 0.3 * random()))
             ELSE l.value * (0.99 + 0.02 * random())
           END) AS value
      FROM (SELECT DISTINCT ON (snmp_id, series) tenant_id, snmp_id, series, value
              FROM openwacht.metrics_snmp_raw ORDER BY snmp_id, series, ts DESC) l
     CROSS JOIN demo_gang z;
    INSERT INTO openwacht.metrics_snmp_raw (tenant_id, snmp_id, ts, series, value)
    SELECT tenant_id, snmp_id, ts, series, value FROM demo_snmp WHERE stufe = 'r';
    INSERT INTO openwacht.metrics_snmp_5m (tenant_id, snmp_id, bucket, series, avg, min, max, n)
    SELECT tenant_id, snmp_id, ts, series, value, value * 0.9, least(1e13, value * 1.1), 5 FROM demo_snmp WHERE stufe = 'm'
    ON CONFLICT DO NOTHING;
    INSERT INTO openwacht.metrics_snmp_1h (tenant_id, snmp_id, bucket, series, avg, min, max, n)
    SELECT tenant_id, snmp_id, ts, series, value, value * 0.8, least(1e13, value * 1.25), 60 FROM demo_snmp WHERE stufe = 'h'
    ON CONFLICT DO NOTHING;

    -- Die Wartung verdichtet ab hier weiter.
    UPDATE openwacht.metrics_rollup_state SET done_until = greatest(done_until, v_bis5) WHERE tier = '5m';
    UPDATE openwacht.metrics_rollup_state SET done_until = greatest(done_until, v_bis1) WHERE tier = '1h';
END
$demo$;`

// lueckeFuellen: Verlauf bis jetzt ergänzen (siehe oben), danach verdichten.
// Rollenwechsel, Ergänzen und Rückwechsel gehen als eine einzige Nachricht an
// PGlite: Mehrere Verbindungen teilen sich dort ein Backend, keine andere
// Anfrage darf dazwischen als Eigentümer laufen. Schlägt etwas fehl, nimmt
// PostgreSQL auch den Rollenwechsel zurück (eine implizite Transaktion).
func lueckeFuellen(ctx context.Context, pool *pgxpool.Pool, rolle string) error {
	start := time.Now()
	r := pgx.Identifier{rolle}.Sanitize()
	if _, err := pool.Exec(ctx, "SET ROLE demo_owner;\n"+lueckeSQL+"\nSET ROLE "+r); err != nil {
		return fmt.Errorf("Verlauf: %w", err)
	}
	if _, err := pool.Exec(ctx, `SELECT openwacht.metrics_maintain()`); err != nil {
		return fmt.Errorf("Verlauf verdichten: %w", err)
	}
	logDauer("Verlauf ergänzt", start)
	return nil
}
