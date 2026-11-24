// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Graphen für die Übersicht (Dashboard) über alle sichtbaren Geräte:
//
//   GET /api/v1/dashboard/verlauf?zeitraum=…   CPU und Arbeitsspeicher der
//       Hosts mit der höchsten mittleren Auslastung (Agent und SNMP gemischt)
//   GET /api/v1/dashboard/kennzahlen           Alarme je Stunde der letzten
//       30 Tage und Verfügbarkeit (7 und 30 Tage) je Check und je Gerät
//
// Mandantentrennung: RLS auf allen gelesenen Tabellen; der Filter
// „mandanten“ grenzt nur ein (wie bei der Prognose).
//
// Grenzen (Entscheidung Etappe 10): höchstens dashTopN Linien je
// Graph, die übrigen zählt „gesamt“; höchstens dashMaxRows Einträge in den
// Verfügbarkeitslisten.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	dashTopN    = 8
	dashMaxRows = 1000
)

// fleetSeriesSQL: eine Reihe (cpu oder speicher) aller sichtbaren Agents und
// SNMP-Quellen, nur für die dashTopN mit dem höchsten Mittel im Zeitraum.
// $1 Mandanten, $2 Spanne, $3 Stufe, $4 Schritt, $5 Reihe, $6 Anzahl.
var fleetSeriesSQL = strings.NewReplacer("{tenants}", "($1::uuid[] IS NULL OR x.tenant_id = ANY ($1))").Replace(`
WITH w AS (
    SELECT now() - $2::interval AS von,
           CASE $3 WHEN '5m' THEN done_5m WHEN '1h' THEN done_1h ELSE now() - $2::interval END AS wm
      FROM openwacht.metrics_watermarks()
), src AS (
    SELECT 'host'::text AS art, r.agent_id AS q, r.ts AS t, r.value AS av, r.value AS mi, r.value AS ma, 1::bigint AS n
      FROM openwacht.metrics_host_raw r JOIN openwacht.agents x ON x.id = r.agent_id, w
     WHERE x.revoked_at IS NULL AND {tenants} AND r.series = $5 AND r.ts >= greatest(w.von, w.wm)
    UNION ALL
    SELECT 'host', m.agent_id, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM openwacht.metrics_host_5m m JOIN openwacht.agents x ON x.id = m.agent_id, w
     WHERE $3 = '5m' AND x.revoked_at IS NULL AND {tenants} AND m.series = $5 AND m.bucket >= w.von AND m.bucket < w.wm
    UNION ALL
    SELECT 'host', m.agent_id, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM openwacht.metrics_host_1h m JOIN openwacht.agents x ON x.id = m.agent_id, w
     WHERE $3 = '1h' AND x.revoked_at IS NULL AND {tenants} AND m.series = $5 AND m.bucket >= w.von AND m.bucket < w.wm
    UNION ALL
    SELECT 'snmp', r.snmp_id, r.ts, r.value, r.value, r.value, 1::bigint
      FROM openwacht.metrics_snmp_raw r JOIN openwacht.snmp_sources x ON x.id = r.snmp_id, w
     WHERE x.enabled AND {tenants} AND r.series = $5 AND r.ts >= greatest(w.von, w.wm)
    UNION ALL
    SELECT 'snmp', m.snmp_id, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM openwacht.metrics_snmp_5m m JOIN openwacht.snmp_sources x ON x.id = m.snmp_id, w
     WHERE $3 = '5m' AND x.enabled AND {tenants} AND m.series = $5 AND m.bucket >= w.von AND m.bucket < w.wm
    UNION ALL
    SELECT 'snmp', m.snmp_id, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM openwacht.metrics_snmp_1h m JOIN openwacht.snmp_sources x ON x.id = m.snmp_id, w
     WHERE $3 = '1h' AND x.enabled AND {tenants} AND m.series = $5 AND m.bucket >= w.von AND m.bucket < w.wm
), agg AS (
    SELECT art, q, date_bin($4::interval, t, timestamptz 'epoch') AS b, sum(av * n) / sum(n) AS av, min(mi) AS mi, max(ma) AS ma
      FROM src GROUP BY 1, 2, 3
), rk AS (
    SELECT art, q, avg(av) AS m, count(*) OVER () AS total FROM agg GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT $6
)
SELECT rk.art, rk.q::text, rk.total, dev.id::text, dev.name, dev.tenant_id::text,
       extract(epoch FROM agg.b)::double precision, agg.av, agg.mi, agg.ma
  FROM rk JOIN agg USING (art, q)
  LEFT JOIN openwacht.agents a ON rk.art = 'host' AND a.id = rk.q
  LEFT JOIN openwacht.snmp_sources s ON rk.art = 'snmp' AND s.id = rk.q
  JOIN openwacht.devices dev ON dev.id = coalesce(a.device_id, s.device_id)
 ORDER BY rk.m DESC, rk.art, rk.q, agg.b`)

type fleetLineOut struct {
	Art       string       `json:"art"`
	QuelleID  string       `json:"quelle_id"`
	GeraetID  string       `json:"geraet_id"`
	Geraet    string       `json:"geraet"`
	MandantID string       `json:"mandant_id"`
	Punkte    [][4]float64 `json:"punkte"`
}

type fleetOut struct {
	// Gesamt: so viele Quellen haben Werte im Zeitraum; Linien zeigt die
	// höchsten dashTopN davon.
	Gesamt int            `json:"gesamt"`
	Linien []fleetLineOut `json:"linien"`
}

func fleetSeries(ctx context.Context, tx pgx.Tx, tenants []string, p period, series string, top int) (fleetOut, error) {
	out := fleetOut{Linien: []fleetLineOut{}}
	rows, err := tx.Query(ctx, fleetSeriesSQL, tenants, interval(p.span), p.tier, interval(p.step), series, top)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var l fleetLineOut
		var total int
		var t, av, mi, ma float64
		if err := rows.Scan(&l.Art, &l.QuelleID, &total, &l.GeraetID, &l.Geraet, &l.MandantID, &t, &av, &mi, &ma); err != nil {
			return out, err
		}
		out.Gesamt = total
		if n := len(out.Linien); n == 0 || out.Linien[n-1].Art != l.Art || out.Linien[n-1].QuelleID != l.QuelleID {
			out.Linien = append(out.Linien, l)
		}
		last := &out.Linien[len(out.Linien)-1]
		last.Punkte = append(last.Punkte, [4]float64{t, round2(av), round2(mi), round2(ma)})
	}
	return out, rows.Err()
}

func (s *Server) handleDashboardHistory(w http.ResponseWriter, r *http.Request) {
	tenants, ok := tenantFilter(w, r)
	if !ok {
		return
	}
	name, p, ok := parsePeriod(w, r)
	if !ok {
		return
	}
	s.handle(w, r, "dashboard verlauf", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		cpu, err := fleetSeries(ctx, tx, tenants, p, "cpu", dashTopN)
		if err != nil {
			return 0, nil, err
		}
		mem, err := fleetSeries(ctx, tx, tenants, p, "speicher", dashTopN)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"zeitraum": name, "spanne_s": int(p.span.Seconds()),
			"schritt_s": int(p.step.Seconds()), "cpu": cpu, "speicher": mem}, nil
	})
}

// --- Kennzahlen -------------------------------------------------------------------------

// alarmsPerHourSQL: begonnene Alarme je Stunde der letzten 30 Tage, nach dem
// schlimmsten Zustand. Die Oberfläche fasst sie zu Tagen ihrer Zeitzone zusammen.
const alarmsPerHourSQL = `
SELECT extract(epoch FROM date_bin('1 hour', started_at, timestamptz 'epoch'))::double precision,
       count(*) FILTER (WHERE worst = 'warn'), count(*) FILTER (WHERE worst = 'crit'), count(*) FILTER (WHERE worst = 'unknown')
  FROM openwacht.alarms
 WHERE started_at >= now() - interval '30 days' AND ($1::uuid[] IS NULL OR tenant_id = ANY ($1))
 GROUP BY 1 ORDER BY 1`

// checkAvailabilitySQL: Anteil erfolgreicher Prüfungen je Check über 7 und 30
// Tage (Stundenstufe plus Rohdaten seit der letzten Verdichtung).
const checkAvailabilitySQL = `
WITH w AS (SELECT done_1h FROM openwacht.metrics_watermarks()), src AS (
    SELECT m.check_id, m.bucket AS t, m.n::bigint AS n, m.n_ok::bigint AS n_ok
      FROM openwacht.metrics_check_1h m, w WHERE m.bucket >= now() - interval '30 days' AND m.bucket < w.done_1h
    UNION ALL
    SELECT r.check_id, r.ts, 1, (r.status = 'ok')::int
      FROM openwacht.metrics_check_raw r, w WHERE r.ts >= greatest(w.done_1h, now() - interval '30 days')
)
SELECT c.id::text, c.name, c.tenant_id::text, d.id::text, d.name,
       coalesce(sum(src.n) FILTER (WHERE src.t >= now() - interval '7 days'), 0),
       coalesce(sum(src.n_ok) FILTER (WHERE src.t >= now() - interval '7 days'), 0),
       coalesce(sum(src.n), 0), coalesce(sum(src.n_ok), 0)
  FROM openwacht.checks c JOIN openwacht.devices d ON d.id = c.device_id
  LEFT JOIN src ON src.check_id = c.id
 WHERE ($1::uuid[] IS NULL OR c.tenant_id = ANY ($1))
 GROUP BY c.id, c.name, c.tenant_id, d.id, d.name
 ORDER BY lower(d.name), lower(c.name), c.id
 LIMIT $2`

// reachabilitySQL: Erreichbarkeit der Agents und SNMP-Quellen: Anteil der
// Zeitblöcke mit Messwerten (Agent: 5 Minuten, SNMP: Abfrageintervall,
// mindestens 5 Minuten) seit Beginn des Zeitraums bzw. seit der Anlage.
const reachabilitySQL = `
WITH w AS (SELECT done_5m FROM openwacht.metrics_watermarks()), q AS (
    SELECT 'host'::text AS art, a.id, a.tenant_id, a.device_id, a.created_at, 300 AS width
      FROM openwacht.agents a WHERE a.revoked_at IS NULL AND ($1::uuid[] IS NULL OR a.tenant_id = ANY ($1))
    UNION ALL
    SELECT 'snmp', s.id, s.tenant_id, s.device_id, s.created_at, greatest(300, s.interval_s)
      FROM openwacht.snmp_sources s WHERE s.enabled AND ($1::uuid[] IS NULL OR s.tenant_id = ANY ($1))
), b AS (
    SELECT m.agent_id AS id, m.bucket AS t FROM openwacht.metrics_host_5m m, w
     WHERE m.series = 'cpu' AND m.bucket >= now() - interval '30 days' AND m.bucket < w.done_5m
    UNION ALL
    SELECT r.agent_id, r.ts FROM openwacht.metrics_host_raw r, w
     WHERE r.series = 'cpu' AND r.ts >= greatest(w.done_5m, now() - interval '30 days')
    UNION ALL
    SELECT m.snmp_id, m.bucket FROM openwacht.metrics_snmp_5m m, w
     WHERE m.bucket >= now() - interval '30 days' AND m.bucket < w.done_5m
    UNION ALL
    SELECT r.snmp_id, r.ts FROM openwacht.metrics_snmp_raw r, w
     WHERE r.ts >= greatest(w.done_5m, now() - interval '30 days')
), seen AS (
    SELECT q.art, q.id, date_bin(make_interval(secs => q.width), b.t, timestamptz 'epoch') AS blk
      FROM q JOIN b ON b.id = q.id GROUP BY 1, 2, 3
)
SELECT q.art, q.id::text, q.tenant_id::text, d.id::text, d.name, q.width,
       extract(epoch FROM now() - greatest(q.created_at, now() - interval '7 days'))::double precision,
       extract(epoch FROM now() - greatest(q.created_at, now() - interval '30 days'))::double precision,
       count(seen.blk) FILTER (WHERE seen.blk >= now() - interval '7 days'), count(seen.blk)
  FROM q JOIN openwacht.devices d ON d.id = q.device_id
  LEFT JOIN seen ON seen.art = q.art AND seen.id = q.id
 GROUP BY q.art, q.id, q.tenant_id, d.id, d.name, q.width, q.created_at
 ORDER BY lower(d.name), q.art, q.id
 LIMIT $2`

type alarmHourOut struct {
	Zeit    float64 `json:"t"`
	Warn    int     `json:"warn"`
	Crit    int     `json:"crit"`
	Unknown int     `json:"unknown"`
}

type checkAvailOut struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	MandantID string   `json:"mandant_id"`
	GeraetID  string   `json:"geraet_id"`
	Geraet    string   `json:"geraet"`
	Tage7     *float64 `json:"tage7"` // Prozent OK, nil = keine Prüfungen
	Tage30    *float64 `json:"tage30"`
	N30       int64    `json:"pruefungen30"`
}

type reachOut struct {
	Art       string   `json:"art"`
	QuelleID  string   `json:"quelle_id"`
	MandantID string   `json:"mandant_id"`
	GeraetID  string   `json:"geraet_id"`
	Geraet    string   `json:"geraet"`
	Tage7     *float64 `json:"tage7"` // Prozent der Zeitblöcke mit Werten
	Tage30    *float64 `json:"tage30"`
}

func percent(part, whole int64) *float64 {
	if whole <= 0 {
		return nil
	}
	v := round2(min(100, float64(part)/float64(whole)*100))
	return &v
}

// coverage: Anteil der Blöcke mit Werten an den erwarteten Blöcken einer
// Zeitspanne (Sekunden). Ein angefangener Block zählt mit, damit eine eben
// angelegte Quelle nicht unter 100 % fällt.
func coverage(seen int64, spanSec float64, width int) *float64 {
	if spanSec <= 0 || width <= 0 {
		return nil
	}
	expected := int64(spanSec/float64(width)) + 1
	return percent(seen, expected)
}

func (s *Server) handleDashboardFigures(w http.ResponseWriter, r *http.Request) {
	tenants, ok := tenantFilter(w, r)
	if !ok {
		return
	}
	s.handle(w, r, "dashboard kennzahlen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, alarmsPerHourSQL, tenants)
		if err != nil {
			return 0, nil, err
		}
		alarms, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (alarmHourOut, error) {
			var a alarmHourOut
			err := row.Scan(&a.Zeit, &a.Warn, &a.Crit, &a.Unknown)
			return a, err
		})
		if err != nil {
			return 0, nil, err
		}
		rows, err = tx.Query(ctx, checkAvailabilitySQL, tenants, dashMaxRows+1)
		if err != nil {
			return 0, nil, err
		}
		checks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (checkAvailOut, error) {
			var c checkAvailOut
			var n7, ok7, n30, ok30 int64
			err := row.Scan(&c.ID, &c.Name, &c.MandantID, &c.GeraetID, &c.Geraet, &n7, &ok7, &n30, &ok30)
			c.Tage7, c.Tage30, c.N30 = percent(ok7, n7), percent(ok30, n30), n30
			return c, err
		})
		if err != nil {
			return 0, nil, err
		}
		rows, err = tx.Query(ctx, reachabilitySQL, tenants, dashMaxRows+1)
		if err != nil {
			return 0, nil, err
		}
		reach, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (reachOut, error) {
			var q reachOut
			var width int
			var span7, span30 float64
			var seen7, seen30 int64
			err := row.Scan(&q.Art, &q.QuelleID, &q.MandantID, &q.GeraetID, &q.Geraet, &width, &span7, &span30, &seen7, &seen30)
			q.Tage7, q.Tage30 = coverage(seen7, span7, width), coverage(seen30, span30, width)
			return q, err
		})
		if err != nil {
			return 0, nil, err
		}
		truncated := len(checks) > dashMaxRows || len(reach) > dashMaxRows
		checks, reach = checks[:min(len(checks), dashMaxRows)], reach[:min(len(reach), dashMaxRows)]
		if alarms == nil {
			alarms = []alarmHourOut{}
		}
		if checks == nil {
			checks = []checkAvailOut{}
		}
		if reach == nil {
			reach = []reachOut{}
		}
		return http.StatusOK, map[string]any{"alarme_je_stunde": alarms, "checks": checks, "erreichbarkeit": reach,
			"gekuerzt": truncated, "stand": time.Now().UTC()}, nil
	})
}
