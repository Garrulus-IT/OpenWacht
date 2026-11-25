// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Verlauf der Messwerte: Reihen aus den Meldungen der Agents, regelmäßige
// Wartung (Partitionen, Verdichtung, Aufräumen; siehe Migration 0008) und
// die Abfrage für die Graphen der Oberfläche.

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/alarm"
)

// Reihen eines Snapshots für den Verlauf: Prozentwerte (belegt) und Last.
// Netzwerkfreigaben fehlen wie bei den Alarmen; doppelte Einhängepunkte
// zählen einmal.
func hostSeries(s *agentproto.Snapshot) (names []string, values []float64) {
	add := func(name string, v float64) {
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1e6 {
			names = append(names, name)
			values = append(values, v)
		}
	}
	used := func(total, free uint64) float64 {
		return float64(total-free) / float64(total) * 100
	}
	add("cpu", s.CPU.Percent)
	if !s.CPU.NoLoad {
		add("last1", s.CPU.Load1)
	}
	if m := s.Memory; m.TotalBytes > 0 && m.AvailableBytes <= m.TotalBytes {
		add("speicher", used(m.TotalBytes, m.AvailableBytes))
	}
	if m := s.Memory; m.SwapTotalBytes > 0 && m.SwapFreeBytes <= m.SwapTotalBytes {
		add("swap", used(m.SwapTotalBytes, m.SwapFreeBytes))
	}
	seen := map[string]bool{}
	for _, d := range s.Disks {
		if d.Mount == "" || d.TotalBytes == 0 || d.FreeBytes > d.TotalBytes || alarm.NetworkFS(d.FSType) || seen[d.Mount] {
			continue
		}
		seen[d.Mount] = true
		add("platte:"+d.Mount, used(d.TotalBytes, d.FreeBytes))
	}
	return names, values
}

// latencyMs: Antwortzeit für den Verlauf, nil = keine Messung.
func latencyMs(d time.Duration) *float64 {
	if d <= 0 {
		return nil
	}
	v := float64(d.Microseconds()) / 1000
	return &v
}

// --- Wartung ------------------------------------------------------------------

// MaintainMetrics legt Partitionen an, verdichtet und räumt auf.
func (s *Server) MaintainMetrics(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `SELECT openwacht.metrics_maintain()`)
	return err
}

// purgeUsers löscht Konten, die seit 90 Tagen gesperrt sind (1.0.6).
func (s *Server) purgeUsers(ctx context.Context) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.users_purge()`).Scan(&n); err != nil {
		if ctx.Err() == nil {
			slog.Warn("Konten: Löschen nach Frist fehlgeschlagen", "fehler", err)
		}
		return
	}
	if n > 0 {
		slog.Info("Konten: nach 90 Tagen Sperre gelöscht", "anzahl", n)
	}
}

// RunMetrics ruft die Wartung sofort und danach alle fünf Minuten auf, bis ctx endet.
func (s *Server) RunMetrics(ctx context.Context) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		if err := s.MaintainMetrics(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Verlauf: Wartung fehlgeschlagen", "fehler", err)
		}
		s.purgeUsers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// --- Abfrage -----------------------------------------------------------------------

// Zeiträume der Oberfläche. Bis 24 Stunden kommen die Werte aus den Rohdaten,
// darüber aus der passenden Verdichtungsstufe; was dort noch nicht verdichtet
// ist, ergänzen die Rohdaten.
type period struct {
	span, step time.Duration
	tier       string // "" = nur Rohdaten, sonst "5m" oder "1h"
}

var periods = map[string]period{
	"1h":  {time.Hour, time.Minute, ""},
	"24h": {24 * time.Hour, 5 * time.Minute, ""},
	"7t":  {7 * 24 * time.Hour, 30 * time.Minute, "5m"},
	"30t": {30 * 24 * time.Hour, 2 * time.Hour, "1h"},
}

func parsePeriod(w http.ResponseWriter, r *http.Request) (string, period, bool) {
	name := r.URL.Query().Get("zeitraum")
	if name == "" {
		name = "24h"
	}
	p, ok := periods[name]
	if !ok {
		writeError(w, http.StatusBadRequest, "Unbekannter Zeitraum (1h, 24h, 7t oder 30t).")
	}
	return name, p, ok
}

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

func round2(v float64) float64 { return math.Round(v*100) / 100 }

type seriesOut struct {
	Name string `json:"name"`
	// je Punkt: Zeit (Unix-Sekunden, Blockbeginn), Mittel, Minimum, Maximum
	Punkte [][4]float64 `json:"punkte"`
}

// seriesHistorySQL: Verlauf aus Rohdaten und Verdichtungsstufen einer
// Quelle (Agent bzw. SNMP-Quelle). Tabellen- und Spaltennamen sind feste
// Werte aus diesem Paket, nie Eingaben.
func seriesHistorySQL(prefix, idCol string) string {
	return strings.NewReplacer("{raw}", "openwacht."+prefix+"_raw", "{m5}", "openwacht."+prefix+"_5m",
		"{h1}", "openwacht."+prefix+"_1h", "{id}", idCol).Replace(`
WITH w AS (
    SELECT now() - $2::interval AS von,
           CASE $3 WHEN '5m' THEN done_5m WHEN '1h' THEN done_1h ELSE now() - $2::interval END AS wm
      FROM openwacht.metrics_watermarks()
), src AS (
    SELECT r.series, r.ts AS t, r.value AS av, r.value AS mi, r.value AS ma, 1::bigint AS n
      FROM {raw} r, w
     WHERE r.{id} = $1 AND r.ts >= greatest(w.von, w.wm)
    UNION ALL
    SELECT m.series, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM {m5} m, w
     WHERE $3 = '5m' AND m.{id} = $1 AND m.bucket >= w.von AND m.bucket < w.wm
    UNION ALL
    SELECT m.series, m.bucket, m.avg, m.min, m.max, m.n::bigint
      FROM {h1} m, w
     WHERE $3 = '1h' AND m.{id} = $1 AND m.bucket >= w.von AND m.bucket < w.wm
)
SELECT series, extract(epoch FROM date_bin($4::interval, t, timestamptz 'epoch'))::double precision,
       sum(av * n) / sum(n), min(mi), max(ma)
  FROM src GROUP BY 1, 2 ORDER BY 1, 2 LIMIT 60000`)
}

var (
	hostHistorySQL = seriesHistorySQL("metrics_host", "agent_id")
	snmpHistorySQL = seriesHistorySQL("metrics_snmp", "snmp_id")
)

func (s *Server) handleAgentHistory(w http.ResponseWriter, r *http.Request) {
	s.seriesHistory(w, r, "verlauf agent", `SELECT 1 FROM openwacht.agents WHERE id = $1`, hostHistorySQL)
}

func (s *Server) handleSNMPHistory(w http.ResponseWriter, r *http.Request) {
	s.seriesHistory(w, r, "verlauf snmp", `SELECT 1 FROM openwacht.snmp_sources WHERE id = $1`, snmpHistorySQL)
}

func (s *Server) seriesHistory(w http.ResponseWriter, r *http.Request, where, visibleSQL, historySQL string) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	name, p, ok := parsePeriod(w, r)
	if !ok {
		return
	}
	s.handle(w, r, where, func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		// Sichtbarkeit zuerst (RLS): Fremde Quellen ergeben 404, nicht eine leere Liste.
		var x int
		if err := tx.QueryRow(ctx, visibleSQL, id).Scan(&x); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, historySQL, id, interval(p.span), p.tier, interval(p.step))
		if err != nil {
			return 0, nil, err
		}
		list, err := collectSeries(rows)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"zeitraum": name, "spanne_s": int(p.span.Seconds()),
			"schritt_s": int(p.step.Seconds()), "reihen": list}, nil
	})
}

const checkHistorySQL = `
WITH w AS (
    SELECT now() - $2::interval AS von,
           CASE $3 WHEN '5m' THEN done_5m WHEN '1h' THEN done_1h ELSE now() - $2::interval END AS wm
      FROM openwacht.metrics_watermarks()
), src AS (
    SELECT r.ts AS t, 1::bigint AS n, (r.status = 'ok')::int::bigint AS n_ok, r.status AS worst,
           (r.ms IS NOT NULL)::int::bigint AS ms_n, r.ms AS ms_avg, r.ms AS ms_min, r.ms AS ms_max
      FROM openwacht.metrics_check_raw r, w
     WHERE r.check_id = $1 AND r.ts >= greatest(w.von, w.wm)
    UNION ALL
    SELECT m.bucket, m.n, m.n_ok, m.worst, m.ms_n, m.ms_avg, m.ms_min, m.ms_max
      FROM openwacht.metrics_check_5m m, w
     WHERE $3 = '5m' AND m.check_id = $1 AND m.bucket >= w.von AND m.bucket < w.wm
    UNION ALL
    SELECT m.bucket, m.n, m.n_ok, m.worst, m.ms_n, m.ms_avg, m.ms_min, m.ms_max
      FROM openwacht.metrics_check_1h m, w
     WHERE $3 = '1h' AND m.check_id = $1 AND m.bucket >= w.von AND m.bucket < w.wm
)
SELECT extract(epoch FROM date_bin($4::interval, t, timestamptz 'epoch'))::double precision,
       sum(n), sum(n_ok), (array_agg(worst ORDER BY openwacht.status_rank(worst) DESC))[1],
       sum(ms_avg * ms_n) / nullif(sum(ms_n), 0), min(ms_min), max(ms_max)
  FROM src GROUP BY 1 ORDER BY 1 LIMIT 5000`

type checkPointOut struct {
	Zeit       float64  `json:"t"`
	Anzahl     int64    `json:"n"`
	OK         int64    `json:"ok"`
	Schlechter string   `json:"schlechtester"`
	MsMittel   *float64 `json:"ms"`
	MsMin      *float64 `json:"ms_min"`
	MsMax      *float64 `json:"ms_max"`
}

type transitionOut struct {
	Zeit    time.Time `json:"zeit"`
	Von     *string   `json:"von"`
	Nach    string    `json:"nach"`
	Meldung *string   `json:"meldung"`
}

func roundPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	x := round2(*v)
	return &x
}

func (s *Server) handleCheckHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	name, p, ok := parsePeriod(w, r)
	if !ok {
		return
	}
	s.handle(w, r, "verlauf check", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var x int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM openwacht.checks WHERE id = $1`, id).Scan(&x); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, checkHistorySQL, id, interval(p.span), p.tier, interval(p.step))
		if err != nil {
			return 0, nil, err
		}
		points, err := collectCheckPoints(rows)
		if err != nil {
			return 0, nil, err
		}
		// Die letzten 200 Wechsel im Zeitraum, älteste zuerst.
		rows, err = tx.Query(ctx, `SELECT ts, old_status, new_status, message FROM (
				SELECT ts, old_status, new_status, message FROM openwacht.check_transitions
				 WHERE check_id = $1 AND ts >= now() - $2::interval ORDER BY ts DESC LIMIT 200) x
			ORDER BY ts`, id, interval(p.span))
		if err != nil {
			return 0, nil, err
		}
		changes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (transitionOut, error) {
			var c transitionOut
			err := row.Scan(&c.Zeit, &c.Von, &c.Nach, &c.Meldung)
			return c, err
		})
		if err != nil {
			return 0, nil, err
		}
		if changes == nil {
			changes = []transitionOut{}
		}
		return http.StatusOK, map[string]any{"zeitraum": name, "spanne_s": int(p.span.Seconds()),
			"schritt_s": int(p.step.Seconds()), "punkte": points, "wechsel": changes}, nil
	})
}
