// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Alarm „Platte voll in < N Tagen“ (Etappe 20b): Die Prognose aus Etappe 10
// fließt als Warnung in den Gegenstand der Platte ein (alarm.EvaluateHost),
// für Agent- und SNMP-Platten. Die Rechnung über 30 Tage Stundenwerte ist
// teuer; die Zentrale hält das Ergebnis deshalb höchstens 10 Minuten vor.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

const fullDaysMaxAge = 10 * time.Minute

type fullDaysCache struct {
	mu sync.Mutex
	at time.Time
	m  map[string]map[string]int // "agent|snmp\x00id" → Einhängepunkt → Tage
}

// refreshFullDays lädt die Prognose neu, wenn sie älter als fullDaysMaxAge
// ist. Vor der Transaktion eines Durchlaufs aufrufen, nie darin:
// loadFullDays braucht eine eigene Verbindung aus dem Pool, und wer dabei eine
// hält, kann bei kleinem Pool auf sich selbst warten.
func (s *Server) refreshFullDays() {
	c := &s.fullDays
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || s.now().Sub(c.at) >= fullDaysMaxAge {
		if m, err := s.loadFullDays(); err == nil {
			c.m, c.at = m, s.now()
		} else {
			slog.Warn("Alarme: Platten-Prognose nicht gelesen, es bleibt der bisherige Stand", "fehler", err)
			if c.m == nil {
				c.m = map[string]map[string]int{}
			}
			c.at = s.now().Add(-fullDaysMaxAge + time.Minute) // in einer Minute erneut
		}
	}
}

// fullDaysFor: Tage bis voll je Platte einer Quelle (kind "agent" oder "snmp");
// nil, wenn keine Platte steigt. Liest nur den Stand von refreshFullDays.
func (s *Server) fullDaysFor(kind, id string) map[string]int {
	c := &s.fullDays
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[kind+"\x00"+id]
}

func (s *Server) loadFullDays() (map[string]map[string]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT art, quelle::text, platte, slope_day, points, span_days, current
		FROM openwacht.disk_forecasts_sys(NULL, $1::interval, $2)`, interval(forecastWindow), forecastDrop)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var art, id, mount string
		var slope, span, cur float64
		var points int
		if err := rows.Scan(&art, &id, &mount, &slope, &points, &span, &cur); err != nil {
			return nil, err
		}
		if stand, days := forecastResult(slope, points, span, cur); stand == forecastRising {
			kind := map[string]string{"host": "agent", "snmp": "snmp"}[art]
			k := kind + "\x00" + id
			if out[k] == nil {
				out[k] = map[string]int{}
			}
			out[k][mount] = *days
		}
	}
	return out, rows.Err()
}

// withFullDays hängt die Prognose an die Messwerte eines Agents.
func (s *Server) withFullDays(m *alarm.HostMetrics, agent string) *alarm.HostMetrics {
	if m != nil {
		m.FullDays = s.fullDaysFor("agent", agent)
	}
	return m
}
