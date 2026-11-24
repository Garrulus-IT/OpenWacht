// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Kleine Verläufe (Sparklines) je Sensor eines Geräts: die letzten 24 Stunden
// in 30-Minuten-Schritten für Agent, SNMP-Quelle und Checks des Geräts, in
// einer Anfrage. Den ausführlichen Verlauf liefern weiter die Endpunkte je
// Quelle (…/verlauf).
//
// Mandantentrennung: Das Gerät muss sichtbar sein (RLS, sonst 404); Agent,
// SNMP-Quelle und Checks hängen am Gerät und haben denselben Mandanten
// (zusammengesetzter Fremdschlüssel). Alle Tabellen haben zusätzlich RLS.

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	sparkSpan = 24 * time.Hour
	sparkStep = 30 * time.Minute
	// sparkMaxChecks: so viele Checks eines Geräts bekommen eine Sparkline.
	sparkMaxChecks = 100
)

type sparkSourceOut struct {
	ID     string      `json:"id"`
	Reihen []seriesOut `json:"reihen"`
}

type sparkCheckOut struct {
	ID     string          `json:"id"`
	Punkte []checkPointOut `json:"punkte"`
}

func collectSeries(rows pgx.Rows) ([]seriesOut, error) {
	defer rows.Close()
	list := []seriesOut{}
	for rows.Next() {
		var series string
		var t, av, mi, ma float64
		if err := rows.Scan(&series, &t, &av, &mi, &ma); err != nil {
			return nil, err
		}
		if len(list) == 0 || list[len(list)-1].Name != series {
			list = append(list, seriesOut{Name: series})
		}
		last := &list[len(list)-1]
		last.Punkte = append(last.Punkte, [4]float64{t, round2(av), round2(mi), round2(ma)})
	}
	return list, rows.Err()
}

func collectCheckPoints(rows pgx.Rows) ([]checkPointOut, error) {
	points, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (checkPointOut, error) {
		var c checkPointOut
		err := row.Scan(&c.Zeit, &c.Anzahl, &c.OK, &c.Schlechter, &c.MsMittel, &c.MsMin, &c.MsMax)
		c.MsMittel, c.MsMin, c.MsMax = roundPtr(c.MsMittel), roundPtr(c.MsMin), roundPtr(c.MsMax)
		return c, err
	})
	if points == nil {
		points = []checkPointOut{}
	}
	return points, err
}

func (s *Server) handleDeviceSparklines(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "sparklines", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		// Sichtbarkeit zuerst (RLS): Fremde Geräte ergeben 404.
		var x int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM openwacht.devices WHERE id = $1`, id).Scan(&x); err != nil {
			return 0, nil, err
		}
		span, step := interval(sparkSpan), interval(sparkStep)
		out := map[string]any{"spanne_s": int(sparkSpan.Seconds()), "schritt_s": int(sparkStep.Seconds()),
			"agent": nil, "snmp": nil, "checks": []sparkCheckOut{}}

		var agent, snmpID *string
		if err := tx.QueryRow(ctx, `SELECT (SELECT a.id::text FROM openwacht.agents a WHERE a.device_id = $1 AND a.revoked_at IS NULL),
				(SELECT q.id::text FROM openwacht.snmp_sources q WHERE q.device_id = $1)`, id).Scan(&agent, &snmpID); err != nil {
			return 0, nil, err
		}
		for _, src := range []struct {
			key, sql string
			id       *string
		}{{"agent", hostHistorySQL, agent}, {"snmp", snmpHistorySQL, snmpID}} {
			if src.id == nil {
				continue
			}
			rows, err := tx.Query(ctx, src.sql, *src.id, span, "5m", step)
			if err != nil {
				return 0, nil, err
			}
			list, err := collectSeries(rows)
			if err != nil {
				return 0, nil, err
			}
			out[src.key] = sparkSourceOut{ID: *src.id, Reihen: list}
		}

		rows, err := tx.Query(ctx, `SELECT id::text FROM openwacht.checks WHERE device_id = $1 ORDER BY lower(name), id LIMIT $2`,
			id, sparkMaxChecks)
		if err != nil {
			return 0, nil, err
		}
		checkIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return 0, nil, err
		}
		checks := []sparkCheckOut{}
		for _, c := range checkIDs {
			rows, err := tx.Query(ctx, checkHistorySQL, c, span, "5m", step)
			if err != nil {
				return 0, nil, err
			}
			points, err := collectCheckPoints(rows)
			if err != nil {
				return 0, nil, err
			}
			checks = append(checks, sparkCheckOut{ID: c, Punkte: points})
		}
		out["checks"] = checks
		return http.StatusOK, out, nil
	})
}
