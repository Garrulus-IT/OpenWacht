// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Aufbewahrung der Messwerte (Etappe 35). Global stellt der Betreiber alle
// drei Stufen ein, je Mandant die 5-Minuten- und Stundenwerte (erbt vom
// nächsten Mandanten darüber). Kürzer stellen löscht beim nächsten
// Wartungslauf (spätestens nach 5 Minuten) unwiderruflich, deshalb nur mit
// frischem 2FA-Code.

// Standard und Grenzen (wie in Migration 0040).
var retention = struct {
	Standard map[string]int    `json:"standard"`
	Grenzen  map[string][2]int `json:"grenzen"`
}{
	Standard: map[string]int{"roh_tage": 2, "fuenf_min_tage": 30, "stunden_tage": 365},
	Grenzen:  map[string][2]int{"roh_tage": {2, 7}, "fuenf_min_tage": {30, 400}, "stunden_tage": {90, 1830}},
}

type retentionIn struct {
	Roh      *int   `json:"roh_tage"`
	FuenfMin *int   `json:"fuenf_min_tage"`
	Stunden  *int   `json:"stunden_tage"`
	Code     string `json:"code"`
}

func checkRetention(field string, v *int) error {
	if v == nil {
		return nil
	}
	g := retention.Grenzen[field]
	if *v < g[0] || *v > g[1] {
		return badRequest("Aufbewahrung: Werte außerhalb der Grenzen (Rohwerte 2–7, 5-Minuten-Werte 30–400, Stundenwerte 90–1830 Tage).")
	}
	return nil
}

func eff(v *int32, std int) int {
	if v == nil {
		return std
	}
	return int(*v)
}

func (s *Server) handleRetentionGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "aufbewahrung", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		var raw, m5, h1 *int32
		if err := tx.QueryRow(ctx, `SELECT keep_raw_days, keep_5m_days, keep_1h_days FROM openwacht.settings`).Scan(&raw, &m5, &h1); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT t.id::text, t.name, t.parent_id::text, ts.keep_5m_days, ts.keep_1h_days, r.days_5m, r.days_1h
			FROM openwacht.settings_tenants() t
			JOIN openwacht.settings_retention() r ON r.tenant_id = t.id
			LEFT JOIN openwacht.tenant_settings ts ON ts.tenant_id = t.id ORDER BY t.name`)
		if err != nil {
			return 0, nil, err
		}
		type tenantRet struct {
			ID       string  `json:"id"`
			Name     string  `json:"name"`
			Eltern   *string `json:"eltern"`
			FuenfMin *int32  `json:"fuenf_min_tage"`
			Stunden  *int32  `json:"stunden_tage"`
			Wirksam  [2]int  `json:"wirksam"`
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantRet, error) {
			var t tenantRet
			err := row.Scan(&t.ID, &t.Name, &t.Eltern, &t.FuenfMin, &t.Stunden, &t.Wirksam[0], &t.Wirksam[1])
			return t, err
		})
		if err != nil {
			return 0, nil, err
		}
		sizes := map[string]int64{}
		srows, err := tx.Query(ctx, `SELECT tier, bytes FROM openwacht.metrics_sizes()`)
		if err != nil {
			return 0, nil, err
		}
		for srows.Next() {
			var tier string
			var b int64
			if err := srows.Scan(&tier, &b); err != nil {
				return 0, nil, err
			}
			sizes[tier] = b
		}
		if err := srows.Err(); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{
			"global":   map[string]*int32{"roh_tage": raw, "fuenf_min_tage": m5, "stunden_tage": h1},
			"standard": retention.Standard, "grenzen": retention.Grenzen,
			"mandanten": list, "groesse_bytes": sizes,
		}, nil
	})
}

// shorter: Wird eine Aufbewahrung kürzer (dann löscht die Wartung Daten)?
func shorter(oldV *int32, newV *int, std int) bool {
	return (newV != nil && *newV < eff(oldV, std)) || (newV == nil && oldV != nil && std < int(*oldV))
}

func (s *Server) handleRetentionPut(w http.ResponseWriter, r *http.Request) {
	var in retentionIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "aufbewahrung", err) }
	for f, v := range map[string]*int{"roh_tage": in.Roh, "fuenf_min_tage": in.FuenfMin, "stunden_tage": in.Stunden} {
		if err := checkRetention(f, v); err != nil {
			fail(err)
			return
		}
	}
	var raw, m5, h1 *int32
	err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		if err := requireOperator(r.Context(), tx); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), `SELECT keep_raw_days, keep_5m_days, keep_1h_days FROM openwacht.settings`).Scan(&raw, &m5, &h1)
	})
	if err != nil {
		fail(err)
		return
	}
	if shorter(raw, in.Roh, 2) || shorter(m5, in.FuenfMin, 30) || shorter(h1, in.Stunden, 365) {
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
	}
	s.handle(w, r, "aufbewahrung", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		_, err := tx.Exec(ctx, `UPDATE openwacht.settings SET keep_raw_days = $1, keep_5m_days = $2, keep_1h_days = $3`,
			in.Roh, in.FuenfMin, in.Stunden)
		return http.StatusNoContent, nil, err
	})
}

func (s *Server) handleTenantRetentionPut(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in retentionIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "aufbewahrung mandant", err) }
	if in.Roh != nil {
		fail(badRequest("Rohwerte gelten für alle Mandanten gemeinsam (nur global einstellbar)."))
		return
	}
	for f, v := range map[string]*int{"fuenf_min_tage": in.FuenfMin, "stunden_tage": in.Stunden} {
		if err := checkRetention(f, v); err != nil {
			fail(err)
			return
		}
	}
	// Probelauf: schreiben, wirksamen Wert (mit Vererbung) lesen, zurückrollen.
	// Wird eine Stufe kürzer, löscht die Wartung Daten: dann mit Code.
	write := func(ctx context.Context, tx pgx.Tx) (cur, next [2]int, err error) {
		err = tx.QueryRow(ctx, `SELECT r.days_5m, r.days_1h FROM openwacht.settings_retention() r
			JOIN openwacht.settings_tenants() t ON t.id = r.tenant_id WHERE r.tenant_id = $1`, id).Scan(&cur[0], &cur[1])
		if errors.Is(err, pgx.ErrNoRows) {
			return cur, next, errNotFound
		}
		if err != nil {
			return cur, next, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO openwacht.tenant_settings AS ts (tenant_id, keep_5m_days, keep_1h_days) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) DO UPDATE SET keep_5m_days = EXCLUDED.keep_5m_days, keep_1h_days = EXCLUDED.keep_1h_days`,
			id, in.FuenfMin, in.Stunden); err != nil {
			return cur, next, err
		}
		if err = pruneTenantSettings(ctx, tx, id); err != nil {
			return cur, next, err
		}
		err = tx.QueryRow(ctx, `SELECT days_5m, days_1h FROM openwacht.settings_retention() WHERE tenant_id = $1`, id).Scan(&next[0], &next[1])
		return cur, next, err
	}
	var cur, next [2]int
	err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		if err := requireOperator(r.Context(), tx); err != nil {
			return err
		}
		var err error
		if cur, next, err = write(r.Context(), tx); err != nil {
			return err
		}
		return errDryRun
	})
	if !errors.Is(err, errDryRun) {
		fail(err)
		return
	}
	if next[0] < cur[0] || next[1] < cur[1] {
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
	}
	s.handle(w, r, "aufbewahrung mandant", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		_, now, err := write(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"wirksam": now}, nil
	})
}

// errDryRun: Probelauf beenden (Transaktion zurückrollen).
var errDryRun = errors.New("probelauf")

// pruneTenantSettings entfernt die Zeile eines Mandanten, wenn nichts mehr gesetzt ist.
func pruneTenantSettings(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM openwacht.tenant_settings WHERE tenant_id = $1 AND check_nets IS NULL AND silent_s IS NULL
		AND disk_warn IS NULL AND disk_crit IS NULL AND mem_warn IS NULL AND mem_crit IS NULL AND cpu_warn IS NULL
		AND cpu_crit IS NULL AND disk_days IS NULL AND keep_5m_days IS NULL AND keep_1h_days IS NULL`, id)
	return err
}
