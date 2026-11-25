// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Hinweise am Rand und Ton (1.0.2): je Benutzer für sich selbst, je
// Wandanzeige durch die Admins ihres Mandanten. Die Klänge erzeugt der
// Browser (Web Audio); gespeichert werden nur diese wenigen Werte.
type alarmUI struct {
	Hinweise    *bool  `json:"hinweise,omitempty"` // nur Benutzer
	Ton         string `json:"ton"`                // aus | krit | warn
	Klang       string `json:"klang"`              // bling | gong | doppel
	Lautstaerke int    `json:"lautstaerke"`        // 0 … 100
	Entwarnung  bool   `json:"entwarnung"`
}

// alarmUIIn: Eingabe mit Pflichtfeldern (nil = fehlt).
type alarmUIIn struct {
	Hinweise    *bool   `json:"hinweise"`
	Ton         *string `json:"ton"`
	Klang       *string `json:"klang"`
	Lautstaerke *int    `json:"lautstaerke"`
	Entwarnung  *bool   `json:"entwarnung"`
}

// check prüft die Eingabe; forUser verlangt zusätzlich „hinweise“.
func (in alarmUIIn) check(forUser bool) (alarmUI, error) {
	var out alarmUI
	if in.Ton == nil || in.Klang == nil || in.Lautstaerke == nil || in.Entwarnung == nil || (forUser && in.Hinweise == nil) {
		return out, badRequest("Es fehlen Angaben: ton, klang, lautstaerke und entwarnung (bei dir selbst auch hinweise).")
	}
	switch *in.Ton {
	case "aus", "krit", "warn":
	default:
		return out, badRequest("Ton: „aus“, „krit“ oder „warn“.")
	}
	switch *in.Klang {
	case "bling", "gong", "doppel":
	default:
		return out, badRequest("Klang: „bling“, „gong“ oder „doppel“.")
	}
	if *in.Lautstaerke < 0 || *in.Lautstaerke > 100 {
		return out, badRequest("Lautstärke: 0 bis 100.")
	}
	out = alarmUI{Ton: *in.Ton, Klang: *in.Klang, Lautstaerke: *in.Lautstaerke, Entwarnung: *in.Entwarnung}
	if forUser {
		out.Hinweise = in.Hinweise
	}
	return out, nil
}

// handleMyAlarmUI: eigene Einstellungen für Hinweise und Ton.
func (s *Server) handleMyAlarmUI(w http.ResponseWriter, r *http.Request) {
	var in alarmUIIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "hinweise-ton", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		v, err := in.check(true)
		if err != nil {
			return 0, nil, err
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT openwacht.set_alarm_ui($1::jsonb)`, raw); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, v, nil
	})
}

// handleDisplaySound: Ton einer Wandanzeige (nur Admins ihres Mandanten).
func (s *Server) handleDisplaySound(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in alarmUIIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "anzeige ton", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		v, err := in.check(false)
		if err != nil {
			return 0, nil, err
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return 0, nil, err
		}
		var tenant, name string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.displays SET sound = $2::jsonb WHERE id = $1 RETURNING tenant_id::text, name`,
			id, raw).Scan(&tenant, &name); err != nil {
			return 0, nil, err // nicht sichtbar (kein Admin): 404
		}
		if err := audit(ctx, tx, &tenant, "anzeige.ton", map[string]any{"id": id, "name": name, "ton": v}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, v, nil
	})
}

// scanAlarmUI liest den gespeicherten Wert; bei Unlesbarem gilt „aus“.
func scanAlarmUI(raw []byte, forUser bool) alarmUI {
	var v alarmUI
	if json.Unmarshal(raw, &v) != nil || v.Ton == "" {
		v = alarmUI{Ton: "aus", Klang: "bling", Lautstaerke: 60}
	}
	if forUser && v.Hinweise == nil {
		t := true
		v.Hinweise = &t
	}
	if !forUser {
		v.Hinweise = nil
	}
	return v
}
