// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Dashboard-Layout je Benutzer (Etappe 17, Migration 0019). Übersicht und
// Dashboard sind eins; jeder Benutzer stellt sich seine Widgets selbst
// zusammen. Das Layout gilt für alle Mandanten und folgt dem Benutzer auf jedes
// Gerät.
//
// Ein Widget kann auf einen festen Mandanten oder (Graph) ein Gerät zeigen.
// Das ist nur ein Anzeigefilter: Welche Daten das Widget bekommt, begrenzen
// weiterhin die Endpunkte und RLS (Leitprinzip 2 und 3). Beim Speichern wird
// trotzdem geprüft, dass der Benutzer den Mandanten bzw. das Gerät sieht, damit
// kein Layout auf Fremdes verweist. Ist ein Verweis später nicht mehr sichtbar
// (Rolle entzogen, Gerät gelöscht), liefert GET ihn als leer.
//
// Dieselben Regeln prüft die Datenbank (openwacht.dashboard_widgets_valid);
// die Anwendung prüft vorher, um verständliche Meldungen zu geben.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

const maxWidgets = 30

var widgetIDPattern = regexp.MustCompile(`^[a-z0-9]{4,16}$`)

var widgetTypes = map[string]bool{
	"zustand": true, "alarme": true, "sensoren": true, "auslastung": true, "platten": true, "prognose": true,
	"alarme_je_tag": true, "verfuegbarkeit": true, "graph": true, "sonne": true, "ereignisse": true,
}

var widgetSizes = map[string]bool{"klein": true, "breit": true, "hoch": true}

var widgetRanges = map[string]bool{"1h": true, "24h": true, "7t": true, "30t": true}

var widgetValues = map[string]bool{"cpu": true, "speicher": true}

type widget struct {
	ID        string  `json:"id"`
	Typ       string  `json:"typ"`
	Groesse   string  `json:"groesse"`
	MandantID *string `json:"mandant_id"`
	GeraetID  *string `json:"geraet_id"`
	Zeitraum  *string `json:"zeitraum"`
	Wert      *string `json:"wert"`
}

type layoutIn struct {
	Widgets []widget `json:"widgets"`
}

// leer setzt leere Zeichenketten auf „nicht gesetzt“.
func leer(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

// validateWidgets prüft Aufbau, Typen, Größen und Einstellungen.
func validateWidgets(ws []widget) error {
	if ws == nil {
		return badRequest("Widgets fehlen.")
	}
	if len(ws) > maxWidgets {
		return badRequest("Höchstens 30 Widgets.")
	}
	ids := map[string]bool{}
	types := map[string]bool{}
	for i := range ws {
		w := &ws[i]
		w.MandantID, w.GeraetID, w.Zeitraum, w.Wert = leer(w.MandantID), leer(w.GeraetID), leer(w.Zeitraum), leer(w.Wert)
		if !widgetIDPattern.MatchString(w.ID) || ids[w.ID] {
			return badRequest("Widget: ungültige oder doppelte Kennung.")
		}
		ids[w.ID] = true
		if !widgetTypes[w.Typ] {
			return badRequest("Unbekannte Widget-Art.")
		}
		if w.Typ != "graph" && types[w.Typ] {
			return badRequest("Jedes Widget außer dem Graphen gibt es nur einmal.")
		}
		types[w.Typ] = true
		if !widgetSizes[w.Groesse] {
			return badRequest("Größe: klein, breit oder hoch.")
		}
		if w.MandantID != nil && !uuidPattern.MatchString(*w.MandantID) {
			return badRequest("Widget: ungültiger Mandant.")
		}
		if w.Typ != "graph" && (w.GeraetID != nil || w.Zeitraum != nil || w.Wert != nil) {
			return badRequest("Gerät, Zeitraum und Wert gibt es nur beim Graphen.")
		}
		if w.GeraetID != nil {
			if !uuidPattern.MatchString(*w.GeraetID) {
				return badRequest("Widget: ungültiges Gerät.")
			}
			if w.MandantID != nil {
				return badRequest("Ein Graph zeigt entweder ein Gerät oder einen Mandanten.")
			}
		}
		if w.Zeitraum != nil && !widgetRanges[*w.Zeitraum] {
			return badRequest("Zeitraum: 1h, 24h, 7t oder 30t.")
		}
		if w.Wert != nil && !widgetValues[*w.Wert] {
			return badRequest("Wert: cpu oder speicher.")
		}
	}
	return nil
}

// visibleIDs liefert, welche der IDs in der Tabelle für den Benutzer sichtbar
// sind (RLS). table ist fest im Code, nie aus der Anfrage.
func visibleIDs(ctx context.Context, tx pgx.Tx, table string, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT id::text FROM openwacht.`+table+` WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, id := range got {
		out[id] = true
	}
	return out, nil
}

func refs(ws []widget) (tenants, devices []string) {
	for _, w := range ws {
		if w.MandantID != nil {
			tenants = append(tenants, *w.MandantID)
		}
		if w.GeraetID != nil {
			devices = append(devices, *w.GeraetID)
		}
	}
	return
}

func (s *Server) handleLayoutGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "dashboard-layout", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var raw []byte
		var at time.Time
		err := tx.QueryRow(ctx, `SELECT widgets, updated_at FROM openwacht.dashboard_layouts WHERE user_id = openwacht.current_user_id()`).Scan(&raw, &at)
		if errors.Is(err, pgx.ErrNoRows) {
			// Noch nichts gespeichert: Die Oberfläche zeigt ihr Standard-Layout.
			return http.StatusOK, map[string]any{"widgets": nil, "gespeichert": nil}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		var ws []widget
		if err := json.Unmarshal(raw, &ws); err != nil {
			return 0, nil, err
		}
		tids, dids := refs(ws)
		vt, err := visibleIDs(ctx, tx, "tenants", tids)
		if err != nil {
			return 0, nil, err
		}
		vd, err := visibleIDs(ctx, tx, "devices", dids)
		if err != nil {
			return 0, nil, err
		}
		for i := range ws {
			if ws[i].MandantID != nil && !vt[*ws[i].MandantID] {
				ws[i].MandantID = nil
			}
			if ws[i].GeraetID != nil && !vd[*ws[i].GeraetID] {
				ws[i].GeraetID = nil
			}
		}
		return http.StatusOK, map[string]any{"widgets": ws, "gespeichert": at}, nil
	})
}

func (s *Server) handleLayoutPut(w http.ResponseWriter, r *http.Request) {
	var in layoutIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "dashboard-layout speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := validateWidgets(in.Widgets); err != nil {
			return 0, nil, err
		}
		tids, dids := refs(in.Widgets)
		vt, err := visibleIDs(ctx, tx, "tenants", tids)
		if err != nil {
			return 0, nil, err
		}
		vd, err := visibleIDs(ctx, tx, "devices", dids)
		if err != nil {
			return 0, nil, err
		}
		for _, id := range tids {
			if !vt[id] {
				return 0, nil, badRequest("Widget: Mandant nicht gefunden.")
			}
		}
		for _, id := range dids {
			if !vd[id] {
				return 0, nil, badRequest("Widget: Gerät nicht gefunden.")
			}
		}
		raw, err := json.Marshal(in.Widgets)
		if err != nil {
			return 0, nil, err
		}
		var at time.Time
		err = tx.QueryRow(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets)
			SELECT u.id, u.tenant_id, $1::jsonb FROM openwacht.users u WHERE u.id = openwacht.current_user_id()
			ON CONFLICT (user_id) DO UPDATE SET widgets = EXCLUDED.widgets, updated_at = now()
			RETURNING updated_at`, raw).Scan(&at)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, &apiError{http.StatusForbidden, "Keine Berechtigung."}
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"gespeichert": at}, nil
	})
}

// handleLayoutDelete stellt das Standard-Layout wieder her.
func (s *Server) handleLayoutDelete(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "dashboard-layout zurücksetzen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `DELETE FROM openwacht.dashboard_layouts WHERE user_id = openwacht.current_user_id()`); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}
