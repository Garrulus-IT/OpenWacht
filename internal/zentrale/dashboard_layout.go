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
//
// 1.0.7 (Migration 0062): freie Breite und Höhe je Widget, eigener Titel,
// jede Art beliebig oft, bis zu acht benannte Seiten und die Arten
// Zertifikate, Wartung, Uhr, Notiz und einzelner Sensor. Layouts mit der
// alten „groesse“ gelten weiter.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const (
	maxWidgets     = 60
	maxPages       = 8
	maxWidgetTitle = 60
	maxWidgetText  = 500
	maxPageName    = 40
)

var widgetIDPattern = regexp.MustCompile(`^[a-z0-9]{4,16}$`)

var widgetTypes = map[string]bool{
	"zustand": true, "alarme": true, "sensoren": true, "auslastung": true, "platten": true, "prognose": true,
	"alarme_je_tag": true, "verfuegbarkeit": true, "graph": true, "sonne": true, "ereignisse": true,
	"zertifikate": true, "wartung": true, "uhr": true, "notiz": true, "sensor": true,
}

var widgetSizes = map[string]bool{"klein": true, "breit": true, "hoch": true}

var widgetRanges = map[string]bool{"1h": true, "24h": true, "7t": true, "30t": true}

var widgetValues = map[string]bool{"cpu": true, "speicher": true}

type widget struct {
	ID  string `json:"id"`
	Typ string `json:"typ"`
	// Groesse: alte Form (klein, breit, hoch); neu Breite (2–12 Spalten) und
	// Hoehe (1–6 Reihen). Eines von beiden muss da sein.
	Groesse   string  `json:"groesse,omitempty"`
	Breite    *int    `json:"breite,omitempty"`
	Hoehe     *int    `json:"hoehe,omitempty"`
	Titel     *string `json:"titel,omitempty"`
	Seite     *int    `json:"seite,omitempty"`
	MandantID *string `json:"mandant_id"`
	GeraetID  *string `json:"geraet_id"`
	Zeitraum  *string `json:"zeitraum"`
	Wert      *string `json:"wert"`
	// Text nur an der Notiz, Sensor (Schlüssel aus /api/v1/sensoren) nur am
	// Widget „sensor“.
	Text   *string `json:"text,omitempty"`
	Sensor *string `json:"sensor,omitempty"`
}

type layoutIn struct {
	Widgets []widget `json:"widgets"`
	Seiten  []string `json:"seiten"`
}

// sauber: keine Steuerzeichen (Zeilenumbruch nur, wenn erlaubt), gültiges UTF-8.
func sauber(s string, zeilen bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(zeilen && r == '\n') {
			return false
		}
	}
	return true
}

// validatePages prüft die Namen der Seiten.
func validatePages(ps []string) error {
	if len(ps) > maxPages {
		return badRequest("Höchstens 8 Seiten.")
	}
	for _, p := range ps {
		if n := utf8.RuneCountInString(p); n < 1 || n > maxPageName || !sauber(p, false) || strings.TrimSpace(p) != p {
			return badRequest("Name der Seite: 1 bis 40 Zeichen.")
		}
	}
	return nil
}

// leer setzt leere Zeichenketten auf „nicht gesetzt“.
func leer(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

// validateWidgets prüft Aufbau, Typen, Größen und Einstellungen.
func validateWidgets(ws []widget, pages int) error {
	if ws == nil {
		return badRequest("Widgets fehlen.")
	}
	if len(ws) > maxWidgets {
		return badRequest("Höchstens 60 Widgets.")
	}
	ids := map[string]bool{}
	for i := range ws {
		w := &ws[i]
		w.MandantID, w.GeraetID, w.Zeitraum, w.Wert = leer(w.MandantID), leer(w.GeraetID), leer(w.Zeitraum), leer(w.Wert)
		w.Titel, w.Text, w.Sensor = leer(w.Titel), leer(w.Text), leer(w.Sensor)
		if !widgetIDPattern.MatchString(w.ID) || ids[w.ID] {
			return badRequest("Widget: ungültige oder doppelte Kennung.")
		}
		ids[w.ID] = true
		if !widgetTypes[w.Typ] {
			return badRequest("Unbekannte Widget-Art.")
		}
		if w.Groesse != "" && !widgetSizes[w.Groesse] {
			return badRequest("Größe: klein, breit oder hoch.")
		}
		if w.Breite != nil || w.Hoehe != nil {
			if w.Breite == nil || w.Hoehe == nil || *w.Breite < 2 || *w.Breite > 12 || *w.Hoehe < 1 || *w.Hoehe > 6 {
				return badRequest("Widget: Breite 2 bis 12 Spalten, Höhe 1 bis 6 Reihen.")
			}
		} else if w.Groesse == "" {
			return badRequest("Widget: Breite und Höhe fehlen.")
		}
		if w.Titel != nil && (utf8.RuneCountInString(*w.Titel) > maxWidgetTitle || !sauber(*w.Titel, false)) {
			return badRequest("Titel: höchstens 60 Zeichen.")
		}
		if w.Seite != nil && (*w.Seite < 0 || *w.Seite >= max(pages, 1)) {
			return badRequest("Widget: Seite gibt es nicht.")
		}
		if w.Text != nil && (w.Typ != "notiz" || utf8.RuneCountInString(*w.Text) > maxWidgetText || !sauber(*w.Text, true)) {
			return badRequest("Text: nur an der Notiz, höchstens 500 Zeichen.")
		}
		if w.Sensor != nil {
			n := utf8.RuneCountInString(*w.Sensor)
			if w.Typ != "sensor" || n < 3 || n > 200 || !sauber(*w.Sensor, false) ||
				!(strings.HasPrefix(*w.Sensor, "c:") || strings.HasPrefix(*w.Sensor, "h:") || strings.HasPrefix(*w.Sensor, "s:")) {
				return badRequest("Widget: ungültiger Sensor.")
			}
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
		var raw, rawPages []byte
		var at time.Time
		err := tx.QueryRow(ctx, `SELECT widgets, pages, updated_at FROM openwacht.dashboard_layouts WHERE user_id = openwacht.current_user_id()`).
			Scan(&raw, &rawPages, &at)
		if errors.Is(err, pgx.ErrNoRows) {
			// Noch nichts gespeichert: Die Oberfläche zeigt ihr Standard-Layout.
			return http.StatusOK, map[string]any{"widgets": nil, "seiten": []string{}, "gespeichert": nil}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		var ws []widget
		if err := json.Unmarshal(raw, &ws); err != nil {
			return 0, nil, err
		}
		pages := []string{}
		if err := json.Unmarshal(rawPages, &pages); err != nil {
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
		return http.StatusOK, map[string]any{"widgets": ws, "seiten": pages, "gespeichert": at}, nil
	})
}

func (s *Server) handleLayoutPut(w http.ResponseWriter, r *http.Request) {
	var in layoutIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "dashboard-layout speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := validatePages(in.Seiten); err != nil {
			return 0, nil, err
		}
		if err := validateWidgets(in.Widgets, len(in.Seiten)); err != nil {
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
		if len(raw) > 32768 {
			return 0, nil, badRequest("Das Dashboard ist zu groß.")
		}
		pages := in.Seiten
		if pages == nil {
			pages = []string{}
		}
		rawPages, err := json.Marshal(pages)
		if err != nil {
			return 0, nil, err
		}
		var at time.Time
		err = tx.QueryRow(ctx, `INSERT INTO openwacht.dashboard_layouts (user_id, tenant_id, widgets, pages)
			SELECT u.id, u.tenant_id, $1::jsonb, $2::jsonb FROM openwacht.users u WHERE u.id = openwacht.current_user_id()
			ON CONFLICT (user_id) DO UPDATE SET widgets = EXCLUDED.widgets, pages = EXCLUDED.pages, updated_at = now()
			RETURNING updated_at`, raw, rawPages).Scan(&at)
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
