// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Eigene Vorlagensätze je Mandant (0.46.0, Migration 0046). Ein Satz ist eine
// Liste von Vorlagen-Kopien; angewendet wird er wie ein eingebauter Satz über
// POST /api/v1/sensor-vorlagen/anwenden mit satz_id. Sichtbarkeit und Rechte
// wie bei eigenen Vorlagen: RLS in openwacht.sensor_template_sets.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/checks"
)

const (
	maxSetItems = 50
	maxSetNote  = 500 // wie in der Datenbank; eingebaute Sätze passen hinein („Als eigenen“)
)

// satzEintragDB: so steht ein Eintrag in sensor_template_sets.items.
type satzEintragDB struct {
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Notiz     string          `json:"notiz"`
	Kennfarbe string          `json:"kennfarbe,omitempty"` // 1.0.1
}

type eigenerSatzOut struct {
	ID        string       `json:"id"`
	MandantID string       `json:"mandant_id"`
	Name      string       `json:"name"`
	Notiz     string       `json:"notiz"`
	Sensoren  []vorlageOut `json:"sensoren"`
	Geaendert time.Time    `json:"geaendert"`
}

type satzIn struct {
	Name     string      `json:"name"`
	Notiz    string      `json:"notiz"`
	Sensoren []vorlageIn `json:"sensoren"`
}

func noControl(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// parseSetIn prüft Name, Notiz und jeden Eintrag wie eine eigene Vorlage.
func parseSetIn(in satzIn) (satzIn, []byte, error) {
	in.Name, in.Notiz = strings.TrimSpace(in.Name), strings.TrimSpace(in.Notiz)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 60 || !noControl(in.Name) {
		return in, nil, badRequest("Name: 1 bis 60 Zeichen, keine Steuerzeichen.")
	}
	if utf8.RuneCountInString(in.Notiz) > maxSetNote || !noControl(in.Notiz) {
		return in, nil, badRequest("Notiz: höchstens 500 Zeichen, keine Steuerzeichen.")
	}
	if len(in.Sensoren) == 0 || len(in.Sensoren) > maxSetItems {
		return in, nil, badRequest("Sensoren: 1 bis 50 je Satz.")
	}
	seen := map[string]bool{}
	items := make([]satzEintragDB, 0, len(in.Sensoren))
	for i, v := range in.Sensoren {
		v, target, err := parseTemplateIn(v)
		if err != nil {
			return in, nil, badRequest("Sensor " + itoa(i+1) + ": " + err.Error())
		}
		if utf8.RuneCountInString(v.Name) > checks.MaxName {
			return in, nil, badRequest("Sensor " + itoa(i+1) + ": Name höchstens 100 Zeichen.")
		}
		key := strings.ToLower(v.Name)
		if seen[key] {
			return in, nil, badRequest("Sensor " + itoa(i+1) + ": Name „" + v.Name + "“ kommt doppelt vor.")
		}
		seen[key] = true
		color := ""
		if v.Kennfarbe != nil && *v.Kennfarbe != "" {
			if !uuidPattern.MatchString(*v.Kennfarbe) {
				return in, nil, badRequest("Sensor " + itoa(i+1) + ": Kennfarbe unbekannt.")
			}
			color = strings.ToLower(*v.Kennfarbe)
		}
		items = append(items, satzEintragDB{Name: v.Name, Typ: v.Typ, Ziel: target, Intervall: v.Intervall, Notiz: v.Notiz, Kennfarbe: color})
	}
	raw, err := json.Marshal(items)
	return in, raw, err
}

func itoa(n int) string { return strconv.Itoa(n) }

// checkSetColors (1.0.1): Jede Kennfarbe im Satz muss dem Mandanten des Satzes
// oder einem darüber gehören; sonst sähe sie nicht jeder, der den Satz sieht.
func checkSetColors(ctx context.Context, tx pgx.Tx, tenant string, raw []byte) error {
	var items []satzEintragDB
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	for i, t := range items {
		if t.Kennfarbe == "" {
			continue
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT openwacht.kennfarbe_allowed($1, $2)`, t.Kennfarbe, tenant).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return badRequest("Sensor " + itoa(i+1) + ": Die Kennfarbe gehört nicht zu diesem Mandanten oder einem übergeordneten.")
		}
	}
	return nil
}

func setItemsOut(id string, raw []byte) ([]vorlageOut, error) {
	var items []satzEintragDB
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	out := make([]vorlageOut, len(items))
	for i, t := range items {
		out[i] = vorlageOut{ID: id + "-" + itoa(i+1), Name: t.Name, Typ: t.Typ, Ziel: t.Ziel, Intervall: t.Intervall, Notiz: t.Notiz,
			AmAgent: checks.IsAgentKind(t.Typ), BrauchtAdresse: checks.UsesPlaceholder(t.Ziel)}
		if t.Kennfarbe != "" {
			k := t.Kennfarbe
			out[i].Kennfarbe = &k
		}
	}
	return out, nil
}

// ownSets: alle sichtbaren eigenen Sätze (RLS).
func ownSets(ctx context.Context, tx pgx.Tx) ([]eigenerSatzOut, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, name, note, items, changed_at
		FROM openwacht.sensor_template_sets ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eigenerSatzOut, error) {
		var s eigenerSatzOut
		var raw []byte
		if err := row.Scan(&s.ID, &s.MandantID, &s.Name, &s.Notiz, &raw, &s.Geaendert); err != nil {
			return s, err
		}
		var err error
		s.Sensoren, err = setItemsOut(s.ID, raw)
		return s, err
	})
	if list == nil {
		list = []eigenerSatzOut{}
	}
	return list, err
}

// loadOwnSet für das Anwenden: nicht sichtbar → pgx.ErrNoRows (404).
func loadOwnSet(ctx context.Context, tx pgx.Tx, id string) ([]vorlageOut, string, error) {
	if !uuidPattern.MatchString(id) {
		return nil, "", badRequest("Vorlagensatz unbekannt.")
	}
	var name string
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT name, items FROM openwacht.sensor_template_sets WHERE id = $1`, id).Scan(&name, &raw); err != nil {
		return nil, "", err
	}
	items, err := setItemsOut(id, raw)
	return items, name, err
}

func (s *Server) handleSetCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in satzIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vorlagensatz anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, items, err := parseSetIn(in)
		if err != nil {
			return 0, nil, err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.sensor_template_sets (tenant_id, name, note, items)
			VALUES ($1, $2, $3, $4) RETURNING id::text`, tid, in.Name, in.Notiz, items).Scan(&id); err != nil {
			return 0, nil, err // fremder Mandant oder Leser: 42501 → 403; Name doppelt: 409
		}
		if err := checkSetColors(ctx, tx, tid, items); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "vorlagensatz.angelegt", map[string]any{"id": id, "name": in.Name, "sensoren": len(in.Sensoren)}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleSetUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in satzIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vorlagensatz ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, items, err := parseSetIn(in)
		if err != nil {
			return 0, nil, err
		}
		var tid string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.sensor_template_sets SET name = $2, note = $3, items = $4
			WHERE id = $1 RETURNING tenant_id::text`, id, in.Name, in.Notiz, items).Scan(&tid); err != nil {
			return 0, nil, err // nicht sichtbar oder nur Leser: 404
		}
		if err := checkSetColors(ctx, tx, tid, items); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "vorlagensatz.geaendert", map[string]any{"id": id, "name": in.Name, "sensoren": len(in.Sensoren)}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleSetDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "vorlagensatz löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.sensor_template_sets WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tid, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "vorlagensatz.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}
