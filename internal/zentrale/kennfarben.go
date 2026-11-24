// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Kennfarben (0.99.2, Migration 0047): ein Name mit einer frei gewählten
// Farbe je Mandant. Ist ein Sensor mit Kennfarbe nicht OK (Warnung, Kritisch,
// Bestätigt), zeigt die Oberfläche ihn in dieser Farbe statt in Gelb bzw. Rot.
// Form und Text der Schwere bleiben, die Schwere für Benachrichtigungen auch.
// Bei gleicher Schwere gewinnt der Sensor ohne Kennfarbe („Rot gewinnt immer“).
//
// Die Farbe ist frei wählbar, muss aber auf hellem und dunklem Grund
// mindestens 3:1 Kontrast haben (WCAG 2.2, 1.4.11 für Grafiken), sonst sieht
// man Form und Fläche nicht mehr. Rechte und Sichtbarkeit setzt RLS durch.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const (
	kennfarbeMinKontrast = 3.0
	kennfarbeMaxName     = 40
)

// Flächen, auf denen eine Kennfarbe erscheint: hell (--flaeche) und dunkel
// (--flaeche im dunklen Thema). Die Wandanzeige ist noch dunkler als die
// dunkle Fläche; wer dort besteht, besteht auch auf der Anzeige.
var (
	kennfarbeHell   = [3]uint8{0xff, 0xff, 0xff}
	kennfarbeDunkel = [3]uint8{0x11, 0x1c, 0x29}
)

var kennfarbePattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// parseHexColor liest „#rrggbb“.
func parseHexColor(s string) ([3]uint8, bool) {
	var c [3]uint8
	if !kennfarbePattern.MatchString(s) {
		return c, false
	}
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(s[1+2*i:3+2*i], 16, 8)
		if err != nil {
			return c, false
		}
		c[i] = uint8(v)
	}
	return c, true
}

// relLuminance nach WCAG 2.2.
func relLuminance(c [3]uint8) float64 {
	lin := func(v uint8) float64 {
		x := float64(v) / 255
		if x <= 0.04045 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c[0]) + 0.7152*lin(c[1]) + 0.0722*lin(c[2])
}

func contrastRatio(a, b [3]uint8) float64 {
	la, lb := relLuminance(a), relLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func ratioText(r float64) string {
	return strings.Replace(strconv.FormatFloat(math.Floor(r*10)/10, 'f', 1, 64), ".", ",", 1)
}

// cleanKennfarbe prüft Farbe und Kontrast und liefert „#rrggbb“ in Kleinbuchstaben.
func cleanKennfarbe(s string) (string, error) {
	s = strings.TrimSpace(s)
	c, ok := parseHexColor(s)
	if !ok {
		return "", badRequest("Die Farbe muss im Format #rrggbb angegeben werden.")
	}
	if r := contrastRatio(c, kennfarbeHell); r < kennfarbeMinKontrast {
		return "", badRequest(fmt.Sprintf("Die Farbe ist auf hellem Grund zu blass (Kontrast %s:1, nötig 3:1). Bitte einen dunkleren oder kräftigeren Ton wählen.", ratioText(r)))
	}
	if r := contrastRatio(c, kennfarbeDunkel); r < kennfarbeMinKontrast {
		return "", badRequest(fmt.Sprintf("Die Farbe ist auf dunklem Grund zu dunkel (Kontrast %s:1, nötig 3:1). Bitte einen helleren Ton wählen.", ratioText(r)))
	}
	return strings.ToLower(s), nil
}

func cleanKennfarbeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > kennfarbeMaxName || !noControl(s) {
		return "", badRequest("Der Name muss 1 bis 40 Zeichen lang sein und darf keine Steuerzeichen enthalten.")
	}
	return s, nil
}

type kennfarbeOut struct {
	ID        string `json:"id"`
	MandantID string `json:"mandant_id"`
	Name      string `json:"name"`
	Farbe     string `json:"farbe"`
	// Zuordnungen, die der Aufrufer sieht (Sensoren, Gegenstände, Trap-Regeln)
	Verwendet int `json:"verwendet"`
}

type kennfarbeIn struct {
	Name  string `json:"name"`
	Farbe string `json:"farbe"`
}

func (s *Server) handleKennfarbeList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "kennfarben", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT k.id::text, k.tenant_id::text, k.name, k.color,
				(SELECT count(*) FROM openwacht.checks c WHERE c.kennfarbe_id = k.id)
				+ (SELECT count(*) FROM openwacht.sensor_kennfarben z WHERE z.kennfarbe_id = k.id)
				+ (SELECT count(*) FROM openwacht.snmp_trap_rules t WHERE t.kennfarbe_id = k.id)
			FROM openwacht.kennfarben k ORDER BY lower(k.name), k.id`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (kennfarbeOut, error) {
			var k kennfarbeOut
			err := row.Scan(&k.ID, &k.MandantID, &k.Name, &k.Farbe, &k.Verwendet)
			return k, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []kennfarbeOut{}
		}
		return http.StatusOK, map[string]any{"kennfarben": list}, nil
	})
}

func parseKennfarbeIn(in kennfarbeIn) (kennfarbeIn, error) {
	var err error
	if in.Name, err = cleanKennfarbeName(in.Name); err != nil {
		return in, err
	}
	in.Farbe, err = cleanKennfarbe(in.Farbe)
	return in, err
}

func (s *Server) handleKennfarbeCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in kennfarbeIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "kennfarbe anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, err := parseKennfarbeIn(in)
		if err != nil {
			return 0, nil, err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.kennfarben (tenant_id, name, color) VALUES ($1, $2, $3)
			RETURNING id::text`, tid, in.Name, in.Farbe).Scan(&id); err != nil {
			return 0, nil, err // fremder Mandant oder Leser: 42501 → 403; Name doppelt: 409
		}
		if err := audit(ctx, tx, &tid, "kennfarbe.angelegt", map[string]any{"id": id, "name": in.Name, "farbe": in.Farbe}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleKennfarbeUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in kennfarbeIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "kennfarbe ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, err := parseKennfarbeIn(in)
		if err != nil {
			return 0, nil, err
		}
		var tid string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.kennfarben SET name = $2, color = $3 WHERE id = $1
			RETURNING tenant_id::text`, id, in.Name, in.Farbe).Scan(&tid); err != nil {
			return 0, nil, err // nicht sichtbar oder nur Leser: 404
		}
		if err := audit(ctx, tx, &tid, "kennfarbe.geaendert", map[string]any{"id": id, "name": in.Name, "farbe": in.Farbe}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleKennfarbeDelete: Sensoren und Regeln verlieren die Kennfarbe
// (Fremdschlüssel SET NULL bzw. CASCADE), sie selbst bleiben.
func (s *Server) handleKennfarbeDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "kennfarbe löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.kennfarben WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tid, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "kennfarbe.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// --- Zuordnung zu Sensoren ------------------------------------------------------

type sensorKennfarbeIn struct {
	Schluessel  string  `json:"schluessel"`
	KennfarbeID *string `json:"kennfarbe_id"`
}

// parseSensorKey zerlegt einen Sensorschlüssel (c:<Check>, h:<Agent>/<Gegenstand>,
// s:<SNMP-Quelle>/<Gegenstand>).
func parseSensorKey(key string) (art, id, subject string, err error) {
	bad := badRequest("Unbekannter Sensor.")
	if len(key) < 3 || len(key) > 2+36+1+300 || !noControl(key) || !utf8.ValidString(key) {
		return "", "", "", bad
	}
	art, rest := key[:2], key[2:]
	switch art {
	case "c:":
		if !uuidPattern.MatchString(rest) {
			return "", "", "", bad
		}
		return "check", rest, "", nil
	case "h:", "s:":
		id, subject, ok := strings.Cut(rest, "/")
		if !ok || !uuidPattern.MatchString(id) || subject == "" || utf8.RuneCountInString(subject) > 300 {
			return "", "", "", bad
		}
		if art == "h:" {
			return "host", id, subject, nil
		}
		return "snmp", id, subject, nil
	}
	return "", "", "", bad
}

func (s *Server) handleSensorKennfarbe(w http.ResponseWriter, r *http.Request) {
	var in sensorKennfarbeIn
	if !readJSON(w, r, &in) {
		return
	}
	art, id, subject, err := parseSensorKey(in.Schluessel)
	if err != nil {
		writeDBError(w, "sensor kennfarbe", err)
		return
	}
	if in.KennfarbeID != nil && !uuidPattern.MatchString(*in.KennfarbeID) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "sensor kennfarbe", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid string
		switch art {
		case "check":
			// 0 Zeilen: nicht sichtbar oder nur Leser (UPDATE-Policy)
			if err := tx.QueryRow(ctx, `UPDATE openwacht.checks SET kennfarbe_id = $2 WHERE id = $1 RETURNING tenant_id::text`,
				id, in.KennfarbeID).Scan(&tid); err != nil {
				return 0, nil, err
			}
		default:
			col, src := "agent_id", "openwacht.agents"
			if art == "snmp" {
				col, src = "snmp_id", "openwacht.snmp_sources"
			}
			if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM `+src+` WHERE id = $1`, id).Scan(&tid); err != nil {
				return 0, nil, err // Quelle nicht sichtbar: 404
			}
			if in.KennfarbeID == nil {
				if _, err := tx.Exec(ctx, `DELETE FROM openwacht.sensor_kennfarben WHERE `+col+` = $1 AND subject = $2`, id, subject); err != nil {
					return 0, nil, err
				}
			} else if _, err := tx.Exec(ctx, `INSERT INTO openwacht.sensor_kennfarben (tenant_id, `+col+`, subject, kennfarbe_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (`+col+`, subject) WHERE `+col+` IS NOT NULL DO UPDATE SET kennfarbe_id = EXCLUDED.kennfarbe_id`,
				tid, id, subject, *in.KennfarbeID); err != nil {
				return 0, nil, err // Leser: 42501 → 403; fremde Kennfarbe: 23514 → 400
			}
		}
		if err := audit(ctx, tx, &tid, "sensor.kennfarbe", map[string]any{"sensor": in.Schluessel, "kennfarbe": in.KennfarbeID}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// --- Auflösung für Sensoren und die Wandanzeige ------------------------------------

// kennfarbeRef: Kennfarbe an Sensoren, Alarmen und Trap-Einträgen.
type kennfarbeRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Farbe string `json:"farbe"`
}

func parseKennfarbeRef(raw []byte) *kennfarbeRef {
	if len(raw) == 0 {
		return nil
	}
	var k kennfarbeRef
	if json.Unmarshal(raw, &k) != nil || k.ID == "" {
		return nil
	}
	return &k
}

// kennfarbenIndex: Zuordnungen der eingebauten Gegenstände, einmal je Abfrage
// gelesen (RLS), dazu die Kennfarben der Trap-Regeln bei Bedarf.
type kennfarbenIndex struct {
	tx    pgx.Tx
	host  map[string]*kennfarbeRef // Agent/Gegenstand
	snmp  map[string]*kennfarbeRef // Quelle/Gegenstand
	rules map[string]*kennfarbeRef
}

func loadKennfarbenIndex(ctx context.Context, tx pgx.Tx) (*kennfarbenIndex, error) {
	ix := &kennfarbenIndex{tx: tx, host: map[string]*kennfarbeRef{}, snmp: map[string]*kennfarbeRef{}, rules: map[string]*kennfarbeRef{}}
	rows, err := tx.Query(ctx, `SELECT agent_id::text, snmp_id::text, subject, openwacht.kennfarbe_json(kennfarbe_id)
		FROM openwacht.sensor_kennfarben`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var agent, snmp *string
		var subject string
		var raw []byte
		if err := rows.Scan(&agent, &snmp, &subject, &raw); err != nil {
			return nil, err
		}
		k := parseKennfarbeRef(raw)
		if k == nil {
			continue // Kennfarbe nicht sichtbar
		}
		if agent != nil {
			ix.host[*agent+"/"+subject] = k
		} else if snmp != nil {
			ix.snmp[*snmp+"/"+subject] = k
		}
	}
	return ix, rows.Err()
}

func (ix *kennfarbenIndex) forHost(agent, subject string) *kennfarbeRef {
	return ix.host[agent+"/"+subject]
}

// forSNMP: eigene Zuordnung, bei Trap-Zuständen sonst die Kennfarbe der Regel.
func (ix *kennfarbenIndex) forSNMP(ctx context.Context, src, subject string) (*kennfarbeRef, error) {
	if k := ix.snmp[src+"/"+subject]; k != nil {
		return k, nil
	}
	rest, ok := strings.CutPrefix(subject, "trap:")
	if !ok || len(rest) < 36 || !uuidPattern.MatchString(rest[:36]) || (len(rest) > 36 && rest[36] != ':') {
		return nil, nil
	}
	rule := rest[:36]
	if k, ok := ix.rules[rule]; ok {
		return k, nil
	}
	var raw []byte
	if err := ix.tx.QueryRow(ctx, `SELECT openwacht.kennfarbe_json(openwacht.trap_rule_kennfarbe($1))`, rule).Scan(&raw); err != nil {
		return nil, err
	}
	k := parseKennfarbeRef(raw)
	ix.rules[rule] = k
	return k, nil
}
