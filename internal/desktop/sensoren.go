// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Eigene Oberfläche der Desktop-App (1.0.6): Liste der Sensoren aus
// GET /api/v1/sensoren. Filtern, Sortieren und Texte stehen hier, damit sie
// ohne Windows testbar sind; das Fenster in cmd/desktop zeigt nur an.

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Sensor: die Felder aus GET /api/v1/sensoren, die das Fenster braucht.
type Sensor struct {
	Schluessel string     `json:"schluessel"`
	Art        string     `json:"art"`       // check | host | snmp
	QuelleID   string     `json:"quelle_id"` // bei check: die ID des Checks
	MandantID  string     `json:"mandant_id"`
	GeraetID   string     `json:"geraet_id"`
	Host       string     `json:"host"`
	Name       string     `json:"name"`
	Gegenstand string     `json:"gegenstand"`
	Status     string     `json:"status"` // ok, warn, crit, unknown, pause, neu
	Meldung    string     `json:"meldung"`
	Seit       *time.Time `json:"seit"`
	Alarm      *Alarm     `json:"alarm"`
	Kennfarbe  *Kennfarbe `json:"kennfarbe"` // 0.99.2, nur bei Warnung, Kritisch, Bestätigt sichtbar
}

// Sensoren holt alle Sensoren, die das Token sieht.
func (c Client) Sensoren(ctx context.Context) ([]Sensor, error) {
	var out struct {
		Sensoren []Sensor `json:"sensoren"`
	}
	if err := c.get(ctx, "/api/v1/sensoren", &out); err != nil {
		return nil, err
	}
	return out.Sensoren, nil
}

// Reihenfolge in der Liste: Schlimmstes oben.
var listenRang = map[string]int{"crit": 0, "warn": 1, "unknown": 2, "neu": 3, "pause": 4, "ok": 5}

// StatusText: Wort für die Spalte Zustand.
func StatusText(s string) string {
	switch s {
	case "crit":
		return "Kritisch"
	case "warn":
		return "Warnung"
	case "unknown":
		return "Unbekannt"
	case "ok":
		return "OK"
	case "pause":
		return "Pausiert"
	case "bestaetigt":
		return "Bestätigt"
	case "neu":
		return "Neu"
	}
	return s
}

// Problem: zählt als Problem (Ansicht „nur Probleme“).
func Problem(s string) bool { return s == "crit" || s == "warn" || s == "unknown" }

// Zeile: eine Zeile im Fenster, fertig zum Anzeigen.
type Zeile struct {
	Status     string // wie von der Zentrale (Sortierung)
	Anzeige    string // Status für Form und Farbe: wie Status, „bestaetigt“ bei bestätigtem offenem Alarm
	Zustand    string
	Geraet     string
	Sensor     string
	Meldung    string
	Seit       string
	GeraetID   string
	Bestaetigt bool
	Schluessel string
	Art        string
	QuelleID   string
	AlarmID    string // offener Alarm, sonst leer
	AlarmNeu   bool   // offen und noch nicht bestätigt
	Kenn       *Kennfarbe
}

// Zeilen filtert und sortiert. alle=false: nur Probleme. filter: Wörter,
// die alle in Gerät, Sensor oder Meldung vorkommen müssen (ohne Groß- und
// Kleinschreibung).
func Zeilen(sensoren []Sensor, alle bool, filter string, jetzt time.Time) []Zeile {
	woerter := strings.Fields(strings.ToLower(filter))
	var gefiltert []Sensor
	for _, s := range sensoren {
		if !alle && !Problem(s.Status) {
			continue
		}
		heu := strings.ToLower(s.Host + " " + s.Name + " " + s.Gegenstand + " " + s.Meldung)
		passt := true
		for _, w := range woerter {
			passt = passt && strings.Contains(heu, w)
		}
		if passt {
			gefiltert = append(gefiltert, s)
		}
	}
	sort.SliceStable(gefiltert, func(i, j int) bool {
		a, b := gefiltert[i], gefiltert[j]
		ra, rb := rangVon(a.Status), rangVon(b.Status)
		if ra != rb {
			return ra < rb
		}
		if !strings.EqualFold(a.Host, b.Host) {
			return strings.ToLower(a.Host) < strings.ToLower(b.Host)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	out := make([]Zeile, 0, len(gefiltert))
	for _, s := range gefiltert {
		z := Zeile{
			Status:     s.Status,
			Anzeige:    s.Status,
			Zustand:    StatusText(s.Status),
			Geraet:     Kuerzen(s.Host, 100),
			Sensor:     Kuerzen(s.Name, 120),
			Meldung:    Kuerzen(einzeilig(s.Meldung), 250),
			GeraetID:   s.GeraetID,
			Schluessel: s.Schluessel,
			Art:        s.Art,
			QuelleID:   s.QuelleID,
			Kenn:       s.Kennfarbe,
		}
		if s.Alarm != nil && s.Alarm.Ende == nil {
			z.AlarmID = s.Alarm.ID
			z.AlarmNeu = s.Alarm.Bestaetigt == nil
		}
		if s.Seit != nil {
			z.Seit = SeitText(*s.Seit, jetzt)
		}
		if s.Alarm != nil && s.Alarm.Bestaetigt != nil && s.Alarm.Ende == nil {
			z.Bestaetigt = true
			if Problem(s.Status) {
				z.Anzeige, z.Zustand = "bestaetigt", StatusText("bestaetigt")
			}
		}
		out = append(out, z)
	}
	return out
}

func rangVon(s string) int {
	if r, ok := listenRang[s]; ok {
		return r
	}
	return 9
}

func einzeilig(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// SeitText: „gerade eben“, „vor 12 Min.“, „vor 3 Std.“, „vor 2 Tagen“
// (docs/design/README.md §7).
func SeitText(t, jetzt time.Time) string {
	d := jetzt.Sub(t)
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("vor %d Std.", int(d.Hours()))
	default:
		return fmt.Sprintf("vor %d Tagen", int(d.Hours()/24))
	}
}

// ZeitText: „26.11.2026, 09:06“ in Ortszeit.
func ZeitText(t time.Time) string {
	return t.Local().Format("02.01.2006, 15:04")
}

// Zaehler: Zahl der Sensoren je Zustand für die Kopfzeile.
type Zaehler struct {
	Kritisch, Warnung, Unbekannt, OK int
	Bestaetigt                       int // Problem mit bestätigtem offenem Alarm (nicht in Kritisch usw.)
	Pausiert, Neu                    int
	Sonst                            int // Pausiert + Neu + Unbekanntes
}

func Zaehlen(sensoren []Sensor) Zaehler {
	var z Zaehler
	for _, s := range sensoren {
		if Problem(s.Status) && s.Alarm != nil && s.Alarm.Ende == nil && s.Alarm.Bestaetigt != nil {
			z.Bestaetigt++
			continue
		}
		switch s.Status {
		case "pause":
			z.Pausiert++
			z.Sonst++
		case "neu":
			z.Neu++
			z.Sonst++
		case "crit":
			z.Kritisch++
		case "warn":
			z.Warnung++
		case "unknown":
			z.Unbekannt++
		case "ok":
			z.OK++
		default:
			z.Sonst++
		}
	}
	return z
}

// Text: „2 kritisch · 1 Warnung · 0 unbekannt · 37 OK“.
func (z Zaehler) Text() string {
	w := "Warnungen"
	if z.Warnung == 1 {
		w = "Warnung"
	}
	return fmt.Sprintf("%d kritisch · %d %s · %d unbekannt · %d OK", z.Kritisch, z.Warnung, w, z.Unbekannt, z.OK)
}

// GeraetPfad: Pfad in der Weboberfläche für ein Gerät (Reiter Sensoren).
func GeraetPfad(id string) string {
	if id == "" {
		return "/hosts"
	}
	return "/hosts?geraet=" + url.QueryEscape(id) + "&ansicht=sensoren"
}
