// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Seite Zertifikate wie web/src/Zertifikate.tsx: alle Sensoren
// „TLS-Zertifikat“, Ablaufdatum und Aussteller aus der Meldung des letzten
// Laufs („…; gültig bis 31.01.2027 (noch 67 Tage), Aussteller …“).

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ZertZeile: eine Zeile der Seite.
type ZertZeile struct {
	Check      Check
	Stand      string // ok, warn, crit, unknown, neu, pause
	Bis        *time.Time
	Rest       *int // ganze Tage bis zum Ablauf, negativ = abgelaufen
	Aussteller string
	Problem    string
}

var (
	zertDatum      = regexp.MustCompile(`(\d{2})\.(\d{2})\.(\d{4})`)
	zertAussteller = regexp.MustCompile(`, Aussteller (.+)$`)
)

// CheckAnzeige: Zustand eines Checks wie anzeige() im Web.
func CheckAnzeige(c Check) string {
	if !c.Aktiv {
		return "pause"
	}
	if c.Status == nil {
		return "neu"
	}
	return *c.Status
}

// AnzeigeRang wie rang im Web (kleiner = schlimmer).
var AnzeigeRang = map[string]int{"crit": 0, "unknown": 1, "warn": 2, "neu": 3, "ok": 4, "pause": 5}

// AnzeigeText wie anzeigeText im Web.
var AnzeigeText = map[string]string{"ok": "OK", "warn": "Warnung", "crit": "Kritisch", "unknown": "Unbekannt",
	"neu": "noch nicht geprüft", "pause": "Pausiert"}

// ZertLesen liest Datum, Aussteller und Problem aus der Meldung.
func ZertLesen(c Check, heute time.Time) ZertZeile {
	m := ""
	if c.Meldung != nil {
		m = *c.Meldung
	}
	z := ZertZeile{Check: c, Stand: CheckAnzeige(c)}
	if d := zertDatum.FindStringSubmatch(m); d != nil {
		tag, _ := strconv.Atoi(d[1])
		mon, _ := strconv.Atoi(d[2])
		jahr, _ := strconv.Atoi(d[3])
		x := time.Date(jahr, time.Month(mon), tag, 0, 0, 0, 0, heute.Location())
		if x.Day() == tag {
			z.Bis = &x
			t0 := time.Date(heute.Year(), heute.Month(), heute.Day(), 0, 0, 0, 0, heute.Location())
			r := int(x.Sub(t0).Round(24*time.Hour) / (24 * time.Hour))
			z.Rest = &r
		}
	}
	if a := zertAussteller.FindStringSubmatch(m); a != nil {
		z.Aussteller = a[1]
	}
	if i := strings.Index(m, "; gültig bis "); i > 0 {
		z.Problem = m[:i]
	} else if z.Bis == nil {
		z.Problem = m
	}
	return z
}

// Zertifikate: Zeilen im Bereich ids, das zuerst ablaufende oben.
func Zertifikate(checks []Check, ids map[string]bool, heute time.Time) []ZertZeile {
	var out []ZertZeile
	for _, c := range checks {
		if c.Typ == "tls" && ids[c.MandantID] {
			out = append(out, ZertLesen(c, heute))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Rest == nil || b.Rest == nil {
			if a.Rest == nil && b.Rest == nil {
				return AnzeigeRang[a.Stand] < AnzeigeRang[b.Stand]
			}
			return b.Rest == nil
		}
		if *a.Rest != *b.Rest {
			return *a.Rest < *b.Rest
		}
		return AnzeigeRang[a.Stand] < AnzeigeRang[b.Stand]
	})
	return out
}

// RestText wie restText im Web.
func (z ZertZeile) RestText() string {
	if z.Rest == nil {
		return "–"
	}
	r := *z.Rest
	switch {
	case r == -1:
		return "seit 1 Tag abgelaufen"
	case r < 0:
		return fmt.Sprintf("seit %d Tagen abgelaufen", -r)
	case r == 0:
		return "läuft heute ab"
	case r == 1:
		return "1 Tag"
	}
	return fmt.Sprintf("%d Tage", r)
}

// Adresse wie adresse() im Web: host[:port][ über verbinde].
func (z ZertZeile) Adresse() string {
	var ziel struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Verbinde string `json:"verbinde"`
	}
	_ = json.Unmarshal(z.Check.Ziel, &ziel)
	s := ziel.Host
	if ziel.Port != 0 && ziel.Port != 443 {
		s += ":" + strconv.Itoa(ziel.Port)
	}
	if ziel.Verbinde != "" {
		s += " über " + ziel.Verbinde
	}
	return s
}

// Bald: läuft in höchstens tage Tagen ab.
func (z ZertZeile) Bald(tage int) bool { return z.Rest != nil && *z.Rest <= tage }

// MitProblem: Kritisch, Warnung oder Unbekannt.
func (z ZertZeile) MitProblem() bool {
	return z.Stand == "crit" || z.Stand == "warn" || z.Stand == "unknown"
}
