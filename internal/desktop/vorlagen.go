// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Seite Sensor-Vorlagen wie web/src/SensorVorlagen.tsx und
// web/src/Kennfarben.tsx: eingebaute und eigene Vorlagen, Vorlagensätze,
// Anwenden auf Geräte oder eine Gruppe, Kennfarben.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Vorlage aus GET /api/v1/sensor-vorlagen (MandantID nil = eingebaut).
type Vorlage struct {
	ID             string          `json:"id"`
	MandantID      *string         `json:"mandant_id"`
	Name           string          `json:"name"`
	Typ            string          `json:"typ"`
	Ziel           json.RawMessage `json:"ziel"`
	Intervall      int             `json:"intervall_sekunden"`
	Notiz          string          `json:"notiz"`
	AmAgent        bool            `json:"am_agent"`
	BrauchtAdresse bool            `json:"braucht_adresse"`
	KennfarbeID    string          `json:"kennfarbe_id,omitempty"`
}

// VorlagenSatz: mehrere Vorlagen für eine Anwendung.
type VorlagenSatz struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Notiz     string    `json:"notiz"`
	Sensoren  []Vorlage `json:"sensoren"`
	MandantID *string   `json:"mandant_id"`
}

// VorlagenListe: Antwort von GET /api/v1/sensor-vorlagen.
type VorlagenListe struct {
	Eingebaut    []Vorlage      `json:"eingebaut"`
	Eigene       []Vorlage      `json:"eigene"`
	Saetze       []VorlagenSatz `json:"saetze"`
	EigeneSaetze []VorlagenSatz `json:"eigene_saetze"`
}

// KennfarbeEintrag aus GET /api/v1/kennfarben.
type KennfarbeEintrag struct {
	Kennfarbe
	MandantID string `json:"mandant_id"`
	Verwendet int    `json:"verwendet"`
}

// Wo: „Zentrale“, „Agent“ oder „SNMP“ (Spalte „misst“).
func (v Vorlage) Wo() string {
	switch {
	case v.AmAgent:
		return "Agent"
	case v.Typ == "snmp_oid":
		return "SNMP"
	}
	return "Zentrale"
}

// WoTitel: Überschrift der Gruppe in der Tabelle.
func WoTitel(wo string) string {
	switch wo {
	case "Agent":
		return "Auf dem Agent"
	case "SNMP":
		return "Über SNMP"
	}
	return "Prüfungen der Zentrale"
}

// IntervallKurz wie intervallKurz im Web („5 Min.“, „1 Std.“, „30 s“).
func IntervallKurz(s int) string {
	switch {
	case s > 0 && s%3600 == 0:
		return fmt.Sprintf("%d Std.", s/3600)
	case s > 0 && s%60 == 0:
		return fmt.Sprintf("%d Min.", s/60)
	}
	return fmt.Sprintf("%d s", s)
}

// Passt: Suche über Texte, ohne Groß- und Kleinschreibung.
func Passt(suche string, texte ...string) bool {
	q := strings.ToLower(strings.TrimSpace(suche))
	if q == "" {
		return true
	}
	for _, t := range texte {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// VorlagenGruppen: gefiltert, nach „misst“ (Zentrale, Agent, SNMP), darin nach Art und Name.
func VorlagenGruppen(l []Vorlage, suche string) [][]Vorlage {
	var g []Vorlage
	for _, v := range l {
		if Passt(suche, v.Name, TypName(v.Typ), v.Notiz, v.Wo()) {
			g = append(g, v)
		}
	}
	rang := map[string]int{"Zentrale": 0, "Agent": 1, "SNMP": 2}
	sort.SliceStable(g, func(i, j int) bool {
		a, b := g[i], g[j]
		if a.Wo() != b.Wo() {
			return rang[a.Wo()] < rang[b.Wo()]
		}
		if x, y := nameSchluessel(TypName(a.Typ)), nameSchluessel(TypName(b.Typ)); x != y {
			return x < y
		}
		return nameSchluessel(a.Name) < nameSchluessel(b.Name)
	})
	var out [][]Vorlage
	for _, v := range g {
		if n := len(out); n == 0 || out[n-1][0].Wo() != v.Wo() {
			out = append(out, nil)
		}
		out[len(out)-1] = append(out[len(out)-1], v)
	}
	return out
}

var satzPraefix = regexp.MustCompile(`^[^:]+:\s*`)

// SatzSensorenText: „3 Sensoren: Ping · Dienst W32Time · …“ wie im Web.
func SatzSensorenText(s VorlagenSatz) string {
	n := make([]string, len(s.Sensoren))
	for i, v := range s.Sensoren {
		n[i] = satzPraefix.ReplaceAllString(v.Name, "")
	}
	if len(n) == 1 {
		return "1 Sensor: " + n[0]
	}
	return fmt.Sprintf("%d Sensoren: %s", len(s.Sensoren), strings.Join(n, " · "))
}

// SatzEingabe: Rumpf für Anlegen und Ändern eines eigenen Satzes.
func SatzEingabe(name, notiz string, eintraege []Vorlage) map[string]any {
	s := make([]map[string]any, len(eintraege))
	for i, v := range eintraege {
		e := map[string]any{"name": v.Name, "typ": v.Typ, "ziel": v.Ziel, "intervall_sekunden": v.Intervall, "notiz": v.Notiz}
		if v.KennfarbeID != "" {
			e["kennfarbe_id"] = v.KennfarbeID
		}
		s[i] = e
	}
	return map[string]any{"name": strings.TrimSpace(name), "notiz": strings.TrimSpace(notiz), "sensoren": s}
}

// Kontrast der Kennfarbe auf hellem und dunklem Grund (je mindestens 3:1).
const (
	grundHell   RGB = 0xffffff
	grundDunkel RGB = 0x111c29
)

// KennfarbePruefen wie kennfarbePruefen im Web.
func KennfarbePruefen(hex string) (hell, dunkel float64, fehler string) {
	k := &Kennfarbe{Farbe: hex}
	c, ok := k.RGB()
	if !ok {
		return 0, 0, "Bitte als #rrggbb angeben, z. B. #c0307a."
	}
	hell, dunkel = Kontrast(c, grundHell), Kontrast(c, grundDunkel)
	switch {
	case hell < 3:
		fehler = "Auf hellem Grund zu blass. Bitte einen dunkleren oder kräftigeren Ton wählen."
	case dunkel < 3:
		fehler = "Auf dunklem Grund zu dunkel. Bitte einen helleren Ton wählen."
	}
	return hell, dunkel, fehler
}

// KennVorschlaege: Farben mit genug Kontrast wie VORSCHLAEGE im Web, ohne
// #8a5a2b: das Braun schafft auf dunklem Grund nur 2,9:1 und fiele durch die
// eigene Prüfung.
var KennVorschlaege = []string{"#c0307a", "#e05a00", "#00838a", "#7b5cd6", "#2a78d6"}
