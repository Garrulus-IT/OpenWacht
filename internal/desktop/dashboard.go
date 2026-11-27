// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Dashboard wie in der Weboberfläche (1.0.7): dasselbe Layout je Benutzer
// (/api/v1/dashboard/layout), dieselben Widgets, dasselbe Raster. Hier stehen
// das Modell, das Packen des Rasters und die Daten der Widgets; gezeichnet
// wird in cmd/desktop. Die Regeln entsprechen web/src/widgets.ts und
// internal/zentrale/dashboard_layout.go.
//
// Das Layout gehört zum Konto. Mit einem API-Token gibt es keines; die App
// zeigt dann das Standard-Layout und kann es nicht speichern.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DashSpalten    = 12
	DashMinBreite  = 2
	DashMaxHoehe   = 6
	DashMaxWidgets = 60
	DashMaxSeiten  = 8
)

// Widget: ein Feld des Dashboards.
type Widget struct {
	ID        string `json:"id"`
	Typ       string `json:"typ"`
	Groesse   string `json:"groesse,omitempty"` // alt: klein, breit, hoch
	Breite    int    `json:"breite,omitempty"`
	Hoehe     int    `json:"hoehe,omitempty"`
	Titel     string `json:"titel,omitempty"`
	Seite     int    `json:"seite,omitempty"`
	MandantID string `json:"mandant_id,omitempty"`
	GeraetID  string `json:"geraet_id,omitempty"`
	Zeitraum  string `json:"zeitraum,omitempty"`
	Wert      string `json:"wert,omitempty"`
	Text      string `json:"text,omitempty"`
	Sensor    string `json:"sensor,omitempty"`
}

// WidgetArt: Titel, Startgröße und Kurztext einer Art.
type WidgetArt struct {
	Typ, Titel    string
	Breite, Hoehe int
	Text          string
}

// WidgetArten in der Reihenfolge des Katalogs (wie im Web).
var WidgetArten = []WidgetArt{
	{"zustand", "Zustand", 8, 1, "Sensoren und Geräte nach Zustand"},
	{"alarme", "Aktive Alarme", 8, 1, "Tabelle der offenen Alarme"},
	{"sensoren", "Sensoren nicht OK", 4, 1, "kurze Liste aller Probleme"},
	{"auslastung", "CPU und RAM", 4, 2, "aktuelle Auslastung der Hosts"},
	{"platten", "Vollste Platten", 4, 1, "die fünf vollsten Platten"},
	{"prognose", "Platten-Prognose", 4, 1, "Platten, die bald voll sind"},
	{"alarme_je_tag", "Alarme je Tag", 4, 1, "begonnene Alarme, 30 Tage"},
	{"verfuegbarkeit", "Verfügbarkeit", 4, 1, "7 und 30 Tage, schlechteste zuerst"},
	{"graph", "Graph", 8, 1, "CPU oder RAM eines Hosts oder der höchsten"},
	{"sonne", "Sonnendiagramm", 4, 2, "Mandanten, Gruppen und Geräte"},
	{"ereignisse", "Ereignisse (4 Std.)", 4, 2, "Beginn, Ende und Bestätigung von Alarmen"},
	{"zertifikate", "Zertifikate", 4, 1, "TLS-Zertifikate, das zuerst ablaufende oben"},
	{"wartung", "Wartung", 4, 1, "laufende und die nächsten Wartungen"},
	{"sensor", "Einzelner Sensor", 3, 1, "ein Sensor groß, mit Zustand und Meldung"},
	{"uhr", "Uhr", 2, 1, "Uhrzeit und Datum, für den Leitstand"},
	{"notiz", "Notiz", 3, 1, "eigener Text, z. B. die Nummer der Bereitschaft"},
}

// WidgetArtVon liefert die Art; unbekannte Arten (neuere Zentrale) haben ok=false.
func WidgetArtVon(typ string) (WidgetArt, bool) {
	for _, a := range WidgetArten {
		if a.Typ == typ {
			return a, true
		}
	}
	return WidgetArt{Typ: typ, Titel: typ, Breite: 4, Hoehe: 1}, false
}

// DashLayout: Widgets und Namen der Seiten; Eigen = aus der Zentrale geladen
// (sonst Standard, weil noch nichts gespeichert ist oder ein Token keines hat).
type DashLayout struct {
	Widgets []Widget
	Seiten  []string
	Eigen   bool
	// NurLesen: mit API-Token gibt es kein Layout zum Speichern.
	NurLesen bool
}

var altGroessen = map[string][2]int{"klein": {4, 1}, "breit": {8, 1}, "hoch": {4, 2}}

func klemmen(n, von, bis int) int { return max(von, min(bis, n)) }

// Normal: alte Größe umrechnen, Maße und Seite in die Grenzen bringen.
func (w Widget) Normal(seiten int) Widget {
	if w.Breite == 0 || w.Hoehe == 0 {
		g, ok := altGroessen[w.Groesse]
		if !ok {
			g = altGroessen["klein"]
		}
		w.Breite, w.Hoehe = g[0], g[1]
	}
	w.Groesse = ""
	w.Breite, w.Hoehe = klemmen(w.Breite, DashMinBreite, DashSpalten), klemmen(w.Hoehe, 1, DashMaxHoehe)
	if w.Seite < 0 || w.Seite >= max(1, seiten) {
		w.Seite = 0
	}
	return w
}

// StandardLayout wie im Web.
func StandardLayout() []Widget {
	var out []Widget
	for i, typ := range []string{"zustand", "sensoren", "alarme", "auslastung", "ereignisse", "platten", "alarme_je_tag", "prognose",
		"graph", "verfuegbarkeit"} {
		a, _ := WidgetArtVon(typ)
		out = append(out, Widget{ID: "std" + strconv.Itoa(i+1), Typ: typ, Breite: a.Breite, Hoehe: a.Hoehe})
	}
	return out
}

// TitelVon: eigener Titel, sonst der der Art (Graph: Wert und Gerät).
func (w Widget) TitelVon(geraete []Geraet) string {
	if t := strings.TrimSpace(w.Titel); t != "" {
		return t
	}
	if w.Typ == "graph" {
		was := "CPU"
		if w.Wert == "speicher" {
			was = "RAM"
		}
		if w.GeraetID == "" {
			return was + ": die höchsten"
		}
		for _, g := range geraete {
			if g.ID == w.GeraetID {
				return was + ": " + g.Name
			}
		}
		return was + ": Gerät"
	}
	a, _ := WidgetArtVon(w.Typ)
	return a.Titel
}

// DashSpaltenFuer: Spalten des Rasters bei dieser Breite in CSS-Pixeln (96 dpi).
func DashSpaltenFuer(breitePx int) int {
	switch {
	case breitePx >= 780:
		return 12
	case breitePx >= 520:
		return 6
	}
	return 1
}

// Spanne im Raster: bei 6 Spalten halb oder ganz, bei einer immer ganz.
func (w Widget) Spanne(spalten int) int {
	switch spalten {
	case 12:
		return w.Breite
	case 6:
		if w.Breite <= 6 {
			return 3
		}
		return 6
	}
	return 1
}

// Platz: Lage eines Widgets im Raster (Spalte und Reihe ab 0).
type Platz struct {
	X, Y, B, H int
}

// DashPacken verteilt die Widgets wie „grid-auto-flow: dense“: jedes in der
// Reihenfolge an die erste freie Stelle von oben links. Liefert die Plätze und
// die Zahl der Reihen. Bei einer Spalte stehen alle untereinander, je H = 1
// (die Höhe richtet sich dort nach dem Inhalt).
func DashPacken(ws []Widget, spalten int) ([]Platz, int) {
	out := make([]Platz, len(ws))
	var belegt [][]bool
	frei := func(x, y, b, h int) bool {
		for r := y; r < y+h; r++ {
			if r >= len(belegt) {
				continue
			}
			for c := x; c < x+b; c++ {
				if belegt[r][c] {
					return false
				}
			}
		}
		return true
	}
	reihen := 0
	for i, w := range ws {
		b, h := min(w.Spanne(spalten), spalten), w.Hoehe
		if spalten == 1 {
			h = 1
		}
	suche:
		for y := 0; ; y++ {
			for x := 0; x+b <= spalten; x++ {
				if !frei(x, y, b, h) {
					continue
				}
				for len(belegt) < y+h {
					belegt = append(belegt, make([]bool, spalten))
				}
				for r := y; r < y+h; r++ {
					for c := x; c < x+b; c++ {
						belegt[r][c] = true
					}
				}
				out[i] = Platz{x, y, b, h}
				reihen = max(reihen, y+h)
				break suche
			}
		}
	}
	return out, reihen
}

// AufSeite: Indizes der Widgets dieser Seite, in Reihenfolge.
func (l DashLayout) AufSeite(seite int) []int {
	var out []int
	for i, w := range l.Widgets {
		if w.Seite == seite {
			out = append(out, i)
		}
	}
	return out
}

// SeitenNamen: mindestens eine Seite („Übersicht“).
func (l DashLayout) SeitenNamen() []string {
	if len(l.Seiten) == 0 {
		return []string{"Übersicht"}
	}
	return l.Seiten
}

// NeueWidgetID: 8 Zeichen a–z, 0–9, eindeutig im Layout; zufall liefert Bytes.
func NeueWidgetID(ws []Widget, zufall func([]byte)) string {
	const zeichen = "abcdefghijklmnopqrstuvwxyz0123456789"
	for {
		b := make([]byte, 8)
		zufall(b)
		for i := range b {
			b[i] = zeichen[int(b[i])%len(zeichen)]
		}
		id := string(b)
		doppelt := false
		for _, w := range ws {
			doppelt = doppelt || w.ID == id
		}
		if !doppelt {
			return id
		}
	}
}

// SeiteLoeschen: Widgets der Seite verschwinden, die dahinter rücken auf.
func SeiteLoeschen(ws []Widget, seite int) []Widget {
	var out []Widget
	for _, w := range ws {
		if w.Seite == seite {
			continue
		}
		if w.Seite > seite {
			w.Seite--
		}
		out = append(out, w)
	}
	return out
}

// Verschieben: Widget von Index von an die Stelle nach.
func Verschieben(ws []Widget, von, nach int) []Widget {
	if von == nach || von < 0 || nach < 0 || von >= len(ws) || nach >= len(ws) {
		return ws
	}
	out := append([]Widget{}, ws...)
	w := out[von]
	out = append(out[:von], out[von+1:]...)
	out = append(out[:nach], append([]Widget{w}, out[nach:]...)...)
	return out
}

// fuerSpeichern: nur, was die Zentrale kennt; leere Einstellungen fallen weg.
func fuerSpeichern(ws []Widget) []map[string]any {
	out := make([]map[string]any, 0, len(ws))
	for _, w := range ws {
		o := map[string]any{"id": w.ID, "typ": w.Typ, "breite": w.Breite, "hoehe": w.Hoehe}
		if t := strings.TrimSpace(w.Titel); t != "" {
			o["titel"] = t
		}
		if w.Seite > 0 {
			o["seite"] = w.Seite
		}
		if w.MandantID != "" && !(w.Typ == "graph" && w.GeraetID != "") {
			o["mandant_id"] = w.MandantID
		}
		if w.Typ == "graph" {
			if w.GeraetID != "" {
				o["geraet_id"] = w.GeraetID
			}
			if w.Zeitraum != "" {
				o["zeitraum"] = w.Zeitraum
			}
			if w.Wert != "" {
				o["wert"] = w.Wert
			}
		}
		if w.Typ == "notiz" && w.Text != "" {
			o["text"] = w.Text
		}
		if w.Typ == "sensor" && w.Sensor != "" {
			o["sensor"] = w.Sensor
		}
		out = append(out, o)
	}
	return out
}

func verboten(err error) bool {
	var fz *FehlerZentrale
	return errors.Is(err, ErrToken) || (errors.As(err, &fz) && (fz.Code == http.StatusForbidden || fz.Code == http.StatusUnauthorized))
}

// DashHolen lädt das Layout des Kontos. Ohne Sitzung (API-Token) kommt das
// Standard-Layout mit NurLesen.
func (c Client) DashHolen(ctx context.Context) (DashLayout, error) {
	if c.Sitzung == nil || !c.Sitzung.Aktiv() {
		return DashLayout{Widgets: StandardLayout(), NurLesen: true}, nil
	}
	var roh struct {
		Widgets []Widget `json:"widgets"`
		Seiten  []string `json:"seiten"`
	}
	if err := c.get(ctx, "/api/v1/dashboard/layout", &roh); err != nil {
		if verboten(err) {
			return DashLayout{Widgets: StandardLayout(), NurLesen: true}, nil
		}
		return DashLayout{}, err
	}
	if roh.Widgets == nil {
		return DashLayout{Widgets: StandardLayout()}, nil
	}
	l := DashLayout{Seiten: roh.Seiten, Eigen: true, Widgets: make([]Widget, 0, len(roh.Widgets))}
	for _, w := range roh.Widgets {
		l.Widgets = append(l.Widgets, w.Normal(len(roh.Seiten)))
	}
	return l, nil
}

// DashSpeichern schreibt das Layout des Kontos.
func (c Client) DashSpeichern(ctx context.Context, l DashLayout) error {
	seiten := l.Seiten
	if seiten == nil {
		seiten = []string{}
	}
	return c.send(ctx, http.MethodPut, "/api/v1/dashboard/layout", map[string]any{"widgets": fuerSpeichern(l.Widgets), "seiten": seiten}, nil)
}

// DashZuruecksetzen stellt den Standard wieder her.
func (c Client) DashZuruecksetzen(ctx context.Context) error {
	return c.send(ctx, http.MethodDelete, "/api/v1/dashboard/layout", nil, nil)
}

// --- Daten der Widgets ------------------------------------------------------------

// DashAlarm: Alarm aus dem Protokoll (für „Ereignisse“).
type DashAlarm struct {
	ID            string     `json:"id"`
	MandantID     string     `json:"mandant_id"`
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	Schlimmster   string     `json:"schlimmster"`
	Beginn        time.Time  `json:"beginn"`
	Ende          *time.Time `json:"ende"`
	Bestaetigt    *time.Time `json:"bestaetigt_am"`
	BestaetigtVon *string    `json:"bestaetigt_von"`
	Kennfarbe     *Kennfarbe `json:"kennfarbe"`
}

// Platte: Belegung und Prognose (/api/v1/prognose/platten).
type Platte struct {
	Art        string   `json:"art"`
	QuelleID   string   `json:"quelle_id"`
	MandantID  string   `json:"mandant_id"`
	GeraetID   string   `json:"geraet_id"`
	Geraet     string   `json:"geraet"`
	Platte     string   `json:"platte"`
	Belegt     float64  `json:"belegt"`
	Stand      string   `json:"stand"` // steigt, stabil, zu_wenig
	Tage       *float64 `json:"tage"`
	NachSprung bool     `json:"nach_sprung"`
}

// PrognoseText wie im Web („voll in ~12 Tagen“).
func (p Platte) PrognoseText() string {
	switch {
	case p.Stand == "zu_wenig" && p.NachSprung:
		return "Prognose nach Löschung erst ab 3 Tagen"
	case p.Stand == "zu_wenig":
		return "Prognose ab 3 Tagen Verlauf"
	case p.Stand == "stabil" || p.Tage == nil:
		return "wächst nicht"
	case *p.Tage < 1 && p.Belegt >= 99.5:
		return "voll"
	case *p.Tage < 1:
		return "voll in < 1 Tag"
	case *p.Tage > 365:
		return "voll in > 1 Jahr"
	}
	n := int(*p.Tage + 0.5)
	if n == 1 {
		return "voll in ~1 Tag"
	}
	return "voll in ~" + strconv.Itoa(n) + " Tagen"
}

// Kennzahlen (/api/v1/dashboard/kennzahlen).
type Kennzahlen struct {
	AlarmeJeStunde []struct {
		T       int64 `json:"t"`
		Warn    int   `json:"warn"`
		Crit    int   `json:"crit"`
		Unknown int   `json:"unknown"`
	} `json:"alarme_je_stunde"`
	Checks []struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		MandantID string   `json:"mandant_id"`
		GeraetID  string   `json:"geraet_id"`
		Geraet    string   `json:"geraet"`
		Tage7     *float64 `json:"tage7"`
		Tage30    *float64 `json:"tage30"`
	} `json:"checks"`
	Erreichbarkeit []struct {
		Art       string   `json:"art"`
		QuelleID  string   `json:"quelle_id"`
		MandantID string   `json:"mandant_id"`
		GeraetID  string   `json:"geraet_id"`
		Geraet    string   `json:"geraet"`
		Tage7     *float64 `json:"tage7"`
		Tage30    *float64 `json:"tage30"`
	} `json:"erreichbarkeit"`
}

// VerfZeile: eine Zeile der Verfügbarkeit.
type VerfZeile struct {
	Geraet, GeraetID, MandantID, Was string
	Tage7, Tage30                    *float64
}

// Verfuegbarkeit: schlechteste zuerst (7 Tage, dann 30 Tage, dann Name).
func (k Kennzahlen) Verfuegbarkeit(ids map[string]bool) []VerfZeile {
	var out []VerfZeile
	for _, r := range k.Erreichbarkeit {
		if ids[r.MandantID] {
			was := "SNMP antwortet"
			if r.Art == "host" {
				was = "Agent meldet sich"
			}
			out = append(out, VerfZeile{r.Geraet, r.GeraetID, r.MandantID, was, r.Tage7, r.Tage30})
		}
	}
	for _, c := range k.Checks {
		if ids[c.MandantID] {
			out = append(out, VerfZeile{c.Geraet, c.GeraetID, c.MandantID, c.Name, c.Tage7, c.Tage30})
		}
	}
	v := func(p *float64) float64 {
		if p == nil {
			return 101
		}
		return *p
	}
	sort.SliceStable(out, func(i, j int) bool {
		if v(out[i].Tage7) != v(out[j].Tage7) {
			return v(out[i].Tage7) < v(out[j].Tage7)
		}
		if v(out[i].Tage30) != v(out[j].Tage30) {
			return v(out[i].Tage30) < v(out[j].Tage30)
		}
		return strings.ToLower(out[i].Geraet) < strings.ToLower(out[j].Geraet)
	})
	return out
}

// AlarmeJeTag: begonnene Alarme der letzten 30 Tage in der Zeitzone ort, ältester zuerst.
type TagAlarme struct {
	Tag                 time.Time
	Warn, Crit, Unknown int
}

func (k Kennzahlen) AlarmeJeTag(jetzt time.Time) []TagAlarme {
	heute := time.Date(jetzt.Year(), jetzt.Month(), jetzt.Day(), 0, 0, 0, 0, jetzt.Location())
	out := make([]TagAlarme, 30)
	nach := map[string]int{}
	for i := range out {
		out[i].Tag = heute.AddDate(0, 0, i-29)
		nach[out[i].Tag.Format("2006-01-02")] = i
	}
	for _, s := range k.AlarmeJeStunde {
		if i, ok := nach[time.Unix(s.T, 0).In(jetzt.Location()).Format("2006-01-02")]; ok {
			out[i].Warn += s.Warn
			out[i].Crit += s.Crit
			out[i].Unknown += s.Unknown
		}
	}
	return out
}

// Auslastung: aktuelle CPU- und RAM-Werte eines Geräts in Prozent (nil = kein Wert).
type Auslastung struct {
	GeraetID, MandantID, Name string
	CPU, RAM                  *float64
}

type messwerte struct {
	Erfasst *time.Time `json:"erfasst"`
	CPU     *struct {
		Auslastung float64 `json:"auslastung_prozent"`
	} `json:"cpu"`
	Speicher *struct {
		Gesamt     float64 `json:"gesamt"`
		Verfuegbar float64 `json:"verfuegbar"`
	} `json:"speicher"`
}

func (m *messwerte) werte() (cpu, ram *float64) {
	if m == nil {
		return nil, nil
	}
	if m.CPU != nil {
		v := m.CPU.Auslastung
		cpu = &v
	}
	if m.Speicher != nil && m.Speicher.Gesamt > 0 {
		v := (m.Speicher.Gesamt - m.Speicher.Verfuegbar) / m.Speicher.Gesamt * 100
		ram = &v
	}
	return cpu, ram
}

type agentRoh struct {
	MandantID string     `json:"mandant_id"`
	GeraetID  string     `json:"geraet_id"`
	ID        string     `json:"id"`
	Hostname  string     `json:"hostname"`
	Gesehen   *time.Time `json:"zuletzt_gesehen"`
	Gesperrt  *string    `json:"gesperrt"`
	Messwerte *messwerte `json:"messwerte"`
}

type snmpRoh struct {
	ID        string     `json:"id"`
	MandantID string     `json:"mandant_id"`
	GeraetID  string     `json:"geraet_id"`
	Adresse   string     `json:"adresse"`
	Intervall int        `json:"intervall_sekunden"`
	Messwerte *messwerte `json:"messwerte"`
}

// auslastungAus: Agents zuerst, SNMP nur für Geräte ohne Agent; nur frische Werte.
func auslastungAus(agents []agentRoh, intervall int, snmp []snmpRoh, namen map[string]string, jetzt time.Time) []Auslastung {
	frisch := func(t *time.Time, iv int) bool {
		return t != nil && jetzt.Sub(*t) < time.Duration(max(3*iv, 180))*time.Second
	}
	name := func(id, sonst string) string {
		if n := namen[id]; n != "" {
			return n
		}
		return sonst
	}
	var out []Auslastung
	mitAgent := map[string]bool{}
	for _, a := range agents {
		if a.Gesperrt != nil || a.Messwerte == nil || !frisch(a.Gesehen, intervall) {
			continue
		}
		cpu, ram := a.Messwerte.werte()
		out = append(out, Auslastung{a.GeraetID, a.MandantID, name(a.GeraetID, a.Hostname), cpu, ram})
		mitAgent[a.GeraetID] = true
	}
	for _, s := range snmp {
		if s.Messwerte == nil || mitAgent[s.GeraetID] || !frisch(s.Messwerte.Erfasst, s.Intervall) {
			continue
		}
		cpu, ram := s.Messwerte.werte()
		if cpu == nil && ram == nil {
			continue
		}
		out = append(out, Auslastung{s.GeraetID, s.MandantID, name(s.GeraetID, s.Adresse), cpu, ram})
	}
	return out
}

// AuslastungTop: die höchsten n Werte (cpu oder ram) im Bereich.
func AuslastungTop(liste []Auslastung, ids map[string]bool, ram bool, n int) []Auslastung {
	wert := func(a Auslastung) *float64 {
		if ram {
			return a.RAM
		}
		return a.CPU
	}
	var out []Auslastung
	for _, a := range liste {
		if ids[a.MandantID] && wert(a) != nil {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if *wert(out[i]) != *wert(out[j]) {
			return *wert(out[i]) > *wert(out[j])
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// GraphLinie: eine Linie; Punkte sind [Zeit (Unix), Mittel, Minimum, Maximum].
type GraphLinie struct {
	Name      string       `json:"name"`
	Geraet    string       `json:"geraet"`
	MandantID string       `json:"mandant_id"`
	Punkte    [][4]float64 `json:"punkte"`
}

// Graph: Verlauf für ein Graph-Widget.
type Graph struct {
	Spanne, Schritt int
	Linien          []GraphLinie
	// Hinweis statt Linien (z. B. Gerät ohne Messwerte)
	Hinweis string
}

// DashDaten: alles, was die Widgets über den Stand des Hauptfensters hinaus brauchen.
type DashDaten struct {
	Layout     DashLayout
	Alarme     []DashAlarm
	Auslastung []Auslastung
	Platten    []Platte
	Kennzahlen *Kennzahlen
	Wartungen  Wartungen
	Graphen    map[string]Graph // je Widget-ID
	// Fehler je Art (ein Widget meldet seinen Fehler, die übrigen bleiben)
	Fehler map[string]string
	Zeit   time.Time

	// Für das Wiederverwenden teurer Abfragen (wie im Web: Kennzahlen und
	// Prognose alle 5 Minuten, Graphen jede Minute)
	filter    string
	kennZeit  time.Time
	graphZeit map[string]time.Time
	graphSig  map[string]string
}

func (l DashLayout) hat(typen ...string) bool {
	for _, w := range l.Widgets {
		for _, t := range typen {
			if w.Typ == t {
				return true
			}
		}
	}
	return false
}

// DashDatenHolen lädt das Layout (wenn layout nil ist) und die Daten der
// vorhandenen Widget-Arten. ids ist der Bereich der Seitenleiste; er grenzt
// Prognose und Kennzahlen ein (bis 200 Mandanten, sonst alles Sichtbare). alt
// sind die Daten vom letzten Mal; Kennzahlen, Prognose und Graphen daraus
// gelten weiter, solange sie frisch genug sind.
func (c Client) DashDatenHolen(ctx context.Context, layout *DashLayout, st Stand, ids map[string]bool, alt *DashDaten) (DashDaten, error) {
	d := DashDaten{Graphen: map[string]Graph{}, Fehler: map[string]string{}, Zeit: time.Now(),
		graphZeit: map[string]time.Time{}, graphSig: map[string]string{}}
	if layout != nil {
		d.Layout = *layout
	} else {
		l, err := c.DashHolen(ctx)
		if err != nil {
			return d, err
		}
		d.Layout = l
	}
	merken := func(art string, err error) {
		if err != nil {
			d.Fehler[art] = err.Error()
		}
	}
	// Bereich als Filter: alle fest gewählten Mandanten gehören dazu.
	filter := ""
	alle := map[string]bool{}
	for id := range ids {
		alle[id] = true
	}
	for _, w := range d.Layout.Widgets {
		if w.MandantID != "" {
			for id := range BereichIDs(st.Mandanten, w.MandantID, true) {
				alle[id] = true
			}
		}
	}
	if len(alle) > 0 && len(alle) <= 200 {
		l := make([]string, 0, len(alle))
		for id := range alle {
			l = append(l, id)
		}
		sort.Strings(l)
		filter = "mandanten=" + strings.Join(l, ",")
	}
	mit := func(pfad string) string {
		if filter == "" {
			return pfad
		}
		if strings.Contains(pfad, "?") {
			return pfad + "&" + filter
		}
		return pfad + "?" + filter
	}
	namen := map[string]string{}
	for _, g := range st.Geraete {
		namen[g.ID] = g.Name
	}
	var agents struct {
		Agents    []agentRoh `json:"agents"`
		Intervall int        `json:"intervall_sekunden"`
	}
	var snmp struct {
		SNMP []snmpRoh `json:"snmp"`
	}
	if d.Layout.hat("auslastung") {
		err := c.get(ctx, "/api/v1/agents", &agents)
		merken("auslastung", err)
		if err == nil {
			// SNMP ist Zugabe: ohne Recht darauf bleiben die Agents.
			_ = c.get(ctx, "/api/v1/snmp", &snmp)
			d.Auslastung = auslastungAus(agents.Agents, agents.Intervall, snmp.SNMP, namen, d.Zeit)
		}
	}
	if d.Layout.hat("ereignisse") {
		var a struct {
			Alarme []DashAlarm `json:"alarme"`
		}
		merken("ereignisse", c.get(ctx, "/api/v1/alarme?limit=500", &a))
		d.Alarme = a.Alarme
	}
	d.filter = filter
	frisch := alt != nil && alt.filter == filter && d.Zeit.Sub(alt.kennZeit) < 5*time.Minute
	brauchtPlatten, brauchtKenn := d.Layout.hat("platten", "prognose"), d.Layout.hat("alarme_je_tag", "verfuegbarkeit")
	if frisch && (!brauchtPlatten || alt.Platten != nil) && (!brauchtKenn || alt.Kennzahlen != nil) {
		d.Platten, d.Kennzahlen, d.kennZeit = alt.Platten, alt.Kennzahlen, alt.kennZeit
	} else {
		d.kennZeit = d.Zeit
		if brauchtPlatten {
			p := struct {
				Platten []Platte `json:"platten"`
			}{Platten: []Platte{}}
			err := c.get(ctx, mit("/api/v1/prognose/platten"), &p)
			merken("platten", err)
			merken("prognose", err)
			if err == nil {
				d.Platten = p.Platten
			}
		}
		if brauchtKenn {
			var k Kennzahlen
			err := c.get(ctx, mit("/api/v1/dashboard/kennzahlen"), &k)
			merken("alarme_je_tag", err)
			merken("verfuegbarkeit", err)
			if err == nil {
				d.Kennzahlen = &k
			}
		}
	}
	if d.Layout.hat("wartung") {
		w, err := c.WartungenHolen(ctx, "")
		merken("wartung", err)
		d.Wartungen = w
	}
	for _, w := range d.Layout.Widgets {
		if w.Typ != "graph" {
			continue
		}
		sig := w.GeraetID + "|" + w.Zeitraum + "|" + w.Wert + "|" + w.MandantID + "|" + filter
		if alt != nil && alt.graphSig[w.ID] == sig && d.Zeit.Sub(alt.graphZeit[w.ID]) < time.Minute {
			d.Graphen[w.ID], d.graphSig[w.ID], d.graphZeit[w.ID] = alt.Graphen[w.ID], sig, alt.graphZeit[w.ID]
			continue
		}
		g, err := c.graphHolen(ctx, w, mit, st.Geraete)
		if err != nil {
			g.Hinweis = err.Error()
		}
		d.Graphen[w.ID], d.graphSig[w.ID], d.graphZeit[w.ID] = g, sig, d.Zeit
	}
	return d, nil
}

func (c Client) graphHolen(ctx context.Context, w Widget, mit func(string) string, geraete []Geraet) (Graph, error) {
	zeitraum, wert := w.Zeitraum, w.Wert
	if zeitraum == "" {
		zeitraum = "24h"
	}
	if wert == "" {
		wert = "cpu"
	}
	q := "?zeitraum=" + url.QueryEscape(zeitraum)
	if w.GeraetID == "" {
		var v struct {
			Spanne  int `json:"spanne_s"`
			Schritt int `json:"schritt_s"`
			CPU     struct {
				Linien []GraphLinie `json:"linien"`
			} `json:"cpu"`
			Speicher struct {
				Linien []GraphLinie `json:"linien"`
			} `json:"speicher"`
		}
		if err := c.get(ctx, mit("/api/v1/dashboard/verlauf"+q), &v); err != nil {
			return Graph{}, err
		}
		g := Graph{Spanne: v.Spanne, Schritt: v.Schritt, Linien: v.CPU.Linien}
		if wert == "speicher" {
			g.Linien = v.Speicher.Linien
		}
		for i := range g.Linien {
			g.Linien[i].Name = g.Linien[i].Geraet
		}
		return g, nil
	}
	pfad, gefunden := "", false
	for _, g := range geraete {
		if g.ID != w.GeraetID {
			continue
		}
		gefunden = true
		switch {
		case g.AgentID != nil && *g.AgentID != "":
			pfad = "/api/v1/agents/" + p(*g.AgentID) + "/verlauf"
		case g.SNMPID != nil && *g.SNMPID != "":
			pfad = "/api/v1/snmp/" + p(*g.SNMPID) + "/verlauf"
		}
	}
	if !gefunden {
		return Graph{Hinweis: "Gerät nicht mehr vorhanden."}, nil
	}
	if pfad == "" {
		return Graph{Hinweis: "Dieses Gerät hat keine Messwerte (kein Agent, kein SNMP)."}, nil
	}
	var v struct {
		Spanne  int          `json:"spanne_s"`
		Schritt int          `json:"schritt_s"`
		Reihen  []GraphLinie `json:"reihen"`
	}
	if err := c.get(ctx, pfad+q, &v); err != nil {
		return Graph{}, err
	}
	g := Graph{Spanne: v.Spanne, Schritt: v.Schritt}
	for _, r := range v.Reihen {
		if r.Name == wert {
			name := "CPU"
			if wert == "speicher" {
				name = "Arbeitsspeicher"
			}
			g.Linien = []GraphLinie{{Name: name, Punkte: r.Punkte}}
		}
	}
	return g, nil
}

// DashEreignis: Zeile im Widget „Ereignisse“.
type DashEreignis struct {
	Zeit   time.Time
	Status string // crit, warn, unknown, ok, bestaetigt
	Text   string
	Alarm  DashAlarm
}

var wechselText = map[string]string{"crit": "Kritisch", "warn": "Warnung", "unknown": "Unbekannt"}

// Ereignisse der letzten 4 Stunden, neueste zuerst.
func Ereignisse(alarme []DashAlarm, ids map[string]bool, jetzt time.Time) []DashEreignis {
	ab := jetzt.Add(-4 * time.Hour)
	var out []DashEreignis
	for _, a := range alarme {
		if !ids[a.MandantID] {
			continue
		}
		if !a.Beginn.Before(ab) {
			t := wechselText[a.Schlimmster]
			if t == "" {
				t = a.Schlimmster
			}
			out = append(out, DashEreignis{a.Beginn, a.Schlimmster, "› " + t, a})
		}
		if a.Ende != nil && !a.Ende.Before(ab) {
			out = append(out, DashEreignis{*a.Ende, "ok", "› OK", a})
		}
		if a.Bestaetigt != nil && !a.Bestaetigt.Before(ab) {
			t := "bestätigt"
			if a.BestaetigtVon != nil && *a.BestaetigtVon != "" {
				t += " von " + *a.BestaetigtVon
			}
			out = append(out, DashEreignis{*a.Bestaetigt, "bestaetigt", t, a})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Zeit.After(out[j].Zeit) })
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// VorZeit: „gerade eben“, „vor 5 Min.“, „vor 3 Std.“, „vor 2 Tagen“.
func VorZeit(t, jetzt time.Time) string {
	d := jetzt.Sub(t)
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return "vor " + strconv.Itoa(int(d/time.Minute)) + " Min."
	case d < 24*time.Hour:
		return "vor " + strconv.Itoa(int(d/time.Hour)) + " Std."
	case d < 48*time.Hour:
		return "vor 1 Tag"
	}
	return "vor " + strconv.Itoa(int(d/(24*time.Hour))) + " Tagen"
}

// SensorGruppe wie im Web: pause, sonst der Zustand (neu zählt als unbekannt).
// Eine laufende Wartung zeigt die Zentrale in /api/v1/sensoren als „pause“
// nicht an; hier zählt nur der Zustand.
func SensorGruppe(s Sensor) string {
	if s.Status == "neu" {
		return "unknown"
	}
	return s.Status
}

// ZustandZahlen: Sensoren und Geräte (nach ihrem schlimmsten Sensor) je Gruppe.
func ZustandZahlen(sensoren []Sensor, ids map[string]bool) (geraete, sens map[string]int) {
	rang := map[string]int{"crit": 0, "unknown": 1, "warn": 2, "ok": 3, "wartung": 4, "pause": 5}
	geraete, sens = map[string]int{}, map[string]int{}
	je := map[string]string{}
	for _, s := range sensoren {
		if !ids[s.MandantID] {
			continue
		}
		g := SensorGruppe(s)
		sens[g]++
		if alt, ok := je[s.GeraetID]; !ok || rang[g] < rang[alt] {
			je[s.GeraetID] = g
		}
	}
	for _, g := range je {
		geraete[g]++
	}
	return geraete, sens
}

// BalkenBreiten in Prozent wie im Web: Probleme mindestens 6 %, der Rest teilt sich, was bleibt.
func BalkenBreiten(zahl map[string]int) map[string]float64 {
	reihenfolge := []string{"crit", "warn", "unknown", "ok", "wartung", "pause"}
	problem := reihenfolge[:3]
	gesamt := 0
	for _, g := range reihenfolge {
		gesamt += zahl[g]
	}
	out := map[string]float64{}
	if gesamt == 0 {
		return out
	}
	fest := 0.0
	for _, g := range problem {
		if zahl[g] > 0 {
			out[g] = max(6, float64(zahl[g])/float64(gesamt)*100)
			fest += out[g]
		}
	}
	rest := 0
	for _, g := range reihenfolge[3:] {
		rest += zahl[g]
	}
	frei := max(0, 100-fest)
	for _, g := range reihenfolge[3:] {
		if rest > 0 {
			out[g] = float64(zahl[g]) / float64(rest) * frei
		}
	}
	if rest == 0 && fest > 0 {
		for _, g := range problem {
			out[g] = out[g] / fest * 100
		}
	}
	return out
}
