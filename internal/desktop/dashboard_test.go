// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestWidgetNormal(t *testing.T) {
	for _, c := range []struct {
		in   Widget
		n    int
		b, h int
		s    int
	}{
		{Widget{Groesse: "klein"}, 0, 4, 1, 0},
		{Widget{Groesse: "breit"}, 0, 8, 1, 0},
		{Widget{Groesse: "hoch"}, 0, 4, 2, 0},
		{Widget{}, 0, 4, 1, 0},
		{Widget{Breite: 12, Hoehe: 6, Seite: 1}, 2, 12, 6, 1},
		{Widget{Breite: 40, Hoehe: 9, Seite: 3}, 2, 12, 6, 0},
		{Widget{Breite: 1, Hoehe: 1, Seite: -1}, 2, 2, 1, 0},
	} {
		got := c.in.Normal(c.n)
		if got.Breite != c.b || got.Hoehe != c.h || got.Seite != c.s || got.Groesse != "" {
			t.Errorf("%+v → %+v", c.in, got)
		}
	}
}

// TestDashPacken: wie „grid-auto-flow: dense“ im Web.
func TestDashPacken(t *testing.T) {
	w := func(b, h int) Widget { return Widget{Breite: b, Hoehe: h} }
	// Standard-Layout im 12er-Raster
	pl, reihen := DashPacken(StandardLayout(), 12)
	want := []Platz{{0, 0, 8, 1}, {8, 0, 4, 1}, {0, 1, 8, 1}, {8, 1, 4, 2}, {0, 2, 4, 2}, {4, 2, 4, 1}, {4, 3, 4, 1}, {8, 3, 4, 1},
		{0, 4, 8, 1}, {8, 4, 4, 1}}
	if !reflect.DeepEqual(pl, want) || reihen != 5 {
		t.Errorf("Standard: %v, %d Reihen", pl, reihen)
	}
	// Lücke wird von einem späteren, passenden Widget gefüllt (dense).
	pl, reihen = DashPacken([]Widget{w(8, 1), w(8, 1), w(4, 1), w(4, 1)}, 12)
	if !reflect.DeepEqual(pl, []Platz{{0, 0, 8, 1}, {0, 1, 8, 1}, {8, 0, 4, 1}, {8, 1, 4, 1}}) || reihen != 2 {
		t.Errorf("dense: %v, %d", pl, reihen)
	}
	// 6 Spalten: halb oder ganz
	pl, reihen = DashPacken([]Widget{w(2, 1), w(6, 2), w(7, 1), w(12, 1)}, 6)
	if !reflect.DeepEqual(pl, []Platz{{0, 0, 3, 1}, {3, 0, 3, 2}, {0, 2, 6, 1}, {0, 3, 6, 1}}) || reihen != 4 {
		t.Errorf("6 Spalten: %v, %d", pl, reihen)
	}
	// eine Spalte: untereinander, je eine Reihe
	pl, reihen = DashPacken([]Widget{w(2, 1), w(6, 4)}, 1)
	if !reflect.DeepEqual(pl, []Platz{{0, 0, 1, 1}, {0, 1, 1, 1}}) || reihen != 2 {
		t.Errorf("1 Spalte: %v, %d", pl, reihen)
	}
	if _, n := DashPacken(nil, 12); n != 0 {
		t.Error("leer")
	}
	for px, want := range map[int]int{1920: 12, 780: 12, 779: 6, 520: 6, 519: 1} {
		if got := DashSpaltenFuer(px); got != want {
			t.Errorf("Spalten bei %d: %d", px, got)
		}
	}
}

func TestDashBearbeiten(t *testing.T) {
	ws := []Widget{{ID: "a"}, {ID: "b", Seite: 1}, {ID: "c", Seite: 2}, {ID: "d"}}
	if got := SeiteLoeschen(ws, 1); len(got) != 3 || got[1].ID != "c" || got[1].Seite != 1 || got[2].Seite != 0 {
		t.Errorf("SeiteLoeschen: %+v", got)
	}
	ids := func(l []Widget) string {
		s := ""
		for _, w := range l {
			s += w.ID
		}
		return s
	}
	if got := ids(Verschieben(ws, 0, 2)); got != "bcad" {
		t.Errorf("Verschieben 0→2: %s", got)
	}
	if got := ids(Verschieben(ws, 3, 0)); got != "dabc" {
		t.Errorf("Verschieben 3→0: %s", got)
	}
	if got := ids(Verschieben(ws, 1, 9)); got != "abcd" {
		t.Errorf("Verschieben außerhalb: %s", got)
	}
	n := byte(0)
	id := NeueWidgetID([]Widget{{ID: "aaaaaaaa"}}, func(b []byte) {
		for i := range b {
			b[i] = n
		}
		n++
	})
	if id != "bbbbbbbb" {
		t.Errorf("NeueWidgetID: %s", id)
	}
	l := DashLayout{Widgets: ws}
	if !reflect.DeepEqual(l.AufSeite(0), []int{0, 3}) || l.SeitenNamen()[0] != "Übersicht" {
		t.Error("AufSeite/SeitenNamen")
	}
}

func TestFuerSpeichern(t *testing.T) {
	got := fuerSpeichern([]Widget{
		{ID: "aaaa", Typ: "graph", Breite: 8, Hoehe: 1, GeraetID: "g", MandantID: "m", Zeitraum: "7t", Wert: "speicher", Text: "x"},
		{ID: "bbbb", Typ: "notiz", Breite: 3, Hoehe: 2, Titel: " Hallo ", Seite: 2, Text: "a\nb", Sensor: "c:x", Zeitraum: "1h"},
		{ID: "cccc", Typ: "sensor", Breite: 3, Hoehe: 1, Sensor: "c:x", MandantID: "m"},
	})
	want := []map[string]any{
		{"id": "aaaa", "typ": "graph", "breite": 8, "hoehe": 1, "geraet_id": "g", "zeitraum": "7t", "wert": "speicher"},
		{"id": "bbbb", "typ": "notiz", "breite": 3, "hoehe": 2, "titel": "Hallo", "seite": 2, "text": "a\nb"},
		{"id": "cccc", "typ": "sensor", "breite": 3, "hoehe": 1, "sensor": "c:x", "mandant_id": "m"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v", got)
	}
}

// TestWidgetArtenWieImWeb: Arten, Titel und Startgrößen stimmen mit web/src/widgets.ts überein.
func TestWidgetArtenWieImWeb(t *testing.T) {
	b, err := os.ReadFile("../../web/src/widgets.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^  (\w+): \{ titel: "([^"]+)", breite: (\d+), hoehe: (\d+), text: "([^"]+)" \},$`)
	web := re.FindAllStringSubmatch(string(b), -1)
	if len(web) != len(WidgetArten) {
		t.Fatalf("Web hat %d Arten, die App %d", len(web), len(WidgetArten))
	}
	for i, m := range web {
		a := WidgetArten[i]
		if m[1] != a.Typ || m[2] != a.Titel || m[3] != itoa(a.Breite) || m[4] != itoa(a.Hoehe) || m[5] != a.Text {
			t.Errorf("Art %d: Web %v, App %+v", i, m[1:], a)
		}
	}
	if !strings.Contains(string(b), "breitePx >= 780 ? 12 : breitePx >= 520 ? 6 : 1") {
		t.Error("Schwellen der Spalten im Web geändert: DashSpaltenFuer anpassen")
	}
}

func TestKennzahlenUndEreignisse(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	var k Kennzahlen
	k.Erreichbarkeit = append(k.Erreichbarkeit, struct {
		Art       string   `json:"art"`
		QuelleID  string   `json:"quelle_id"`
		MandantID string   `json:"mandant_id"`
		GeraetID  string   `json:"geraet_id"`
		Geraet    string   `json:"geraet"`
		Tage7     *float64 `json:"tage7"`
		Tage30    *float64 `json:"tage30"`
	}{"host", "q", "m", "g1", "web01", f(99.5), f(99.9)})
	k.Checks = append(k.Checks, struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		MandantID string   `json:"mandant_id"`
		GeraetID  string   `json:"geraet_id"`
		Geraet    string   `json:"geraet"`
		Tage7     *float64 `json:"tage7"`
		Tage30    *float64 `json:"tage30"`
	}{"c1", "Ping", "m", "g2", "db01", f(90), f(95)}, struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		MandantID string   `json:"mandant_id"`
		GeraetID  string   `json:"geraet_id"`
		Geraet    string   `json:"geraet"`
		Tage7     *float64 `json:"tage7"`
		Tage30    *float64 `json:"tage30"`
	}{"c2", "Ping", "fremd", "g3", "x", f(1), f(1)})
	v := k.Verfuegbarkeit(map[string]bool{"m": true})
	if len(v) != 2 || v[0].Geraet != "db01" || v[1].Was != "Agent meldet sich" {
		t.Errorf("Verfügbarkeit: %+v", v)
	}
	ort := time.FixedZone("MEZ", 3600)
	jetzt := time.Date(2026, 11, 27, 10, 0, 0, 0, ort)
	k.AlarmeJeStunde = append(k.AlarmeJeStunde, struct {
		T       int64 `json:"t"`
		Warn    int   `json:"warn"`
		Crit    int   `json:"crit"`
		Unknown int   `json:"unknown"`
	}{jetzt.Add(-2 * time.Hour).Unix(), 1, 2, 0}, struct {
		T       int64 `json:"t"`
		Warn    int   `json:"warn"`
		Crit    int   `json:"crit"`
		Unknown int   `json:"unknown"`
	}{jetzt.AddDate(0, 0, -40).Unix(), 5, 5, 5})
	tage := k.AlarmeJeTag(jetzt)
	if len(tage) != 30 || tage[29].Crit != 2 || tage[29].Warn != 1 || tage[0].Crit != 0 || tage[0].Tag.Day() != 29 {
		t.Errorf("AlarmeJeTag: %+v … %+v", tage[0], tage[29])
	}

	ende, best, von := jetzt.Add(-time.Hour), jetzt.Add(-30*time.Minute), "erika"
	ev := Ereignisse([]DashAlarm{
		{ID: "1", MandantID: "m", Name: "web01 · Ping", Schlimmster: "crit", Beginn: jetzt.Add(-2 * time.Hour), Ende: &ende},
		{ID: "2", MandantID: "m", Name: "db01 · Platte", Schlimmster: "warn", Beginn: jetzt.Add(-9 * time.Hour), Bestaetigt: &best, BestaetigtVon: &von},
		{ID: "3", MandantID: "fremd", Schlimmster: "crit", Beginn: jetzt},
	}, map[string]bool{"m": true}, jetzt)
	if len(ev) != 3 || ev[0].Text != "bestätigt von erika" || ev[1].Status != "ok" || ev[2].Text != "› Kritisch" {
		t.Errorf("Ereignisse: %+v", ev)
	}
	for d, want := range map[time.Duration]string{30 * time.Second: "gerade eben", 5 * time.Minute: "vor 5 Min.", 3 * time.Hour: "vor 3 Std.",
		30 * time.Hour: "vor 1 Tag", 72 * time.Hour: "vor 3 Tagen"} {
		if got := VorZeit(jetzt.Add(-d), jetzt); got != want {
			t.Errorf("VorZeit(%v) = %q", d, got)
		}
	}
}

func TestAuslastungUndZustand(t *testing.T) {
	jetzt := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	frisch, alt := jetzt.Add(-time.Minute), jetzt.Add(-time.Hour)
	mw := func(cpu, gesamt, frei float64, t *time.Time) *messwerte {
		m := &messwerte{Erfasst: t}
		m.CPU = &struct {
			Auslastung float64 `json:"auslastung_prozent"`
		}{cpu}
		m.Speicher = &struct {
			Gesamt     float64 `json:"gesamt"`
			Verfuegbar float64 `json:"verfuegbar"`
		}{gesamt, frei}
		return m
	}
	gesperrt := "x"
	l := auslastungAus([]agentRoh{
		{MandantID: "m", GeraetID: "g1", Hostname: "web01", Gesehen: &frisch, Messwerte: mw(80, 100, 25, nil)},
		{MandantID: "m", GeraetID: "g2", Hostname: "alt", Gesehen: &alt, Messwerte: mw(99, 100, 1, nil)},
		{MandantID: "m", GeraetID: "g3", Hostname: "zu", Gesehen: &frisch, Gesperrt: &gesperrt, Messwerte: mw(99, 100, 1, nil)},
	}, 60, []snmpRoh{
		{MandantID: "m", GeraetID: "g1", Adresse: "10.0.0.1", Intervall: 300, Messwerte: mw(5, 100, 90, &frisch)},
		{MandantID: "m", GeraetID: "g4", Adresse: "10.0.0.4", Intervall: 300, Messwerte: mw(40, 0, 0, &frisch)},
		{MandantID: "x", GeraetID: "g5", Adresse: "10.0.0.5", Intervall: 300, Messwerte: mw(90, 10, 5, &frisch)},
	}, map[string]string{"g1": "Webserver"}, jetzt)
	if len(l) != 3 || l[0].Name != "Webserver" || *l[0].RAM != 75 || l[1].RAM != nil || l[1].Name != "10.0.0.4" {
		t.Fatalf("Auslastung: %+v", l)
	}
	top := AuslastungTop(l, map[string]bool{"m": true}, false, 8)
	if len(top) != 2 || top[0].GeraetID != "g1" {
		t.Errorf("Top CPU: %+v", top)
	}
	if top := AuslastungTop(l, map[string]bool{"m": true}, true, 8); len(top) != 1 {
		t.Errorf("Top RAM: %+v", top)
	}

	ger, sens := ZustandZahlen([]Sensor{
		{MandantID: "m", GeraetID: "a", Status: "ok"}, {MandantID: "m", GeraetID: "a", Status: "crit"},
		{MandantID: "m", GeraetID: "b", Status: "neu"}, {MandantID: "m", GeraetID: "b", Status: "warn"},
		{MandantID: "m", GeraetID: "c", Status: "pause"}, {MandantID: "x", GeraetID: "d", Status: "crit"},
	}, map[string]bool{"m": true})
	if ger["crit"] != 1 || ger["unknown"] != 1 || ger["pause"] != 1 || sens["crit"] != 1 || sens["ok"] != 1 || sens["unknown"] != 1 {
		t.Errorf("Zustand: %v %v", ger, sens)
	}
	b := BalkenBreiten(map[string]int{"crit": 1, "ok": 999})
	if b["crit"] != 6 || b["ok"] != 94 {
		t.Errorf("Balken: %v", b)
	}
	if b := BalkenBreiten(map[string]int{"crit": 1, "warn": 3}); b["crit"]+b["warn"] < 99.9 || b["crit"]+b["warn"] > 100.1 {
		t.Errorf("Balken nur Probleme: %v", b)
	}
}

func TestPrognoseText(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for want, p := range map[string]Platte{
		"voll in ~12 Tagen":           {Stand: "steigt", Tage: f(12.4)},
		"voll in ~1 Tag":              {Stand: "steigt", Tage: f(1.2)},
		"voll":                        {Stand: "steigt", Tage: f(0.2), Belegt: 99.8},
		"voll in < 1 Tag":             {Stand: "steigt", Tage: f(0.2), Belegt: 97},
		"voll in > 1 Jahr":            {Stand: "steigt", Tage: f(400)},
		"wächst nicht":                {Stand: "stabil"},
		"Prognose ab 3 Tagen Verlauf": {Stand: "zu_wenig"},
	} {
		if got := p.PrognoseText(); got != want {
			t.Errorf("%+v: %q", p, got)
		}
	}
}
