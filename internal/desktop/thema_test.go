// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"math"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Die Farben der App müssen genau den Tokens der Oberfläche entsprechen.
func TestFarbenWieTokens(t *testing.T) {
	b, err := os.ReadFile("../../web/src/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	hell := css[strings.Index(css, ":root {"):strings.Index(css, `:root[data-thema="dunkel"]`)]
	dunkel := css[strings.Index(css, `:root[data-thema="dunkel"]`):]
	dunkel = dunkel[:strings.Index(dunkel, "}")]
	re := regexp.MustCompile(`--([a-z0-9-]+):\s*#([0-9a-f]{6});`)
	werte := func(block string) map[string]RGB {
		m := map[string]RGB{}
		for _, x := range re.FindAllStringSubmatch(block, -1) {
			v, _ := strconv.ParseUint(x[2], 16, 32)
			m[x[1]] = RGB(v)
		}
		return m
	}
	h, d := werte(hell), werte(dunkel)
	rt := reflect.TypeOf(Farben{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Tag.Get("token")
		hv, ok := h[name]
		if !ok {
			t.Fatalf("Token --%s fehlt in tokens.css", name)
		}
		if got := RGB(reflect.ValueOf(Hell).Field(i).Uint()); got != hv {
			t.Errorf("hell --%s: App %06x, Tokens %06x", name, got, hv)
		}
		dv, ok := d[name]
		if !ok {
			t.Fatalf("Token --%s fehlt im dunklen Block", name)
		}
		if got := RGB(reflect.ValueOf(Dunkel).Field(i).Uint()); got != dv {
			t.Errorf("dunkel --%s: App %06x, Tokens %06x", name, got, dv)
		}
	}
}

func TestFormen(t *testing.T) {
	for _, f := range []Form{FormKreis, FormDreieck, FormAchteck, FormAchteckHaken, FormQuadrat, FormRaute, FormRing} {
		img := FormBild(f, Hell.OK, 16)
		voll := 0
		for i := 3; i < len(img.Pix); i += 4 {
			if img.Pix[i] > 128 {
				voll++
			}
		}
		if voll < 20 || voll > 16*16-10 {
			t.Errorf("Form %d: %d gedeckte Pixel", f, voll)
		}
	}
	// Raute und Achteck unterscheiden sich in der Ecke
	r, a := FormBild(FormRaute, Hell.OK, 32), FormBild(FormAchteck, Hell.OK, 32)
	if r.NRGBAAt(6, 6).A != 0 || a.NRGBAAt(6, 6).A == 0 {
		t.Error("Raute oder Achteck falsch")
	}
}

func TestEingebettet(t *testing.T) {
	if len(Schriften()) != 3 || len(Lizenztexte()) != 2 {
		t.Fatalf("Schriften %d, Lizenzen %d", len(Schriften()), len(Lizenztexte()))
	}
	for _, px := range []int{16, 32, 33, 100} {
		if len(Zeichen(px)) < 100 {
			t.Fatalf("Zeichen %d fehlt", px)
		}
	}
}

// Die Farben der Sonne entsprechen den --wand-*-Tokens.
func TestWandFarben(t *testing.T) {
	b, err := os.ReadFile("../../web/src/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	block := css[strings.Index(css, ".wand,"):]
	block = block[:strings.Index(block, "}")]
	re := regexp.MustCompile(`--(wand-[a-z-]+):\s*#([0-9a-f]{6});`)
	m := map[string]RGB{}
	for _, x := range re.FindAllStringSubmatch(block, -1) {
		v, _ := strconv.ParseUint(x[2], 16, 32)
		m[x[1]] = RGB(v)
	}
	for name, v := range map[string]RGB{"wand-ok": Wand.OK, "wand-warn": Wand.Warn, "wand-krit": Wand.Krit, "wand-best": Wand.Best,
		"wand-unbek": Wand.Unbek, "wand-wartung": Wand.Wartung, "wand-text-dunkel": Wand.TextDunkel, "wand-auf-signal": Wand.AufSignal} {
		if m[name] != v {
			t.Errorf("--%s: App %06x, Tokens %06x", name, v, m[name])
		}
	}
}

func TestSonne(t *testing.T) {
	st := Stand{
		Mandanten: []Mandant{{ID: "m1", Name: "Firma", Rolle: "operator"}},
		Gruppen:   []Gruppe{{ID: "g1", MandantID: "m1", Name: "Server"}},
		Geraete: []Geraet{{ID: "d1", MandantID: "m1", Name: "web", GruppeID: sp("g1")}, {ID: "d2", MandantID: "m1", Name: "db", GruppeID: sp("g1")},
			{ID: "d3", MandantID: "m1", Name: "drucker"}},
		Sensoren: []Sensor{{GeraetID: "d1", Status: "crit"}, {GeraetID: "d2", Status: "ok"}, {GeraetID: "d3", Status: "ok"}},
	}
	w := BaumBauen(st)
	seg, ringe := Sonne(w[0])
	if len(seg) != 4 || len(ringe) != 4 {
		t.Fatalf("%d Segmente, %d Radien", len(seg), len(ringe))
	}
	// Gruppe Server hat zwei Geräte und damit zwei Drittel des Kreises
	if s := seg[0]; s.Knoten.Name != "Server" || math.Abs(s.A1-s.A0-4*math.Pi/3) > 1e-9 || s.Status != "crit" {
		t.Fatalf("Server: %+v", s)
	}
	// web (kritisch) tritt hervor, db (OK) endet am Außenrand
	db, web := seg[1], seg[2]
	if db.Knoten.Name != "db" || web.Knoten.Name != "web" || web.R1 <= db.R1 {
		t.Fatalf("Problem tritt nicht hervor: %+v %+v", db, web)
	}
	if i := SonnenTreffer(seg, ringe, 0, -(db.R0+db.R1)/2); i != 1 {
		t.Fatalf("Treffer oben: %d", i)
	}
	img := SonnenBild(seg, ringe, "crit", nil, 120, Hell.Flaeche)
	if img.NRGBAAt(60, 10).A == 0 || img.NRGBAAt(1, 1).A != 0 {
		t.Fatal("Bild leer")
	}
	if b := SonnenBeschriftung("ein sehr langer Gerätename", seg[1].R0, seg[1].R1, seg[1].A0, seg[1].A1); b == nil || b.Text == "" {
		t.Fatalf("Beschriftung %+v", b)
	}
}

// Die Piktogramme der Seitenleiste sind dieselben Pfade wie im Web.
func TestPiktogrammeWieImWeb(t *testing.T) {
	b, err := os.ReadFile("../../web/src/Oberflaeche.tsx")
	if err != nil {
		t.Fatal(err)
	}
	web := string(b)
	for name, pfad := range Piktogramme {
		if name == "extern" {
			continue // nur in der App
		}
		if !strings.Contains(web, `"`+pfad+`"`) {
			t.Errorf("Piktogramm %s: Pfad steht so nicht in Oberflaeche.tsx", name)
		}
		img := PiktogrammBild(name, 0x102030, 20)
		deck := 0
		for i := 3; i < len(img.Pix); i += 4 {
			if img.Pix[i] > 128 {
				deck++
			}
		}
		if deck < 20 || deck > 20*20/2 {
			t.Errorf("Piktogramm %s: %d deckende Pixel", name, deck)
		}
	}
}

func TestWebPfad(t *testing.T) {
	if p := WebPfad("/hosts", "m1", false); p != "/hosts?mandant=m1&unter=nein" {
		t.Fatal(p)
	}
	if p := WebPfad("/hosts?geraet=d1", "m1", true); p != "/hosts?geraet=d1&mandant=m1" {
		t.Fatal(p)
	}
}
