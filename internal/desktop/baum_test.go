// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/checks"
)

func sp(s string) *string { return &s }

func TestBaumBauen(t *testing.T) {
	st := Stand{
		Mandanten: []Mandant{{ID: "m1", Name: "Firma", Rolle: "operator"}, {ID: "m2", Ueber: sp("m1"), Name: "Werk", Rolle: "leser"}},
		Gruppen: []Gruppe{{ID: "g2", MandantID: "m1", ElternID: sp("g1"), Name: "Linux"}, {ID: "g1", MandantID: "m1", Name: "Server"},
			{ID: "gx", MandantID: "m9", Name: "fremd"}},
		Geraete: []Geraet{{ID: "d1", MandantID: "m1", Name: "web", GruppeID: sp("g2")}, {ID: "d2", MandantID: "m1", Name: "Drucker"},
			{ID: "d3", MandantID: "m2", Name: "sps", GruppeID: sp("weg")}},
		Sensoren: []Sensor{{GeraetID: "d1", Status: "crit"}, {GeraetID: "d1", Status: "ok"}, {GeraetID: "d3", Status: "warn"},
			{GeraetID: "d2", Status: "pause"}},
	}
	w := BaumBauen(st)
	if len(w) != 1 || w[0].ID != "m1" {
		t.Fatalf("Wurzeln: %+v", w)
	}
	var namen []string
	for _, k := range w[0].Kinder {
		namen = append(namen, k.Name)
	}
	if !reflect.DeepEqual(namen, []string{"Werk", "Server", "Drucker"}) {
		t.Fatalf("Reihenfolge: %v", namen)
	}
	if z := w[0].Zaehler; z.Kritisch != 1 || z.Warnung != 1 || z.OK != 1 || z.Sonst != 1 {
		t.Fatalf("Zähler: %+v", z)
	}
	if got := w[0].Beschriftung(); got != "Firma" {
		t.Fatalf("Beschriftung %q", got)
	}
	web := Finden(w, KnotenGeraet, "d1")
	if web == nil || web.Rolle != "operator" || web.Zustand() != "crit" {
		t.Fatalf("d1: %+v", web)
	}
	sps := Finden(w, KnotenGeraet, "d3") // Gruppe unbekannt: direkt unter dem Mandanten
	if sps == nil || sps.Rolle != "leser" || DarfAendern(sps.Rolle) {
		t.Fatalf("d3: %+v", sps)
	}
	if n := len(SensorenUnter(Finden(w, KnotenGruppe, "g1"), st.Sensoren)); n != 2 {
		t.Fatalf("Sensoren unter Server: %d", n)
	}
	if Finden(w, KnotenGeraet, "d2").Zustand() != "pause" {
		t.Fatal("nur pausierte Sensoren")
	}
}

// Jeder Typ bietet genau die Felder an, die die Zentrale für ihn annimmt.
func TestTypenPassenZurZentrale(t *testing.T) {
	if len(Typen) != len(checks.Kinds) {
		t.Fatalf("%d Typen, die Zentrale kennt %d", len(Typen), len(checks.Kinds))
	}
	for _, k := range checks.Kinds {
		typ, ok := TypNach(k)
		if !ok {
			t.Fatalf("Typ %s fehlt", k)
		}
		if typ.AmAgent != checks.IsAgentKind(k) {
			t.Errorf("%s: AmAgent falsch", k)
		}
		alle := map[string]bool{}
		for _, f := range typ.Felder {
			alle[f.Schluessel] = true
			// Ein Feld allein: Die Zentrale darf es nie als fremd ablehnen.
			z, err := ZielAusWerten(Typ{Felder: []Feld{f}}, map[string]string{f.Schluessel: beispiel(f)})
			if err != nil {
				t.Fatalf("%s/%s: %v", k, f.Schluessel, err)
			}
			if _, err := checks.Parse(k, z); err != nil && strings.Contains(err.Error(), "passt nicht") {
				t.Errorf("%s: %v", k, err)
			}
		}
		// Und kein Feld der Zentrale fehlt: ein JSON-Name aus Spec, der hier
		// nicht angeboten wird, muss abgelehnt werden.
		for _, name := range specFelder() {
			if alle[name] {
				continue
			}
			z, _ := json.Marshal(map[string]any{name: probe(name)})
			if _, err := checks.Parse(k, z); err == nil || !strings.Contains(err.Error(), "passt nicht") {
				t.Errorf("%s: Feld %s nimmt die Zentrale an, der Dialog bietet es nicht (%v)", k, name, err)
			}
		}
	}
}

func specFelder() []string {
	var out []string
	rt := reflect.TypeOf(checks.Spec{})
	for i := 0; i < rt.NumField(); i++ {
		if n, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ","); n != "" && n != "-" {
			out = append(out, n)
		}
	}
	return out
}

func probe(name string) any {
	f := reflect.TypeOf(checks.Spec{})
	for i := 0; i < f.NumField(); i++ {
		if n, _, _ := strings.Cut(f.Field(i).Tag.Get("json"), ","); n == name {
			return probeWert(f.Field(i).Type)
		}
	}
	return nil
}

// probeWert: ein Wert ungleich null, damit das Feld im JSON nicht wegfällt.
func probeWert(t reflect.Type) any {
	switch t.Kind() {
	case reflect.String:
		return "x"
	case reflect.Bool:
		return true
	case reflect.Int, reflect.Int64, reflect.Float64:
		return 1
	case reflect.Slice:
		return []any{probeWert(t.Elem())}
	case reflect.Pointer:
		return probeWert(t.Elem())
	}
	return nil
}

func beispiel(f Feld) string {
	switch f.Art {
	case FeldGanzzahl:
		return "5"
	case FeldZahl:
		return "1,5"
	case FeldJaNein:
		return "ja"
	case FeldZahlListe:
		return "200, 204"
	case FeldAuswahl:
		return f.Optionen[len(f.Optionen)-1]
	}
	return "x"
}

func TestZielUmwandeln(t *testing.T) {
	typ, _ := TypNach("http_json")
	z, err := ZielAusWerten(typ, map[string]string{"url": " https://a.example/x ", "erwarte_status": "200, 204",
		"warnung_ueber": "1,5", "kritisch_ueber": "", "timeout_s": "7"})
	if err != nil {
		t.Fatal(err)
	}
	if string(z) != `{"erwarte_status":[200,204],"timeout_s":7,"url":"https://a.example/x","warnung_ueber":1.5}` {
		t.Fatalf("Ziel %s", z)
	}
	w := WerteAusZiel(typ, z)
	if w["warnung_ueber"] != "1,5" || w["erwarte_status"] != "200, 204" || w["timeout_s"] != "7" {
		t.Fatalf("Werte %v", w)
	}
	if _, err := ZielAusWerten(typ, map[string]string{"timeout_s": "sieben"}); err == nil || !strings.Contains(err.Error(), "Zeitlimit") {
		t.Fatalf("Fehler %v", err)
	}
	if got := ZielText("tcp", json.RawMessage(`{"host":"a","port":22}`)); got != "Adresse: a · Port: 22" {
		t.Fatalf("ZielText %q", got)
	}
}

func TestAenderungen(t *testing.T) {
	var log []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		log = append(log, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+string(b))
		if r.Header.Get("Authorization") != "Bearer owt1.x" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/api/v1/checks/c1" && r.Method == http.MethodPut {
			w.WriteHeader(400)
			w.Write([]byte(`{"fehler":"Intervall: 30 Sekunden bis 1 Tag."}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := Client{Zentrale: srv.URL, Token: "owt1.x", HTTP: srv.Client()}
	ctx := context.Background()
	if err := c.CheckAnlegen(ctx, "d1", CheckEingabe{Name: "", Typ: "ping", Ziel: json.RawMessage(`{"host":"a"}`), Intervall: 60}); err != nil {
		t.Fatal(err)
	}
	err := c.CheckAktiv(ctx, Check{ID: "c1", Name: "Ping", Typ: "ping", Ziel: json.RawMessage(`{}`), Intervall: 5}, false)
	var fz *FehlerZentrale
	if !errors.As(err, &fz) || fz.Code != 400 || err.Error() != "Intervall: 30 Sekunden bis 1 Tag." {
		t.Fatalf("Fehler %v", err)
	}
	if err := c.GeraetLoeschen(ctx, "d/1", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.AlarmBestaetigen(ctx, "a1", "schaue ich mir an"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /api/v1/geraete/d1/checks application/json {"name":"","typ":"ping","ziel":{"host":"a"},"intervall_sekunden":60}`,
		`PUT /api/v1/checks/c1 application/json {"name":"Ping","typ":"ping","ziel":{},"intervall_sekunden":5,"aktiv":false}`,
		`DELETE /api/v1/geraete/d/1  `,
		`POST /api/v1/alarme/a1/bestaetigen application/json {"kommentar":"schaue ich mir an"}`,
	}
	if !reflect.DeepEqual(log, want) {
		t.Fatalf("Anfragen:\n%s", strings.Join(log, "\n"))
	}
	c.Token = "owt1.falsch"
	if err := c.CheckJetzt(ctx, "c1"); !errors.Is(err, ErrToken) {
		t.Fatalf("falsches Token: %v", err)
	}
}

func TestBereich(t *testing.T) {
	st := Stand{
		Mandanten: []Mandant{{ID: "a", Name: "Firma"}, {ID: "b", Ueber: sp("a"), Name: "Werk"}, {ID: "c", Ueber: sp("b"), Name: "Halle"},
			{ID: "x", Name: "Andere"}},
		Geraete:  []Geraet{{ID: "d1", MandantID: "a", Name: "eins"}, {ID: "d2", MandantID: "c", Name: "zwei"}, {ID: "d3", MandantID: "x", Name: "drei"}},
		Sensoren: []Sensor{{GeraetID: "d1", MandantID: "a", Status: "ok"}, {GeraetID: "d2", MandantID: "c", Status: "crit"}},
	}
	reihe := MandantenReihe(st.Mandanten)
	var namen []string
	for _, z := range reihe {
		namen = append(namen, strings.Repeat(" ", z.Tiefe)+z.Mandant.Name)
	}
	if !reflect.DeepEqual(namen, []string{"Andere", "Firma", " Werk", "  Halle"}) {
		t.Fatalf("Reihe: %q", namen)
	}
	w := BaumBauen(BereichStand(st, "b", true))
	if len(w) != 1 || w[0].ID != "b" || w[0].Zaehler.Kritisch != 1 || len(w[0].Geraete) != 1 {
		t.Fatalf("Bereich b mit Unter: %+v", w)
	}
	w = BaumBauen(BereichStand(st, "a", false))
	if len(w) != 1 || len(w[0].Geraete) != 1 || w[0].Geraete[0] != "d1" {
		t.Fatalf("Bereich a ohne Unter: %+v", w[0])
	}
	if !HatUntermandanten(st.Mandanten, "b") || HatUntermandanten(st.Mandanten, "c") {
		t.Fatal("HatUntermandanten")
	}
}
