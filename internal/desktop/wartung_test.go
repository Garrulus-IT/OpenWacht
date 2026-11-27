package desktop

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWartungen(t *testing.T) {
	var put map[string]any
	var geloescht, beendet string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/wartung":
			if r.URL.Query().Get("mandant") != "m1" {
				t.Errorf("mandant fehlt: %s", r.URL.RawQuery)
			}
			io.WriteString(w, `{"laufend":[{"id":"l1","geraet_id":"d1","check_id":"c1","geraet":"srv","sensor":"CPU","seit":"2026-11-26T10:00:00Z","bis":"2026-11-26T12:00:00Z","grund":"Update"}],
			"fenster":[{"id":"f1","name":"Patchtag","grund":"","ziel_art":"gruppe","ziel_id":"g1","ziel_name":"Server","untergruppen":true,"wiederholung":"woechentlich","beginn":"2026-11-01T00:00:00Z","ende":null,"wochentage":[2],"nter":null,"wochentag":null,"versatz":null,"uhrzeit":"22:00","dauer_min":60,"zeitzone":"Europe/Berlin","aktiv":true,"text":"dienstags 22:00","laeuft_bis":"2026-11-26T23:00:00Z","naechstes":["2026-12-01T21:00:00Z","2026-12-01T22:00:00Z"]}],"ziele":[]}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/wartungsfenster/f1":
			json.NewDecoder(r.Body).Decode(&put)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/wartungsfenster/f1":
			geloescht = "f1"
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/checks/c1/wartung":
			beendet = "c1"
		default:
			t.Errorf("unerwartet: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	c := Client{Zentrale: srv.URL, Token: "owt1.gut", HTTP: srv.Client()}
	ctx := context.Background()
	w, err := c.WartungenHolen(ctx, "m1")
	if err != nil || len(w.Laufend) != 1 || len(w.Fenster) != 1 {
		t.Fatalf("holen: %v %+v", err, w)
	}
	if f := w.Fenster[0]; f.LaeuftBis == nil || len(f.Naechstes) != 2 || WartungZeit(f.Naechstes[0], f.Zeitzone) != "Di., 01.12., 22:00" {
		t.Errorf("Zeiten im Fenster: %+v", f)
	}
	if z := w.Laufend[0].Ziel(); z != "srv · CPU" {
		t.Errorf("Ziel = %q", z)
	}
	if b := w.Fenster[0].Beschreibung(); b != "Gruppe Server mit Untergruppen · dienstags 22:00" {
		t.Errorf("Beschreibung = %q", b)
	}
	if z := WartungZeit(w.Laufend[0].Bis, "Europe/Berlin"); z != "Do., 26.11., 13:00" {
		t.Errorf("WartungZeit = %q", z)
	}
	if err := c.FensterAktiv(ctx, w.Fenster[0], false); err != nil {
		t.Fatal(err)
	}
	if put["aktiv"] != false || put["ziel_id"] != "g1" || put["nter"] != float64(0) || put["uhrzeit"] != "22:00" || put["dauer_min"] != float64(60) {
		t.Errorf("PUT-Rumpf: %v", put)
	}
	if _, ok := put["text"]; ok {
		t.Error("Anzeigefeld text im PUT")
	}
	if err := c.FensterLoeschen(ctx, "f1"); err != nil || geloescht != "f1" {
		t.Errorf("löschen: %v", err)
	}
	if err := c.LaufendBeenden(ctx, w.Laufend[0]); err != nil || beendet != "c1" {
		t.Errorf("beenden: %v", err)
	}
	if err := c.LaufendBeenden(ctx, WartungLaufend{}); err == nil {
		t.Error("ohne Ziel kein Fehler")
	}
}

func TestWartungenImBereich(t *testing.T) {
	w := Wartungen{
		Laufend: []WartungLaufend{{ID: "a", MandantID: "m1"}, {ID: "b", MandantID: "m2"}},
		Fenster: []WartungFenster{{ID: "c", MandantID: "m2"}, {ID: "d", MandantID: "m3"}},
	}
	r := w.ImBereich(map[string]bool{"m2": true})
	if len(r.Laufend) != 1 || r.Laufend[0].ID != "b" || len(r.Fenster) != 1 || r.Fenster[0].ID != "c" {
		t.Errorf("ImBereich: %+v", r)
	}
}
