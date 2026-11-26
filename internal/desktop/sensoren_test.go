// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func zeit(s string) *time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return &t
}

func TestZeilen(t *testing.T) {
	jetzt, _ := time.Parse(time.RFC3339, "2026-11-26T10:00:00Z")
	sensoren := []Sensor{
		{Host: "srv-web", Name: "HTTPS", Status: "ok", GeraetID: "g1"},
		{Host: "srv-db01", Name: "Platte /", Gegenstand: "platte:/", Status: "warn", Meldung: "85 %\nbelegt", Seit: zeit("2026-11-26T09:48:00Z"), GeraetID: "g2"},
		{Host: "nas", Name: "Ping", Status: "crit", Meldung: "keine Antwort", Seit: zeit("2026-11-24T09:00:00Z"),
			Alarm: &Alarm{Bestaetigt: zeit("2026-11-24T09:05:00Z")}, GeraetID: "g3"},
		{Host: "Alt-Server", Name: "Dienst", Status: "pause", GeraetID: "g4"},
		{Host: "agent-1", Name: "CPU", Status: "unknown", Seit: zeit("2026-11-26T07:00:00Z")},
	}
	z := Zeilen(sensoren, false, "", jetzt)
	if len(z) != 3 || z[0].Geraet != "nas" || z[1].Geraet != "srv-db01" || z[2].Geraet != "agent-1" {
		t.Fatalf("nur Probleme, schlimmste oben: %+v", z)
	}
	if z[0].Zustand != "Bestätigt" || z[0].Anzeige != "bestaetigt" || z[1].Anzeige != z[1].Status || z[1].Anzeige == "" || !z[0].Bestaetigt || z[0].Seit != "vor 2 Tagen" {
		t.Errorf("bestätigt: %+v", z[0])
	}
	if z[1].Meldung != "85 % belegt" || z[1].Seit != "vor 12 Min." || z[2].Seit != "vor 3 Std." {
		t.Errorf("Texte: %+v %+v", z[1], z[2])
	}
	if alle := Zeilen(sensoren, true, "", jetzt); len(alle) != 5 || alle[3].Status != "pause" || alle[4].Status != "ok" {
		t.Errorf("alle: %+v", alle)
	}
	if f := Zeilen(sensoren, true, "SRV  platte", jetzt); len(f) != 1 || f[0].GeraetID != "g2" {
		t.Errorf("Filter mit zwei Wörtern: %+v", f)
	}
	if f := Zeilen(sensoren, false, "gibtsnicht", jetzt); len(f) != 0 {
		t.Errorf("Filter ohne Treffer: %+v", f)
	}
	c := Zaehlen(sensoren)
	if c.Text() != "0 kritisch · 1 Warnung · 1 unbekannt · 1 OK" || c.Bestaetigt != 1 || c.Pausiert != 1 || c.Sonst != 1 {
		t.Errorf("Zähler: %q %+v", c.Text(), c)
	}
	if p := GeraetPfad("g2"); p != "/hosts?geraet=g2&ansicht=sensoren" {
		t.Errorf("Pfad: %q", p)
	}
	if SeitText(jetzt.Add(-10*time.Second), jetzt) != "gerade eben" {
		t.Error("gerade eben")
	}
}

func TestSensorenAbfrage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensoren" || r.Header.Get("Authorization") != "Bearer owt1.test" {
			http.Error(w, "nein", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"sensoren":[{"schluessel":"c:1","host":"nas","name":"Ping","status":"crit","geraet_id":"g3"}],"stumm_nach_s":300}`))
	}))
	defer srv.Close()
	c := Client{Zentrale: srv.URL, Token: "owt1.test", HTTP: srv.Client()}
	s, err := c.Sensoren(context.Background())
	if err != nil || len(s) != 1 || s[0].Host != "nas" || s[0].Status != "crit" {
		t.Fatalf("%+v %v", s, err)
	}
	c.Token = "owt1.falsch"
	if _, err := c.Sensoren(context.Background()); err != ErrToken {
		t.Fatalf("falsches Token: %v", err)
	}
	// Weiterleitung: nicht folgen (Token bleibt bei der Zentrale)
	umleiten := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://fremd.example/", http.StatusFound)
	}))
	defer umleiten.Close()
	c = Client{Zentrale: umleiten.URL, Token: "owt1.test", HTTP: umleiten.Client()}
	if _, err := c.Sensoren(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("Weiterleitung: %v", err)
	}
}
