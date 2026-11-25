// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"context"
	"errors"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanZentrale(t *testing.T) {
	for in, want := range map[string]string{
		"openwacht.firma.example":          "https://openwacht.firma.example",
		"https://openwacht.firma.example/": "https://openwacht.firma.example",
		" https://10.20.0.5:8443 ":         "https://10.20.0.5:8443",
	} {
		if got, err := CleanZentrale(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"http://openwacht.example", "https://user:pw@openwacht.example", "https://openwacht.example/pfad",
		"https://openwacht.example/?x=1", "ftp://x", "https://", ""} {
		if _, err := CleanZentrale(in); err == nil {
			t.Errorf("%q angenommen", in)
		}
	}
}

func TestCleanToken(t *testing.T) {
	ok := "owt1." + strings.Repeat("A", 43)
	if got, err := CleanToken(" " + ok + "\n"); err != nil || got != ok {
		t.Errorf("gültig: %q %v", got, err)
	}
	for _, in := range []string{"owa1." + strings.Repeat("A", 43), "owt1." + strings.Repeat("A", 42), "owt1." + strings.Repeat("+", 43), ""} {
		if _, err := CleanToken(in); err == nil {
			t.Errorf("%q angenommen", in)
		}
	}
}

func TestConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "OpenWacht", "desktop.json")
	if c, err := LoadConfig(p); err != nil || c.Zentrale != "" {
		t.Fatalf("ohne Datei: %+v %v", c, err)
	}
	if err := SaveConfig(p, Config{Zentrale: "https://openwacht.example"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("Rechte %v", st.Mode().Perm())
	}
	if c, err := LoadConfig(p); err != nil || c.Zentrale != "https://openwacht.example" {
		t.Errorf("gelesen: %+v %v", c, err)
	}
	os.WriteFile(p, []byte(`{"zentrale":"http://boese.example"}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("http in der Datei angenommen")
	}
}

func TestClient(t *testing.T) {
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v1/alarme":
			if auth != "Bearer owt1.gut" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"alarme":[{"id":"a","name":"srv-01 · Ping","status":"crit","meldung":"keine Antwort"}]}`))
		}
	}))
	defer srv.Close()
	c := Client{Zentrale: srv.URL, Token: "owt1.gut", HTTP: srv.Client()}
	a, err := c.Alarme(context.Background())
	if err != nil || len(a) != 1 || a[0].Status != "crit" || auth != "Bearer owt1.gut" {
		t.Fatalf("Alarme: %+v %v %q", a, err, auth)
	}
	c.Token = "owt1.falsch"
	if _, err := c.Alarme(context.Background()); !errors.Is(err, ErrToken) {
		t.Errorf("falsches Token: %v", err)
	}
	// Weiterleitung: Das Token geht nie an eine andere Adresse.
	var fremd string
	ziel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fremd = r.Header.Get("Authorization") }))
	defer ziel.Close()
	umleiten := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ziel.URL+"/api/v1/alarme", http.StatusFound)
	}))
	defer umleiten.Close()
	c = Client{Zentrale: umleiten.URL, Token: "owt1.gut", HTTP: umleiten.Client()}
	if _, err := c.Alarme(context.Background()); err == nil || fremd != "" {
		t.Errorf("Weiterleitung gefolgt: %v %q", err, fremd)
	}
}

func TestVergleichenUndZusammenfassen(t *testing.T) {
	jetzt := time.Now()
	alt := []Alarm{{ID: "1", Status: "warn"}, {ID: "2", Status: "crit"}, {ID: "3", Status: "warn"}}
	neu := []Alarm{
		{ID: "1", Status: "crit"},               // schlimmer
		{ID: "2", Status: "crit", Ende: &jetzt}, // Entwarnung
		{ID: "3", Status: "warn", Bestaetigt: &jetzt},
		{ID: "4", Status: "warn", Name: "drucker"},    // neu
		{ID: "5", Status: "crit", Bestaetigt: &jetzt}, // neu, aber bestätigt
	}
	if e := Vergleichen(nil, neu); e != nil {
		t.Errorf("erster Stand meldet: %v", e)
	}
	e := Vergleichen(alt, neu)
	if len(e) != 3 || e[0].Art != "schlimmer" || e[0].Titel() != "Jetzt Kritisch" || e[1].Art != "neu" || e[2].Art != "entwarnung" {
		t.Fatalf("Ereignisse: %+v", e)
	}
	z := Zusammenfassen(neu)
	if z.Zustand != ZustandKrit || z.Kritisch != 1 || z.Warnungen != 1 || z.Tooltip() != "OpenWacht: 1 kritisch, 1 Warnung" {
		t.Errorf("Zusammenfassung: %+v %q", z, z.Tooltip())
	}
	if z := Zusammenfassen(nil); z.Zustand != ZustandOK || z.Tooltip() != "OpenWacht: alles in Ordnung" {
		t.Errorf("leer: %+v", z)
	}
	lang := Ereignis{"neu", Alarm{Name: strings.Repeat("x", 300), Status: "crit", Meldung: "a\x07b"}}
	if n := len([]rune(lang.Text())); n > 255 || strings.ContainsRune(lang.Text(), 7) {
		t.Errorf("Text: %d Zeichen", n)
	}
}

func TestSymbol(t *testing.T) {
	for _, z := range []Zustand{ZustandOK, ZustandWarn, ZustandKrit, ZustandUnbekannt, ZustandStoerung} {
		img := Bild(z, 32)
		mitte := img.NRGBAAt(16, 16)
		if z != ZustandStoerung && z != ZustandUnbekannt && mitte.A == 0 {
			t.Errorf("%s: Mitte leer", z)
		}
		if ecke := img.NRGBAAt(0, 0); ecke.A != 0 && z != ZustandUnbekannt {
			t.Errorf("%s: Ecke gefüllt", z)
		}
		res := IconRessource(img)
		if want := 40 + 32*32*4 + 4*32; len(res) != want {
			t.Errorf("%s: Ressource %d Bytes, erwartet %d", z, len(res), want)
		}
		if os.Getenv("SYMBOLE") != "" {
			f, _ := os.Create(filepath.Join(os.Getenv("SYMBOLE"), string(z)+".png"))
			png.Encode(f, Bild(z, 64))
			f.Close()
		}
	}
	// Warnung und OK unterscheiden sich in der Form, nicht nur in der Farbe.
	ok, warn := Bild(ZustandOK, 32), Bild(ZustandWarn, 32)
	if ok.NRGBAAt(5, 27).A != 0 || warn.NRGBAAt(5, 27).A == 0 {
		t.Error("Formen nicht unterscheidbar")
	}
}
