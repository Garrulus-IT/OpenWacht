package desktop

import (
	"encoding/json"
	"testing"
	"time"
)

func TestZertifikate(t *testing.T) {
	s := func(x string) *string { return &x }
	heute := time.Date(2026, 11, 26, 15, 0, 0, 0, time.Local)
	checks := []Check{
		{ID: "a", MandantID: "m", Typ: "tls", Aktiv: true, Status: s("ok"), Ziel: json.RawMessage(`{"host":"web.example","port":443}`),
			Meldung: s("gültig bis 31.01.2027 (noch 66 Tage), Aussteller R11")},
		{ID: "b", MandantID: "m", Typ: "tls", Aktiv: true, Status: s("crit"), Ziel: json.RawMessage(`{"host":"alt.example","port":8443,"verbinde":"10.0.0.1"}`),
			Meldung: s("Name passt nicht; gültig bis 01.12.2026 (noch 5 Tage), Aussteller X")},
		{ID: "c", MandantID: "m", Typ: "tls", Aktiv: true, Status: s("unknown"), Meldung: s("keine Verbindung")},
		{ID: "d", MandantID: "m", Typ: "ping", Aktiv: true},
		{ID: "e", MandantID: "x", Typ: "tls", Aktiv: true},
	}
	z := Zertifikate(checks, map[string]bool{"m": true}, heute)
	if len(z) != 3 || z[0].Check.ID != "b" || z[1].Check.ID != "a" || z[2].Check.ID != "c" {
		t.Fatalf("Reihenfolge: %+v", z)
	}
	if *z[0].Rest != 5 || z[0].Problem != "Name passt nicht" || z[0].Aussteller != "X" || z[0].Adresse() != "alt.example:8443 über 10.0.0.1" {
		t.Errorf("b: %+v %q", z[0], z[0].Adresse())
	}
	if z[1].RestText() != "66 Tage" || z[1].Problem != "" || z[1].Adresse() != "web.example" {
		t.Errorf("a: %q %q", z[1].RestText(), z[1].Problem)
	}
	if z[2].Problem != "keine Verbindung" || z[2].RestText() != "–" || !z[2].MitProblem() {
		t.Errorf("c: %+v", z[2])
	}
	if !z[0].Bald(30) || z[1].Bald(30) {
		t.Error("Bald")
	}
	r := -1
	if (ZertZeile{Rest: &r}).RestText() != "seit 1 Tag abgelaufen" {
		t.Error("RestText -1")
	}
}
