// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
)

func TestAutoDienste(t *testing.T) {
	list := []autoService{
		{Name: "Spooler", Display: "Druckwarteschlange", Running: true},
		{Name: "W32Time", Display: "Windows-Zeitgeber"},
		{Name: "sppsvc", Display: "Softwareschutz", Trigger: true},
		{Name: "MapsBroker", Display: "Downloadmanager für Karten", Delayed: true},
		{Name: "edgeupdate", Display: "Microsoft Edge Update Service (edgeupdate)"},
		{Name: "BITS", Display: "Intelligenter Hintergrundübertragungsdienst"},
	}
	cases := []struct {
		name   string
		up     time.Duration
		ex     []string
		status string
		msg    string
	}{
		{"drei gestoppt", time.Hour, []string{"edgeupdate"}, checks.Crit, "3 Dienste gestoppt: BITS, MapsBroker, W32Time"},
		{"Ausnahme mit Stern und Anzeigename", time.Hour, []string{"Microsoft Edge*", "windows-zeitgeber", "bits", "MapsBroker"},
			checks.OK, "alle 1 automatisch startenden Dienste laufen"},
		{"kurz nach dem Start", 5 * time.Minute, []string{"edge*"}, checks.Crit, "2 Dienste gestoppt: BITS, W32Time"},
		{"einer", time.Hour, []string{"edge*", "W32Time", "MapsBroker"}, checks.Crit, "Dienst gestoppt: BITS"},
	}
	for _, c := range cases {
		r := autoServicesResult(list, c.up, c.ex)
		if r.Status != c.status || r.Message != c.msg {
			t.Errorf("%s: %v %q", c.name, r.Status, r.Message)
		}
	}
	// Nicht lesbarer Starttyp: laufend nur gezählt, stehend eine Warnung,
	// Ausnahmen gelten auch hier.
	unread := []autoService{
		{Name: "Spooler", Running: true},
		{Name: "GDScan", Running: true, Unreadable: true},
		{Name: "AVKProxy", Unreadable: true},
	}
	for _, c := range []struct {
		name   string
		list   []autoService
		ex     []string
		status string
		msg    string
	}{
		{"nur laufend", unread[:2], nil, checks.OK, "alle 1 automatisch startenden Dienste laufen; 1 nicht lesbar"},
		{"einer steht", unread, nil, checks.Warn, "alle 1 automatisch startenden Dienste laufen; Starttyp nicht lesbar, steht: AVKProxy"},
		{"Ausnahme", unread, []string{"AVK*"}, checks.OK, "alle 1 automatisch startenden Dienste laufen; 1 nicht lesbar"},
		{"mit gestopptem", append([]autoService{{Name: "W32Time"}}, unread...), nil, checks.Crit,
			"Dienst gestoppt: W32Time; Starttyp nicht lesbar, steht: AVKProxy"},
	} {
		if r := autoServicesResult(c.list, time.Hour, c.ex); r.Status != c.status || r.Message != c.msg {
			t.Errorf("%s: %v %q", c.name, r.Status, r.Message)
		}
	}
	// Viele gestoppte Dienste: Meldung bleibt kurz
	var many []autoService
	for range 200 {
		many = append(many, autoService{Name: "Dienst" + strings.Repeat("x", 20)})
	}
	if r := autoServicesResult(many, time.Hour, nil); len([]rune(r.Message)) > 250 || r.Metric != "200 gestoppt" {
		t.Errorf("lang: %d Zeichen, %q", len([]rune(r.Message)), r.Metric)
	}
}

func TestAutoDiensteMessen(t *testing.T) {
	e := testEnv(time.Now())
	rel := &agentproto.SensorRelease{Kinds: []string{"autodienste"}}
	j := job("autodienste", `{"ausnahmen":["W32Time"]}`)
	if r := e.measure(context.Background(), rel, j); r.Status != checks.Unknown || r.Message != "nur Windows-Agent" {
		t.Errorf("ohne Windows: %+v", r)
	}
	e.autoSvc = func(context.Context) ([]autoService, time.Duration, error) {
		return []autoService{{Name: "W32Time"}, {Name: "Spooler", Running: true}}, time.Hour, nil
	}
	if r := e.measure(context.Background(), rel, j); r.Status != checks.OK {
		t.Errorf("mit Ausnahme: %+v", r)
	}
	// nicht freigegeben: keine Abfrage
	called := false
	e.autoSvc = func(context.Context) ([]autoService, time.Duration, error) { called = true; return nil, 0, nil }
	if r := e.measure(context.Background(), &agentproto.SensorRelease{Kinds: []string{"dienst"}}, j); r.Status != checks.Unknown || called {
		t.Errorf("nicht freigegeben: %+v, abgefragt %v", r, called)
	}
	// ungültige Ausnahme von der Zentrale: keine Abfrage
	if r := e.measure(context.Background(), rel, job("autodienste", `{"ausnahmen":["*"]}`)); r.Status != checks.Unknown || called {
		t.Errorf("Ausnahme *: %+v", r)
	}
	e.autoSvc = func(context.Context) ([]autoService, time.Duration, error) { return nil, 0, errors.New("kein Zugriff") }
	if r := e.measure(context.Background(), rel, j); r.Status != checks.Unknown {
		t.Errorf("Fehler: %+v", r)
	}
}
