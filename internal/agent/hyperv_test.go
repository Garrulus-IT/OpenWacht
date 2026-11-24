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

const hvSample = `[{"ElementName":"HV01","Name":"HV01","EnabledState":2},
{"ElementName":"dc01","Name":"6B1D0C2A-7E0F-4C3B-9A51-0D3E2F1A9B77","EnabledState":2},
{"ElementName":"Büro-PC (alt)","Name":"0f6f1c2a-7e0f-4c3b-9a51-0d3e2f1a9b78","EnabledState":3},
{"ElementName":"sql","Name":"1f6f1c2a-7e0f-4c3b-9a51-0d3e2f1a9b79","EnabledState":32769},
{"ElementName":"doppelt","Name":"2f6f1c2a-7e0f-4c3b-9a51-0d3e2f1a9b70","EnabledState":2},
{"ElementName":"doppelt","Name":"3f6f1c2a-7e0f-4c3b-9a51-0d3e2f1a9b71","EnabledState":3},
{"ElementName":"neu","Name":"4f6f1c2a-7e0f-4c3b-9a51-0d3e2f1a9b72","EnabledState":12345}]`

func TestHyperVParse(t *testing.T) {
	list, err := parseHyperV([]byte("\ufeff" + hvSample + "\r\n"))
	if err != nil || len(list) != 6 {
		t.Fatalf("%d %v", len(list), err)
	}
	for _, v := range list {
		if v.ElementName == "HV01" {
			t.Error("Host selbst als VM gezählt")
		}
	}
	one, err := parseHyperV([]byte(`{"ElementName":"x","Name":"6B1D0C2A-7E0F-4C3B-9A51-0D3E2F1A9B77","EnabledState":2}`))
	if err != nil || len(one) != 1 {
		t.Errorf("einzeln: %v %v", one, err)
	}
	if l, err := parseHyperV([]byte("  ")); err != nil || len(l) != 0 {
		t.Errorf("leer: %v %v", l, err)
	}
	for _, bad := range []string{"nicht json", `[{"Name":1}]`, strings.Repeat(" ", maxHypervList+1)} {
		if _, err := parseHyperV([]byte(bad)); err == nil {
			t.Errorf("angenommen: %.20q", bad)
		}
	}
}

func TestHyperVResult(t *testing.T) {
	list, _ := parseHyperV([]byte(hvSample))
	for name, want := range map[string]string{
		"dc01":          checks.OK + " VM läuft",
		"DC01":          checks.OK + " VM läuft",
		"Büro-PC (alt)": checks.Crit + " VM ausgeschaltet",
		"sql":           checks.Warn + " VM gespeichert",
		"doppelt":       checks.Crit + " VM ausgeschaltet (mehrere VMs mit diesem Namen)",
		"neu":           checks.Unknown + " VM Zustand unbekannt",
		"fehlt":         checks.Crit + " VM nicht gefunden",
		"HV01":          checks.Crit + " VM nicht gefunden",
	} {
		r := hypervResult(list, name)
		if got := r.Status + " " + r.Message; got != want {
			t.Errorf("%s: %q, erwartet %q", name, got, want)
		}
	}
	for st, want := range map[int]string{2: checks.OK, 3: checks.Crit, 6: checks.Warn, 9: checks.Warn, 32768: checks.Warn,
		32770: checks.Warn, 32773: checks.Warn, 32774: checks.Warn, 4: checks.Warn, 32776: checks.Warn, 32777: checks.Warn, 0: checks.Unknown} {
		if got, _ := hypervStateText(st); got != want {
			t.Errorf("Zustand %d: %s", st, got)
		}
	}
}

func TestHyperVSensor(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	e := testEnv(now)
	e.now = func() time.Time { return now }
	calls := 0
	var fail error
	e.hyperv = func(context.Context) ([]hypervVM, error) {
		calls++
		if fail != nil {
			return nil, fail
		}
		return parseHyperV([]byte(hvSample))
	}
	rel := &agentproto.SensorRelease{Kinds: []string{"hyperv"}}
	if err := rel.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if r := e.measure(ctx, &agentproto.SensorRelease{Kinds: []string{"dienst"}}, job("hyperv", `{"name":"dc01"}`)); r.Status != checks.Unknown ||
		!strings.Contains(r.Message, "-arten hyperv") || calls != 0 {
		t.Errorf("ohne Freigabe: %+v %d", r, calls)
	}
	if r := e.measure(ctx, rel, job("hyperv", `{"name":"-x"}`)); r.Status != checks.Unknown || calls != 0 {
		t.Errorf("ungültiger Name: %+v", r)
	}
	if r := e.measure(ctx, rel, job("hyperv", `{"name":"dc01"}`)); r.Status != checks.OK {
		t.Errorf("dc01: %+v", r)
	}
	if r := e.measure(ctx, rel, job("hyperv", `{"name":"sql"}`)); r.Status != checks.Warn || calls != 1 {
		t.Errorf("zweiter Sensor ohne neue Abfrage: %+v %d", r, calls)
	}
	// Nach Ablauf des Zwischenspeichers neu; Fehler werden gemeldet, gekürzt.
	now = now.Add(hypervCacheFor)
	fail = errors.New(strings.Repeat("kein Zugriff ", 50))
	r := e.measure(ctx, rel, job("hyperv", `{"name":"dc01"}`))
	if calls != 2 || r.Status != checks.Unknown || len([]rune(r.Message)) > 250 {
		t.Errorf("Fehler: %+v %d", r, calls)
	}
	// Uhr läuft rückwärts: neu abfragen statt ewig zwischenzuspeichern.
	now = now.Add(-time.Hour)
	fail = nil
	if r := e.measure(ctx, rel, job("hyperv", `{"name":"dc01"}`)); r.Status != checks.OK || calls != 3 {
		t.Errorf("Uhr zurück: %+v %d", r, calls)
	}
	// Ohne Windows
	e.hyperv = nil
	if r := e.measure(ctx, rel, job("hyperv", `{"name":"dc01"}`)); r.Status != checks.Unknown || !strings.Contains(r.Message, "Windows") {
		t.Errorf("ohne Windows: %+v", r)
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := limitedBuffer{max: 5}
	n, err := b.Write([]byte("abc"))
	b.Write([]byte("defgh"))
	if n != 3 || err != nil || b.String() != "abcde" {
		t.Errorf("%q", b.String())
	}
}
