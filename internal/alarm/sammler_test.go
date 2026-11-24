// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"
)

func TestSammlerAmHost(t *testing.T) {
	lim := HostLimits{SilentAfter: 3 * time.Minute}
	ago := func(d time.Duration) *float64 { s := d.Seconds(); return &s }
	find := func(out []Finding, sub string) *Finding {
		for i := range out {
			if out[i].Subject == sub {
				return &out[i]
			}
		}
		return nil
	}
	for name, c := range map[string]struct {
		m        *CollectorMetrics
		status   string
		contains string
	}{
		"läuft":         {&CollectorMetrics{Devices: 3, On: true, FetchedAgoS: ago(time.Minute)}, OK, "sammelt für 3 Geräte"},
		"holt nicht ab": {&CollectorMetrics{Devices: 1, On: true, FetchedAgoS: ago(10 * time.Minute)}, Crit, "1 Gerät ohne Abfrage"},
		"nie":           {&CollectorMetrics{Devices: 2, On: true}, Crit, "noch nie"},
		"lokal aus":     {&CollectorMetrics{Devices: 2, On: false, FetchedAgoS: ago(time.Second)}, Crit, "lokal ausgeschaltet"},
		"ohne Geräte":   {&CollectorMetrics{Devices: 0, On: false}, "", ""},
		"kein Sammler":  {nil, "", ""},
	} {
		out := EvaluateHost(HostInput{Hostname: "h", Metrics: &HostMetrics{Collector: c.m}}, nil, lim)
		f := find(out, SubjectCollector)
		if c.status == "" {
			if f != nil {
				t.Errorf("%s: %+v", name, f)
			}
			continue
		}
		if f == nil || f.Status != c.status || !strings.Contains(f.Message, c.contains) || f.Name != "h · Sammler" {
			t.Errorf("%s: %+v", name, f)
		}
	}
	// Verschwindet die Zuweisung, wird der Alarm entwarnt.
	out := EvaluateHost(HostInput{Hostname: "h", Metrics: &HostMetrics{}}, map[string]string{SubjectCollector: Crit}, lim)
	if f := find(out, SubjectCollector); f == nil || f.Status != OK {
		t.Errorf("Entwarnung: %+v", f)
	}
	// Stummer Agent: nur der Stumm-Alarm, mit Hinweis auf die Geräte.
	out = EvaluateHost(HostInput{Hostname: "h", Silent: time.Hour, Metrics: &HostMetrics{Collector: &CollectorMetrics{Devices: 4, On: true}}},
		map[string]string{SubjectCollector: Crit}, lim)
	if len(out) != 1 || out[0].Subject != SubjectSilent || !strings.Contains(out[0].Message, "4 Geräte aus") {
		t.Errorf("stumm: %+v", out)
	}
}

func TestSNMPMitAusgefallenemSammler(t *testing.T) {
	lim := HostLimits{SilentAfter: 3 * time.Minute}
	in := SNMPInput{Name: "sw", Silent: time.Hour, Interval: time.Minute, CollectorDown: "Sammler x meldet sich nicht"}
	if out := EvaluateSNMP(in, map[string]string{SubjectSilent: Crit}, lim); out != nil {
		t.Errorf("Ausfall des Sammlers bewertet: %+v", out)
	}
	// Ausgeschaltet geht vor: entwarnen
	in.Disabled = true
	if out := EvaluateSNMP(in, map[string]string{SubjectSilent: Crit}, lim); len(out) != 1 || out[0].Status != OK {
		t.Errorf("ausgeschaltet: %+v", out)
	}
	in = SNMPInput{Name: "sw", Silent: time.Hour, Interval: time.Minute}
	if out := EvaluateSNMP(in, nil, lim); len(out) != 1 || out[0].Status != Crit {
		t.Errorf("ohne Sammler: %+v", out)
	}
}
