// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"
)

func TestTrapFindings(t *testing.T) {
	rule := "0b6c3f5e-1234-4abc-8def-0123456789ab"
	in := SNMPInput{Name: "sw-1", Interval: time.Minute, Traps: []TrapState{
		{Rule: rule, Name: "Port getrennt", Instance: "4", Status: Crit, Message: "linkDown: ifIndex.4 = 4"},
		{Rule: rule, Name: "Port getrennt", Instance: "4", Status: Warn, Message: "doppelt"}, // gleicher Gegenstand: einmal
		{Rule: rule, Name: "Neustart", Status: "ok", Message: "ungültiger Status"},
		{Rule: "kaputt", Name: "x", Status: Crit},
	}}
	prev := map[string]string{"trap:" + rule + ":9": Crit}
	var got []string
	for _, f := range EvaluateSNMP(in, prev, HostLimits{}) {
		if strings.HasPrefix(f.Subject, TrapPrefix) {
			got = append(got, f.Subject+"="+f.Status+"|"+f.Name)
		}
	}
	want := []string{"trap:" + rule + ":4=crit|sw-1 · Port getrennt (4)", "trap:" + rule + ":9=ok|sw-1 · Trap"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Funde: %v", got)
	}
	// Gerät stumm: Trap-Zustände bleiben unbewertet (offene Alarme stehen weiter).
	in.Silent = time.Hour
	for _, f := range EvaluateSNMP(in, prev, HostLimits{}) {
		if strings.HasPrefix(f.Subject, TrapPrefix) {
			t.Errorf("stumm: %+v", f)
		}
	}
	for sub, ok := range map[string]bool{"trap:" + rule: true, "trap:" + rule + ":Port 1": true, "trap:" + rule + ":": false,
		"trap:" + strings.ToUpper(rule): false, "trap:x": false, "trap:" + rule + ":a\nb": false} {
		if SNMPSubject(sub) != ok {
			t.Errorf("SNMPSubject(%q) != %v", sub, ok)
		}
	}
}
