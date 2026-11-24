// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
)

func diskMetrics(pct int, days map[string]int) *HostMetrics {
	m := &HostMetrics{FullDays: days}
	m.Disks = append(m.Disks, struct {
		Mount  string `json:"einhaengepunkt"`
		FSType string `json:"dateisystem"`
		Total  uint64 `json:"gesamt"`
		Free   uint64 `json:"frei"`
	}{"/data", "ext4", 1000, uint64(1000 - pct*10)})
	return m
}

func diskFinding(t *testing.T, pct int, days map[string]int, prev string, lim HostLimits) Finding {
	t.Helper()
	for _, f := range EvaluateHost(HostInput{Hostname: "h", Metrics: diskMetrics(pct, days)}, map[string]string{"platte:/data": prev}, lim) {
		if f.Subject == "platte:/data" {
			return f
		}
	}
	t.Fatal("keine Platte bewertet")
	return Finding{}
}

func TestPlatteVoll(t *testing.T) {
	lim := HostLimits{SilentAfter: 1e12, DiskWarn: 90, DiskCrit: 95, DiskDays: 14}
	f := diskFinding(t, 70, map[string]int{"/data": 9}, "", lim)
	if f.Status != Warn || f.Message != "70 % belegt, voll in etwa 9 Tagen (Warnung unter 14 Tagen)" {
		t.Errorf("bald voll: %+v", f)
	}
	if f := diskFinding(t, 70, map[string]int{"/data": 14}, "", lim); f.Status != OK {
		t.Errorf("genau an der Schwelle: %+v", f)
	}
	// Hysterese: gemeldete Warnung endet erst ab 14 + 3 Tagen
	if f := diskFinding(t, 70, map[string]int{"/data": 16}, Warn, lim); f.Status != Warn {
		t.Errorf("Hysterese: %+v", f)
	}
	if f := diskFinding(t, 70, map[string]int{"/data": 17}, Warn, lim); f.Status != OK {
		t.Errorf("nach Hysterese: %+v", f)
	}
	// Belegung kritisch bleibt kritisch, Prognose steht dabei
	if f := diskFinding(t, 96, map[string]int{"/data": 1}, "", lim); f.Status != Crit || !strings.Contains(f.Message, "voll in etwa einem Tag") {
		t.Errorf("kritisch: %+v", f)
	}
	// Aus: 0 Tage
	off := lim
	off.DiskDays = 0
	if f := diskFinding(t, 70, map[string]int{"/data": 2}, "", off); f.Status != OK {
		t.Errorf("aus: %+v", f)
	}
	// Nur Prognose an, Belegungsschwellen aus
	only := HostLimits{SilentAfter: 1e12, DiskDays: 30}
	if f := diskFinding(t, 99, map[string]int{"/data": 3}, "", only); f.Status != Warn {
		t.Errorf("nur Prognose: %+v", f)
	}
	// Ohne Prognose (stabil): nichts
	if f := diskFinding(t, 70, nil, "", lim); f.Status != OK {
		t.Errorf("ohne Prognose: %+v", f)
	}
	if !FullSoon(0, 14, "") || FullSoon(-1, 14, "") || FullSoon(5, 0, "") {
		t.Error("FullSoon Grenzen")
	}
}
