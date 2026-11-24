// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"reflect"
	"testing"
	"time"
)

func TestLevelMitHysterese(t *testing.T) {
	cases := []struct {
		pct, warn, crit float64
		prev, want      string
	}{
		{89.9, 90, 95, "", OK},
		{90, 90, 95, "", Warn},
		{94.9, 90, 95, "", Warn},
		{95, 90, 95, "", Crit},
		{100, 90, 95, Crit, Crit},
		// Hysterese: erst 2 Punkte unter der Schwelle entwarnen.
		{88, 90, 95, Warn, Warn},
		{87.9, 90, 95, Warn, OK},
		{93, 90, 95, Crit, Crit},
		{92.9, 90, 95, Crit, Warn},
		{88, 90, 95, Crit, Warn},
		{87.9, 90, 95, Crit, OK},
		// Nicht gemeldet: keine Hysterese.
		{89, 90, 95, "", OK},
		{94, 90, 95, Warn, Warn},
		// Schwellen aus.
		{99, 0, 95, "", Crit},
		{94, 0, 95, "", OK},
		{94, 0, 95, Crit, Crit},
		{92.9, 0, 95, Crit, OK},
		{99, 90, 0, "", Warn},
		{99, 0, 0, Crit, OK},
	}
	for _, c := range cases {
		if got := Level(c.pct, c.warn, c.crit, c.prev); got != c.want {
			t.Errorf("Level(%v, %v, %v, %q) = %s, erwartet %s", c.pct, c.warn, c.crit, c.prev, got, c.want)
		}
	}
}

func metrics(memTotal, memAvail uint64, disks ...[4]any) *HostMetrics {
	m := &HostMetrics{}
	m.Memory.Total, m.Memory.Available = memTotal, memAvail
	for _, d := range disks {
		m.Disks = append(m.Disks, struct {
			Mount  string `json:"einhaengepunkt"`
			FSType string `json:"dateisystem"`
			Total  uint64 `json:"gesamt"`
			Free   uint64 `json:"frei"`
		}{d[0].(string), d[1].(string), uint64(d[2].(int)), uint64(d[3].(int))})
	}
	return m
}

var lim = HostLimits{SilentAfter: 3 * time.Minute, DiskWarn: 90, DiskCrit: 95, MemWarn: 90, MemCrit: 95}

func TestEvaluateHost(t *testing.T) {
	m := metrics(100, 50,
		[4]any{"/", "ext4", 100, 8},        // 92 % → warn
		[4]any{"/srv", "xfs", 1000, 40},    // 96 % → crit
		[4]any{"/mnt/nas", "nfs4", 100, 1}, // Netzwerk: nie
		[4]any{"/leer", "ext4", 0, 0},      // ohne Größe: nie
		[4]any{"/", "ext4", 100, 100},      // doppelt: nur der erste zählt
	)
	got := EvaluateHost(HostInput{Hostname: "srv1", Silent: time.Minute, Metrics: m}, map[string]string{"platte:/alt": Crit}, lim)
	want := []Finding{
		{"stumm", "srv1", OK, "meldet sich wieder"},
		{"speicher", "srv1 · Arbeitsspeicher", OK, "50 % belegt"},
		{"platte:/", "srv1 · Platte /", Warn, "92 % belegt (Warnung ab 90 %)"},
		{"platte:/srv", "srv1 · Platte /srv", Crit, "96 % belegt (kritisch ab 95 %)"},
		{"platte:/alt", "srv1 · Platte /alt", OK, "wird nicht mehr gemeldet oder überwacht"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EvaluateHost:\n%+v\nerwartet\n%+v", got, want)
	}
}

func TestEvaluateHostStumm(t *testing.T) {
	m := metrics(100, 1, [4]any{"/", "ext4", 100, 1})
	prev := map[string]string{"platte:/": Crit}
	// Stumm: nur „stumm“, Messwerte veraltet und unberührt.
	got := EvaluateHost(HostInput{Hostname: "h", Silent: 3 * time.Minute, Metrics: m}, prev, lim)
	if len(got) != 1 || got[0] != (Finding{"stumm", "h", Crit, "meldet sich nicht, seit 3 Min."}) {
		t.Errorf("stumm: %+v", got)
	}
	// Knapp darunter: noch nicht stumm.
	got = EvaluateHost(HostInput{Hostname: "h", Silent: 3*time.Minute - time.Second, Metrics: m}, prev, lim)
	if len(got) != 3 || got[0].Status != OK || got[2].Status != Crit {
		t.Errorf("knapp: %+v", got)
	}
	// Schonfrist nach dem Start der Zentrale: gar nichts bewerten.
	if got := EvaluateHost(HostInput{Hostname: "h", Silent: time.Hour, Warming: true, Metrics: m}, prev, lim); got != nil {
		t.Errorf("Schonfrist: %+v", got)
	}
	// In der Schonfrist werden frische Agents normal bewertet.
	if got := EvaluateHost(HostInput{Hostname: "h", Silent: time.Second, Warming: true, Metrics: m}, nil, lim); len(got) != 3 {
		t.Errorf("Schonfrist, frischer Agent: %+v", got)
	}
	// Ohne Messwerte: nur stumm bewerten, gemeldete Probleme nicht entwarnen.
	if got := EvaluateHost(HostInput{Hostname: "h", Silent: time.Second}, prev, lim); len(got) != 1 {
		t.Errorf("ohne Messwerte: %+v", got)
	}
}

func TestEvaluateHostGesperrt(t *testing.T) {
	got := EvaluateHost(HostInput{Hostname: "h", Revoked: true, Silent: time.Hour, Metrics: metrics(100, 1)},
		map[string]string{"stumm": Crit, "speicher": Warn}, lim)
	want := []Finding{
		{"speicher", "h · Arbeitsspeicher", OK, "Agent gesperrt, wird nicht mehr überwacht"},
		{"stumm", "h", OK, "Agent gesperrt, wird nicht mehr überwacht"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("gesperrt: %+v", got)
	}
	if got := EvaluateHost(HostInput{Hostname: "h", Revoked: true}, nil, lim); len(got) != 0 {
		t.Errorf("gesperrt ohne Probleme: %+v", got)
	}
}

func TestEvaluateHostSchwellenAus(t *testing.T) {
	m := metrics(100, 1, [4]any{"/", "ext4", 100, 1})
	got := EvaluateHost(HostInput{Hostname: "h", Metrics: m}, map[string]string{"speicher": Crit, "platte:/": Crit},
		HostLimits{SilentAfter: time.Minute})
	// Abgeschaltete Messwerte entwarnen, was noch gemeldet ist.
	if len(got) != 3 || got[1].Status != OK || got[2].Status != OK {
		t.Errorf("Schwellen aus: %+v", got)
	}
}

func TestSince(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second:               "seit 1 Min.",
		3*time.Minute + 59*time.Second: "seit 3 Min.",
		2 * time.Hour:                  "seit 2 Std.",
		2*time.Hour + 5*time.Minute:    "seit 2 Std. 5 Min.",
		50 * time.Hour:                 "seit 2 Tagen",
	} {
		if got := since(d); got != want {
			t.Errorf("since(%s) = %q, erwartet %q", d, got, want)
		}
	}
}

func TestEvaluateHostCPU(t *testing.T) {
	l := lim
	l.CPUWarn, l.CPUCrit = 90, 98
	cpu := func(v float64) *HostMetrics {
		m := metrics(0, 0)
		m.CPU15 = &v
		return m
	}
	find := func(f []Finding) *Finding {
		for i := range f {
			if f[i].Subject == SubjectCPU {
				return &f[i]
			}
		}
		return nil
	}
	in := HostInput{Hostname: "h"}
	cases := []struct {
		v          float64
		prev, want string
		msg        string
	}{
		{89.9, "", OK, "89 % ausgelastet, Mittel 15 Min."},
		{90, "", Warn, "90 % ausgelastet, Mittel 15 Min. (Warnung ab 90 %)"},
		{98, "", Crit, "98 % ausgelastet, Mittel 15 Min. (kritisch ab 98 %)"},
		{88.5, Warn, Warn, ""}, // Hysterese
		{87.9, Warn, OK, ""},
		{96.5, Crit, Crit, ""},
	}
	for _, c := range cases {
		in.Metrics = cpu(c.v)
		f := find(EvaluateHost(in, map[string]string{SubjectCPU: c.prev}, l))
		if f == nil || f.Status != c.want || c.msg != "" && f.Message != c.msg || f.Name != "h · CPU" {
			t.Errorf("CPU %v (vorher %q): %+v, erwartet %s %q", c.v, c.prev, f, c.want, c.msg)
		}
	}
	// Ohne ausreichende Werte: nicht bewertet; ein gemeldetes Problem wird entwarnt.
	in.Metrics = metrics(0, 0)
	if f := find(EvaluateHost(in, nil, l)); f != nil {
		t.Errorf("ohne Mittelwert bewertet: %+v", f)
	}
	if f := find(EvaluateHost(in, map[string]string{SubjectCPU: Crit}, l)); f == nil || f.Status != OK {
		t.Errorf("ohne Mittelwert nicht entwarnt: %+v", f)
	}
	// Unsinnige Werte und abgeschaltete Schwellen.
	in.Metrics = cpu(150)
	if f := find(EvaluateHost(in, nil, l)); f != nil {
		t.Errorf("150 %% bewertet: %+v", f)
	}
	in.Metrics = cpu(99)
	if f := find(EvaluateHost(in, nil, lim)); f != nil {
		t.Errorf("ohne CPU-Schwellen bewertet: %+v", f)
	}
}
