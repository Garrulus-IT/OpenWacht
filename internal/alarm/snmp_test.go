// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func findings(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Subject] = f
	}
	return m
}

func ip(n int) *int         { return &n }
func fp(f float64) *float64 { return &f }

var snmpLim = HostLimits{SilentAfter: 3 * time.Minute, DiskWarn: 90, DiskCrit: 95, MemWarn: 90, MemCrit: 95, CPUWarn: 90, CPUCrit: 98}

func TestEvaluateSNMP(t *testing.T) {
	snap := &snmp.Snapshot{
		Memory: &snmp.Memory{TotalBytes: 100, AvailableBytes: 4}, // 96 % belegt
		Disks:  []snmp.Disk{{Mount: "/volume1", TotalBytes: 100, FreeBytes: 50}},
		Interfaces: []snmp.Interface{
			{Index: 1, Name: "Port 1", AdminUp: true, Oper: "up", SpeedBps: 1_000_000_000},
			{Index: 2, Name: "Port 2", AdminUp: true, Oper: "down"},
			{Index: 3, Name: "Port 3", AdminUp: false, Oper: "down"},
			{Index: 4, Name: "Port 4", AdminUp: true, Oper: "down"}, // nicht überwacht
		},
		Synology: &snmp.Synology{SystemStatus: 1, PowerStatus: 1, SystemFan: 1, CPUFan: 2, Temperature: ip(66),
			Disks: []snmp.SynoDisk{{Name: "Laufwerk 1", Status: 1, Temperature: ip(40)}, {Name: "Laufwerk 2", Status: 1, Health: 3}},
			Raids: []snmp.SynoRaid{{Name: "Speicherpool 1", Status: 13}, {Name: "Speicherpool 2", Status: 11}}},
		UPS:      &snmp.UPS{OnBattery: true, ChargePct: fp(40)},
		Supplies: []snmp.Supply{{Name: "Toner Schwarz", Percent: fp(5)}, {Name: "Toner Cyan", Percent: fp(60)}},
	}
	reboot := 3 * time.Minute
	in := SNMPInput{Name: "nas", Interval: time.Minute, Snapshot: snap, Silent: 30 * time.Second, RebootedAgo: &reboot,
		Watched: []string{"Port 1", "Port 2", "Port 3", "Port 9"}, CPU15: fp(99)}
	got := findings(EvaluateSNMP(in, nil, snmpLim))
	want := map[string]string{
		SubjectSilent: OK, SubjectMemory: Crit, SubjectCPU: Crit, "platte:/volume1": OK, SubjectReboot: Warn,
		"if:Port 1": OK, "if:Port 2": Crit, "if:Port 3": Warn, "if:Port 9": Crit,
		SubjectSystem: Crit, SubjectTemperature: Warn, "laufwerk:Laufwerk 1": OK, "laufwerk:Laufwerk 2": Crit,
		"raid:Speicherpool 1": OK, "raid:Speicherpool 2": Crit, SubjectUPS: Crit,
		"toner:Toner Schwarz": Warn, "toner:Toner Cyan": OK,
	}
	for sub, st := range want {
		if got[sub].Status != st {
			t.Errorf("%s: %q (%s), erwartet %q", sub, got[sub].Status, got[sub].Message, st)
		}
		if !SNMPSubject(sub) {
			t.Errorf("%s gilt nicht als Gegenstand", sub)
		}
	}
	if _, ok := got["if:Port 4"]; ok {
		t.Error("nicht überwachte Schnittstelle bewertet")
	}
	if len(got) != len(want) {
		t.Errorf("%d Gegenstände, erwartet %d: %v", len(got), len(want), got)
	}
	if !strings.Contains(got[SubjectSystem].Message, "CPU-Lüfter") || got["if:Port 1"].Message != "verbunden, 1 Gbit/s" {
		t.Errorf("Meldungen: %q, %q", got[SubjectSystem].Message, got["if:Port 1"].Message)
	}
	if got["laufwerk:Laufwerk 2"].Name != "nas · Laufwerk Laufwerk 2" {
		t.Errorf("Name: %q", got["laufwerk:Laufwerk 2"].Name)
	}

	// Stumm: nur „antwortet nicht“ mit dem letzten Fehler, alte Werte werden weder gemeldet noch entwarnt.
	in.Silent, in.LastError = 10*time.Minute, "keine Antwort"
	fs := EvaluateSNMP(in, map[string]string{"if:Port 2": Crit}, snmpLim)
	if len(fs) != 1 || fs[0].Subject != SubjectSilent || fs[0].Status != Crit || !strings.Contains(fs[0].Message, "keine Antwort") {
		t.Errorf("stumm: %+v", fs)
	}
	// Langes Intervall: stumm erst nach drei Intervallen.
	in.Interval, in.Silent = 10*time.Minute, 20*time.Minute
	if f := findings(EvaluateSNMP(in, nil, snmpLim)); f[SubjectSilent].Status != OK {
		t.Errorf("zu früh stumm bei langem Intervall: %+v", f[SubjectSilent])
	}
	in.Interval, in.Silent = time.Minute, 0
	// Während die Zentrale startet: keine Bewertung.
	in.Silent, in.Warming = 10*time.Minute, true
	if fs := EvaluateSNMP(in, nil, snmpLim); fs != nil {
		t.Errorf("Schonfrist: %+v", fs)
	}
	in.Silent, in.Warming = 0, false

	// Ausgeschaltet: alles Gemeldete entwarnen.
	off := EvaluateSNMP(SNMPInput{Name: "nas", Disabled: true}, map[string]string{"if:Port 2": Crit, SubjectUPS: Warn}, snmpLim)
	if len(off) != 2 || off[0].Status != OK || off[1].Status != OK {
		t.Errorf("ausgeschaltet: %+v", off)
	}

	// Verschwundener Gegenstand wird entwarnt; Neustart-Fenster vorbei.
	old := 20 * time.Minute
	in.RebootedAgo = &old
	got = findings(EvaluateSNMP(in, map[string]string{"raid:Alt": Crit, SubjectReboot: Warn}, snmpLim))
	if got["raid:Alt"].Status != OK || got[SubjectReboot].Status != OK {
		t.Errorf("Entwarnung: %+v / %+v", got["raid:Alt"], got[SubjectReboot])
	}

	// Gekürzte Schnittstellentabelle: Fehlen ist kein Alarm.
	snap.Truncated = []string{"Schnittstellen"}
	if got = findings(EvaluateSNMP(in, nil, snmpLim)); got["if:Port 9"].Status != "" {
		t.Errorf("fehlende Schnittstelle trotz gekürzter Tabelle: %+v", got["if:Port 9"])
	}
}

func TestSNMPHysterese(t *testing.T) {
	snap := &snmp.Snapshot{Supplies: []snmp.Supply{{Name: "Toner", Percent: fp(11)}},
		Synology: &snmp.Synology{SystemStatus: 1, Temperature: ip(64)}}
	in := SNMPInput{Name: "x", Interval: time.Minute, Snapshot: snap}
	got := findings(EvaluateSNMP(in, map[string]string{"toner:Toner": Warn, SubjectTemperature: Warn}, snmpLim))
	if got["toner:Toner"].Status != Warn || got[SubjectTemperature].Status != Warn {
		t.Errorf("Hysterese: %+v %+v", got["toner:Toner"], got[SubjectTemperature])
	}
	got = findings(EvaluateSNMP(in, nil, snmpLim))
	if got["toner:Toner"].Status != OK || got[SubjectTemperature].Status != OK {
		t.Errorf("ohne Vorzustand: %+v %+v", got["toner:Toner"], got[SubjectTemperature])
	}
}

func TestRaidUndUSV(t *testing.T) {
	for n, want := range map[int]string{1: OK, 7: OK, 8: OK, 13: OK, 2: Warn, 4: Warn, 11: Crit, 12: Crit, 21: Unknown, 99: Unknown} {
		if st, _ := raidState(n); st != want {
			t.Errorf("RAID %d: %s, erwartet %s", n, st, want)
		}
	}
	cases := []struct {
		u    snmp.UPS
		want string
	}{
		{snmp.UPS{}, OK},
		{snmp.UPS{OnBattery: true, ChargePct: fp(90)}, Warn},
		{snmp.UPS{OnBattery: true, ChargePct: fp(30)}, Crit},
		{snmp.UPS{LowBattery: true}, Crit},
		{snmp.UPS{Replace: true}, Warn},
	}
	for _, c := range cases {
		if st, msg := upsState(&c.u); st != c.want {
			t.Errorf("USV %+v: %s (%s)", c.u, st, msg)
		}
	}
	for _, bad := range []string{"", "check", "if:", "unbekannt", "platte"} {
		if SNMPSubject(bad) {
			t.Errorf("%q gilt als Gegenstand", bad)
		}
	}
}

// Ausnahmen (0.99.2): ausgenommene Gegenstände gelten als OK, die
// Erreichbarkeit nie.
func TestEvaluateSNMPAusnahmen(t *testing.T) {
	in := SNMPInput{Name: "sw-1", Interval: time.Minute, Silent: time.Hour, Excluded: map[string]string{SubjectSilent: "x"}}
	f := EvaluateSNMP(in, nil, snmpLim)
	if len(f) != 1 || f[0].Status != Crit {
		t.Fatalf("stumm trotz Ausnahme: %+v", f)
	}
	in = SNMPInput{Name: "sw-1", Interval: time.Minute, Traps: []TrapState{{Rule: "0b6a8a00-1111-4222-8333-444455556666", Name: "Port", Status: Crit}}}
	sub := in.Traps[0].Subject()
	in.Excluded = map[string]string{sub: "alter Port"}
	for _, x := range EvaluateSNMP(in, nil, snmpLim) {
		if x.Subject == sub && (x.Status != OK || x.Message != "ausgenommen: alter Port") {
			t.Errorf("Ausnahme: %+v", x)
		}
	}
}
