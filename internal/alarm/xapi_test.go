// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func xapiSnap() *snmp.Snapshot {
	return &snmp.Snapshot{
		Memory: &snmp.Memory{TotalBytes: 400, AvailableBytes: 200},
		Disks:  []snmp.Disk{{Mount: "SR NFS", TotalBytes: 100, FreeBytes: 4}, {Mount: "SR iSCSI", TotalBytes: 100, FreeBytes: 70}},
		XAPI: &snmp.XAPI{Pool: "pool", Master: "xs-01",
			HA: snmp.XAPIHA{Enabled: true, Tolerate: 1, Plan: 0},
			Hosts: []snmp.XAPIHost{
				{Name: "xs-01", Master: true, Live: true, Enabled: true, UptimeS: 40 * 86400, CPUPct: fp(35), MemTotal: 100, MemFree: 50, Updates: "aktuell"},
				{Name: "xs-02", Live: true, Enabled: true, CPUPct: fp(99), MemTotal: 100, MemFree: 8, Updates: "ausstehend", Pending: []string{"reboot_host"}},
				{Name: "xs-03", Live: true, Enabled: false, Maintenance: true, MetricsError: "Adresse nicht freigegeben"},
				{Name: "xs-04", Live: false, Enabled: true, CPUPct: fp(99)},
				{Name: "xs-05", Live: true, Enabled: false},
			},
			VMs: []snmp.XAPIVM{
				{UUID: "aaaaaaaa-0000-4000-8000-000000000001", Name: "srv-dc01", State: "running", Host: "xs-01", AutoStart: true},
				{UUID: "aaaaaaaa-0000-4000-8000-000000000002", Name: "srv-app01", State: "halted", AutoStart: true},
				{UUID: "aaaaaaaa-0000-4000-8000-000000000003", Name: "srv-print", State: "paused", Host: "xs-01", AutoStart: true},
				{UUID: "aaaaaaaa-0000-4000-8000-000000000004", Name: "test-vm", State: "halted"},
			},
			SRs: []snmp.XAPISR{{Name: "NFS", Total: 100, Used: 96}, {Name: "iSCSI", Total: 100, Used: 30, Detached: []string{"xs-02"}},
				{Name: "ISO"}},
		},
	}
}

func TestEvaluateXAPI(t *testing.T) {
	in := SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: xapiSnap(), XAPI: true}
	got := findings(EvaluateSNMP(in, nil, snmpLim))
	want := map[string]string{
		SubjectSilent: OK, "platte:SR NFS": Crit, "platte:SR iSCSI": OK, SubjectMemory: OK,
		"xenhost:xs-01": OK, "xenhost:xs-02": OK, "xenhost:xs-03": Warn, "xenhost:xs-04": Crit, "xenhost:xs-05": Warn,
		"xencpu:xs-01": OK, "xencpu:xs-02": Crit, "xenram:xs-01": OK, "xenram:xs-02": Warn,
		"xenvm:aaaaaaaa-0000-4000-8000-000000000001": OK, "xenvm:aaaaaaaa-0000-4000-8000-000000000002": Crit,
		"xenvm:aaaaaaaa-0000-4000-8000-000000000003": Warn,
		"xensr:iSCSI": Crit, SubjectXenHA: Warn, SubjectXenUpdates: Warn,
	}
	for sub, st := range want {
		if got[sub].Status != st {
			t.Errorf("%s: %q (%s), erwartet %q", sub, got[sub].Status, got[sub].Message, st)
		}
		if !SNMPSubject(sub) {
			t.Errorf("%s gilt nicht als Gegenstand", sub)
		}
	}
	// keine Bewertung: VM ohne „soll laufen“, ausgefallener Host ohne CPU, angebundene SRs ohne frühere Störung
	for _, sub := range []string{"xenvm:aaaaaaaa-0000-4000-8000-000000000004", "xencpu:xs-04", "xensr:NFS", "xensr:ISO", "xencpu:xs-03"} {
		if f, ok := got[sub]; ok {
			t.Errorf("%s bewertet: %+v", sub, f)
		}
	}
	for sub, parts := range map[string][]string{
		"xenhost:xs-01":   {"Pool-Master", "seit 40 Tagen"},
		"xenhost:xs-03":   {"Wartungsmodus"},
		"xenhost:xs-04":   {"nicht erreichbar"},
		"xenhost:xs-05":   {"deaktiviert"},
		"xencpu:xs-02":    {"99 %", "kritisch ab 98"},
		"xenram:xs-02":    {"92 %", "Warnung ab 90"},
		"xensr:iSCSI":     {"nicht angebunden auf xs-02"},
		SubjectXenHA:      {"0 von 1"},
		SubjectXenUpdates: {"Updates ausstehend auf xs-02", "xs-02: Host neu starten"},
		"xenvm:aaaaaaaa-0000-4000-8000-000000000002": {"soll aber laufen"},
	} {
		for _, p := range parts {
			if !strings.Contains(got[sub].Message, p) {
				t.Errorf("%s: %q ohne %q", sub, got[sub].Message, p)
			}
		}
	}
	for sub, name := range map[string]string{
		"platte:SR NFS": "pool · SR NFS", "xenhost:xs-02": "pool · Host xs-02", "xencpu:xs-02": "pool · Host xs-02 CPU",
		"xenvm:aaaaaaaa-0000-4000-8000-000000000003": "pool · VM srv-print auf xs-01", "xensr:iSCSI": "pool · SR iSCSI Anbindung",
	} {
		if got[sub].Name != name {
			t.Errorf("Name %s: %q", sub, got[sub].Name)
		}
	}
}

func TestXAPIEinzelhostUndHA(t *testing.T) {
	snap := xapiSnap()
	x := snap.XAPI
	x.Hosts = x.Hosts[:1]
	x.HA = snmp.XAPIHA{}
	x.Hosts[0].Updates = ""
	got := findings(EvaluateSNMP(SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: snap, XAPI: true}, nil, snmpLim))
	// ein Host: CPU/RAM nur als „CPU“ und „Speicher“ des Pools; HA aus ohne frühere Störung: nicht bewertet; Updates unbekannt
	for _, sub := range []string{"xencpu:xs-01", "xenram:xs-01", SubjectXenHA, SubjectXenUpdates} {
		if f, ok := got[sub]; ok {
			t.Errorf("%s bewertet: %+v", sub, f)
		}
	}
	x.HA = snmp.XAPIHA{Enabled: true, Tolerate: 1, Plan: 1, Overcommitted: false}
	got = findings(EvaluateSNMP(SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: snap, XAPI: true}, nil, snmpLim))
	if got[SubjectXenHA].Status != OK {
		t.Errorf("HA: %+v", got[SubjectXenHA])
	}
	x.HA.Overcommitted = true
	got = findings(EvaluateSNMP(SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: snap, XAPI: true}, nil, snmpLim))
	if got[SubjectXenHA].Status != Crit || !strings.Contains(got[SubjectXenHA].Message, "überbucht") {
		t.Errorf("HA überbucht: %+v", got[SubjectXenHA])
	}
}

func TestXAPIEntwarnungUndTeile(t *testing.T) {
	snap := xapiSnap()
	prev := map[string]string{"xensr:NFS": Crit, "xenvm:aaaaaaaa-0000-4000-8000-0000000000ff": Crit, "xenhost:alt": Crit, SubjectXenHA: Warn}
	snap.XAPI.HA = snmp.XAPIHA{}
	got := findings(EvaluateSNMP(SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: snap, XAPI: true}, prev, snmpLim))
	if got["xensr:NFS"].Status != OK || !strings.Contains(got["xensr:NFS"].Message, "wieder angebunden") {
		t.Errorf("SR: %+v", got["xensr:NFS"])
	}
	if f := got["xenvm:aaaaaaaa-0000-4000-8000-0000000000ff"]; f.Status != OK || f.Name != "pool · VM aaaaaaaa-0000-4000-8000-0000000000ff" {
		t.Errorf("verschwundene VM: %+v", f)
	}
	if f := got["xenhost:alt"]; f.Status != OK || f.Name != "pool · Host alt" {
		t.Errorf("verschwundener Host: %+v", f)
	}
	if got[SubjectXenHA].Status != OK {
		t.Errorf("HA aus nach Warnung: %+v", got[SubjectXenHA])
	}
	// Teile, deren Abfrage scheiterte, behalten ihren Zustand.
	snap = xapiSnap()
	snap.Partial = []string{"VMs", "Speicher"}
	snap.XAPI.VMs, snap.XAPI.SRs = nil, nil
	prev = map[string]string{"xenvm:aaaaaaaa-0000-4000-8000-000000000002": Crit, "xensr:iSCSI": Crit}
	got = findings(EvaluateSNMP(SNMPInput{Name: "pool", Interval: time.Minute, Snapshot: snap, XAPI: true}, prev, snmpLim))
	for sub := range prev {
		if got[sub].Status != Crit || !strings.Contains(got[sub].Message, "nicht abfragbar") {
			t.Errorf("%s: %+v", sub, got[sub])
		}
	}
	// Ausgeschaltet und stumm mit XAPI-Texten
	got = findings(EvaluateSNMP(SNMPInput{Name: "pool", Disabled: true, XAPI: true}, map[string]string{"xenhost:xs-01": Crit}, snmpLim))
	if !strings.Contains(got["xenhost:xs-01"].Message, "XenServer-Abfrage ausgeschaltet") {
		t.Errorf("aus: %+v", got)
	}
	got = findings(EvaluateSNMP(SNMPInput{Name: "pool", Silent: time.Hour, Interval: time.Minute, XAPI: true,
		LastError: "Pool-Master gewechselt"}, nil, snmpLim))
	if !strings.Contains(got[SubjectSilent].Message, "(XAPI)") || !strings.Contains(got[SubjectSilent].Message, "Pool-Master gewechselt") {
		t.Errorf("stumm: %+v", got[SubjectSilent])
	}
}
