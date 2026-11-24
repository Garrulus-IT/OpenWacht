// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func tp(t time.Time) *time.Time { return &t }
func bp(b bool) *bool           { return &b }

func proxmoxSnap(now time.Time) *snmp.Snapshot {
	return &snmp.Snapshot{
		Disks: []snmp.Disk{{Mount: "local-lvm", FSType: "lvmthin", TotalBytes: 100, FreeBytes: 4}},
		Proxmox: &snmp.Proxmox{Node: "pve-1", BackupInfo: true,
			Guests: []snmp.Guest{
				{VMID: 100, Type: "qemu", Name: "srv-dms", Status: "running", OnBoot: bp(true), InJob: bp(true),
					BackupOK: tp(now.Add(-11 * time.Hour))},
				{VMID: 101, Type: "lxc", Name: "openwacht", Status: "stopped", OnBoot: bp(true), InJob: bp(true),
					BackupOK: tp(now.Add(-30 * time.Hour)), BackupTry: tp(now.Add(-6 * time.Hour)), BackupError: "Permission denied"},
				{VMID: 102, Type: "qemu", Name: "test", Status: "stopped", OnBoot: bp(false), InJob: bp(true),
					BackupOK: tp(now.Add(-51 * time.Hour))},
				{VMID: 103, Type: "qemu", Name: "neu", Status: "paused", OnBoot: bp(true), InJob: bp(true)},
				{VMID: 104, Type: "qemu", Name: "ohne-job", Status: "stopped", InJob: bp(false)},
				{VMID: 105, Type: "qemu", Name: "vorlage", Status: "stopped", Template: true, OnBoot: bp(true), InJob: bp(false)},
			},
			Storages: []snmp.Storage{{Name: "local-lvm", Enabled: true, Active: true}, {Name: "nas-backup", Enabled: true},
				{Name: "alt", Enabled: false}},
			ThinPools: []snmp.ThinPool{{Name: "pve/data", MetaSizeBytes: 100, MetaUsedBytes: 85}},
		},
	}
}

func TestEvaluateProxmox(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	in := SNMPInput{Name: "pve-1", Interval: time.Minute, Snapshot: proxmoxSnap(now), Proxmox: true, Now: now}
	got := findings(EvaluateSNMP(in, nil, snmpLim))
	want := map[string]string{
		SubjectSilent: OK, "platte:local-lvm": Crit,
		"gast:100": OK, "gast:101": Crit, "gast:103": Warn,
		"backup:100": OK, "backup:101": Warn, "backup:102": Crit, "backup:103": Crit,
		"pvespeicher:nas-backup": Crit, "meta:pve/data": Warn,
	}
	for sub, st := range want {
		if got[sub].Status != st {
			t.Errorf("%s: %q (%s), erwartet %q", sub, got[sub].Status, got[sub].Message, st)
		}
		if !SNMPSubject(sub) {
			t.Errorf("%s gilt nicht als Gegenstand", sub)
		}
	}
	for _, sub := range []string{"gast:102", "gast:104", "gast:105", "backup:104", "backup:105", "pvespeicher:alt", "pvespeicher:local-lvm"} {
		if f, ok := got[sub]; ok {
			t.Errorf("%s bewertet: %+v", sub, f)
		}
	}
	if f := got["backup:101"]; f.Name != "pve-1 · Backup CT 101 (openwacht)" ||
		!strings.Contains(f.Message, "vor 30 Std.") || !strings.Contains(f.Message, "fehlgeschlagen: Permission denied") {
		t.Errorf("%+v", f)
	}
	if f := got["gast:101"]; f.Name != "pve-1 · CT 101 (openwacht)" || !strings.Contains(f.Message, "stopped") {
		t.Errorf("%+v", f)
	}
	if f := got["platte:local-lvm"]; f.Name != "pve-1 · Speicher local-lvm" {
		t.Errorf("%+v", f)
	}
	if f := got["meta:pve/data"]; !strings.Contains(f.Message, "85 %") || !strings.Contains(f.Message, "Warnung ab 80") {
		t.Errorf("%+v", f)
	}
	if f := got["backup:102"]; !strings.Contains(f.Message, "vor 51 Std. (kritisch ab 50 Std.)") {
		t.Errorf("%+v", f)
	}

	// Hysterese der Metadaten: 79 % bleibt Warnung, 77 % entwarnt
	in.Snapshot.Proxmox.ThinPools[0].MetaUsedBytes = 79
	if f := findings(EvaluateSNMP(in, map[string]string{"meta:pve/data": Warn}, snmpLim))["meta:pve/data"]; f.Status != Warn {
		t.Errorf("Hysterese: %+v", f)
	}
	in.Snapshot.Proxmox.ThinPools[0].MetaUsedBytes = 77
	if f := findings(EvaluateSNMP(in, map[string]string{"meta:pve/data": Warn}, snmpLim))["meta:pve/data"]; f.Status != OK {
		t.Errorf("Entwarnung: %+v", f)
	}

	if _, ok := got["pvespeicher:local-lvm"]; ok {
		t.Error("verfügbarer Speicher ohne vorige Störung gemeldet")
	}
	if f := findings(EvaluateSNMP(in, map[string]string{"pvespeicher:local-lvm": Crit}, snmpLim))["pvespeicher:local-lvm"]; f.Status != OK ||
		f.Message != "wieder verfügbar" {
		t.Errorf("Entwarnung Speicher: %+v", f)
	}

	// Gast verschwunden: Entwarnung mit Ersatzname
	gone := findings(EvaluateSNMP(in, map[string]string{"gast:199": Crit, "backup:199": Crit}, snmpLim))
	if f := gone["gast:199"]; f.Status != OK || f.Name != "pve-1 · Gast 199" {
		t.Errorf("%+v", f)
	}

	// Backup-Jobs unbekannt: nur Gäste mit bekanntem Backup
	px := in.Snapshot.Proxmox
	for i := range px.Guests {
		px.Guests[i].InJob = nil
	}
	got = findings(EvaluateSNMP(in, nil, snmpLim))
	if got["backup:100"].Status != OK || got["backup:103"].Status != "" {
		t.Errorf("ohne Job-Info: %+v %+v", got["backup:100"], got["backup:103"])
	}
}

func TestProxmoxStummUndAus(t *testing.T) {
	in := SNMPInput{Name: "pve-1", Interval: time.Minute, Silent: 10 * time.Minute, Proxmox: true, LastError: "Token abgelehnt"}
	fs := EvaluateSNMP(in, nil, snmpLim)
	if len(fs) != 1 || fs[0].Status != Crit || !strings.Contains(fs[0].Message, "Proxmox-API") || !strings.Contains(fs[0].Message, "Token") {
		t.Fatalf("%+v", fs)
	}
	off := EvaluateSNMP(SNMPInput{Name: "pve-1", Disabled: true, Proxmox: true}, map[string]string{"backup:100": Crit}, snmpLim)
	if len(off) != 1 || off[0].Status != OK || !strings.Contains(off[0].Message, "Proxmox") {
		t.Fatalf("%+v", off)
	}
}

func TestProxmoxGegenstaende(t *testing.T) {
	for _, bad := range []string{"gast:", "gast:99", "gast:0100", "gast:1x0", "backup:1234567890", "meta:", "pvespeicher:"} {
		if SNMPSubject(bad) {
			t.Errorf("%q angenommen", bad)
		}
	}
	for _, ok := range []string{"gast:100", "backup:999999999", "meta:pve/data", "pvespeicher:nas-backup"} {
		if !SNMPSubject(ok) {
			t.Errorf("%q abgelehnt", ok)
		}
	}
}
