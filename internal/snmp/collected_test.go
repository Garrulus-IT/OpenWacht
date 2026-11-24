// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

// roundtrip: was ein Sammler schickt (JSON), wieder eingelesen.
func roundtrip(t *testing.T, s *Snapshot) *Snapshot {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// Ein ehrlicher Sammler (derselbe Poll-Code) besteht die Prüfung immer, auch
// bei kaputten oder großen Geräten.
func TestValidateCollectedEhrlicherSammler(t *testing.T) {
	var many []gosnmp.SnmpPDU
	for i := 1; i <= MaxInterfaces+5; i++ {
		idx := "." + itoa(i)
		many = append(many, snmptest.Str(oidIfDescr+idx, "port\x00"+itoa(i)), snmptest.Num(oidIfOperStatus+idx, i%9))
	}
	// nacheinander starten: snmptest teilt Zustand in gosnmp, gleichzeitige
	// Gegenstellen meldet der Race-Detektor
	devices := map[string]func() *snmptest.Agent{
		"Synology/USV/Drucker": func() *snmptest.Agent {
			return snmptest.New(t, "c",
				snmptest.Num(oidSynoSystemStatus, 1), snmptest.Num(oidSynoTemperature, 47), snmptest.Str(oidSynoModel, "DS920+"),
				snmptest.Num(oidSynoDiskStatus+".0", 1), snmptest.Str(oidSynoDiskName+".0", "Laufwerk 1"), snmptest.Num(oidSynoDiskTemp+".0", 38),
				snmptest.Num(oidSynoRaidStatus+".0", 99999), // Unsinn bleibt Zahl
				snmptest.Str(oidSynoUPSStatus, "OB DISCHRG"),
				gosnmp.SnmpPDU{Name: oidSynoUPSCharge, Type: gosnmp.OpaqueFloat, Value: float32(83.5)},
				snmptest.Str(oidPrtSupplyDescr+".1.1", "Black Toner"), snmptest.Num(oidPrtSupplyMax+".1.1", 3), snmptest.Num(oidPrtSupplyLevel+".1.1", 1),
				snmptest.Str(oidPrtSupplyDescr+".1.2", "Waste\x07Box"), snmptest.Num(oidPrtSupplyMax+".1.2", -2), snmptest.Num(oidPrtSupplyLevel+".1.2", -3))
		},
		"RFC 1628": func() *snmptest.Agent {
			return snmptest.New(t, "c", snmptest.Num(oidUpsBatteryStatus, 3), snmptest.Num(oidUpsOutputSource, 5),
				snmptest.Num(oidUpsChargeRemaining, 20), snmptest.Num(oidUpsMinutesRemaining, 4))
		},
		"zu viele": func() *snmptest.Agent { return snmptest.New(t, "c", many...) },
		"Schleife": func() *snmptest.Agent {
			return snmptest.NewLoop(t, "c", oidIfDescr+".1", snmptest.Str(oidIfDescr+".1", "eth0"))
		},
		"Unsinn": func() *snmptest.Agent {
			return snmptest.New(t, "c", snmptest.Num(oidHrProcLoad+".2", 250), snmptest.Gauge(oidMemTotalReal, 0), snmptest.Num(oidSynoTemperature, 9999))
		},
		"Bidi-Name": func() *snmptest.Agent {
			return snmptest.New(t, "c", snmptest.Str("1.3.6.1.2.1.1.5.0", "sw\u202e-gpj.exe"))
		},
	}
	c := loopbackClient()
	for name, mk := range devices {
		f := mk()
		snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
		if err != nil {
			t.Fatal(name, err)
		}
		if err := roundtrip(t, snap).ValidateCollected(time.Now()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	t.Run("snmpd", func(t *testing.T) {
		host, port, community := testTarget(t)
		snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: host, Port: port, Community: community}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := roundtrip(t, snap).ValidateCollected(time.Now()); err != nil {
			t.Errorf("snmpd: %v", err)
		}
	})
}

func validCollected(now time.Time) *Snapshot {
	pct := 50.0
	temp := 40
	return &Snapshot{CollectedAt: now, System: System{Descr: "Switch", Name: "sw", ObjectID: "1.3.6.1.4.1.9", UptimeTicks: 12345, UptimeS: 123},
		CPU: &CPU{Cores: 2, Percent: 10}, Memory: &Memory{TotalBytes: 10, AvailableBytes: 5},
		Disks:      []Disk{{Mount: "/", TotalBytes: 10, FreeBytes: 1}},
		Interfaces: []Interface{{Index: 1, Name: "Port 1", Oper: "up"}, {Index: 2, Name: "Port 2", Oper: "down", HC: true, InOctets: 1 << 40}},
		Synology:   &Synology{Model: "DS", Temperature: &temp, Disks: []SynoDisk{{Name: "L1", Health: 1}}, Raids: []SynoRaid{{Name: "R", TotalBytes: 2, FreeBytes: 1}}},
		UPS:        &UPS{Source: "synology", Status: "OL", ChargePct: &pct},
		Supplies:   []Supply{{Name: "Toner", Level: 1, Max: 4, Percent: func() *float64 { p := 25.0; return &p }()}},
		Partial:    []string{"Drucker"},
		Counters:   &CounterInfo{At: now, UptimeTicks: 12345}}
}

func TestValidateCollectedNegativ(t *testing.T) {
	now := time.Now().UTC()
	if err := validCollected(now).ValidateCollected(now); err != nil {
		t.Fatalf("gültiger Snapshot abgelehnt: %v", err)
	}
	big := 101.0
	for name, mod := range map[string]func(s *Snapshot){
		"Zeit Zukunft":          func(s *Snapshot) { s.CollectedAt = now.Add(5 * time.Minute); s.Counters.At = s.CollectedAt },
		"Zeit alt":              func(s *Snapshot) { s.CollectedAt = now.Add(-time.Hour); s.Counters.At = s.CollectedAt },
		"ohne Zähler":           func(s *Snapshot) { s.Counters = nil },
		"Zählerzeit":            func(s *Snapshot) { s.Counters.At = now.Add(-time.Second) },
		"Ticks":                 func(s *Snapshot) { s.Counters.UptimeTicks = 1 },
		"Laufzeit":              func(s *Snapshot) { s.System.UptimeS = 999 },
		"Proxmox":               func(s *Snapshot) { s.Proxmox = &Proxmox{} },
		"FRITZ!Box":             func(s *Snapshot) { s.FritzBox = &FritzBox{} },
		"Steuerzeichen":         func(s *Snapshot) { s.System.Name = "a\nb" },
		"Bidi":                  func(s *Snapshot) { s.System.Location = "a\u202eb" },
		"zu lang":               func(s *Snapshot) { s.System.Descr = strings.Repeat("x", MaxText+1) },
		"Leerraum":              func(s *Snapshot) { s.System.Descr = "a  b" },
		"ohne Namen":            func(s *Snapshot) { s.System.Descr, s.System.Name = "", "" },
		"OID":                   func(s *Snapshot) { s.System.ObjectID = ".1.3" },
		"CPU":                   func(s *Snapshot) { s.CPU.Percent = 150 },
		"Kerne":                 func(s *Snapshot) { s.CPU.Cores = MaxCPUs + 1 },
		"Speicher":              func(s *Snapshot) { s.Memory.AvailableBytes = 11 },
		"Platte frei":           func(s *Snapshot) { s.Disks[0].FreeBytes = 11 },
		"Platte doppelt":        func(s *Snapshot) { s.Disks = append(s.Disks, s.Disks[0]) },
		"Platte Typ":            func(s *Snapshot) { s.Disks[0].FSType = "nfs" },
		"Platten nil":           func(s *Snapshot) { s.Disks = nil },
		"Schnittstelle Status":  func(s *Snapshot) { s.Interfaces[0].Oper = "<b>" },
		"Schnittstelle Reihe":   func(s *Snapshot) { s.Interfaces[1].Index = 0 },
		"Schnittstelle leer":    func(s *Snapshot) { s.Interfaces[0].Name = "" },
		"32-Bit-Zähler":         func(s *Snapshot) { s.Interfaces[0].InOctets = 1 << 33 },
		"Schnittstellen zuviel": func(s *Snapshot) { s.Interfaces = make([]Interface, MaxInterfaces+1) },
		"Synology Temperatur":   func(s *Snapshot) { *s.Synology.Temperature = 500 },
		"Laufwerk Gesundheit":   func(s *Snapshot) { s.Synology.Disks[0].Health = 9 },
		"RAID frei":             func(s *Snapshot) { s.Synology.Raids[0].FreeBytes = 3 },
		"USV Quelle":            func(s *Snapshot) { s.UPS.Source = "x" },
		"USV Ladung":            func(s *Snapshot) { s.UPS.ChargePct = &big },
		"Toner Prozent":         func(s *Snapshot) { p := 99.0; s.Supplies[0].Percent = &p },
		"Toner ohne Prozent":    func(s *Snapshot) { s.Supplies[0].Percent = nil },
		"Teil unbekannt":        func(s *Snapshot) { s.Partial = []string{"<script>"} },
		"Teile zu viele":        func(s *Snapshot) { s.Truncated = make([]string, 9) },
	} {
		s := validCollected(now)
		mod(s)
		if err := roundtrip(t, s).ValidateCollected(now); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
}

func TestApplyRatesVerwirftFremdeRaten(t *testing.T) {
	now := time.Now()
	prev := validCollected(now.Add(-time.Minute))
	prev.Interfaces[1].InOctets = 1 << 40
	cur := validCollected(now)
	cur.Interfaces[1].InOctets = 1<<40 + 750
	fake := 1e15
	cur.Interfaces[0].InBps = &fake
	cur.Interfaces[0].NewErrors = new(uint64)
	ApplyRates(cur, prev)
	if cur.Interfaces[0].InBps == nil || *cur.Interfaces[0].InBps != 0 {
		t.Errorf("Port 1: %v", cur.Interfaces[0].InBps)
	}
	if r := cur.Interfaces[1].InBps; r == nil || *r != 100 {
		t.Errorf("Port 2: %v", r)
	}
	ApplyRates(cur, nil)
	if cur.Interfaces[0].InBps != nil || cur.Interfaces[0].NewErrors != nil {
		t.Error("ohne vorige Werte bleiben Raten stehen")
	}
}
