// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

func TestSynologyUSVDrucker(t *testing.T) {
	f := snmptest.New(t, "c",
		snmptest.Num(oidSynoSystemStatus, 1), snmptest.Num(oidSynoTemperature, 47), snmptest.Num(oidSynoPowerStatus, 1),
		snmptest.Num(oidSynoSystemFan, 1), snmptest.Num(oidSynoCPUFan, 2), snmptest.Str(oidSynoModel, "DS920+"), snmptest.Str(oidSynoVersion, "DSM 7.2.2"),
		snmptest.Num(oidSynoDiskStatus+".0", 1), snmptest.Str(oidSynoDiskName+".0", "Laufwerk 1"), snmptest.Num(oidSynoDiskTemp+".0", 38),
		snmptest.Num(oidSynoDiskHealth+".0", 1),
		snmptest.Num(oidSynoDiskStatus+".1", 5), snmptest.Str(oidSynoDiskName+".1", "Laufwerk 2"), snmptest.Num(oidSynoDiskTemp+".1", 41),
		snmptest.Str(oidSynoRaidName+".0", "Speicherpool 1"), snmptest.Num(oidSynoRaidStatus+".0", 11),
		gosnmp.SnmpPDU{Name: oidSynoRaidFree + ".0", Type: gosnmp.Counter64, Value: uint64(1 << 40)},
		gosnmp.SnmpPDU{Name: oidSynoRaidTotal + ".0", Type: gosnmp.Counter64, Value: uint64(4 << 40)},
		snmptest.Str(oidSynoUPSModel, "Back-UPS ES 700"), snmptest.Str(oidSynoUPSStatus, "OB DISCHRG"),
		gosnmp.SnmpPDU{Name: oidSynoUPSCharge, Type: gosnmp.OpaqueFloat, Value: float32(83.5)},
		snmptest.Str(oidPrtSupplyDescr+".1.1", "Black Toner"), snmptest.Num(oidPrtSupplyMax+".1.1", 100), snmptest.Num(oidPrtSupplyLevel+".1.1", 7),
		snmptest.Str(oidPrtSupplyDescr+".1.2", "Waste\x07Box"), snmptest.Num(oidPrtSupplyMax+".1.2", -2), snmptest.Num(oidPrtSupplyLevel+".1.2", -3),
	)
	c := loopbackClient()
	for _, v := range []string{V1, V2c} {
		snap, err := c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
		if err != nil {
			t.Fatal(v, err)
		}
		syn := snap.Synology
		if syn == nil || syn.Model != "DS920+" || syn.CPUFan != 2 || syn.Temperature == nil || *syn.Temperature != 47 {
			t.Fatalf("v%s Synology: %+v", v, syn)
		}
		if len(syn.Disks) != 2 || syn.Disks[1].Status != 5 || syn.Disks[1].Name != "Laufwerk 2" || syn.Disks[0].Health != 1 {
			t.Errorf("v%s Laufwerke: %+v", v, syn.Disks)
		}
		if len(syn.Raids) != 1 || syn.Raids[0].Status != 11 || syn.Raids[0].TotalBytes != 4<<40 && v == V2c {
			t.Errorf("v%s RAID: %+v", v, syn.Raids)
		}
		u := snap.UPS
		if u == nil || u.Source != "synology" || !u.OnBattery || u.LowBattery || u.ChargePct == nil || *u.ChargePct != 83.5 {
			t.Errorf("v%s USV: %+v", v, u)
		}
		if len(snap.Supplies) != 2 || snap.Supplies[0].Percent == nil || math.Abs(*snap.Supplies[0].Percent-7) > 1e-9 ||
			snap.Supplies[1].Percent != nil || snap.Supplies[1].Name != "Waste Box" {
			t.Errorf("v%s Material: %+v", v, snap.Supplies)
		}
		if len(snap.Partial) > 0 {
			t.Errorf("v%s teilweise: %v", v, snap.Partial)
		}
	}
}

func TestUSVNachRFC1628(t *testing.T) {
	f := snmptest.New(t, "c", snmptest.Num(oidUpsBatteryStatus, 3), snmptest.Num(oidUpsOutputSource, 5), snmptest.Num(oidUpsChargeRemaining, 20),
		snmptest.Num(oidUpsMinutesRemaining, 4), snmptest.Str(oidUpsIdentModel, "Smart-UPS"))
	snap, err := loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := snap.UPS
	if u == nil || u.Source != "rfc1628" || !u.OnBattery || !u.LowBattery || u.RuntimeS == nil || *u.RuntimeS != 240 {
		t.Errorf("USV: %+v", u)
	}
}

func TestKaputteGeraete(t *testing.T) {
	// Große Tabelle: wird bei der Grenze abgeschnitten und als gekürzt gemeldet.
	var many []gosnmp.SnmpPDU
	for i := 1; i <= MaxInterfaces+50; i++ {
		idx := "." + itoa(i)
		many = append(many, snmptest.Str(oidIfDescr+idx, "port"+itoa(i)), snmptest.Num(oidIfOperStatus+idx, 1), snmptest.Num(oidIfAdminStatus+idx, 1))
	}
	f := snmptest.New(t, "c", many...)
	snap, err := loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Interfaces) != MaxInterfaces || len(snap.Truncated) == 0 {
		t.Errorf("Grenze: %d Schnittstellen, gekürzt %v", len(snap.Interfaces), snap.Truncated)
	}

	// Gerät liefert eine kleinere OID (Endlosschleife): Teil scheitert, Abfrage endet.
	g := snmptest.NewLoop(t, "c", oidIfDescr+".1", snmptest.Str(oidIfDescr+".1", "eth0"))
	start := time.Now()
	snap, err = loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: g.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Partial) == 0 || time.Since(start) > 10*time.Second {
		t.Errorf("Schleife nicht erkannt: %v nach %s", snap.Partial, time.Since(start))
	}

	// Falscher Typ (Text statt Zahl) und Unsinnswerte werden ignoriert.
	h := snmptest.New(t, "c", snmptest.Str(oidHrProcLoad+".1", "100"), snmptest.Num(oidHrProcLoad+".2", 250),
		snmptest.Gauge(oidMemTotalReal, 0), snmptest.Num(oidSynoSystemStatus, 1), snmptest.Num(oidSynoTemperature, 9999))
	snap, err = loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: h.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.CPU != nil || snap.Memory != nil || snap.Synology == nil || snap.Synology.Temperature != nil {
		t.Errorf("Unsinn übernommen: CPU %+v, Speicher %+v, Synology %+v", snap.CPU, snap.Memory, snap.Synology)
	}

	// Ohne Systemdaten (nichts unter SNMPv2-MIB): Fehler.
	empty, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	_, err = loopbackClient().Probe(context.Background(), Config{Version: V2c, Host: "127.0.0.1",
		Port: uint16(empty.LocalAddr().(*net.UDPAddr).Port), Community: "c"})
	if !errors.Is(err, ErrNoResponse) {
		t.Errorf("stummes Gerät: %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
