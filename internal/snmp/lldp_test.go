// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

// LLDP-Nachbarn landen an der richtigen Schnittstelle: über die Portkennung
// des Geräts, sonst über die Portnummer als ifIndex. Gelesen werden nur Name
// und Port des Nachbarn.
func TestLLDPNachbarn(t *testing.T) {
	raw := func(oid string, b []byte) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: b}
	}
	f := snmptest.New(t, "c",
		snmptest.Str(oidIfDescr+".1", "Port 1"), snmptest.Str(oidIfDescr+".2", "Port 2"),
		snmptest.Str(oidIfDescr+".3", "Port 3"), snmptest.Str(oidIfDescr+".10", "Uplink A"),
		// Portnummer 7 des Geräts ist die Schnittstelle „Uplink A“ (ifIndex 10)
		snmptest.Str(oidLldpLocPortId+".7", "Uplink A"),
		// Nachbar an Portnummer 1 (= ifIndex 1): Name und Portbeschreibung
		snmptest.Str(oidLldpRemSysName+".0.1.1", "sw-keller"),
		snmptest.Str(oidLldpRemPortDesc+".0.1.1", "GigabitEthernet 1/24"),
		snmptest.Str(oidLldpRemPortId+".0.1.1", "gi24"),
		// Portnummer 2: nur eine MAC-Adresse als Portkennung
		snmptest.Str(oidLldpRemSysName+".0.2.1", "ap-flur"),
		raw(oidLldpRemPortId+".0.2.1", []byte{0x00, 0xa0, 0x57, 0x01, 0x02, 0xff}),
		// Portnummer 7 → ifIndex 10 über die Portkennung
		snmptest.Str(oidLldpRemSysName+".0.7.1", "core-01"),
		snmptest.Str(oidLldpRemPortDesc+".0.7.1", strings.Repeat("x", 200)),
		// Portnummer 99: keine Schnittstelle, fällt weg
		snmptest.Str(oidLldpRemSysName+".0.99.1", "verloren"),
		// Verwaltungsadressen (1.0.12): Port 1 mit IPv6 und IPv4 (IPv4 gewinnt),
		// Port 2 nur IPv6 ohne vorangestellte Länge, Port 7 mit unbekannter Art
		snmptest.Num(oidLldpRemManAddrIfSubtype+".0.1.1.2.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1", 2),
		snmptest.Num(oidLldpRemManAddrIfSubtype+".0.1.1.1.4.10.20.0.7", 2),
		snmptest.Num(oidLldpRemManAddrIfSubtype+".0.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.42", 2),
		snmptest.Num(oidLldpRemManAddrIfSubtype+".0.7.1.6.6.0.160.87.1.2.255", 2),
	)
	c := loopbackClient()
	for _, v := range []string{V1, V2c} {
		snap, err := c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.LLDP) != 3 || len(snap.Partial) != 0 {
			t.Fatalf("v%s: %+v, teilweise %v", v, snap.LLDP, snap.Partial)
		}
		if n := snap.LLDP[0]; n != (LLDPNeighbor{Index: 1, Name: "sw-keller", Port: "GigabitEthernet 1/24", Adresse: "10.20.0.7"}) {
			t.Errorf("v%s Port 1: %+v", v, n)
		}
		if n := snap.LLDP[1]; n != (LLDPNeighbor{Index: 2, Name: "ap-flur", Port: "00:a0:57:01:02:ff", Adresse: "2001:db8::2a"}) {
			t.Errorf("v%s Port 2: %+v", v, n)
		}
		if n := snap.LLDP[2]; n.Index != 10 || n.Name != "core-01" || len(n.Port) != MaxLLDPText || n.Adresse != "" {
			t.Errorf("v%s Uplink: %+v", v, n)
		}
		if err := roundtrip(t, snap).ValidateCollected(time.Now()); err != nil {
			t.Errorf("v%s: ValidateCollected: %v", v, err)
		}
		bad := roundtrip(t, snap)
		bad.LLDP[0].Name = strings.Repeat("x", MaxLLDPText+1)
		if bad.ValidateCollected(time.Now()) == nil {
			t.Error("zu langer Name angenommen")
		}
		for _, a := range []string{"10.20.0.07", "fe80::1%eth0", "keine", "10.20.0.7 "} {
			bad = roundtrip(t, snap)
			bad.LLDP[0].Adresse = a
			if bad.ValidateCollected(time.Now()) == nil {
				t.Errorf("Adresse %q angenommen", a)
			}
		}
		bad = roundtrip(t, snap)
		bad.LLDP[0].Name, bad.LLDP[0].Port = "", ""
		if bad.ValidateCollected(time.Now()) == nil {
			t.Error("leerer Nachbar angenommen")
		}
	}
	// Ohne LLDP: keine Nachbarn, kein Fehler.
	ohne := snmptest.New(t, "c", snmptest.Str(oidIfDescr+".1", "eth0"))
	snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: ohne.Port(), Community: "c"}, nil)
	if err != nil || len(snap.LLDP) != 0 || len(snap.Partial) != 0 {
		t.Errorf("ohne LLDP: %v %+v", err, snap)
	}
}

// Seit wann (1.0.11): sysUpTime minus ifLastChange in Sekunden; ohne die
// Spalte oder mit einem Wert nach der Laufzeit fehlt die Angabe.
func TestSchnittstelleSeit(t *testing.T) {
	ticks := func(oid string, v uint32) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.TimeTicks, Value: v}
	}
	f := snmptest.New(t, "c",
		ticks("1.3.6.1.2.1.1.3.0", 1_000_000),
		snmptest.Str(oidIfDescr+".1", "Port 1"), snmptest.Str(oidIfDescr+".2", "Port 2"), snmptest.Str(oidIfDescr+".3", "Port 3"),
		ticks(oidIfLastChange+".1", 400_000), ticks(oidIfLastChange+".2", 2_000_000),
	)
	c := loopbackClient()
	snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Interfaces) != 3 {
		t.Fatalf("%+v", snap.Interfaces)
	}
	if s := snap.Interfaces[0].SinceS; s == nil || *s != 6000 {
		t.Errorf("Port 1: %v", s)
	}
	if snap.Interfaces[1].SinceS != nil || snap.Interfaces[2].SinceS != nil {
		t.Errorf("Port 2 und 3: %v %v", snap.Interfaces[1].SinceS, snap.Interfaces[2].SinceS)
	}
	if err := roundtrip(t, snap).ValidateCollected(time.Now()); err != nil {
		t.Errorf("ValidateCollected: %v", err)
	}
	bad := roundtrip(t, snap)
	zuViel := uint64(1 << 40)
	bad.Interfaces[0].SinceS = &zuViel
	if bad.ValidateCollected(time.Now()) == nil {
		t.Error("unplausible Dauer angenommen")
	}
}
