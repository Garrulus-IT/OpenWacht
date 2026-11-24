// SPDX-License-Identifier: AGPL-3.0-only

package traps

// Fuzz-Ziele für den Trap-Empfang (Befund M3). Trap-Absender sind per UDP
// fälschbar: Jedes Byte eines Pakets kommt von außen. Die Ziele prüfen, dass
// kein Paket eine Panik auslöst und dass angenommene Traps die Grenzen
// einhalten. In der CI läuft jedes Ziel 30 Sekunden (`go test -fuzz`).

import (
	"testing"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

var fuzzV3 = &snmp.V3Auth{User: "wtest", Auth: snmp.AuthSHA256, AuthPass: "auth-pass-123", Priv: snmp.PrivAES, PrivPass: "priv-pass-123"}

const fuzzEngine = "\x80\x00\x1f\x88\x80\x01\x02\x03\x04\x05\x06\x07"

// seedPackets: gültige Pakete als Ausgangspunkt (v1-Trap, v2c-Trap und
// -Inform, v3-Trap authPriv, v3-Discovery).
func seedPackets(t testing.TB) [][]byte {
	vars := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1234)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: 2},
		{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: gosnmp.OctetString, Value: []byte("eth1")},
	}
	var out [][]byte
	add := func(p *gosnmp.SnmpPacket) {
		b, err := p.MarshalMsg()
		if err != nil {
			t.Fatalf("Startpaket: %v", err)
		}
		out = append(out, b)
	}
	add(&gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "c", PDUType: gosnmp.SNMPv2Trap, RequestID: 7, Variables: vars})
	add(&gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "c", PDUType: gosnmp.InformRequest, RequestID: 8, Variables: vars})
	add(&gosnmp.SnmpPacket{Version: gosnmp.Version1, Community: "c", PDUType: gosnmp.Trap, Variables: vars[2:],
		SnmpTrap: gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.8072", AgentAddress: "127.0.0.1", GenericTrap: 6, SpecificTrap: 3, Timestamp: 99}})
	usm := fuzzV3.USM(fuzzEngine)
	usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime = 1, 100
	usm.Logger = gosnmp.NewLogger(nil)
	v3 := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.AuthPriv, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: usm, PDUType: gosnmp.SNMPv2Trap, RequestID: 9, MsgID: 9, MsgMaxSize: MaxPacket, Variables: vars,
		ContextEngineID: fuzzEngine}
	if err := usm.InitSecurityKeys(); err != nil {
		t.Fatalf("v3-Schlüssel: %v", err)
	}
	if err := usm.InitPacket(v3); err != nil {
		t.Fatalf("v3-Salz: %v", err)
	}
	add(v3)
	disc := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.Reportable, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{Logger: gosnmp.NewLogger(nil)}, PDUType: gosnmp.GetRequest, RequestID: 10, MsgID: 10,
		MsgMaxSize: MaxPacket}
	if b, err := disc.MarshalMsg(); err == nil {
		out = append(out, b)
	}
	out = append(out, []byte{0x30, 0x03, 0x02, 0x01, 0x01}, []byte{0x30, 0x82, 0xff, 0xff, 0x02, 0x01, 0x03})
	// andere bekannte Community (Fund des Fuzzers in der CI: Zuordnung zum richtigen Eintrag)
	add(&gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "x", PDUType: gosnmp.SNMPv2Trap, RequestID: 11, Variables: vars})
	return out
}

func addSeeds(f *testing.F) {
	for _, p := range seedPackets(f) {
		f.Add(p)
	}
}

// checkNotification: Grenzen, die ein angenommener Trap einhalten muss.
func checkNotification(t *testing.T, n *Notification) {
	t.Helper()
	if n == nil {
		t.Fatal("Trap ohne Inhalt angenommen")
	}
	if len(n.Varbinds) > MaxVarbinds {
		t.Fatalf("%d Werte angenommen (höchstens %d)", len(n.Varbinds), MaxVarbinds)
	}
	for _, v := range n.Varbinds {
		if !utf8.ValidString(v.Value) || utf8.RuneCountInString(v.Value) > MaxValue+1 {
			t.Fatalf("Wert ungeprüft übernommen: %q", v.Value)
		}
	}
	_ = Message(n)
	_ = TrapName(n.TrapOID)
}

func FuzzPeekVersion(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := peekVersion(b)
		if err == nil && v != snmp.V1 && v != snmp.V2c && v != snmp.V3 {
			t.Fatalf("unbekannte Version %q angenommen", v)
		}
	})
}

func FuzzDecodeCommunity(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, v := range []string{snmp.V1, snmp.V2c} {
			n, pkt, idx, err := decodeCommunity(b, v, []string{"x", "c"})
			if err != nil {
				continue
			}
			comms := []string{"x", "c"}
			if pkt == nil || idx < 0 || idx >= len(comms) || comms[idx] != pkt.Community {
				t.Fatalf("Community %q dem Eintrag %d zugeordnet", pkt.Community, idx)
			}
			checkNotification(t, n)
			if pkt.PDUType == gosnmp.InformRequest {
				_, _ = informResponseV2(pkt)
			}
		}
	})
}

func FuzzDiscoveryProbe(f *testing.F) {
	addSeeds(f)
	eng := &localEngine{id: fuzzEngine, boots: 1}
	f.Fuzz(func(t *testing.T, b []byte) {
		pkt, ok := discoveryProbe(b)
		if !ok {
			return
		}
		usm := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if usm.UserName != "" || pkt.MsgFlags&gosnmp.AuthPriv != 0 {
			t.Fatal("Discovery mit Benutzer oder Schlüssel angenommen")
		}
		_, _ = report(pkt, eng, 1, oidUnknownEngID, 1, nil)
	})
}

func FuzzDecodeV3(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		pkt, err := decodeV3(b, fuzzV3)
		if err != nil {
			return
		}
		if pkt.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
			t.Fatal("v3 ohne authPriv angenommen")
		}
		if n, err := notification(pkt, snmp.V3); err == nil {
			checkNotification(t, n)
		}
	})
}

// FuzzNotification: beliebige PDU-Listen (Typ und Wert aus den Daten), wie
// sie gosnmp nach dem Dekodieren liefert.
func FuzzNotification(f *testing.F) {
	f.Add(uint8(0), []byte("1.3.6.1.6.3.1.1.4.1.0\x001.3.6.1.6.3.1.1.5.3"), uint8(6))
	f.Add(uint8(1), []byte("1.3.6.1.2.1.1.3.0\x00\x00\x01"), uint8(0x43))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte, typ uint8) {
		pkt := &gosnmp.SnmpPacket{PDUType: gosnmp.SNMPv2Trap}
		version := snmp.V2c
		if kind%2 == 1 {
			version = snmp.V1
			pkt.PDUType = gosnmp.Trap
			pkt.Enterprise, pkt.GenericTrap, pkt.SpecificTrap = ".1.3.6.1.4.1."+string(data[:min(len(data), 8)]), int(kind%8), int(typ)
		}
		for len(data) > 0 && len(pkt.Variables) < 40 {
			name, rest, _ := cutByte(data, 0)
			val, rest2, _ := cutByte(rest, 0)
			data = rest2
			p := gosnmp.SnmpPDU{Name: "." + string(name), Type: gosnmp.Asn1BER(typ)}
			switch p.Type {
			case gosnmp.Integer:
				p.Value = len(val) * 1000003
			case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
				p.Value = uint32(len(val)) << 20
			case gosnmp.Counter64:
				p.Value = uint64(len(val)) << 50
			case gosnmp.ObjectIdentifier, gosnmp.IPAddress:
				p.Value = string(val)
			case gosnmp.OpaqueFloat:
				p.Value = float32(len(val)) / 3
			case gosnmp.OpaqueDouble:
				p.Value = float64(len(val)) / 7
			default:
				p.Value = val
			}
			pkt.Variables = append(pkt.Variables, p)
			typ = typ*31 + 7
		}
		if n, err := notification(pkt, version); err == nil {
			checkNotification(t, n)
		}
	})
}

func cutByte(b []byte, sep byte) (before, after []byte, found bool) {
	for i, c := range b {
		if c == sep {
			return b[:i], b[i+1:], true
		}
	}
	return b, nil, false
}

// Die Startpakete müssen gültig sein, sonst beginnt das Fuzzing nur mit Müll.
func TestFuzzStartpakete(t *testing.T) {
	p := seedPackets(t)
	if len(p) != 8 {
		t.Fatalf("%d Startpakete, erwartet 8 (v3 nicht kodierbar?)", len(p))
	}
	for i, v := range []string{snmp.V2c, snmp.V2c, snmp.V1} {
		if _, _, idx, err := decodeCommunity(p[i], v, []string{"c"}); err != nil || idx != 0 {
			t.Errorf("Paket %d: %v", i, err)
		}
	}
	if pkt, err := decodeV3(p[3], fuzzV3); err != nil {
		t.Errorf("v3: %v", err)
	} else if _, err := notification(pkt, snmp.V3); err != nil {
		t.Errorf("v3-Trap: %v", err)
	}
	if _, ok := discoveryProbe(p[4]); !ok {
		t.Error("Discovery nicht erkannt")
	}
}
