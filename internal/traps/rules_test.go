// SPDX-License-Identifier: AGPL-3.0-only

package traps

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

func TestRuleMatch(t *testing.T) {
	src := &Source{ID: "s", Tenant: "kind", Device: "dev", Tenants: []string{"kind", "eltern"}, Groups: []string{"g-unten", "g-oben"}}
	n := &Notification{TrapOID: linkDown, Varbinds: []Varbind{{OID: ifIndex + ".5", Type: "Zahl", Value: "5"},
		{OID: "1.3.6.1.2.1.2.2.1.2.5", Type: "Text", Value: "GigabitEthernet 5"}}}
	rs := RuleSet{
		"eltern": {
			{ID: "e1", Name: "alle", TrapOID: "*", Action: "warn"},
		},
		"kind": {
			{ID: "k0", TrapOID: linkDown, Device: "anderes", Action: "crit"}, // anderes Gerät
			{ID: "k1", TrapOID: linkDown, Group: "g-fremd", Action: "crit"},  // andere Gruppe
			{ID: "k2", TrapOID: "1.3.6.1.6.3.1.1.5.4", Action: "ok"},         // andere OID
			{ID: "k3", TrapOID: linkDown, VbOID: "1.3.6.1.2.1.2.2.1.2", VbOp: "enthaelt", VbValue: "TenGig", Action: "crit"},
			{ID: "k4", TrapOID: "1.3.6.1.6.3.1.1.5.*", Group: "g-oben", VbOID: "1.3.6.1.2.1.2.2.1.2", VbOp: "beginnt",
				VbValue: "gigabit", Action: "crit", KeyOID: ifIndex},
			{ID: "k5", TrapOID: linkDown, Action: "warn"},
		},
	}
	r, inst := rs.Match(src, n)
	if r == nil || r.ID != "k4" || inst != "5" {
		t.Fatalf("Treffer %+v %q", r, inst)
	}
	// ohne passende Kind-Regel: Eltern
	n2 := &Notification{TrapOID: "1.3.6.1.4.1.9.9.1"}
	if r, _ := rs.Match(src, n2); r == nil || r.ID != "e1" {
		t.Fatalf("Eltern: %+v", r)
	}
	// Geschwister-Regeln gelten nicht
	if r, _ := (RuleSet{"geschwister": {{ID: "x", TrapOID: "*", Action: "crit"}}}).Match(src, n2); r != nil {
		t.Fatalf("Geschwister: %+v", r)
	}
	// Bedingung „nicht“: wahr, wenn kein Wert passt
	rn := Rule{TrapOID: "*", VbOID: "1.3.6.1.2.1.2.2.1.2", VbOp: "nicht", VbValue: "gigabitethernet 5"}
	if rn.condition(n) {
		t.Error("nicht gleich trifft trotz gleichem Wert")
	}
	rn.VbValue = "Port 7"
	if !rn.condition(n) {
		t.Error("nicht gleich trifft nicht")
	}
	rg := Rule{TrapOID: "*", VbOID: ifIndex, VbOp: "gleich", VbValue: "5"}
	if !rg.condition(n) {
		t.Error("gleich über Präfix")
	}
	rg.VbOID = "1.3.6.1.2.1.2.2.1.11" // 1.11 ist kein Präfix von 1.1.5
	if rg.condition(n) {
		t.Error("Präfix ohne Punktgrenze")
	}
	for pat, want := range map[string]bool{"*": true, linkDown: true, "1.3.6.1.6.3.1.1.5.*": true, "1.3.6.1.6.3.1.1.5.3.*": true,
		"1.3.6.1.6.3.1.1.*": true, "1.3.6.1.6.3.1.1.5": false, "1.3.6.1.6.3.1.1.5.33": false, "1.3.6.1.6.3.1.1.53.*": false} {
		if got := oidMatches(pat, linkDown); got != want {
			t.Errorf("oidMatches(%q) = %v", pat, got)
		}
	}
	// ignorieren unterscheidet nicht
	ri := RuleSet{"kind": {{ID: "i", TrapOID: "*", Action: "ignore", KeyOID: ifIndex}}}
	if r, inst := ri.Match(src, n); r == nil || inst != "" {
		t.Errorf("ignore: %+v %q", r, inst)
	}
}

func TestMessage(t *testing.T) {
	n := &Notification{TrapOID: linkDown, Varbinds: []Varbind{{OID: ifIndex + ".5", Value: "5"},
		{OID: "1.3.6.1.2.1.2.2.1.8.5", Value: "2"}, {OID: "1.3.6.1.4.1.1", Value: strings.Repeat("x", 500)}, {OID: "1.2", Value: "y"}}}
	m := Message(n)
	if !strings.HasPrefix(m, "linkDown: ifIndex.5 = 5, ifOperStatus.5 = 2, 1.3.6.1.4.1.1 = xxx") || !strings.HasSuffix(m, "(unbestätigt: v1/v2c)") ||
		len([]rune(m)) > 300 {
		t.Fatalf("Meldung %q", m)
	}
	n.Authentic = true
	if strings.Contains(Message(n), "unbestätigt") {
		t.Error("v3 als unbestätigt")
	}
}

func TestFormatValue(t *testing.T) {
	for _, c := range []struct {
		p          gosnmp.SnmpPDU
		typ, value string
	}{
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: []byte("Port\x003")}, "Bytes", "0x506f72740033"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: []byte("Port 3\x00")}, "Text", "Port 3"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: []byte{0x00, 0x1a, 0x2b}}, "Bytes", "0x001a2b"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.OctetString, Value: []byte("a‮b")}, "Text", "a b"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.Integer, Value: -5}, "Zahl", "-5"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.Counter64, Value: uint64(1 << 60)}, "Zahl", "1152921504606846976"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6"}, "OID", "1.3.6"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.ObjectIdentifier, Value: "kaputt"}, "OID", ""},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.IPAddress, Value: "10.0.0.1"}, "IP", "10.0.0.1"},
		{gosnmp.SnmpPDU{Name: ".1.2.3", Type: gosnmp.Null}, "Leer", ""},
	} {
		v := formatValue(c.p)
		if v.Type != c.typ || v.Value != c.value || v.OID != "1.2.3" {
			t.Errorf("%v: %+v", c.p, v)
		}
	}
	long := formatValue(gosnmp.SnmpPDU{Name: ".1", Type: gosnmp.OctetString, Value: []byte(strings.Repeat("ä", 1000))})
	if len([]rune(long.Value)) != MaxValue {
		t.Errorf("Länge %d", len([]rune(long.Value)))
	}
	bin := formatValue(gosnmp.SnmpPDU{Name: ".1", Type: gosnmp.OctetString, Value: make([]byte, 1000)})
	if len(bin.Value) > MaxValue {
		t.Errorf("Bytes-Länge %d", len(bin.Value))
	}
	if _, ok := normOID("1.3.6." + strings.Repeat("1.", 100) + "1"); ok {
		t.Error("zu lange OID")
	}
}

func TestPeekVersion(t *testing.T) {
	for b, want := range map[string]string{"\x30\x10\x02\x01\x00": snmp.V1, "\x30\x10\x02\x01\x01": snmp.V2c,
		"\x30\x81\x90\x02\x01\x03": snmp.V3, "\x30\x82\x01\x00\x02\x01\x01": snmp.V2c} {
		if got, err := peekVersion([]byte(b)); err != nil || got != want {
			t.Errorf("%x: %q %v", b, got, err)
		}
	}
	for _, b := range []string{"", "\x30", "\x31\x10\x02\x01\x01", "\x30\x10\x02\x01\x02", "\x30\x85\x00\x00\x00\x00\x00\x02\x01\x01",
		"\x30\x10\x04\x01\x01", "\x30\x80\x02\x01\x01"} {
		if _, err := peekVersion([]byte(b)); err == nil {
			t.Errorf("%x angenommen", b)
		}
	}
}

func TestZeitfenster(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	st, ok := checkRemote(nil, 5, 1000, t0)
	if !ok || st.boots != 5 || st.time != 1000 {
		t.Fatal("erster Trap")
	}
	if _, ok := checkRemote(&st, 4, 9999, t0); ok {
		t.Error("ältere Boots angenommen")
	}
	// 200 s später schätzt der Empfänger 1200; 1049 liegt außerhalb des Fensters.
	if _, ok := checkRemote(&st, 5, 1049, t0.Add(200*time.Second)); ok {
		t.Error("veraltete Zeit angenommen")
	}
	if n, ok := checkRemote(&st, 5, 1051, t0.Add(200*time.Second)); !ok || n.time != 1051 {
		t.Error("Zeit im Fenster abgelehnt")
	}
	// kleinere Zeit im Fenster: angenommen, Stand bleibt
	if n, ok := checkRemote(&st, 5, 990, t0); !ok || n.time != 1000 {
		t.Error("kleinere Zeit im Fenster")
	}
	if n, ok := checkRemote(&st, 6, 1, t0); !ok || n.boots != 6 {
		t.Error("Neustart des Absenders")
	}
	max := remoteState{boots: maxBoots, time: 1, at: t0}
	if _, ok := checkRemote(&max, maxBoots, 2, t0); ok {
		t.Error("Boots am Maximum")
	}
	if _, ok := checkRemote(nil, maxBoots, 2, t0); ok {
		t.Error("Boots am Maximum (neu)")
	}

	e := localEngine{id: "\x80\x00\x00\x00\x05abc", boots: 3, start: t0}
	now := t0.Add(1000 * time.Second)
	for _, c := range []struct {
		boots, time uint32
		ok          bool
	}{{3, 1000, true}, {3, 850, true}, {3, 1150, true}, {3, 849, false}, {3, 1151, false}, {2, 1000, false}, {4, 1000, false}} {
		if got := e.inWindow(c.boots, c.time, now); got != c.ok {
			t.Errorf("inWindow(%d, %d) = %v", c.boots, c.time, got)
		}
	}
}

func TestRateUndWiederholung(t *testing.T) {
	t0 := time.Now()
	var b tokenBucket
	n := 0
	for i := 0; i < 100; i++ {
		if b.allow(10, 50, t0) {
			n++
		}
	}
	if n != 50 {
		t.Fatalf("Puffer: %d", n)
	}
	if !b.allow(10, 50, t0.Add(150*time.Millisecond)) || b.allow(10, 50, t0.Add(150*time.Millisecond)) {
		t.Error("Nachfüllen")
	}
	c := newReplayCache(2)
	if !c.first([]byte("a"), t0) || c.first([]byte("a"), t0.Add(time.Second)) {
		t.Error("Wiederholung")
	}
	if !c.first([]byte("b"), t0) || c.first([]byte("c"), t0) {
		t.Error("voll: neues Paket muss abgelehnt werden")
	}
	if !c.first([]byte("c"), t0.Add(301*time.Second)) {
		t.Error("nach Ablauf frei")
	}
	if !c.first([]byte("a"), t0.Add(302*time.Second)) {
		t.Error("nach Ablauf wieder angenommen")
	}
}

// fakeConn sammelt, was der Dienst sendet.
type fakeConn struct {
	net.PacketConn
	sent [][]byte
}

func (f *fakeConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.sent = append(f.sent, append([]byte(nil), b...))
	return len(b), nil
}

// TestInformZeitfenster: Ein v3-Inform mit falschen Boots bekommt einen
// authentifizierten Report mit der eigenen Zeit und wird nicht angenommen.
func TestInformZeitfenster(t *testing.T) {
	user := &snmp.V3Auth{User: "wtest", Auth: snmp.AuthSHA256, AuthPass: testAuthPass, Priv: snmp.PrivAES, PrivPass: testPrivPass}
	src := &Source{ID: "s", Tenant: "t", Version: snmp.V3, Secret: Secret{V3: user}, Tenants: []string{"t"}}
	now := time.Now()
	fc := &fakeConn{}
	s := &Service{cfg: Config{Conn: fc, Now: func() time.Time { return now }}, buckets: map[netipAddr]*tokenBucket{},
		unknown: map[netipAddr]int{}, remote: map[string]*remoteState{}, replay: newReplayCache(10), queue: make(chan record, 10)}
	s.cfg.defaults()
	s.engine = localEngine{id: "\x80\x00\x00\x00\x05" + "0123456789abcdef", boots: 7, start: now.Add(-100 * time.Second)}
	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
	s.snap.Store(&snapshot{byAddr: map[netipAddr][]*Source{mustAddr("192.0.2.1"): {src}}, rules: RuleSet{}})

	build := func(boots, tm uint32, engine ...string) []byte {
		eid := s.engine.id
		if len(engine) > 0 {
			eid = engine[0]
		}
		sp := user.USM(eid)
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = boots, tm
		if err := sp.InitSecurityKeys(); err != nil {
			t.Fatal(err)
		}
		sp.PrivacyParameters = []byte{1, 2, 3, 4, 5, 6, 7, 8}
		p := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.AuthPriv | gosnmp.Reportable,
			SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: sp, ContextEngineID: eid,
			PDUType: gosnmp.InformRequest, MsgID: 42, RequestID: 43, MsgMaxSize: 1500,
			Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(5)},
				{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.99.9"}}}
		b, err := p.MarshalMsg()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s.handle(build(6, 100), from)
	if len(fc.sent) != 1 || len(s.queue) != 0 {
		t.Fatalf("falsche Boots: gesendet %d, angenommen %d", len(fc.sent), len(s.queue))
	}
	// Der Report ist mit dem Benutzer authentifiziert und nennt unsere Zeit.
	x := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthNoPriv,
		SecurityParameters: user.USM("")}
	rep, err := x.UnmarshalTrap(fc.sent[0], true)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	usm := rep.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if rep.PDUType != gosnmp.Report || rep.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthNoPriv || usm.AuthoritativeEngineBoots != 7 ||
		usm.AuthoritativeEngineTime < 99 || usm.AuthoritativeEngineTime > 101 || len(rep.Variables) != 1 ||
		rep.Variables[0].Name != oidNotInTimeWin || rep.RequestID != 43 {
		t.Fatalf("Report: %+v %+v", rep, usm)
	}
	// passende Zeit: Antwort und angenommen
	s.handle(build(7, 100), from)
	if len(fc.sent) != 2 || len(s.queue) != 1 {
		t.Fatalf("im Fenster: gesendet %d, angenommen %d", len(fc.sent), len(s.queue))
	}
	resp, err := (&gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: user.USM("")}).UnmarshalTrap(fc.sent[1], true)
	if err != nil || resp.PDUType != gosnmp.GetResponse || resp.RequestID != 43 {
		t.Fatalf("Antwort: %+v %v", resp, err)
	}
	// Das Salz der Antwort ist neu (kein wiederverwendeter Schlüsselstrom).
	if string(resp.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyParameters) == "\x01\x02\x03\x04\x05\x06\x07\x08" {
		t.Error("Salz des Informs wiederverwendet")
	}
	// fremde Engine-ID im Inform: verworfen, keine Antwort
	s.handle(build(7, 100, "\x80\x00\x00\x00\x05"+"fedcba9876543210"), from)
	if len(fc.sent) != 2 || len(s.queue) != 1 {
		t.Fatalf("fremde Engine: gesendet %d, angenommen %d", len(fc.sent), len(s.queue))
	}
	// Discovery von einem unbekannten Absender: keine Antwort (kein Reflektor).
	probe := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.Reportable, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{}, PDUType: gosnmp.GetRequest, MsgID: 1, RequestID: 2, MsgMaxSize: 1500}
	pb, err := probe.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	s.handle(pb, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1})
	if len(fc.sent) != 2 {
		t.Fatal("Discovery an Unbekannte beantwortet")
	}
	s.handle(pb, from)
	if len(fc.sent) != 3 {
		t.Fatal("Discovery eines bekannten Geräts nicht beantwortet")
	}
}

type netipAddr = netip.Addr

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
