// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// Fuzz-Ziele für SNMP-Antworten (Befund M3). Antworten kommen von Geräten
// und Sammlern, also von außen. FuzzPollAntworten lässt eine Gegenstelle
// beliebige Werte unter allen OIDs liefern, die OpenWacht liest (Typ,
// Index und Inhalt aus den Daten); die Abfrage darf nicht abstürzen, und
// was sie liefert, muss die Prüfung für Sammler bestehen (sonst würde ein
// ehrlicher Sammler abgewiesen oder die Prüfung hätte eine Lücke).
// FuzzValidateCollected prüft die Annahme beliebiger Sammler-Snapshots.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp/snmptest"
)

// fuzzOIDs: alle OIDs, die der Abfragecode kennt (aus dem Quelltext gelesen,
// damit neue OIDs automatisch mitgeprüft werden).
func fuzzOIDs(t testing.TB) []string {
	set := map[string]bool{}
	for _, f := range []string{"poll.go", "snmp.go", "eigene.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`"(1\.3\.6\.1(?:\.[0-9]+)+)"`).FindAllSubmatch(b, -1) {
			set[string(m[1])] = true
		}
	}
	var out []string
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	if len(out) < 40 {
		t.Fatalf("nur %d OIDs im Quelltext gefunden", len(out))
	}
	return out
}

var fuzzTypes = []gosnmp.Asn1BER{gosnmp.Integer, gosnmp.OctetString, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks,
	gosnmp.Counter64, gosnmp.ObjectIdentifier, gosnmp.IPAddress, gosnmp.OpaqueFloat, gosnmp.OpaqueDouble, gosnmp.Null}

// fuzzPDUs macht aus Bytes eine Liste von Werten: je Eintrag 1 Byte OID,
// 1 Byte Index, 1 Byte Typ, 8 Byte Zahl, 1 Byte Textlänge, Text.
func fuzzPDUs(oids []string, data []byte) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU
	for len(data) >= 11 && len(out) < 600 {
		oid := oids[int(data[0])%len(oids)]
		idx := int(data[1])
		typ := fuzzTypes[int(data[2])%len(fuzzTypes)]
		num := binary.BigEndian.Uint64(data[3:11])
		data = data[11:]
		var text []byte
		if len(data) > 0 {
			n := min(int(data[0]), len(data)-1)
			text, data = data[1:1+n], data[1+n:]
		}
		name := oid
		if idx != 0 && len(oid) > 2 && oid[len(oid)-2:] != ".0" {
			name = oid + "." + itoa(idx%40)
			if idx >= 200 {
				name += "." + itoa(idx%3)
			}
		}
		p := gosnmp.SnmpPDU{Name: name, Type: typ}
		switch typ {
		case gosnmp.Integer:
			p.Value = int(int32(num))
		case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
			p.Value = uint32(num)
		case gosnmp.Counter64:
			p.Value = num
		case gosnmp.OctetString:
			p.Value = text
		case gosnmp.ObjectIdentifier:
			p.Value = ".1.3.6.1.4.1." + itoa(int(num%100000))
		case gosnmp.IPAddress:
			p.Value = "10.0.0." + itoa(int(num%256))
		case gosnmp.OpaqueFloat:
			p.Value = math.Float32frombits(uint32(num))
		case gosnmp.OpaqueDouble:
			p.Value = math.Float64frombits(num)
		case gosnmp.Null:
			p.Value = nil
		}
		out = append(out, p)
	}
	return out
}

func FuzzPollAntworten(f *testing.F) {
	oids := fuzzOIDs(f)
	f.Add([]byte{})
	seed := []byte{}
	for i := range oids {
		seed = append(seed, byte(i), byte(i*7), byte(i), 0, 0, 0, 0, 0, 0, 1, byte(i), 4, 'e', 't', 'h', '0')
	}
	f.Add(seed)
	f.Add([]byte{3, 5, 8, 0x7f, 0xc0, 0, 0, 0, 0, 0, 0, 0}) // NaN
	c := loopbackClient()
	c.Budget, c.Timeout = 3*time.Second, 50*time.Millisecond
	f.Fuzz(func(t *testing.T, data []byte) {
		safe.ResetForTest()
		dev := snmptest.New(t, "c", fuzzPDUs(oids, data)...)
		cfg := Config{Version: V2c, Host: "127.0.0.1", Port: dev.Port(), Community: "c"}
		snap, err := c.Poll(context.Background(), cfg, nil)
		if errors.Is(err, safe.ErrPanic) || safe.Total() != 0 {
			t.Fatalf("Panik in der Abfrage: %v", safe.Counts())
		}
		if err != nil {
			return
		}
		rt := roundtrip(t, snap)
		if err := rt.ValidateCollected(time.Now()); err != nil {
			t.Fatalf("eigene Abfrage besteht die Sammler-Prüfung nicht: %v", err)
		}
		_, _ = Series(rt)
		// zweite Abfrage mit vorigen Werten (Raten, Neustart)
		if snap2, err := c.Poll(context.Background(), cfg, snap); err == nil {
			ApplyRates(roundtrip(t, snap2), rt)
		}
	})
}

func FuzzValidateCollected(f *testing.F) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	ok := &Snapshot{CollectedAt: now, System: System{Name: "sw", UptimeTicks: 5}, Counters: &CounterInfo{At: now, UptimeTicks: 5}}
	b, _ := json.Marshal(ok)
	f.Add(b)
	f.Add([]byte(`{"erfasst":"2026-11-22T12:00:00Z","schnittstellen":[{"index":1,"name":"\u202e"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var s Snapshot
		if json.Unmarshal(b, &s) != nil {
			return
		}
		if err := s.ValidateCollected(now); err != nil {
			return
		}
		// Angenommene Snapshots muss die Zentrale weiterverarbeiten können.
		prev := s
		ApplyRates(&s, &prev)
		_, _ = Series(&s)
		if _, err := json.Marshal(&s); err != nil {
			t.Fatalf("angenommener Snapshot nicht speicherbar: %v", err)
		}
	})
}

// Eine Panik in der Abfrage wird zum Fehler, nicht zum Absturz (M3).
func TestPollPanik(t *testing.T) {
	safe.ResetForTest()
	testPollHook = func() { panic("kaputte Antwort") }
	t.Cleanup(func() { testPollHook = nil; safe.ResetForTest() })
	_, err := loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: 9, Community: "c"}, nil)
	if !errors.Is(err, safe.ErrPanic) || safe.Counts()["snmp"] != 1 {
		t.Fatalf("Fehler %v, Zähler %v", err, safe.Counts())
	}
}
