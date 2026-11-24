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

func TestEigeneOIDs(t *testing.T) {
	f := snmptest.New(t, "c",
		snmptest.Num("1.3.6.1.4.1.99.1.0", 47),
		snmptest.Str("1.3.6.1.4.1.99.2.0", "Normal geheim"),
		snmptest.Str("1.3.6.1.4.1.99.3.0", "12.5"),
		gosnmp.SnmpPDU{Name: "1.3.6.1.4.1.99.4.0", Type: gosnmp.Counter32, Value: uint(4000000000)},
		gosnmp.SnmpPDU{Name: "1.3.6.1.4.1.99.5.0", Type: gosnmp.Counter64, Value: uint64(1 << 50)},
	)
	c := loopbackClient()
	oids := []string{"1.3.6.1.4.1.99.1.0", "1.3.6.1.4.1.99.2.0", "1.3.6.1.4.1.99.3.0", "1.3.6.1.4.1.99.4.0", "1.3.6.1.4.1.99.5.0", "1.3.6.1.4.1.99.9.0"}
	for _, v := range []string{V1, V2c} {
		snap, err := c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: f.Port(), Community: "c", Extra: oids}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Extra) != len(oids) {
			t.Fatalf("v%s: %d Werte %+v", v, len(snap.Extra), snap.Extra)
		}
		e := snap.Extra
		if e[0].Number == nil || *e[0].Number != 47 {
			t.Errorf("Zahl: %+v", e[0])
		}
		if e[1].TextHash != TextHash("Normal geheim") || e[1].Number != nil {
			t.Errorf("Text: %+v", e[1])
		}
		if e[2].Number == nil || *e[2].Number != 12.5 || e[2].TextHash == "" {
			t.Errorf("Zahl als Text: %+v", e[2])
		}
		if e[3].Counter == nil || *e[3].Counter != 4000000000 || e[3].Bits != 32 {
			t.Errorf("Counter32: %+v", e[3])
		}
		if e[4].Counter == nil || *e[4].Counter != 1<<50 || e[4].Bits != 64 {
			t.Errorf("Counter64: %+v", e[4])
		}
		if !e[5].Missing {
			t.Errorf("fehlende OID: %+v", e[5])
		}
		// Kein Text im gespeicherten Snapshot
		raw, _ := json.Marshal(snap)
		if strings.Contains(string(raw), "geheim") {
			t.Errorf("Text im Snapshot: %s", raw)
		}
		if err := snap.ValidateCollected(time.Now()); err != nil {
			t.Errorf("v%s: ValidateCollected: %v", v, err)
		}
	}
	// ungültige Liste: Teil fehlt, Rest der Abfrage geht
	snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c", Extra: []string{"x"}}, nil)
	if err != nil || len(snap.Extra) != 0 || !strings.Contains(strings.Join(snap.Partial, ","), "Eigene OIDs") {
		t.Errorf("ungültig: %v %+v", err, snap)
	}
}

func TestEigeneValidate(t *testing.T) {
	n := 1.0
	big := uint64(1 << 40)
	small := uint64(5)
	for _, bad := range [][]ExtraValue{
		{{OID: "x", Number: &n}},
		{{OID: "1.3.6", Number: &n}, {OID: "1.3.6", Number: &n}},
		{{OID: "1.3.6"}},
		{{OID: "1.3.6", Missing: true, Number: &n}},
		{{OID: "1.3.6", Counter: &big, Bits: 32}},
		{{OID: "1.3.6", Counter: &small, Bits: 16}},
		{{OID: "1.3.6", Counter: &small, Bits: 32, Number: &n}},
		{{OID: "1.3.6", TextHash: "Klartext statt Hash"}},
		{{OID: "1.3.6", Number: &n, Bits: 32}},
	} {
		s := Snapshot{Extra: bad}
		if err := validateExtra(s.Extra); err == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
	if err := CheckExtraOIDs(make([]string, 33)); err == nil {
		t.Error("33 OIDs angenommen")
	}
}
