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

// TestZahlAusText (1.0.8): Die Abfrage liest die gewünschten Zahlen aus dem
// Text; gespeichert werden nur Hash und Zahlen.
func TestZahlAusText(t *testing.T) {
	const cpu, fan, temp = "1.3.6.1.4.1.2356.14.1.1.1.24.0", "1.3.6.1.4.1.2356.14.1.1.1.17.0", "1.3.6.1.4.1.2356.14.1.1.1.22.0"
	a := snmptest.New(t, "c",
		gosnmp.SnmpPDU{Name: cpu, Type: gosnmp.OctetString, Value: []byte("100ms:52%, 1s:57%, 10s:50%")},
		gosnmp.SnmpPDU{Name: fan, Type: gosnmp.OctetString, Value: []byte("1500RPM")},
		gosnmp.SnmpPDU{Name: temp, Type: gosnmp.OctetString, Value: []byte("none")})
	cfg := Config{Version: V2c, Host: "127.0.0.1", Port: a.Port(), Community: "c", Extra: []string{cpu, fan, temp},
		ExtraText: []TextZahl{{OID: cpu, N: 6}, {OID: cpu, Nach: "1s:"}, {OID: fan, N: 1}, {OID: temp, N: 1}}}
	snap, err := loopbackClient().Poll(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Extra) != 3 {
		t.Fatalf("eigene: %+v", snap.Extra)
	}
	c, f, tm := snap.Extra[0], snap.Extra[1], snap.Extra[2]
	if len(c.AusText) != 2 || *c.AusText[0].Zahl != 50 || c.AusText[1].Nach != "1s:" || *c.AusText[1].Zahl != 57 || c.Number != nil || c.TextHash == "" {
		t.Errorf("CPU: %+v", c)
	}
	if len(f.AusText) != 1 || *f.AusText[0].Zahl != 1500 {
		t.Errorf("Lüfter: %+v", f)
	}
	if len(tm.AusText) != 1 || tm.AusText[0].Zahl != nil {
		t.Errorf("ohne Zahl: %+v", tm)
	}
	raw, _ := json.Marshal(snap)
	for _, text := range []string{"RPM", "100ms", "none"} {
		if strings.Contains(string(raw), text) {
			t.Errorf("Text des Geräts im Snapshot: %q", text)
		}
	}
	if err := validateExtra(snap.Extra); err != nil {
		t.Errorf("eigener Snapshot abgelehnt: %v", err)
	}

	// Aufträge: nur zu eigenen OIDs, gültig und nicht doppelt
	for name, list := range map[string][]TextZahl{
		"fremde OID":    {{OID: "1.3.6.1.2.1.1.5.0", N: 1}},
		"n und nach":    {{OID: cpu, N: 2, Nach: "x"}},
		"ohne beides":   {{OID: cpu}},
		"n zu groß":     {{OID: cpu, N: 17}},
		"Steuerzeichen": {{OID: cpu, Nach: "a\x00"}},
		"doppelt":       {{OID: cpu, N: 1}, {OID: cpu, N: 1}},
	} {
		if err := CheckExtraText(list, cfg.Extra); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
	// Gemeldete Werte (vom Sammler): unplausible werden abgelehnt
	h := TextHash("x")
	z := 5.0
	for name, e := range map[string]ExtraValue{
		"ohne Text":  {OID: cpu, Number: &z, AusText: []TextWert{{N: 1, Zahl: &z}}},
		"ungültig":   {OID: cpu, TextHash: h, AusText: []TextWert{{N: 0}}},
		"doppelt":    {OID: cpu, TextHash: h, AusText: []TextWert{{N: 1}, {N: 1, Zahl: &z}}},
		"fehlt+Zahl": {OID: cpu, Missing: true, AusText: []TextWert{{N: 1}}},
	} {
		if err := validateExtra([]ExtraValue{e}); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
}
