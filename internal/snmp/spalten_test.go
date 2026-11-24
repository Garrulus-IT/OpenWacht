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

// NetScaler-ähnliche Tabellen: Index ist der Name (als OID-Teile kodiert).
func nameIndex(name string) string {
	parts := []string{itoa(len(name))}
	for _, c := range []byte(name) {
		parts = append(parts, itoa(int(c)))
	}
	return strings.Join(parts, ".")
}

const (
	colDays  = "1.3.6.1.4.1.5951.4.1.1.56.1.1.5"
	colState = "1.3.6.1.4.1.5951.4.1.3.1.1.5"
)

func TestEigeneSpalten(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		snmptest.Num(colDays+"."+nameIndex("geheim-portal"), 12),
		snmptest.Num(colDays+"."+nameIndex("intern-ca"), 3650),
		snmptest.Num(colDays+"."+nameIndex("abgelaufen"), -3),
		snmptest.Num(colState+"."+nameIndex("vs-a"), 7),
		snmptest.Num(colState+"."+nameIndex("vs-b"), 1),
		snmptest.Num(colState+"."+nameIndex("vs-c"), 7),
		snmptest.Num(colState+"."+nameIndex("vs-d"), 4),
		snmptest.Str("1.3.6.1.4.1.99.7.1", "Name geheim"),
		snmptest.Str("1.3.6.1.4.1.99.7.2", "noch ein Name"),
	}
	// eine Spalte mit vielen verschiedenen Werten
	for i := 0; i < 40; i++ {
		pdus = append(pdus, snmptest.Num("1.3.6.1.4.1.99.8."+itoa(i+1), i))
	}
	f := snmptest.New(t, "c", pdus...)
	c := loopbackClient()
	cols := []string{colDays, colState, "1.3.6.1.4.1.99.7", "1.3.6.1.4.1.99.8", "1.3.6.1.4.1.99.9"}
	for _, v := range []string{V1, V2c} {
		snap, err := c.Poll(context.Background(), Config{Version: v, Host: "127.0.0.1", Port: f.Port(), Community: "c", Columns: cols}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Columns) != len(cols) {
			t.Fatalf("v%s: %d Spalten %+v", v, len(snap.Columns), snap.Columns)
		}
		d := snap.Columns[0]
		if d.Rows != 3 || d.Numbers != 3 || *d.Min != -3 || *d.Max != 3650 || *d.Sum != 3659 || d.Truncated {
			t.Errorf("Tage: %+v", d)
		}
		s := snap.Columns[1]
		if s.Rows != 4 || s.Values["7"] != 2 || s.Values["1"] != 1 || s.Values["4"] != 1 || len(s.Values) != 3 {
			t.Errorf("Zustand: %+v", s)
		}
		txt := snap.Columns[2]
		if txt.Rows != 2 || txt.Numbers != 0 || txt.Min != nil || txt.Values != nil {
			t.Errorf("Text: %+v", txt)
		}
		many := snap.Columns[3]
		if many.Rows != 40 || !many.ValuesCut || many.Values != nil || *many.Max != 39 {
			t.Errorf("viele Werte: %+v", many)
		}
		if e := snap.Columns[4]; e.Rows != 0 || e.Numbers != 0 {
			t.Errorf("leer: %+v", e)
		}
		// Keine Indizes (Namen) und keine Texte im gespeicherten Snapshot
		raw, _ := json.Marshal(snap)
		for _, secret := range []string{"geheim", "Name", nameIndex("vs-a"), "103.101.104"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("v%s: %q im Snapshot: %s", v, secret, raw)
			}
		}
		if err := snap.ValidateCollected(time.Now()); err != nil {
			t.Errorf("v%s: ValidateCollected: %v", v, err)
		}
	}
	// ungültige Liste: Teil fehlt, Rest der Abfrage geht
	snap, err := c.Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c", Columns: []string{"1.3", "1.3"}}, nil)
	if err != nil || len(snap.Columns) != 0 || !strings.Contains(strings.Join(snap.Partial, ","), "Eigene Spalten") {
		t.Errorf("ungültig: %v %+v", err, snap)
	}
}

func TestEigeneSpalteGekuerzt(t *testing.T) {
	pdus := make([]gosnmp.SnmpPDU, 0, MaxColumnRows+5)
	for i := 0; i < MaxColumnRows+5; i++ {
		pdus = append(pdus, snmptest.Num("1.3.6.1.4.1.99.5."+itoa(i+1), 7))
	}
	f := snmptest.New(t, "c", pdus...)
	snap, err := loopbackClient().Poll(context.Background(), Config{Version: V2c, Host: "127.0.0.1", Port: f.Port(), Community: "c",
		Columns: []string{"1.3.6.1.4.1.99.5"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Columns) != 1 || !snap.Columns[0].Truncated || snap.Columns[0].Rows != MaxColumnRows || snap.Columns[0].Values["7"] != MaxColumnRows {
		t.Fatalf("gekürzt: %+v", snap.Columns)
	}
	if err := snap.ValidateCollected(time.Now()); err != nil {
		t.Error(err)
	}
}

func TestSpaltenValidate(t *testing.T) {
	one, two, nan := 1.0, 2.0, 0.0
	nan = nan / nan
	ok := ColumnValue{OID: "1.3.6", Rows: 2, Numbers: 2, Min: &one, Max: &two, Sum: &two, Values: map[string]int{"1": 1, "2": 1}}
	if err := validateColumns([]ColumnValue{ok}); err != nil {
		t.Fatal(err)
	}
	mod := func(f func(c *ColumnValue)) []ColumnValue {
		c := ok
		c.Values = map[string]int{"1": 1, "2": 1}
		f(&c)
		return []ColumnValue{c}
	}
	for name, bad := range map[string][]ColumnValue{
		"OID":             mod(func(c *ColumnValue) { c.OID = "x" }),
		"doppelt":         {ok, ok},
		"negativ":         mod(func(c *ColumnValue) { c.Rows = -1 }),
		"zu viele Zeilen": mod(func(c *ColumnValue) { c.Rows = MaxColumnRows + 1 }),
		"Zahlen > Zeilen": mod(func(c *ColumnValue) { c.Numbers = 3 }),
		"gekürzt":         mod(func(c *ColumnValue) { c.Truncated = true }),
		"ohne Zahlen":     mod(func(c *ColumnValue) { c.Numbers = 0 }),
		"Min fehlt":       mod(func(c *ColumnValue) { c.Min = nil }),
		"NaN":             mod(func(c *ColumnValue) { c.Sum = &nan }),
		"Min > Max":       mod(func(c *ColumnValue) { c.Min, c.Max, c.Values = &two, &one, nil }),
		"Wert kein Int":   mod(func(c *ColumnValue) { c.Values = map[string]int{"1.5": 1} }),
		"Wert führend 0":  mod(func(c *ColumnValue) { c.Values = map[string]int{"01": 1} }),
		"Wert außerhalb":  mod(func(c *ColumnValue) { c.Values = map[string]int{"9": 1} }),
		"Anzahl 0":        mod(func(c *ColumnValue) { c.Values = map[string]int{"1": 0} }),
		"Anzahl riesig":   mod(func(c *ColumnValue) { c.Values = map[string]int{"1": 1 << 62, "2": 1 << 62} }),
		"Summe > Zahlen":  mod(func(c *ColumnValue) { c.Values = map[string]int{"1": 2, "2": 1} }),
		"gekürzt + Werte": mod(func(c *ColumnValue) { c.ValuesCut = true }),
		"zu viele Werte": mod(func(c *ColumnValue) {
			c.Values = map[string]int{}
			for i := 0; i <= MaxColumnValues; i++ {
				c.Values[itoa(i)] = 1
			}
		}),
	} {
		if err := validateColumns(bad); err == nil {
			t.Errorf("%s: angenommen %+v", name, bad)
		}
	}
	// ValidateCollected prüft die Spalten mit (Sammler)
	now := time.Now()
	snap := Snapshot{CollectedAt: now, Counters: &CounterInfo{At: now}, System: System{Name: "ns", ObjectID: "1.3.6.1.4.1.5951"},
		Disks: []Disk{}, Interfaces: []Interface{}, Supplies: []Supply{}, Columns: []ColumnValue{ok}}
	if err := snap.ValidateCollected(now); err != nil {
		t.Fatalf("gültiger Snapshot: %v", err)
	}
	snap.Columns = mod(func(c *ColumnValue) { c.Rows = -1 })
	if err := snap.ValidateCollected(now); err == nil || !strings.Contains(err.Error(), "spalten") {
		t.Errorf("Snapshot mit unplausibler Spalte: %v", err)
	}
	if err := validateColumns(make([]ColumnValue, MaxExtraOIDs+1)); err == nil {
		t.Error("33 Spalten angenommen")
	}
	if err := CheckColumns(make([]string, MaxExtraOIDs+1)); err == nil {
		t.Error("33 Spalten angenommen")
	}
	if err := CheckColumns([]string{"1.3.6", "1.3.6"}); err == nil {
		t.Error("doppelte Spalte angenommen")
	}
}
