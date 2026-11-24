// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// Eigene Tabellenspalten (0.47.0): Ein Sensor „SNMP eigene OID“ kann eine
// Spalte einer Tabelle zusammenfassen (kürzeste Restlaufzeit der Zertifikate
// am NetScaler, Zahl der virtuellen Server im Zustand „down“). Abgefragt wird
// die Spalte nur lesend (GETNEXT/GETBULK). Gemeldet werden nur Kennzahlen der
// Spalte, nie die Indizes der Zeilen (darin stehen oft Namen) und nie Texte.

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
)

const (
	// MaxColumnRows: höchstens so viele Zeilen je Spalte werden gelesen.
	MaxColumnRows = 2000
	// MaxColumnValues: höchstens so viele verschiedene ganze Zahlen werden
	// gezählt (Zustände wie up/down); mehr ist keine Zustandsspalte.
	MaxColumnValues = 32
)

// ColumnValue: Kennzahlen einer Spalte. Min, Max und Sum gibt es nur, wenn
// mindestens eine Zeile eine Zahl ist.
type ColumnValue struct {
	OID     string   `json:"oid"`
	Rows    int      `json:"zeilen"`
	Numbers int      `json:"zahlen"`
	Min     *float64 `json:"minimum,omitempty"`
	Max     *float64 `json:"maximum,omitempty"`
	Sum     *float64 `json:"summe,omitempty"`
	// Values: ganze Zahl (dezimal) → Anzahl der Zeilen; fehlt, wenn es mehr
	// als MaxColumnValues verschiedene Werte gab (ValuesCut).
	Values    map[string]int `json:"werte,omitempty"`
	ValuesCut bool           `json:"werte_gekuerzt,omitempty"`
	// Truncated: Die Spalte hatte mehr als MaxColumnRows Zeilen.
	Truncated bool `json:"gekuerzt,omitempty"`
}

// summarize fasst die gelesenen Zeilen einer Spalte zusammen.
func summarize(oid string, rows []row, truncated bool) ColumnValue {
	c := ColumnValue{OID: oid, Rows: len(rows), Truncated: truncated}
	var lo, hi, sum float64
	values := map[string]int{}
	for _, r := range rows {
		if r.v.missing() {
			continue
		}
		f, ok := r.v.float()
		if !ok {
			continue
		}
		if c.Numbers == 0 {
			lo, hi = f, f
		}
		lo, hi = math.Min(lo, f), math.Max(hi, f)
		sum += f
		c.Numbers++
		if !c.ValuesCut && f == math.Trunc(f) && math.Abs(f) < 1e15 {
			k := strconv.FormatInt(int64(f), 10)
			if _, seen := values[k]; !seen && len(values) >= MaxColumnValues {
				c.ValuesCut = true
				continue
			}
			values[k]++
		}
	}
	if c.Numbers > 0 {
		if math.IsInf(sum, 0) || math.Abs(sum) > 1e300 {
			sum = math.Copysign(1e300, sum)
		}
		c.Min, c.Max, c.Sum = &lo, &hi, &sum
	}
	if !c.ValuesCut && len(values) > 0 {
		c.Values = values
	}
	return c
}

func (s *session) columns(snap *Snapshot, oids []string) error {
	var firstErr error
	for _, o := range oids {
		rows, err := s.walk(o, MaxColumnRows)
		switch {
		case errors.Is(err, ErrTooMuch) && len(rows) == MaxColumnRows:
			snap.Columns = append(snap.Columns, summarize(o, rows, true))
		case err != nil:
			// Ohne Spalte trifft der Sensor diesmal keine Aussage.
			if firstErr == nil {
				firstErr = err
			}
			if errors.Is(err, ErrTooMuch) { // Anfragen der Abfrage aufgebraucht
				return err
			}
		default:
			snap.Columns = append(snap.Columns, summarize(o, rows, false))
		}
	}
	return firstErr
}

// CheckColumns prüft eine Liste eigener Spalten (Zentrale und Sammler).
func CheckColumns(oids []string) error {
	if len(oids) > MaxExtraOIDs {
		return fmt.Errorf("eigene Spalten: höchstens %d", MaxExtraOIDs)
	}
	for i, o := range oids {
		if o == "" || len(o) > 200 || !validOID(o) || slices.Contains(oids[:i], o) {
			return errors.New("eigene Spalten: ungültig oder doppelt")
		}
	}
	return nil
}

func finite(p *float64) bool { return p != nil && !math.IsNaN(*p) && *p <= 1e300 && *p >= -1e300 }

func validateColumns(list []ColumnValue) error {
	if len(list) > MaxExtraOIDs {
		return fmt.Errorf("spalten: höchstens %d", MaxExtraOIDs)
	}
	var seen []string
	for i, c := range list {
		f := fmt.Sprintf("spalten[%d]", i)
		if c.OID == "" || len(c.OID) > 200 || !validOID(c.OID) || slices.Contains(seen, c.OID) {
			return errors.New(f + ": OID ungültig oder doppelt")
		}
		seen = append(seen, c.OID)
		if c.Rows < 0 || c.Rows > MaxColumnRows || c.Numbers < 0 || c.Numbers > c.Rows || c.Truncated && c.Rows != MaxColumnRows {
			return errors.New(f + ": Zeilen unplausibel")
		}
		if c.Numbers == 0 {
			if c.Min != nil || c.Max != nil || c.Sum != nil || len(c.Values) > 0 {
				return errors.New(f + ": Werte ohne Zahlen")
			}
		} else if !finite(c.Min) || !finite(c.Max) || !finite(c.Sum) || *c.Min > *c.Max {
			return errors.New(f + ": Kennzahlen unplausibel")
		}
		if c.ValuesCut && c.Values != nil || len(c.Values) > MaxColumnValues {
			return errors.New(f + ": Werte unplausibel")
		}
		total := 0
		for k, n := range c.Values {
			v, err := strconv.ParseInt(k, 10, 64)
			if err != nil || strconv.FormatInt(v, 10) != k || n < 1 || n > c.Numbers || float64(v) < *c.Min || float64(v) > *c.Max {
				return errors.New(f + ": Werte unplausibel")
			}
			total += n
		}
		if total > c.Numbers {
			return errors.New(f + ": Werte unplausibel")
		}
	}
	return nil
}
