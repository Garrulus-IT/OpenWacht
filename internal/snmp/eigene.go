// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// Eigene OIDs (Etappe 18b): Werte für Sensoren „SNMP eigene OID“. Sie werden
// mit der normalen Abfrage des Geräts gelesen, von der Zentrale oder vom
// Sammler. Texte werden nicht gespeichert, nur ihr Hash: Der Sensor vergleicht
// mit einem erwarteten Text, zeigt ihn aber nie an (Leitprinzip 5).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/gosnmp/gosnmp"
)

// MaxExtraOIDs: höchstens so viele eigene OIDs je Gerät.
const MaxExtraOIDs = 32

// ExtraValue: Wert einer eigenen OID. Genau eins von Number, Counter,
// TextHash ist gesetzt, oder Missing.
type ExtraValue struct {
	OID     string   `json:"oid"`
	Missing bool     `json:"fehlt,omitempty"`
	Number  *float64 `json:"zahl,omitempty"`
	// Zähler (Counter32/Counter64) roh, Rate rechnet die Zentrale
	Counter *uint64 `json:"zaehler,omitempty"`
	Bits    int     `json:"bits,omitempty"`
	// Text: nur SHA-256 (hex, 32 Zeichen) des bereinigten Texts
	TextHash string `json:"text_hash,omitempty"`
}

// TextHash: so wird ein Text für den Vergleich gespeichert (bereinigt wie
// beim Lesen vom Gerät).
func TextHash(s string) string {
	h := sha256.Sum256([]byte(cleanBytes([]byte(s), MaxText)))
	return hex.EncodeToString(h[:16])
}

func extraValue(oid string, v value) ExtraValue {
	e := ExtraValue{OID: oid}
	switch {
	case v.missing():
		e.Missing = true
	case v.pdu.Type == gosnmp.Counter32 || v.pdu.Type == gosnmp.Counter64:
		n, _ := v.uint()
		e.Counter = &n
		e.Bits = 32
		if v.pdu.Type == gosnmp.Counter64 {
			e.Bits = 64
		}
	case v.pdu.Type == gosnmp.OctetString:
		t, _ := v.text()
		if f, ok := v.float(); ok {
			e.Number = &f
		}
		e.TextHash = TextHash(t)
	default:
		if f, ok := v.float(); ok {
			e.Number = &f
		} else {
			e.Missing = true
		}
	}
	return e
}

func (s *session) extra(snap *Snapshot, oids []string) error {
	if len(oids) == 0 {
		return nil
	}
	vals, err := s.get(oids...)
	if err != nil {
		return err
	}
	for _, o := range oids {
		v, ok := vals[o]
		if !ok {
			snap.Extra = append(snap.Extra, ExtraValue{OID: o, Missing: true})
			continue
		}
		snap.Extra = append(snap.Extra, extraValue(o, v))
	}
	return nil
}

// CheckExtraOIDs prüft eine Liste eigener OIDs (Zentrale und Sammler).
func CheckExtraOIDs(oids []string) error {
	if len(oids) > MaxExtraOIDs {
		return fmt.Errorf("eigene OIDs: höchstens %d", MaxExtraOIDs)
	}
	for i, o := range oids {
		if o == "" || len(o) > 200 || !validOID(o) || slices.Contains(oids[:i], o) {
			return errors.New("eigene OIDs: ungültig oder doppelt")
		}
	}
	return nil
}

func validateExtra(list []ExtraValue) error {
	if len(list) > MaxExtraOIDs {
		return fmt.Errorf("eigene: höchstens %d", MaxExtraOIDs)
	}
	var seen []string
	for i, e := range list {
		if e.OID == "" || len(e.OID) > 200 || !validOID(e.OID) || slices.Contains(seen, e.OID) {
			return fmt.Errorf("eigene[%d]: OID ungültig oder doppelt", i)
		}
		seen = append(seen, e.OID)
		set := 0
		if e.Number != nil {
			set++
			if f := *e.Number; f != f || f > 1e300 || f < -1e300 {
				return fmt.Errorf("eigene[%d]: Zahl unplausibel", i)
			}
		}
		if e.Counter != nil {
			set++
			if e.Bits != 32 && e.Bits != 64 || e.Bits == 32 && *e.Counter > 1<<32-1 {
				return fmt.Errorf("eigene[%d]: Zähler unplausibel", i)
			}
		} else if e.Bits != 0 {
			return fmt.Errorf("eigene[%d]: Bits ohne Zähler", i)
		}
		if e.TextHash != "" {
			if len(e.TextHash) != 32 || hex.EncodeToString(mustHex(e.TextHash)) != e.TextHash {
				return fmt.Errorf("eigene[%d]: Text-Hash ungültig", i)
			}
		}
		if e.Missing && (set > 0 || e.TextHash != "") || !e.Missing && set == 0 && e.TextHash == "" || e.Counter != nil && (e.Number != nil || e.TextHash != "") {
			return fmt.Errorf("eigene[%d]: Felder passen nicht zusammen", i)
		}
	}
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
