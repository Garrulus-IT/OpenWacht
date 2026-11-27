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
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/checks"
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
	// AusText (1.0.8): Zahlen, die auf Wunsch eines Sensors aus dem Text
	// gelesen wurden. Der Text selbst wird weiterhin nie gespeichert.
	AusText []TextWert `json:"aus_text,omitempty"`
}

// TextZahl: Auftrag, aus dem Text einer eigenen OID eine Zahl zu lesen: die
// N-te (ab 1) oder die erste hinter Nach. Genau eins von beiden ist gesetzt.
type TextZahl struct {
	OID  string `json:"oid"`
	N    int    `json:"n,omitempty"`
	Nach string `json:"nach,omitempty"`
}

// TextWert: Ergebnis eines Auftrags; Zahl fehlt, wenn im Text keine stand.
type TextWert struct {
	N    int      `json:"n,omitempty"`
	Nach string   `json:"nach,omitempty"`
	Zahl *float64 `json:"zahl,omitempty"`
}

// MaxExtraText: höchstens so viele Aufträge „Zahl aus Text“ je Gerät.
const MaxExtraText = 64

func textAuftragOK(n int, nach string) bool {
	if nach == "" {
		return n >= 1 && n <= checks.MaxTextIndex
	}
	return n == 0 && utf8.ValidString(nach) && utf8.RuneCountInString(nach) <= checks.MaxTextAfter && !strings.ContainsFunc(nach, unicode.IsControl)
}

// CheckExtraText prüft die Aufträge „Zahl aus Text“ (Zentrale und Sammler):
// jede OID muss unter den eigenen OIDs stehen, kein Auftrag doppelt.
func CheckExtraText(list []TextZahl, oids []string) error {
	if len(list) > MaxExtraText {
		return fmt.Errorf("Zahl aus Text: höchstens %d", MaxExtraText)
	}
	for i, t := range list {
		if !slices.Contains(oids, t.OID) || !textAuftragOK(t.N, t.Nach) || slices.Contains(list[:i], t) {
			return errors.New("Zahl aus Text: ungültig oder doppelt")
		}
	}
	return nil
}

// TextHash: so wird ein Text für den Vergleich gespeichert (bereinigt wie
// beim Lesen vom Gerät).
func TextHash(s string) string {
	h := sha256.Sum256([]byte(cleanBytes([]byte(s), MaxText)))
	return hex.EncodeToString(h[:16])
}

func extraValue(oid string, v value, wanted []TextZahl) ExtraValue {
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
		for _, w := range wanted {
			if w.OID != oid {
				continue
			}
			tw := TextWert{N: w.N, Nach: w.Nach}
			if f, ok := checks.NumberFromText(t, w.N, w.Nach); ok && f <= 1e300 && f >= -1e300 {
				tw.Zahl = &f
			}
			e.AusText = append(e.AusText, tw)
		}
	default:
		if f, ok := v.float(); ok {
			e.Number = &f
		} else {
			e.Missing = true
		}
	}
	return e
}

func (s *session) extra(snap *Snapshot, oids []string, wanted []TextZahl) error {
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
		snap.Extra = append(snap.Extra, extraValue(o, v, wanted))
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
		if len(e.AusText) > MaxExtraText || len(e.AusText) > 0 && e.TextHash == "" {
			return fmt.Errorf("eigene[%d]: Zahl aus Text ohne Text", i)
		}
		for j, t := range e.AusText {
			if !textAuftragOK(t.N, t.Nach) || t.Zahl != nil && (*t.Zahl != *t.Zahl || *t.Zahl > 1e300 || *t.Zahl < -1e300) ||
				slices.ContainsFunc(e.AusText[:j], func(x TextWert) bool { return x.N == t.N && x.Nach == t.Nach }) {
				return fmt.Errorf("eigene[%d]: Zahl aus Text ungültig", i)
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
