// SPDX-License-Identifier: AGPL-3.0-only

package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf8"
)

// Kleiner CBOR-Leser (RFC 8949) nur für das, was WebAuthn braucht: Zahlen,
// Byte- und Textketten, Felder, Zuordnungen, true/false/null. Keine
// unbestimmten Längen, keine Tags, keine Gleitkommazahlen. Daten vom
// Authenticator sind nicht vertrauenswürdig: Tiefe, Anzahl und Längen sind
// begrenzt, und die Länge wird vor jeder Zuteilung gegen die Eingabe geprüft.

var errCBOR = errors.New("CBOR ungültig")

const (
	maxDepth = 8
	maxItems = 64
)

// decodeCBOR liest genau einen Wert und gibt den Rest zurück.
func decodeCBOR(b []byte) (any, []byte, error) {
	return decode(b, 0)
}

func head(b []byte) (major byte, arg uint64, rest []byte, err error) {
	if len(b) < 1 {
		return 0, 0, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	switch {
	case info < 24:
		return major, uint64(info), b, nil
	case info == 24:
		if len(b) < 1 {
			return 0, 0, nil, errCBOR
		}
		if b[0] < 24 { // nicht kürzeste Form
			return 0, 0, nil, errCBOR
		}
		return major, uint64(b[0]), b[1:], nil
	case info == 25:
		if len(b) < 2 {
			return 0, 0, nil, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint16(b)), b[2:], nil
	case info == 26:
		if len(b) < 4 {
			return 0, 0, nil, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint32(b)), b[4:], nil
	case info == 27:
		if len(b) < 8 {
			return 0, 0, nil, errCBOR
		}
		return major, binary.BigEndian.Uint64(b), b[8:], nil
	}
	return 0, 0, nil, errCBOR // 28–31: reserviert bzw. unbestimmte Länge
}

func decode(b []byte, depth int) (any, []byte, error) {
	if depth > maxDepth {
		return nil, nil, errCBOR
	}
	major, arg, rest, err := head(b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0: // positive Zahl
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return int64(arg), rest, nil
	case 1: // negative Zahl: -1 - arg
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return -1 - int64(arg), rest, nil
	case 2, 3:
		if arg > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		v := rest[:arg]
		if major == 3 {
			if !utf8.Valid(v) {
				return nil, nil, errCBOR
			}
			return string(v), rest[arg:], nil
		}
		return append([]byte(nil), v...), rest[arg:], nil
	case 4:
		if arg > maxItems || arg > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var v any
			if v, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, rest, nil
	case 5:
		if arg > maxItems || arg*2 > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			var k, v any
			if k, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, errCBOR
			}
			if _, dup := out[k]; dup {
				return nil, nil, errCBOR
			}
			if v, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out[k] = v
		}
		return out, rest, nil
	case 7:
		switch b[0] {
		case 0xf4:
			return false, rest, nil
		case 0xf5:
			return true, rest, nil
		case 0xf6:
			return nil, rest, nil
		}
	}
	return nil, nil, errCBOR // Tags (6), Gleitkomma und Unbekanntes
}
