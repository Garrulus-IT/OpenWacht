// SPDX-License-Identifier: AGPL-3.0-only

package main

// Compound File Binary (MS-CFB, Version 3, Sektoren zu 512 Byte): der
// Container, in dem ein MSI liegt. Nur Schreiben, nur ein Speicher (die
// Wurzel) mit Datenströmen darin, so wie Windows Installer es braucht.
// Ströme unter 4096 Byte liegen im Mini-Strom (64-Byte-Sektoren), wie die
// Spezifikation es verlangt.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf16"
)

const (
	cfbSector     = 512
	cfbMiniSector = 64
	cfbMiniCutoff = 4096
	cfbFree       = 0xFFFFFFFF
	cfbEnd        = 0xFFFFFFFE
	cfbFATSect    = 0xFFFFFFFD
	cfbDIFSect    = 0xFFFFFFFC
	cfbNoStream   = 0xFFFFFFFF
	cfbDirEntries = cfbSector / 128
)

// cfbStream: ein Datenstrom mit Namen (UTF-16, höchstens 31 Zeichen).
type cfbStream struct {
	name []uint16
	data []byte
}

// cfbLess: Reihenfolge der Namen im Verzeichnisbaum (MS-CFB 2.6.4): erst
// die Länge, dann Zeichen für Zeichen in Großbuchstaben.
func cfbLess(a, b []uint16) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	for i := range a {
		x, y := cfbUpper(a[i]), cfbUpper(b[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func cfbUpper(c uint16) uint16 {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

// writeCFB baut die Datei. clsid: Kennung des Wurzelspeichers (MSI-Datenbank).
func writeCFB(streams []cfbStream, clsid [16]byte) ([]byte, error) {
	sort.Slice(streams, func(i, j int) bool { return cfbLess(streams[i].name, streams[j].name) })
	for i, s := range streams {
		if len(s.name) == 0 || len(s.name) > 31 {
			return nil, errors.New("CFB: Name leer oder länger als 31 Zeichen")
		}
		if i > 0 && !cfbLess(streams[i-1].name, s.name) {
			return nil, errors.New("CFB: Name doppelt: " + string(utf16.Decode(s.name)))
		}
	}

	// Mini-Strom und Mini-FAT für kleine Ströme
	var mini bytes.Buffer
	var miniFAT []uint32
	start := make([]uint32, len(streams))
	for i, s := range streams {
		if len(s.data) >= cfbMiniCutoff {
			continue
		}
		if len(s.data) == 0 {
			start[i] = cfbEnd
			continue
		}
		first := uint32(len(miniFAT))
		n := (len(s.data) + cfbMiniSector - 1) / cfbMiniSector
		for k := range n {
			if k == n-1 {
				miniFAT = append(miniFAT, cfbEnd)
			} else {
				miniFAT = append(miniFAT, first+uint32(k)+1)
			}
		}
		mini.Write(s.data)
		for mini.Len()%cfbMiniSector != 0 {
			mini.WriteByte(0)
		}
		start[i] = first
	}

	// Sektoren: [Mini-FAT][Mini-Strom][große Ströme][Verzeichnis][FAT][DIFAT]
	var sectors [][]byte
	var fat []uint32
	chain := func(data []byte) uint32 {
		if len(data) == 0 {
			return cfbEnd
		}
		first := uint32(len(sectors))
		n := (len(data) + cfbSector - 1) / cfbSector
		for k := range n {
			sec := make([]byte, cfbSector)
			copy(sec, data[k*cfbSector:])
			sectors = append(sectors, sec)
			if k == n-1 {
				fat = append(fat, cfbEnd)
			} else {
				fat = append(fat, first+uint32(k)+1)
			}
		}
		return first
	}

	nEntries := len(streams) + 1
	dirSize := ((nEntries + cfbDirEntries - 1) / cfbDirEntries) * cfbSector
	var miniFATBytes []byte
	for _, v := range miniFAT {
		miniFATBytes = binary.LittleEndian.AppendUint32(miniFATBytes, v)
	}
	for len(miniFATBytes)%cfbSector != 0 && len(miniFATBytes) > 0 {
		miniFATBytes = binary.LittleEndian.AppendUint32(miniFATBytes, cfbFree)
	}
	miniFATStart := chain(miniFATBytes)
	miniStart := chain(mini.Bytes())
	for i, s := range streams {
		if len(s.data) >= cfbMiniCutoff {
			start[i] = chain(s.data)
		}
	}
	// Verzeichnis nicht in den ersten Sektor: osslsigncode bis 2.8 hält das
	// für beschädigt (der Spezifikation nach erlaubt). Notfalls ein freier Sektor davor.
	if len(sectors) == 0 {
		sectors = append(sectors, make([]byte, cfbSector))
		fat = append(fat, cfbFree)
	}
	dirStart := chain(make([]byte, dirSize)) // Inhalt folgt unten

	// FAT selbst: so viele Sektoren, dass alle Einträge (auch ihre eigenen
	// und die der DIFAT) passen. Über 109 FAT-Sektoren stehen die übrigen in
	// DIFAT-Sektoren (je 127 Verweise und ein Verweis auf den nächsten).
	nFAT, nDIFAT := 0, 0
	for {
		nDIFAT = 0
		if nFAT > 109 {
			nDIFAT = (nFAT - 109 + 126) / 127
		}
		total := len(sectors) + nFAT + nDIFAT
		if (total+cfbSector/4-1)/(cfbSector/4) <= nFAT {
			break
		}
		nFAT++
	}
	fatStart := uint32(len(sectors))
	difatStart := fatStart + uint32(nFAT)
	for range nFAT {
		fat = append(fat, cfbFATSect)
	}
	for range nDIFAT {
		fat = append(fat, cfbDIFSect)
	}
	for len(fat)%(cfbSector/4) != 0 {
		fat = append(fat, cfbFree)
	}
	var difat [][]byte
	for d := range nDIFAT {
		sec := make([]byte, cfbSector)
		for k := range 127 {
			v := uint32(cfbFree)
			if i := 109 + d*127 + k; i < nFAT {
				v = fatStart + uint32(i)
			}
			binary.LittleEndian.PutUint32(sec[4*k:], v)
		}
		next := uint32(cfbEnd)
		if d < nDIFAT-1 {
			next = difatStart + uint32(d) + 1
		}
		binary.LittleEndian.PutUint32(sec[508:], next)
		difat = append(difat, sec)
	}

	// Verzeichnis: Eintrag 0 ist die Wurzel, die Ströme hängen als
	// Rot-Schwarz-Baum darunter (ausgeglichen, unterste Ebene rot).
	dir := make([]byte, dirSize)
	entry := func(idx int, name []uint16, typ, color byte, left, right, child, startSec uint32, size uint64, cls *[16]byte) {
		e := dir[idx*128 : idx*128+128]
		for k, c := range name {
			binary.LittleEndian.PutUint16(e[2*k:], c)
		}
		binary.LittleEndian.PutUint16(e[64:], uint16(2*(len(name)+1)))
		e[66], e[67] = typ, color
		binary.LittleEndian.PutUint32(e[68:], left)
		binary.LittleEndian.PutUint32(e[72:], right)
		binary.LittleEndian.PutUint32(e[76:], child)
		if cls != nil {
			copy(e[80:96], cls[:])
		}
		binary.LittleEndian.PutUint32(e[116:], startSec)
		binary.LittleEndian.PutUint64(e[120:], size)
	}
	for i := len(streams) + 1; i < dirSize/128; i++ {
		e := dir[i*128 : i*128+128]
		binary.LittleEndian.PutUint32(e[68:], cfbNoStream)
		binary.LittleEndian.PutUint32(e[72:], cfbNoStream)
		binary.LittleEndian.PutUint32(e[76:], cfbNoStream)
	}
	maxDepth := 0
	for n := len(streams); n > 0; n /= 2 {
		maxDepth++
	}
	maxDepth--
	var build func(lo, hi, depth int) uint32
	build = func(lo, hi, depth int) uint32 {
		if lo > hi {
			return cfbNoStream
		}
		mid := (lo + hi) / 2
		l := build(lo, mid-1, depth+1)
		r := build(mid+1, hi, depth+1)
		color := byte(1) // schwarz
		if depth == maxDepth && depth > 0 {
			color = 0
		}
		s := streams[mid]
		entry(mid+1, s.name, 2, color, l, r, cfbNoStream, start[mid], uint64(len(s.data)), nil)
		return uint32(mid + 1)
	}
	rootChild := build(0, len(streams)-1, 0)
	rootStart := miniStart
	if mini.Len() == 0 {
		rootStart = cfbEnd
	}
	entry(0, utf16.Encode([]rune("Root Entry")), 5, 1, cfbNoStream, cfbNoStream, rootChild, rootStart, uint64(mini.Len()), &clsid)
	copy(sectors[dirStart:], splitSectors(dir))

	hdr := make([]byte, cfbSector)
	copy(hdr, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003)
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9)
	binary.LittleEndian.PutUint16(hdr[32:], 6)
	binary.LittleEndian.PutUint32(hdr[44:], uint32(nFAT))
	binary.LittleEndian.PutUint32(hdr[48:], dirStart)
	binary.LittleEndian.PutUint32(hdr[56:], cfbMiniCutoff)
	if len(miniFAT) > 0 {
		binary.LittleEndian.PutUint32(hdr[60:], miniFATStart)
		binary.LittleEndian.PutUint32(hdr[64:], uint32(len(miniFATBytes)/cfbSector))
	} else {
		binary.LittleEndian.PutUint32(hdr[60:], cfbEnd)
	}
	if nDIFAT > 0 {
		binary.LittleEndian.PutUint32(hdr[68:], difatStart)
	} else {
		binary.LittleEndian.PutUint32(hdr[68:], cfbEnd)
	}
	binary.LittleEndian.PutUint32(hdr[72:], uint32(nDIFAT))
	for k := range 109 {
		v := uint32(cfbFree)
		if k < nFAT {
			v = fatStart + uint32(k)
		}
		binary.LittleEndian.PutUint32(hdr[76+4*k:], v)
	}

	var out bytes.Buffer
	out.Write(hdr)
	for _, s := range sectors {
		out.Write(s)
	}
	for _, v := range fat {
		out.Write(binary.LittleEndian.AppendUint32(nil, v))
	}
	for _, d := range difat {
		out.Write(d)
	}
	return out.Bytes(), nil
}

func splitSectors(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		out = append(out, b[:cfbSector])
		b = b[cfbSector:]
	}
	return out
}

// cfbName: Name als UTF-16.
func cfbName(s string) []uint16 { return utf16.Encode([]rune(s)) }
