// SPDX-License-Identifier: AGPL-3.0-only

package main

// Cabinet (MS-CAB) ohne Kompression mit genau einer Datei, eingebettet im
// MSI. Unkomprimiert, weil der Agent als Go-Binary kaum schrumpft und so
// kein Kompressionsformat (MSZIP/LZX) nachgebaut werden muss. Jeder
// Datenblock trägt die Prüfsumme nach MS-CAB 2.4 (manche Leser verlangen
// sie); gegen Veränderung schützt die Signatur des MSI.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

const cabBlock = 32768

// cabinet schreibt ein Cabinet mit der Datei name (im MSI: Schlüssel der File-Tabelle).
func cabinet(name string, data []byte, mtime time.Time) ([]byte, error) {
	if len(name) == 0 || len(name) > 255 {
		return nil, errors.New("Cabinet: Name ungültig")
	}
	nBlocks := (len(data) + cabBlock - 1) / cabBlock
	if nBlocks == 0 {
		nBlocks = 1
	}
	if nBlocks > 0xffff {
		return nil, errors.New("Cabinet: Datei zu groß")
	}
	const hdrSize, folderSize = 36, 8
	fileSize := 16 + len(name) + 1
	firstData := hdrSize + folderSize + fileSize
	total := firstData + 8*nBlocks + len(data)

	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	b.WriteString("MSCF")
	w(uint32(0))
	w(uint32(total))
	w(uint32(0))
	w(uint32(hdrSize + folderSize)) // coffFiles
	w(uint32(0))
	b.Write([]byte{3, 1}) // Version 1.3
	w(uint16(1))          // Ordner
	w(uint16(1))          // Dateien
	w(uint16(0))          // Kennzeichen
	w(uint16(0x4f57))     // setID („OW“)
	w(uint16(0))          // Nummer im Satz
	w(uint32(firstData))  // CFFOLDER.coffCabStart
	w(uint16(nBlocks))    // cCFData
	w(uint16(0))          // ohne Kompression
	w(uint32(len(data)))  // CFFILE.cbFile
	w(uint32(0))          // uoffFolderStart
	w(uint16(0))          // iFolder
	t := mtime.UTC()
	w(uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day()))
	w(uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2))
	w(uint16(0x20)) // Archiv
	b.WriteString(name)
	b.WriteByte(0)
	for i := range nBlocks {
		end := min((i+1)*cabBlock, len(data))
		chunk := data[i*cabBlock : end]
		sizes := binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, uint16(len(chunk))), uint16(len(chunk)))
		w(cabChecksum(sizes, cabChecksum(chunk, 0)))
		b.Write(sizes)
		b.Write(chunk)
	}
	if b.Len() != total {
		return nil, errors.New("Cabinet: Größe stimmt nicht")
	}
	return b.Bytes(), nil
}

// cabChecksum: XOR über 32-Bit-Wörter, der Rest in umgekehrter Reihenfolge
// (wie in MS-CAB beschrieben und in cabextract umgesetzt).
func cabChecksum(data []byte, seed uint32) uint32 {
	c := seed
	n := len(data) / 4
	for i := range n {
		c ^= binary.LittleEndian.Uint32(data[4*i:])
	}
	rest := data[4*n:]
	var ul uint32
	switch len(rest) {
	case 3:
		ul = uint32(rest[0])<<16 | uint32(rest[1])<<8 | uint32(rest[2])
	case 2:
		ul = uint32(rest[0])<<8 | uint32(rest[1])
	case 1:
		ul = uint32(rest[0])
	}
	return c ^ ul
}
