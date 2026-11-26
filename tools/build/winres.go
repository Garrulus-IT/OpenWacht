// SPDX-License-Identifier: AGPL-3.0-only

package main

// Programmbeschreibung für die Windows-Programme (1.0.6): eine COFF-Datei
// (.syso) mit einer Ressource VERSIONINFO, die der Linker von Go selbst
// einbindet. Windows zeigt daraus den Namen in Benachrichtigungen, im
// Task-Manager und unter Eigenschaften → Details statt des Dateinamens.
// Nur Standardbibliothek, ohne Zeitstempel (reproduzierbar).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

// verInfo: Inhalt der Ressource.
type verInfo struct {
	Description  string // FileDescription, z. B. „OpenWacht Desktop“
	OriginalName string // OriginalFilename, z. B. „openwacht-desktop.exe“
	Version      string // „1.0.6“
	Commit       string
}

const (
	langDeutsch   = 0x0407
	codepageUTF16 = 1200
)

// versionWords: „1.0.6“ → 1.0.6.0 als zwei DWORD (MS, LS). Was keine Zahl
// ist (z. B. „-rc1“), zählt als 0.
func versionWords(v string) (uint32, uint32) {
	var n [4]uint32
	for i, part := range strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 4) {
		x, _ := strconv.ParseUint(part, 10, 16)
		n[i] = uint32(x)
	}
	return n[0]<<16 | n[1], n[2]<<16 | n[3]
}

func utf16z(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, c)
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// resNode baut einen Knoten der VERSIONINFO: wLength, wValueLength, wType,
// Schlüssel (UTF-16 mit Null), Ausrichtung, Wert, Ausrichtung, Kinder.
// valueLen ist bei Texten die Zahl der Zeichen samt Null, sonst Bytes.
func resNode(key string, value []byte, valueLen int, text bool, children ...[]byte) []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 6)) // Kopf, unten gefüllt
	b.Write(utf16z(key))
	pad4(&b)
	b.Write(value)
	for _, c := range children {
		pad4(&b)
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out[0:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[2:], uint16(valueLen))
	if text {
		binary.LittleEndian.PutUint16(out[4:], 1)
	}
	return out
}

func resString(key, value string) []byte {
	v := utf16z(value)
	return resNode(key, v, len(v)/2, true)
}

// versionInfo: der Datenblock VS_VERSIONINFO.
func versionInfo(vi verInfo) []byte {
	ms, ls := versionWords(vi.Version)
	var fixed bytes.Buffer
	for _, x := range []uint32{
		0xFEEF04BD, 0x00010000, // Signatur, Strukturversion
		ms, ls, ms, ls, // Datei- und Produktversion
		0x3F, 0, // FileFlagsMask, FileFlags
		0x00040004, 1, 0, // VOS_NT_WINDOWS32, VFT_APP, Subtyp
		0, 0, // Datum: keins (reproduzierbar)
	} {
		binary.Write(&fixed, binary.LittleEndian, x)
	}
	product := vi.Version
	if vi.Commit != "" && vi.Commit != "unknown" {
		product += " (" + vi.Commit + ")"
	}
	table := resNode(fmt.Sprintf("%04X%04X", langDeutsch, codepageUTF16), nil, 0, true,
		resString("CompanyName", "Garrulus IT"),
		resString("FileDescription", vi.Description),
		resString("FileVersion", vi.Version),
		resString("InternalName", strings.TrimSuffix(vi.OriginalName, ".exe")),
		resString("LegalCopyright", "Copyright (C) 2026 "+copyrightHolder+", AGPL-3.0-only"),
		resString("OriginalFilename", vi.OriginalName),
		resString("ProductName", "OpenWacht"),
		resString("ProductVersion", product),
	)
	strInfo := resNode("StringFileInfo", nil, 0, true, table)
	trans := make([]byte, 4)
	binary.LittleEndian.PutUint16(trans[0:], langDeutsch)
	binary.LittleEndian.PutUint16(trans[2:], codepageUTF16)
	varInfo := resNode("VarFileInfo", nil, 0, true, resNode("Translation", trans, 4, false))
	return resNode("VS_VERSION_INFO", fixed.Bytes(), fixed.Len(), false, strInfo, varInfo)
}

// cofMachine und Typ der Relocation „Adresse relativ zum Abbild“ (ADDR32NB).
func coffMachine(arch string) (machine, reloc uint16, err error) {
	switch arch {
	case "amd64":
		return 0x8664, 0x0003, nil // IMAGE_REL_AMD64_ADDR32NB
	case "arm64":
		return 0xAA64, 0x0002, nil // IMAGE_REL_ARM64_ADDR32NB
	case "386":
		return 0x014C, 0x0007, nil // IMAGE_REL_I386_DIR32NB
	}
	return 0, 0, fmt.Errorf("Windows-Ressource: Architektur %s nicht unterstützt", arch)
}

// versionSyso baut die COFF-Datei mit einem Abschnitt .rsrc: Verzeichnis
// Typ 16 (RT_VERSION) → Name 1 → Sprache 0x0407 → Daten.
func versionSyso(arch string, vi verInfo) ([]byte, error) {
	machine, relType, err := coffMachine(arch)
	if err != nil {
		return nil, err
	}
	data := versionInfo(vi)
	var rs bytes.Buffer
	dir := func(id uint32, target uint32) {
		binary.Write(&rs, binary.LittleEndian, [4]uint32{0, 0, 0, 1 << 16}) // 0 benannte, 1 ID-Eintrag
		binary.Write(&rs, binary.LittleEndian, [2]uint32{id, target})
	}
	const (
		lvl2  = 24
		lvl3  = 48
		entry = 72
		start = 88
	)
	dir(16, 0x80000000|lvl2) // RT_VERSION
	dir(1, 0x80000000|lvl3)
	dir(langDeutsch, entry)
	// Datenbeschreibung: Adresse (wird verschoben), Größe, Codepage, reserviert
	binary.Write(&rs, binary.LittleEndian, [4]uint32{start, uint32(len(data)), 0, 0})
	rs.Write(data)
	pad4(&rs)

	const headers = 20 + 40
	raw := rs.Len()
	relocAt := headers + raw
	symAt := relocAt + 10
	var f bytes.Buffer
	// COFF-Kopf
	binary.Write(&f, binary.LittleEndian, struct {
		Machine, Sections          uint16
		Time, SymPtr, Symbols      uint32
		OptHeader, Characteristics uint16
	}{machine, 1, 0, uint32(symAt), 1, 0, 0})
	// Abschnitt .rsrc
	name := [8]byte{'.', 'r', 's', 'r', 'c'}
	f.Write(name[:])
	binary.Write(&f, binary.LittleEndian, struct {
		VSize, VAddr, RawSize, RawPtr, RelocPtr, LinePtr uint32
		Relocs, Lines                                    uint16
		Characteristics                                  uint32
	}{0, 0, uint32(raw), headers, uint32(relocAt), 0, 1, 0, 0x40000040}) // INITIALIZED_DATA | MEM_READ
	f.Write(rs.Bytes())
	// eine Relocation: Feld OffsetToData der Datenbeschreibung
	binary.Write(&f, binary.LittleEndian, struct {
		VAddr, Sym uint32
		Type       uint16
	}{entry, 0, relType})
	// Symbol des Abschnitts, dann leere Zeichenkettentabelle
	f.Write(name[:])
	binary.Write(&f, binary.LittleEndian, struct {
		Value             uint32
		Section, Type     uint16
		Class, AuxSymbols uint8
	}{0, 1, 0, 3, 0}) // IMAGE_SYM_CLASS_STATIC
	binary.Write(&f, binary.LittleEndian, uint32(4))
	return f.Bytes(), nil
}

// writeVersionSyso legt die Ressource für genau einen Bau in das Paket und
// liefert eine Funktion zum Aufräumen. Der Name endet auf _windows_<arch>,
// damit Go sie nur für dieses Ziel einbindet.
func writeVersionSyso(pkgDir, arch string, vi verInfo) (func(), error) {
	b, err := versionSyso(arch, vi)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(pkgDir, "zz_versioninfo_windows_"+arch+".syso")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return nil, err
	}
	return func() { os.Remove(p) }, nil
}
