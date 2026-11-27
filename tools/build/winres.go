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
	"image/png"
	"os"
	"path/filepath"
	"sort"
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

// winResource: ein Eintrag im Abschnitt .rsrc (Typ, ID, Sprache, Daten).
type winResource struct {
	typ, id, lang uint32
	data          []byte
}

const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
	rtManifest  = 24
)

// resourceSyso baut die COFF-Datei mit einem Abschnitt .rsrc: Verzeichnis
// Typ → ID → Sprache und je Ressource eine Datenbeschreibung, deren Adresse
// der Linker per Relocation einsetzt. Typen und IDs werden aufsteigend
// sortiert (Vorgabe des Formats); jede Kombination Typ/ID nur einmal.
func resourceSyso(arch string, res []winResource) ([]byte, error) {
	machine, relType, err := coffMachine(arch)
	if err != nil {
		return nil, err
	}
	res = append([]winResource(nil), res...)
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].typ != res[j].typ {
			return res[i].typ < res[j].typ
		}
		return res[i].id < res[j].id
	})
	var typen []uint32
	jeTyp := map[uint32][]int{}
	for i, r := range res {
		if len(jeTyp[r.typ]) == 0 {
			typen = append(typen, r.typ)
		} else if res[jeTyp[r.typ][len(jeTyp[r.typ])-1]].id == r.id {
			return nil, fmt.Errorf("Ressource Typ %d ID %d doppelt", r.typ, r.id)
		}
		jeTyp[r.typ] = append(jeTyp[r.typ], i)
	}
	n := uint32(len(res))
	// Aufteilung: Wurzel, je Typ ein ID-Verzeichnis, je Ressource ein
	// Sprachverzeichnis (24), dann die Datenbeschreibungen (je 16), dann die
	// Daten (8-Byte-Grenze).
	idDirAt := map[uint32]uint32{}
	at := 16 + 8*uint32(len(typen))
	for _, t := range typen {
		idDirAt[t] = at
		at += 16 + 8*uint32(len(jeTyp[t]))
	}
	langAt := at
	entries := langAt + 24*n
	dataAt := entries + 16*n
	var rs bytes.Buffer
	binary.Write(&rs, binary.LittleEndian, [4]uint32{0, 0, 0, uint32(len(typen)) << 16})
	for _, t := range typen {
		binary.Write(&rs, binary.LittleEndian, [2]uint32{t, 0x80000000 | idDirAt[t]})
	}
	for _, t := range typen {
		binary.Write(&rs, binary.LittleEndian, [4]uint32{0, 0, 0, uint32(len(jeTyp[t])) << 16})
		for _, i := range jeTyp[t] {
			binary.Write(&rs, binary.LittleEndian, [2]uint32{res[i].id, 0x80000000 | (langAt + 24*uint32(i))})
		}
	}
	for i, r := range res {
		binary.Write(&rs, binary.LittleEndian, [4]uint32{0, 0, 0, 1 << 16})
		binary.Write(&rs, binary.LittleEndian, [2]uint32{r.lang, entries + 16*uint32(i)})
	}
	offs := make([]uint32, n)
	at = dataAt
	for i, r := range res {
		offs[i] = at
		at += uint32(len(r.data))
		at = (at + 7) &^ 7
	}
	for i, r := range res {
		binary.Write(&rs, binary.LittleEndian, [4]uint32{offs[i], uint32(len(r.data)), 0, 0})
	}
	for _, r := range res {
		rs.Write(r.data)
		for rs.Len()%8 != 0 {
			rs.WriteByte(0)
		}
	}

	const headers = 20 + 40
	raw := rs.Len()
	relocAt := headers + raw
	symAt := relocAt + 10*int(n)
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
	}{0, 0, uint32(raw), headers, uint32(relocAt), 0, uint16(n), 0, 0x40000040}) // INITIALIZED_DATA | MEM_READ
	f.Write(rs.Bytes())
	// je Ressource eine Relocation: Feld OffsetToData der Datenbeschreibung
	for i := range res {
		binary.Write(&f, binary.LittleEndian, struct {
			VAddr, Sym uint32
			Type       uint16
		}{entries + 16*uint32(i), 0, relType})
	}
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

// versionSyso: nur die Programmbeschreibung.
func versionSyso(arch string, vi verInfo) ([]byte, error) {
	return resourceSyso(arch, []winResource{{rtVersion, 1, langDeutsch, versionInfo(vi)}})
}

// desktopManifest: moderne Steuerelemente (Common Controls 6) und scharfe
// Darstellung bei jeder Skalierung (PerMonitorV2), läuft ohne Adminrechte.
func desktopManifest(ver string) []byte {
	ms, ls := versionWords(ver)
	v := fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xffff, ls>>16, ls&0xffff)
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="OpenWacht.Desktop" version="` + v + `" processorArchitecture="*"/>
  <description>OpenWacht Desktop</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
`)
}

// writeVersionSyso legt die Ressource für genau einen Bau in das Paket und
// liefert eine Funktion zum Aufräumen. Der Name endet auf _windows_<arch>,
// damit Go sie nur für dieses Ziel einbindet.
func writeVersionSyso(pkgDir, arch string, vi verInfo, manifest []byte, icons [][]byte) (func(), error) {
	res := []winResource{{rtVersion, 1, langDeutsch, versionInfo(vi)}}
	if manifest != nil {
		res = append(res, winResource{rtManifest, 1, 0, manifest})
	}
	if len(icons) > 0 {
		ic, err := iconResources(icons)
		if err != nil {
			return nil, err
		}
		res = append(res, ic...)
	}
	b, err := resourceSyso(arch, res)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(pkgDir, "zz_versioninfo_windows_"+arch+".syso")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return nil, err
	}
	return func() { os.Remove(p) }, nil
}

// iconResources: Programmsymbol aus PNG-Bildern (je Größe eins, quadratisch,
// höchstens 256 px). Windows nimmt PNG in Icon-Ressourcen seit Vista. Die
// Gruppe hat die ID 1; die exe zeigt sie im Explorer, das Fenster lädt sie.
func iconResources(pngs [][]byte) ([]winResource, error) {
	var res []winResource
	var grp bytes.Buffer
	binary.Write(&grp, binary.LittleEndian, [3]uint16{0, 1, uint16(len(pngs))})
	for i, b := range pngs {
		cfg, err := png.DecodeConfig(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("Symbol %d: %w", i+1, err)
		}
		if cfg.Width != cfg.Height || cfg.Width > 256 || cfg.Width < 1 {
			return nil, fmt.Errorf("Symbol %d: %d×%d (quadratisch, höchstens 256)", i+1, cfg.Width, cfg.Height)
		}
		w := byte(cfg.Width % 256) // 256 steht als 0
		binary.Write(&grp, binary.LittleEndian, struct {
			W, H, Colors, Reserved byte
			Planes, BitCount       uint16
			Bytes                  uint32
			ID                     uint16
		}{w, w, 0, 0, 1, 32, uint32(len(b)), uint16(i + 1)})
		res = append(res, winResource{rtIcon, uint32(i + 1), 0, b})
	}
	return append(res, winResource{rtGroupIcon, 1, 0, grp.Bytes()}), nil
}

// desktopIcons liest die Bilder des Programmsymbols (internal/desktop/marke/app-*.png).
func desktopIcons() ([][]byte, error) {
	var out [][]byte
	for _, n := range []int{16, 20, 24, 32, 40, 48, 64, 256} {
		b, err := os.ReadFile(filepath.Join("internal", "desktop", "marke", fmt.Sprintf("app-%d.png", n)))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
