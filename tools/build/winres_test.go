// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

func TestVersionWords(t *testing.T) {
	for v, want := range map[string][2]uint32{
		"1.0.6":     {1 << 16, 6 << 16},
		"1.2.3.4":   {1<<16 | 2, 3<<16 | 4},
		"2.0.0-rc1": {2 << 16, 0},
		"kaputt":    {0, 0},
	} {
		ms, ls := versionWords(v)
		if ms != want[0] || ls != want[1] {
			t.Errorf("%s: %x %x", v, ms, ls)
		}
	}
	if d := windowsDescription("openwacht-desktop"); d != "OpenWacht Desktop" {
		t.Errorf("Beschreibung: %q", d)
	}
}

func u16(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, c)
	}
	return b.Bytes()
}

func TestVersionSyso(t *testing.T) {
	vi := verInfo{Description: "OpenWacht Desktop", OriginalName: "openwacht-desktop.exe", Version: "1.0.6", Commit: "abc"}
	for arch, m := range map[string]uint16{"amd64": 0x8664, "arm64": 0xAA64} {
		b, err := versionSyso(arch, vi)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint16(b); got != m {
			t.Errorf("%s: Maschine %x", arch, got)
		}
		if !bytes.Equal(b[20:25], []byte(".rsrc")) {
			t.Errorf("%s: Abschnitt %q", arch, b[20:28])
		}
		for _, s := range []string{"VS_VERSION_INFO", "StringFileInfo", "040704B0", "OpenWacht Desktop", "1.0.6 (abc)", "VarFileInfo"} {
			if !bytes.Contains(b, u16(s)) {
				t.Errorf("%s: %q fehlt", arch, s)
			}
		}
		// Datenbeschreibung zeigt auf die Daten hinter dem Verzeichnis
		raw := b[60:]
		if off, size := binary.LittleEndian.Uint32(raw[72:]), binary.LittleEndian.Uint32(raw[76:]); off != 88 ||
			binary.LittleEndian.Uint16(raw[88:]) != uint16(size) {
			t.Errorf("%s: Daten bei %d, Größe %d", arch, off, size)
		}
		// mit Manifest: zwei Typen, aufsteigend
		m, err := resourceSyso(arch, []winResource{{rtVersion, 1, langDeutsch, versionInfo(vi)}, {rtManifest, 1, 0, desktopManifest("1.0.6")}})
		if err != nil || !bytes.Contains(m, []byte("PerMonitorV2")) || !bytes.Contains(m, []byte(`version="1.0.6.0"`)) {
			t.Errorf("%s: Manifest fehlt (%v)", arch, err)
		}
		// reproduzierbar
		b2, _ := versionSyso(arch, vi)
		if !bytes.Equal(b, b2) {
			t.Errorf("%s: nicht reproduzierbar", arch)
		}
	}
	if _, err := versionSyso("mips", vi); err == nil {
		t.Error("unbekannte Architektur angenommen")
	}
}

func TestIconResources(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir("tools/build")
	pngs, err := desktopIcons()
	if err != nil {
		t.Fatal(err)
	}
	res, err := iconResources(pngs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != len(pngs)+1 || res[len(res)-1].typ != rtGroupIcon || len(res[len(res)-1].data) != 6+14*len(pngs) {
		t.Fatalf("Gruppe falsch: %d Einträge", len(res))
	}
	if _, err := resourceSyso("amd64", append(res, winResource{rtVersion, 1, 0, []byte("x")})); err != nil {
		t.Fatal(err)
	}
	if _, err := resourceSyso("amd64", []winResource{{rtIcon, 1, 0, nil}, {rtIcon, 1, 0, nil}}); err == nil {
		t.Fatal("doppelte ID nicht abgelehnt")
	}
}
