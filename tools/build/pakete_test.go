// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

var testTime = time.Date(2026, 11, 22, 18, 0, 0, 0, time.UTC)

// readCFB liest eine Compound File (unabhängig vom Schreiber: über FAT,
// DIFAT und Mini-FAT) und liefert die Ströme unter dem Wurzelspeicher.
func readCFB(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	if !bytes.Equal(b[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) || len(b)%512 != 0 {
		t.Fatal("keine Compound File")
	}
	le := binary.LittleEndian
	sector := func(i uint32) []byte { return b[512+int(i)*512 : 1024+int(i)*512] }
	nFAT := le.Uint32(b[44:])
	var fatSecs []uint32
	for k := range 109 {
		if uint32(k) < nFAT {
			fatSecs = append(fatSecs, le.Uint32(b[76+4*k:]))
		}
	}
	for d := le.Uint32(b[68:]); d != cfbEnd && uint32(len(fatSecs)) < nFAT; {
		s := sector(d)
		for k := range 127 {
			if uint32(len(fatSecs)) < nFAT {
				fatSecs = append(fatSecs, le.Uint32(s[4*k:]))
			}
		}
		d = le.Uint32(s[508:])
	}
	if uint32(len(fatSecs)) != nFAT {
		t.Fatalf("FAT unvollständig: %d von %d", len(fatSecs), nFAT)
	}
	var fat []uint32
	for _, f := range fatSecs {
		s := sector(f)
		for k := range 128 {
			fat = append(fat, le.Uint32(s[4*k:]))
		}
	}
	for _, f := range fatSecs {
		if fat[f] != cfbFATSect {
			t.Fatalf("FAT-Sektor %d nicht als FAT markiert", f)
		}
	}
	read := func(start uint32, size int) []byte {
		var out []byte
		for s, n := start, 0; s != cfbEnd; s = fat[s] {
			if n++; n > len(fat) {
				t.Fatal("Kette mit Schleife")
			}
			out = append(out, sector(s)...)
		}
		if len(out) < size {
			t.Fatalf("Kette zu kurz: %d < %d", len(out), size)
		}
		return out[:size]
	}
	dirBytes := func() []byte {
		var out []byte
		for s := le.Uint32(b[48:]); s != cfbEnd; s = fat[s] {
			out = append(out, sector(s)...)
		}
		return out
	}()
	entry := func(i uint32) []byte { return dirBytes[i*128 : i*128+128] }
	root := entry(0)
	if root[66] != 5 {
		t.Fatal("Eintrag 0 ist nicht die Wurzel")
	}
	miniStream := read(le.Uint32(root[116:]), int(le.Uint64(root[120:])))
	var miniFAT []uint32
	if n := le.Uint32(b[64:]); n > 0 {
		mf := read(le.Uint32(b[60:]), int(n)*512)
		for k := 0; k < len(mf); k += 4 {
			miniFAT = append(miniFAT, le.Uint32(mf[k:]))
		}
	}
	out := map[string][]byte{}
	var walk func(i uint32)
	walk = func(i uint32) {
		if i == cfbNoStream {
			return
		}
		e := entry(i)
		nl := int(le.Uint16(e[64:]))/2 - 1
		name := make([]uint16, nl)
		for k := range name {
			name[k] = le.Uint16(e[2*k:])
		}
		size := int(le.Uint64(e[120:]))
		start := le.Uint32(e[116:])
		var data []byte
		if size < cfbMiniCutoff {
			for s := start; s != cfbEnd && len(data) < size; s = miniFAT[s] {
				data = append(data, miniStream[int(s)*64:int(s)*64+64]...)
			}
			data = data[:size]
		} else {
			data = read(start, size)
		}
		out[string(utf16.Decode(name))] = data
		walk(le.Uint32(e[68:]))
		walk(le.Uint32(e[72:]))
	}
	walk(le.Uint32(root[76:]))
	return out
}

// msiDB liest Zeichenketten und Tabellen eines MSI (Werte als Text).
func msiDB(t *testing.T, streams map[string][]byte) map[string][]map[string]string {
	t.Helper()
	key := func(n string) string { return string(utf16.Decode(msiStreamName(n, true))) }
	pool, data := streams[key("_StringPool")], streams[key("_StringData")]
	if binary.LittleEndian.Uint32(pool) != 1252 {
		t.Fatal("Codepage nicht 1252")
	}
	strs := []string{""}
	off := 0
	for k := 4; k < len(pool); k += 4 {
		n := int(binary.LittleEndian.Uint16(pool[k:]))
		strs = append(strs, string(data[off:off+n]))
		off += n
	}
	if off != len(data) {
		t.Fatal("_StringData passt nicht zu _StringPool")
	}
	u16 := func(b []byte, i int) uint32 { return uint32(binary.LittleEndian.Uint16(b[2*i:])) }
	tables := streams[key("_Tables")]
	cols := streams[key("_Columns")]
	nc := len(cols) / 8
	type col struct {
		table, name string
		typ         uint16
	}
	var cs []col
	for i := range nc {
		cs = append(cs, col{strs[u16(cols, i)], strs[u16(cols, 2*nc+i)], uint16(u16(cols, 3*nc+i) - 0x8000)})
	}
	db := map[string][]map[string]string{}
	for i := range len(tables) / 2 {
		name := strs[u16(tables, i)]
		var tc []col
		width := 0
		for _, c := range cs {
			if c.table == name {
				tc = append(tc, c)
				width += colWidth(c.typ)
			}
		}
		raw := streams[key(name)]
		if width == 0 || len(raw)%width != 0 {
			t.Fatalf("Tabelle %s: Größe %d passt nicht zu Breite %d", name, len(raw), width)
		}
		n := len(raw) / width
		rows := make([]map[string]string, n)
		pos := 0
		for _, c := range tc {
			w := colWidth(c.typ)
			for r := range n {
				if rows[r] == nil {
					rows[r] = map[string]string{}
				}
				var v uint32
				if w == 2 {
					v = uint32(binary.LittleEndian.Uint16(raw[pos:]))
				} else {
					v = binary.LittleEndian.Uint32(raw[pos:])
				}
				pos += w
				switch {
				case colIsString(c.typ):
					rows[r][c.name] = strs[v]
				case v == 0:
					rows[r][c.name] = ""
				case w == 2:
					rows[r][c.name] = strconv.Itoa(int(v) - 0x8000)
				default:
					rows[r][c.name] = strconv.Itoa(int(int32(v - 0x80000000)))
				}
			}
		}
		db[name] = rows
	}
	return db
}

func find(rows []map[string]string, col, val string) map[string]string {
	for _, r := range rows {
		if r[col] == val {
			return r
		}
	}
	return nil
}

func TestMSI(t *testing.T) {
	for _, size := range []int{3000, 9_500_000} { // Mini-Strom bzw. DIFAT
		exe := bytes.Repeat([]byte("MZ-openwacht"), size/12+1)[:size]
		b, err := msiPackage(exe, "amd64", "0.34.0", testTime)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := msiPackage(exe, "amd64", "0.34.0", testTime)
		if !bytes.Equal(b, again) {
			t.Fatal("MSI nicht reproduzierbar")
		}
		if binary.LittleEndian.Uint32(b[48:]) == 0 {
			t.Error("Verzeichnis im ersten Sektor: osslsigncode bis 2.8 lehnt das MSI ab")
		}
		streams := readCFB(t, b)
		db := msiDB(t, streams)

		props := db["Property"]
		if find(props, "Property", "MsiHiddenProperties")["Value"] != "TOKEN" {
			t.Error("TOKEN ist keine versteckte Eigenschaft")
		}
		if !strings.Contains(find(props, "Property", "SecureCustomProperties")["Value"], "TOKEN") {
			t.Error("TOKEN fehlt in SecureCustomProperties (verwaltete Installation)")
		}
		pc := find(props, "Property", "ProductCode")["Value"]
		if pc == "" || pc == find(props, "Property", "UpgradeCode")["Value"] {
			t.Error("ProductCode fehlt oder gleich UpgradeCode")
		}
		ca := find(db["CustomAction"], "Action", "PaketEinrichten")
		typ, _ := strconv.Atoi(ca["Type"])
		if typ&caHideTarget == 0 || typ&caNoImpersonat == 0 || typ&caInScript == 0 || typ&caContinue != 0 {
			t.Errorf("PaketEinrichten: Typ %d (verdeckt, als SYSTEM, verzögert, Fehler bricht ab)", typ)
		}
		if !strings.Contains(ca["Target"], "[TOKEN]") || ca["Source"] != "AgentExe" {
			t.Errorf("PaketEinrichten: %v", ca)
		}
		rm := find(db["CustomAction"], "Action", "PaketEntfernen")
		typ, _ = strconv.Atoi(rm["Type"])
		if typ&caContinue == 0 {
			t.Error("PaketEntfernen darf das Entfernen nicht blockieren")
		}
		seq := db["InstallExecuteSequence"]
		at := func(a string) int { n, _ := strconv.Atoi(find(seq, "Action", a)["Sequence"]); return n }
		if !(at("InstallFiles") < at("PaketEinrichten") && at("PaketEinrichten") < at("InstallFinalize")) {
			t.Error("PaketEinrichten läuft nicht nach dem Kopieren")
		}
		if !(at("StopServices") < at("PaketEntfernen") && at("PaketEntfernen") < at("RemoveFiles")) {
			t.Error("PaketEntfernen läuft nicht vor dem Löschen")
		}
		if !strings.Contains(find(seq, "Action", "PaketEntfernen")["Condition"], "NOT UPGRADINGPRODUCTCODE") {
			t.Error("Ein Update entfernt den Dienst")
		}
		if find(db["LaunchCondition"], "Condition", "NOT OW_NEUER") == nil {
			t.Error("Rückstufung nicht verhindert")
		}
		// Windows 10 / Server 2016 (0.99.2): über die Registry, nicht VersionNT (603 auch auf Windows 10)
		if find(db["LaunchCondition"], "Condition", "Installed OR OW_WIN10") == nil {
			t.Error("Mindestversion Windows 10 fehlt")
		}
		reg := find(db["RegLocator"], "Signature_", "OwWinZehn")
		if reg == nil || reg["Root"] != "2" || reg["Name"] != "CurrentMajorVersionNumber" || reg["Key"] != `SOFTWARE\Microsoft\Windows NT\CurrentVersion` {
			t.Errorf("RegLocator: %v", reg)
		}
		if find(db["AppSearch"], "Property", "OW_WIN10")["Signature_"] != "OwWinZehn" {
			t.Error("AppSearch fehlt")
		}
		// AppSearch liest immer die Tabelle Signature; ohne sie Fehler 2228/1603 (1.0.0).
		if sig, ok := db["Signature"]; !ok || len(sig) != 0 {
			t.Errorf("Tabelle Signature fehlt oder ist nicht leer: %v", sig)
		}
		for _, sq := range []string{"InstallExecuteSequence", "InstallUISequence"} {
			n := func(a string) int { v, _ := strconv.Atoi(find(db[sq], "Action", a)["Sequence"]); return v }
			if !(n("AppSearch") > 0 && n("AppSearch") < n("LaunchConditions")) {
				t.Errorf("%s: AppSearch nicht vor LaunchConditions", sq)
			}
		}
		file := find(db["File"], "File", "AgentExe")
		if file["FileSize"] != strconv.Itoa(size) {
			t.Errorf("FileSize %s", file["FileSize"])
		}
		cab := streams[string(utf16.Decode(msiStreamName("agent.cab", false)))]
		if got := cabExtract(t, cab); !bytes.Equal(got, exe) {
			t.Fatal("Cabinet enthält nicht den Agent")
		}
		if _, ok := streams[summaryStream]; !ok {
			t.Fatal("Zusammenfassung fehlt")
		}
	}
}

func TestMSIProduktcodeJeVersion(t *testing.T) {
	a, _ := msiPackage([]byte("x"), "amd64", "0.34.0", testTime)
	b, _ := msiPackage([]byte("x"), "amd64", "0.35.0", testTime)
	c, _ := msiPackage([]byte("x"), "arm64", "0.34.0", testTime)
	prop := func(m []byte, p string) string {
		return find(msiDB(t, readCFB(t, m))["Property"], "Property", p)["Value"]
	}
	if prop(a, "ProductCode") == prop(b, "ProductCode") || prop(a, "UpgradeCode") != prop(b, "UpgradeCode") {
		t.Error("neue Version braucht neuen ProductCode bei gleichem UpgradeCode (Major Upgrade)")
	}
	if prop(a, "UpgradeCode") == prop(c, "UpgradeCode") {
		t.Error("amd64 und arm64 teilen den UpgradeCode")
	}
	for _, bad := range []string{"0.34.0-dev", "1.2", "256.0.0", "0.0.65536"} {
		if _, err := msiPackage([]byte("x"), "amd64", bad, testTime); err == nil {
			t.Errorf("Version %q angenommen", bad)
		}
	}
	if _, err := msiPackage([]byte("x"), "386", "0.34.0", testTime); err == nil {
		t.Error("386 angenommen")
	}
}

func TestMSIStromnamen(t *testing.T) {
	// So heißt der Strom in jedem MSI („䡀㽿䅤䈯䠶“).
	got := msiStreamName("_Tables", true)
	want := []uint16{0x4840, 0x3f7f, 0x4164, 0x422f, 0x4836}
	if len(got) != len(want) {
		t.Fatalf("%x", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("_Tables: %x, erwartet %x", got, want)
		}
	}
	if n := msiStreamName("a-b", false); n[1] != '-' {
		t.Errorf("Zeichen außerhalb des Alphabets bleiben: %x", n)
	}
}

func TestMSINurASCII(t *testing.T) {
	_, err := encodeDB([]msiTable{{name: "Property", cols: []msiCol{{"Property", cK(72)}, {"Value", cL(0)}},
		rows: [][]any{{"X", "Grüße"}}}})
	if err == nil {
		t.Fatal("Nicht-ASCII angenommen")
	}
	_, err = encodeDB([]msiTable{{name: "Property", cols: []msiCol{{"Property", cK(72)}, {"Value", cL(0)}},
		rows: [][]any{{"X", "a"}, {"X", "b"}}}})
	if err == nil {
		t.Fatal("doppelter Schlüssel angenommen")
	}
}

// cabExtract liest ein unkomprimiertes Cabinet und prüft die Prüfsummen.
func cabExtract(t *testing.T, b []byte) []byte {
	t.Helper()
	le := binary.LittleEndian
	if string(b[:4]) != "MSCF" || int(le.Uint32(b[8:])) != len(b) {
		t.Fatal("kein Cabinet")
	}
	off := int(le.Uint32(b[36:]))
	n := int(le.Uint16(b[40:]))
	if le.Uint16(b[42:]) != 0 {
		t.Fatal("komprimiert")
	}
	var out []byte
	for range n {
		csum := le.Uint32(b[off:])
		cb := int(le.Uint16(b[off+4:]))
		data := b[off+8 : off+8+cb]
		if cabChecksum(b[off+4:off+8], cabChecksum(data, 0)) != csum {
			t.Fatal("Prüfsumme eines Blocks falsch")
		}
		out = append(out, data...)
		off += 8 + cb
	}
	return out
}

func TestCabPruefsumme(t *testing.T) {
	// von Hand: erstes Wort (little endian) 0x04030201, Rest 5,6,7 als 0x050607
	if got := cabChecksum([]byte{1, 2, 3, 4, 5, 6, 7}, 0); got != 0x04030201^0x00050607 {
		t.Fatalf("%08x", got)
	}
}

func TestRPM(t *testing.T) {
	dir := t.TempDir()
	bin := bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 5000)
	if err := writeFile(dir+"/openwacht-agent_linux_amd64", bin); err != nil {
		t.Fatal(err)
	}
	names, err := buildAgentPackages(dir, "openwacht-agent_linux_amd64", "amd64", "0.34.0", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if names[0] != "openwacht-agent_0.34.0_amd64.deb" || names[1] != "openwacht-agent-0.34.0-1.x86_64.rpm" {
		t.Fatalf("Namen: %v", names)
	}
	rpm := readFile(t, dir+"/"+names[1])
	if !bytes.Equal(rpm[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		t.Fatal("Lead fehlt")
	}
	be := binary.BigEndian
	hdrLen := func(off int) int {
		if !bytes.Equal(rpm[off:off+3], []byte{0x8e, 0xad, 0xe8}) {
			t.Fatalf("kein Header bei %d", off)
		}
		return 16 + 16*int(be.Uint32(rpm[off+8:])) + int(be.Uint32(rpm[off+12:]))
	}
	sigOff := 96
	sigLen := hdrLen(sigOff)
	hOff := sigOff + sigLen
	for hOff%8 != 0 {
		hOff++
	}
	hLen := hdrLen(hOff)
	header := rpm[hOff : hOff+hLen]
	payload := rpm[hOff+hLen:]
	sig := rpmTags(rpm[sigOff : sigOff+sigLen])
	s256 := sha256.Sum256(header)
	s1 := sha1.Sum(header)
	if string(sig[sigSHA256]) != hex.EncodeToString(s256[:])+"\x00" || string(sig[sigSHA1]) != hex.EncodeToString(s1[:])+"\x00" {
		t.Error("Prüfsumme des Headers falsch")
	}
	m := md5.Sum(append(append([]byte{}, header...), payload...))
	if !bytes.Equal(sig[sigMD5], m[:]) {
		t.Error("MD5 über Header und Nutzlast falsch")
	}
	h := rpmTags(header)
	ps := sha256.Sum256(payload)
	if string(h[tagPayloadDigest]) != hex.EncodeToString(ps[:])+"\x00" {
		t.Error("Prüfsumme der Nutzlast falsch")
	}
	if !strings.Contains(string(h[tagPostIn]), "paket-einrichten -aus-umgebung") || string(h[tagArch]) != "x86_64\x00" {
		t.Error("Skript oder Architektur fehlt")
	}
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	cpio, _ := io.ReadAll(zr)
	if !bytes.Contains(cpio, []byte("./usr/bin/openwacht-agent\x00")) || !bytes.Contains(cpio, bin) ||
		!bytes.Contains(cpio, []byte("./usr/lib/systemd/system/openwacht-agent.service\x00")) {
		t.Error("Nutzlast unvollständig")
	}
	if int(be.Uint32(sig[sigPayloadSize])) != len(cpio) {
		t.Error("Größe der Nutzlast falsch")
	}

	// .deb: Inhalt und Skripte
	deb := readFile(t, dir+"/"+names[0])
	files := debMembers(t, deb)
	if !bytes.Equal(files["./usr/bin/openwacht-agent"], bin) || !strings.Contains(string(files["./postinst"]), "paket-einrichten -aus-umgebung") {
		t.Error(".deb unvollständig")
	}
	if !strings.Contains(string(files["./control"]), "Package: openwacht-agent\n") {
		t.Error("control falsch")
	}

	// reproduzierbar
	dir2 := t.TempDir()
	writeFile(dir2+"/openwacht-agent_linux_amd64", bin)
	buildAgentPackages(dir2, "openwacht-agent_linux_amd64", "amd64", "0.34.0", testTime)
	for _, n := range names {
		if !bytes.Equal(readFile(t, dir+"/"+n), readFile(t, dir2+"/"+n)) {
			t.Errorf("%s nicht reproduzierbar", n)
		}
	}
	if _, err := writeRPM(dir, "386", testTime, pkgSpec{name: "x", version: "1.0.0"}, rpmScripts{}); err == nil {
		t.Error("386 als RPM angenommen")
	}
}

// rpmTags: Rohdaten je Tag eines Headers (Region-Trailer geprüft).
func rpmTags(h []byte) map[uint32][]byte {
	be := binary.BigEndian
	n := int(be.Uint32(h[8:]))
	store := h[16+16*n:]
	type ent struct{ tag, typ, off, count uint32 }
	var es []ent
	for i := range n {
		e := h[16+16*i:]
		es = append(es, ent{be.Uint32(e), be.Uint32(e[4:]), be.Uint32(e[8:]), be.Uint32(e[12:])})
	}
	out := map[uint32][]byte{}
	for i, e := range es {
		end := len(store)
		for _, o := range es {
			if o.off > e.off && int(o.off) < end {
				end = int(o.off)
			}
		}
		if i == 0 {
			tr := store[e.off : e.off+16]
			if int32(be.Uint32(tr[8:])) != int32(-16*n) {
				panic("Region-Trailer falsch")
			}
		}
		out[e.tag] = store[e.off:end]
		if e.typ == rpmString || e.typ == rpmStringArray && e.count == 1 {
			if k := bytes.IndexByte(out[e.tag], 0); k >= 0 {
				out[e.tag] = out[e.tag][:k+1]
			}
		}
		if e.typ == rpmBin {
			out[e.tag] = store[e.off : e.off+e.count]
		}
		if e.typ == rpmInt32 {
			out[e.tag] = store[e.off : e.off+4*e.count]
		}
	}
	return out
}

func debMembers(t *testing.T, deb []byte) map[string][]byte {
	t.Helper()
	if string(deb[:8]) != "!<arch>\n" {
		t.Fatal("kein ar-Archiv")
	}
	out := map[string][]byte{}
	for off := 8; off < len(deb); {
		name := strings.TrimSpace(string(deb[off : off+16]))
		size, _ := strconv.Atoi(strings.TrimSpace(string(deb[off+48 : off+58])))
		data := deb[off+60 : off+60+size]
		off += 60 + size + size%2
		if strings.HasSuffix(name, ".tar.gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			tr := tar.NewReader(zr)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(tr)
				out[h.Name] = b
			}
		}
	}
	return out
}

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o644) }

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
