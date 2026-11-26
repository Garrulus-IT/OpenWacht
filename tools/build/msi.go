// SPDX-License-Identifier: AGPL-3.0-only

package main

// Windows-Installer-Paket (MSI) für den Agent (Etappe 34), nur mit der
// Standardbibliothek: keine neue Abhängigkeit (WiX hat die Lizenz MS-RL,
// msitools LGPL; beide stehen nicht auf der Liste in CONTRIBUTING.md).
//
// Ein MSI ist eine relationale Datenbank in einer Compound File (cfb.go):
// Zeichenkettentabelle (_StringPool, _StringData), Tabellenkatalog (_Tables,
// _Columns), je Tabelle ein Strom (spaltenweise), dazu die
// Zusammenfassung (\x05SummaryInformation) und das eingebettete Cabinet mit
// dem Agent (unkomprimiert, cab.go).
//
// Was das Paket tut:
//   - kopiert openwacht-agent.exe nach C:\Program Files\OpenWacht
//   - ruft danach als SYSTEM „openwacht-agent paket-einrichten“ auf, mit den
//     Eigenschaften ZENTRALE, TOKEN und HOSTNAME (für die stille
//     Installation per GPO/Intune: msiexec /i … /qn ZENTRALE=… TOKEN=…).
//     TOKEN ist eine versteckte Eigenschaft (MsiHiddenProperties) und die
//     Befehlszeile steht nicht im Protokoll (msidbCustomActionTypeHideTarget).
//   - hält den Dienst vor dem Austausch an (ServiceControl) und entfernt ihn
//     beim Deinstallieren („paket-entfernen“), nicht bei einem Update.
//   - ersetzt ältere Versionen (Major Upgrade) und lehnt eine Rückstufung ab.
// Signiert wird es (Authenticode) erst danach offline beim Herausgeber
// (Handbuch Kapitel 15), dann neu gebaut mit dem signierten Agent.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Spaltentypen (_Columns.Type, MSI SDK msiquery: icd…).
const (
	colPersist = 0x0100
	colLocal   = 0x0200
	colShort   = 0x0400
	colString  = 0x0C00
	colBinary  = 0x0800 // mit colPersist: Strom „Tabelle.Schlüssel“
	colNull    = 0x1000
	colKey     = 0x2000
)

func cS(n int) uint16   { return colString | colPersist | uint16(n) } // sNN
func cSN(n int) uint16  { return cS(n) | colNull }                    // SNN
func cK(n int) uint16   { return cS(n) | colKey }                     // sNN, Schlüssel
func cL(n int) uint16   { return cS(n) | colLocal }                   // lNN
func cLN(n int) uint16  { return cS(n) | colLocal | colNull }         // LNN
func cI2() uint16       { return colShort | colPersist | 2 }          // i2
func cI2N() uint16      { return cI2() | colNull }                    // I2
func cI4() uint16       { return colPersist | 4 }                     // i4
func cI4N() uint16      { return cI4() | colNull }                    // I4
func cI2K() uint16      { return cI2() | colKey }                     // i2, Schlüssel
func cSNK(n int) uint16 { return cSN(n) | colKey }                    // SNN, Schlüssel
func cI4K() uint16      { return cI4() | colKey }                     // i4, Schlüssel

func cV() uint16                { return colBinary | colPersist } // v0, Datenstrom (Binary.Data)
func colIsString(t uint16) bool { return t&colString == colString }
func colIsBinary(t uint16) bool { return t&^colNull == colBinary|colPersist }
func colIsKey(t uint16) bool    { return t&colKey != 0 }
func colWidth(t uint16) int {
	switch {
	case colIsString(t), colIsBinary(t):
		return 2
	case t&colShort != 0:
		return 2
	}
	return 4
}

type msiCol struct {
	name string
	typ  uint16
}

// msiStrom: Inhalt einer Spalte vom Typ v0 (eigener Strom „Tabelle.Schlüssel“).
type msiStrom []byte

// msiTable: Werte sind string, int, msiStrom oder nil (NULL).
type msiTable struct {
	name string
	cols []msiCol
	rows [][]any
}

// msiStrings: Zeichenkettentabelle (Kennung ab 1, mit Zähler der Verweise).
type msiStrings struct {
	ids   map[string]int
	list  []string
	count []int
}

// cp1252Hoch: Zeichen 0x80–0x9F der Codepage 1252 (darüber gilt Latin-1).
var cp1252Hoch = []rune("€\x81‚ƒ„…†‡ˆ‰Š‹Œ\x8dŽ\x8f\x90‘’“”•–—˜™š›œ\x9džŸ")

// cp1252 kodiert Text für die Zeichenkettentabelle (Codepage 1252 wie in der
// Zusammenfassung). Steuerzeichen und Zeichen außerhalb der Codepage sind ein Fehler.
func cp1252(s string) (string, error) {
	var b []byte
	for _, r := range s {
		switch {
		case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xff:
			b = append(b, byte(r))
		default:
			i := slices.Index(cp1252Hoch, r)
			if i < 0 || r < 0x100 {
				return "", fmt.Errorf("MSI: Zeichen %q gibt es in Codepage 1252 nicht (in %q)", r, s)
			}
			b = append(b, byte(0x80+i))
		}
	}
	return string(b), nil
}

func (p *msiStrings) ref(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	s, err := cp1252(s)
	if err != nil {
		return 0, err
	}
	id, ok := p.ids[s]
	if !ok {
		p.list = append(p.list, s)
		p.count = append(p.count, 0)
		id = len(p.list)
		p.ids[s] = id
	}
	p.count[id-1]++
	return id, nil
}

// msiStreamName kodiert den Namen eines Stroms wie Windows Installer:
// Zeichen aus [0-9A-Za-z._] werden zu zweit in ein UTF-16-Zeichen gepackt;
// Tabellen bekommen das Zeichen 0x4840 davor.
func msiStreamName(name string, table bool) []uint16 {
	m := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'A' && c <= 'Z':
			return int(c-'A') + 10
		case c >= 'a' && c <= 'z':
			return int(c-'a') + 36
		case c == '.':
			return 62
		case c == '_':
			return 63
		}
		return -1
	}
	var out []uint16
	if table {
		out = append(out, 0x4840)
	}
	for i := 0; i < len(name); i++ {
		a := m(name[i])
		if a < 0 {
			out = append(out, uint16(name[i]))
			continue
		}
		if i+1 < len(name) {
			if b := m(name[i+1]); b >= 0 {
				out = append(out, uint16(0x3800+a+(b<<6)))
				i++
				continue
			}
		}
		out = append(out, uint16(0x4800+a))
	}
	return out
}

// msiGUID: feste GUID aus einem Namen (wie UUID Version 5, mit SHA-256),
// damit derselbe Stand dieselben Kennungen bekommt.
func msiGUID(name string) string {
	h := sha256.Sum256([]byte("openwacht msi v1\n" + name))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("{%x-%x-%x-%x-%x}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

// encodeDB baut die Ströme der Datenbank aus den Tabellen.
func encodeDB(tables []msiTable) ([]cfbStream, error) {
	sort.Slice(tables, func(i, j int) bool { return tables[i].name < tables[j].name })
	pool := &msiStrings{ids: map[string]int{}}
	tablesTbl := msiTable{name: "_Tables", cols: []msiCol{{"Name", cK(64)}}}
	columnsTbl := msiTable{name: "_Columns", cols: []msiCol{{"Table", cK(64)}, {"Number", cI2K()}, {"Name", cS(64)}, {"Type", cI2()}}}
	for _, t := range tables {
		tablesTbl.rows = append(tablesTbl.rows, []any{t.name})
		for k, c := range t.cols {
			columnsTbl.rows = append(columnsTbl.rows, []any{t.name, k + 1, c.name, int(c.typ)})
		}
	}
	all := append([]msiTable{tablesTbl, columnsTbl}, tables...)
	var extra []cfbStream
	// Werte in Rohwerte (Kennung der Zeichenkette, verschobene Zahl) umsetzen.
	raw := make([][][]uint32, len(all))
	for ti, t := range all {
		for _, r := range t.rows {
			if len(r) != len(t.cols) {
				return nil, fmt.Errorf("MSI: Tabelle %s: %d Werte für %d Spalten", t.name, len(r), len(t.cols))
			}
			rr := make([]uint32, len(r))
			for ci, v := range r {
				c := t.cols[ci]
				switch x := v.(type) {
				case nil:
					if c.typ&colNull == 0 {
						return nil, fmt.Errorf("MSI: %s.%s darf nicht leer sein", t.name, c.name)
					}
				case string:
					if !colIsString(c.typ) {
						return nil, fmt.Errorf("MSI: %s.%s erwartet eine Zahl", t.name, c.name)
					}
					if x == "" && c.typ&colNull == 0 {
						return nil, fmt.Errorf("MSI: %s.%s darf nicht leer sein", t.name, c.name)
					}
					if n := int(c.typ & 0xff); n > 0 && utf8.RuneCountInString(x) > n {
						return nil, fmt.Errorf("MSI: %s.%s länger als %d Zeichen", t.name, c.name, n)
					}
					id, err := pool.ref(x)
					if err != nil {
						return nil, err
					}
					rr[ci] = uint32(id)
				case msiStrom:
					if !colIsBinary(c.typ) || ci == 0 {
						return nil, fmt.Errorf("MSI: %s.%s ist keine Spalte für Daten", t.name, c.name)
					}
					key, ok := r[0].(string)
					if !ok {
						return nil, fmt.Errorf("MSI: %s: Daten brauchen einen Text als Schlüssel", t.name)
					}
					// Wie Windows Installer: In der Zelle steht 1, die Daten liegen im
					// Strom „Tabelle.Schlüssel“ (Namen ohne Tabellenzeichen kodiert).
					rr[ci] = 1
					extra = append(extra, cfbStream{name: msiStreamName(t.name+"."+key, false), data: x})
				case int:
					switch {
					case colIsString(c.typ):
						return nil, fmt.Errorf("MSI: %s.%s erwartet Text", t.name, c.name)
					case colWidth(c.typ) == 2:
						if x < -32767 || x > 32767 {
							return nil, fmt.Errorf("MSI: %s.%s: %d passt nicht in 16 Bit", t.name, c.name, x)
						}
						rr[ci] = uint32(uint16(x + 0x8000))
					default:
						rr[ci] = uint32(int32(x)) + 0x80000000
					}
				default:
					return nil, fmt.Errorf("MSI: %s.%s: unbekannter Wert %T", t.name, c.name, v)
				}
			}
			raw[ti] = append(raw[ti], rr)
		}
		// Zeilen nach Schlüssel sortieren; doppelte Schlüssel sind ein Fehler.
		var keys []int
		for ci, c := range t.cols {
			if colIsKey(c.typ) {
				keys = append(keys, ci)
			}
		}
		less := func(a, b []uint32) int {
			for _, k := range keys {
				if a[k] != b[k] {
					if a[k] < b[k] {
						return -1
					}
					return 1
				}
			}
			return 0
		}
		rows := raw[ti]
		sort.SliceStable(rows, func(i, j int) bool { return less(rows[i], rows[j]) < 0 })
		for i := 1; i < len(rows); i++ {
			if less(rows[i-1], rows[i]) == 0 {
				return nil, fmt.Errorf("MSI: Tabelle %s: Schlüssel doppelt", t.name)
			}
		}
	}
	if len(pool.list) > 0xffff {
		return nil, errors.New("MSI: zu viele Zeichenketten")
	}

	var streams []cfbStream
	for ti, t := range all {
		var b bytes.Buffer
		for ci, c := range t.cols {
			for _, r := range raw[ti] {
				if colWidth(c.typ) == 2 {
					binary.Write(&b, binary.LittleEndian, uint16(r[ci]))
				} else {
					binary.Write(&b, binary.LittleEndian, r[ci])
				}
			}
		}
		streams = append(streams, cfbStream{name: msiStreamName(t.name, true), data: b.Bytes()})
	}
	var sp, sd bytes.Buffer
	binary.Write(&sp, binary.LittleEndian, uint32(1252))
	for i, s := range pool.list {
		binary.Write(&sp, binary.LittleEndian, uint16(len(s)))
		binary.Write(&sp, binary.LittleEndian, uint16(pool.count[i]))
		sd.WriteString(s)
	}
	streams = append(streams,
		cfbStream{name: msiStreamName("_StringPool", true), data: sp.Bytes()},
		cfbStream{name: msiStreamName("_StringData", true), data: sd.Bytes()})
	return append(streams, extra...), nil
}

// Eigenschaften der Zusammenfassung (MSI SDK „Summary Information Stream“).
const (
	pidCodepage   = 1
	pidTitle      = 2
	pidSubject    = 3
	pidAuthor     = 4
	pidKeywords   = 5
	pidComments   = 6
	pidTemplate   = 7
	pidRevision   = 9
	pidCreated    = 12
	pidSaved      = 13
	pidPageCount  = 14
	pidWordCount  = 15
	pidAppName    = 18
	pidSecurity   = 19
	vtI2          = 2
	vtI4          = 3
	vtLPSTR       = 30
	vtFILETIME    = 64
	summaryStream = "\x05SummaryInformation"
)

type summaryProp struct {
	id  uint32
	val any // int16, int32, string, time.Time
}

// summaryInfo schreibt den Eigenschaftssatz (MS-OLEPS).
func summaryInfo(props []summaryProp) []byte {
	sort.Slice(props, func(i, j int) bool { return props[i].id < props[j].id })
	var body bytes.Buffer
	offsets := make([]uint32, len(props))
	head := 8 + 8*len(props)
	for i, p := range props {
		offsets[i] = uint32(head + body.Len())
		switch v := p.val.(type) {
		case int16:
			binary.Write(&body, binary.LittleEndian, uint32(vtI2))
			binary.Write(&body, binary.LittleEndian, v)
			body.Write([]byte{0, 0})
		case int32:
			binary.Write(&body, binary.LittleEndian, uint32(vtI4))
			binary.Write(&body, binary.LittleEndian, v)
		case string:
			binary.Write(&body, binary.LittleEndian, uint32(vtLPSTR))
			binary.Write(&body, binary.LittleEndian, uint32(len(v)+1))
			body.WriteString(v)
			body.WriteByte(0)
			for body.Len()%4 != 0 {
				body.WriteByte(0)
			}
		case time.Time:
			binary.Write(&body, binary.LittleEndian, uint32(vtFILETIME))
			ft := uint64(v.Unix()+11644473600) * 10000000
			binary.Write(&body, binary.LittleEndian, ft)
		}
	}
	var sec bytes.Buffer
	binary.Write(&sec, binary.LittleEndian, uint32(head+body.Len()))
	binary.Write(&sec, binary.LittleEndian, uint32(len(props)))
	for i, p := range props {
		binary.Write(&sec, binary.LittleEndian, p.id)
		binary.Write(&sec, binary.LittleEndian, offsets[i])
	}
	sec.Write(body.Bytes())

	var out bytes.Buffer
	out.Write([]byte{0xFE, 0xFF, 0, 0})                // Byte-Reihenfolge, Version 0
	out.Write([]byte{0x06, 0x00, 0x02, 0x00})          // „Betriebssystem“ (Win32)
	out.Write(make([]byte, 16))                        // CLSID
	binary.Write(&out, binary.LittleEndian, uint32(1)) // ein Satz
	// FMTID_SummaryInformation {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
	out.Write([]byte{0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9})
	binary.Write(&out, binary.LittleEndian, uint32(48))
	out.Write(sec.Bytes())
	return out.Bytes()
}

// msiCLSID: Kennung einer MSI-Datenbank {000C1084-0000-0000-C000-000000000046}.
var msiCLSID = [16]byte{0x84, 0x10, 0x0C, 0x00, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

// msiArch: Plattform im MSI.
func msiArch(goarch string) (template string, err error) {
	switch goarch {
	case "amd64":
		return "x64;1033", nil
	case "arm64":
		return "Arm64;1033", nil
	}
	return "", fmt.Errorf("Architektur %s gibt es als MSI nicht", goarch)
}

// msiVersion: ProductVersion a.b.c (a, b < 256, c < 65536).
func msiVersion(v string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("MSI braucht die Version a.b.c, nicht %q", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		limit := 255
		if i == 2 {
			limit = 65535
		}
		if err != nil || n < 0 || n > limit {
			return "", fmt.Errorf("MSI braucht die Version a.b.c, nicht %q", v)
		}
	}
	return v, nil
}

// Benutzerdefinierte Aktionen (MSI SDK „Custom Action Types“).
const (
	caExeFromFile  = 18     // Programm aus der File-Tabelle
	caSetProperty  = 51     // Eigenschaft aus formatiertem Text setzen
	caContinue     = 0x40   // Fehler ignorieren
	caInScript     = 0x400  // verzögert (im Installationsskript)
	caRollback     = 0x100  // nur beim Zurückrollen
	caNoImpersonat = 0x800  // als SYSTEM
	caHideTarget   = 0x2000 // Befehlszeile nicht protokollieren
)

// msiTables: Inhalt des Agent-MSI.
func msiTables(goarch, ver string, exeSize int) []msiTable {
	productCode := msiGUID("agent product " + goarch + " " + ver)
	upgradeCode := msiGUID("agent upgrade " + goarch)
	component := msiGUID("agent component exe " + goarch)
	str := func(s string) any { return s }
	// Ein Leerzeichen vor dem schließenden Anführungszeichen: Endet ein Ordner
	// auf \, würde \" sonst das Anführungszeichen maskieren (der Agent kürzt es).
	setup := "paket-einrichten -zentrale \"[ZENTRALE]\" -token \"[TOKEN]\" -hostname \"[HOSTNAME]\"" +
		" -arten \"[OW_ARTEN]\" -ordner \"[ORDNER] \" -indikatoren \"[INDIKATOREN]\" -netze \"[NETZE]\""
	return append(msiUITabellen(), []msiTable{
		{name: "Property", cols: []msiCol{{"Property", cK(72)}, {"Value", cL(0)}}, rows: [][]any{
			{"ProductCode", productCode}, {"ProductName", "OpenWacht-Agent"}, {"ProductVersion", ver},
			{"ProductLanguage", "1033"}, {"Manufacturer", "OpenWacht"}, {"UpgradeCode", upgradeCode},
			{"ALLUSERS", "1"}, {"ARPNOMODIFY", "1"}, {"ARPNOREPAIR", "1"},
			{"ARPURLINFOABOUT", "https://github.com/garrulus-it/openwacht"},
			{"MsiHiddenProperties", "TOKEN"},
			{"SecureCustomProperties", msiOeffentlich() + ";OW_ALTE;OW_NEUER;OW_WIN10"},
			{"DefaultUIFont", "OwText"},
			{"ErrorDialog", "ErrorDlg"},
		}},
		// Mindestens Windows 10 bzw. Server 2016 (0.99.2): VersionNT und WindowsBuild
		// melden dort aus Kompatibilitätsgründen 603/9600 wie Windows 8.1 bzw.
		// Server 2012 R2 (Microsoft KB 3202260). Den Wert CurrentMajorVersionNumber
		// gibt es erst ab Windows 10; fehlt er, bleibt OW_WIN10 leer.
		// RegLocator: Root 2 = HKLM, Typ 2 = Rohwert | 16 = 64-Bit-Ansicht.
		{name: "RegLocator", cols: []msiCol{{"Signature_", cK(72)}, {"Root", cI2()}, {"Key", cS(255)}, {"Name", cSN(255)}, {"Type", cI2N()}}, rows: [][]any{
			{"OwWinZehn", 2, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentMajorVersionNumber", 2 | 16},
		}},
		{name: "AppSearch", cols: []msiCol{{"Property", cK(72)}, {"Signature_", cK(72)}}, rows: [][]any{
			{"OW_WIN10", "OwWinZehn"},
		}},
		// AppSearch fragt immer die Tabelle Signature ab, auch wenn nur ein
		// RegLocator ohne Dateisuche gesucht wird. Fehlt sie, bricht jede
		// Installation mit Fehler 2228 bzw. 1603 ab. Sie bleibt leer.
		{name: "Signature", cols: []msiCol{{"Signature", cK(72)}, {"FileName", cS(255)}, {"MinVersion", cSN(20)},
			{"MaxVersion", cSN(20)}, {"MinSize", cI4N()}, {"MaxSize", cI4N()}, {"MinDate", cI4N()}, {"MaxDate", cI4N()},
			{"Languages", cSN(255)}}},
		{name: "Directory", cols: []msiCol{{"Directory", cK(72)}, {"Directory_Parent", cSN(72)}, {"DefaultDir", cL(255)}}, rows: [][]any{
			{"TARGETDIR", nil, "SourceDir"},
			{"ProgramFiles64Folder", "TARGETDIR", "."},
			{"INSTALLDIR", "ProgramFiles64Folder", "OPENWACH|OpenWacht"},
		}},
		{name: "Component", cols: []msiCol{{"Component", cK(72)}, {"ComponentId", cSN(38)}, {"Directory_", cS(72)},
			{"Attributes", cI2()}, {"Condition", cSN(255)}, {"KeyPath", cSN(72)}}, rows: [][]any{
			{"Agent", component, "INSTALLDIR", 256, nil, "AgentExe"}, // 256: 64-Bit-Komponente
		}},
		{name: "Feature", cols: []msiCol{{"Feature", cK(38)}, {"Feature_Parent", cSN(38)}, {"Title", cLN(64)},
			{"Description", cLN(255)}, {"Display", cI2N()}, {"Level", cI2()}, {"Directory_", cSN(72)}, {"Attributes", cI2()}}, rows: [][]any{
			{"Agent", nil, str("OpenWacht-Agent"), nil, 0, 1, "INSTALLDIR", 0},
		}},
		{name: "FeatureComponents", cols: []msiCol{{"Feature_", cK(38)}, {"Component_", cK(72)}}, rows: [][]any{{"Agent", "Agent"}}},
		{name: "File", cols: []msiCol{{"File", cK(72)}, {"Component_", cS(72)}, {"FileName", cL(255)}, {"FileSize", cI4()},
			{"Version", cSN(72)}, {"Language", cSN(20)}, {"Attributes", cI2N()}, {"Sequence", cI2()}}, rows: [][]any{
			{"AgentExe", "Agent", "OPENWACHT.EXE|openwacht-agent.exe", exeSize, nil, nil, 0, 1},
		}},
		{name: "Media", cols: []msiCol{{"DiskId", cI2K()}, {"LastSequence", cI2()}, {"DiskPrompt", cLN(64)},
			{"Cabinet", cSN(255)}, {"VolumeLabel", cSN(32)}, {"Source", cSN(72)}}, rows: [][]any{
			{1, 1, nil, "#agent.cab", nil, nil},
		}},
		// Dienst vor dem Austausch und beim Entfernen anhalten (2 = beim Installieren, 32 = beim Entfernen;
		// bis 1.0.6 standen hier versehentlich 1|16 = starten).
		{name: "ServiceControl", cols: []msiCol{{"ServiceControl", cK(72)}, {"Name", cL(255)}, {"Event", cI2()},
			{"Arguments", cLN(255)}, {"Wait", cI2N()}, {"Component_", cS(72)}}, rows: [][]any{
			{"AgentStop", "openwacht-agent", 2 | 32, nil, 1, "Agent"},
		}},
		// Altes Binary eines Selbst-Updates beim Entfernen mitnehmen (2 = beim Entfernen).
		// Die Widerrufsliste (openwacht-agent.exe.widerrufen) bleibt bewusst liegen.
		{name: "RemoveFile", cols: []msiCol{{"FileKey", cK(72)}, {"Component_", cS(72)}, {"FileName", cLN(255)},
			{"DirProperty", cS(72)}, {"InstallMode", cI2()}}, rows: [][]any{
			{"AgentAlt", "Agent", "OPENWACHT.ALT|openwacht-agent.exe.alt", "INSTALLDIR", 2},
		}},
		{name: "Upgrade", cols: []msiCol{{"UpgradeCode", cK(38)}, {"VersionMin", cSNK(20)}, {"VersionMax", cSNK(20)},
			{"Language", cSNK(255)}, {"Attributes", cI4K()}, {"Remove", cSN(255)}, {"ActionProperty", cS(72)}}, rows: [][]any{
			{upgradeCode, "0.0.0", ver, nil, 256 | 1, nil, "OW_ALTE"}, // ältere: entfernen
			{upgradeCode, ver, nil, nil, 2, nil, "OW_NEUER"},          // neuere: nur erkennen
		}},
		{name: "LaunchCondition", cols: []msiCol{{"Condition", cK(255)}, {"Description", cL(255)}}, rows: [][]any{
			{"NOT OW_NEUER", "Eine neuere Version des OpenWacht-Agents ist bereits installiert."},
			{"VersionNT64", "Der OpenWacht-Agent braucht ein 64-Bit-Windows."},
			{"Installed OR OW_WIN10", "Der OpenWacht-Agent braucht Windows 10 bzw. Windows Server 2016 oder neuer. Aeltere Windows-Versionen (z. B. Server 2012 R2) bitte ohne Agent von aussen ueberwachen (Ping, SNMP)."},
		}},
		{name: "CustomAction", cols: []msiCol{{"Action", cK(72)}, {"Type", cI2()}, {"Source", cSN(72)}, {"Target", cSN(255)}}, rows: [][]any{
			{"ArtenSetzen", caSetProperty, "OW_ARTEN", msiArtenZiel()},
			{"PaketEinrichten", caExeFromFile | caInScript | caNoImpersonat | caHideTarget, "AgentExe", setup},
			// Rückweg: scheitert die Installation nach PaketEinrichten, kommt der Dienst wieder weg.
			{"PaketZurueck", caExeFromFile | caInScript | caRollback | caNoImpersonat | caContinue, "AgentExe", "paket-entfernen"},
			{"PaketEntfernen", caExeFromFile | caInScript | caNoImpersonat | caContinue, "AgentExe", "paket-entfernen"},
		}},
		{name: "InstallExecuteSequence", cols: []msiCol{{"Action", cK(72)}, {"Condition", cSN(255)}, {"Sequence", cI2N()}}, rows: [][]any{
			{"FindRelatedProducts", nil, 25}, {"AppSearch", nil, 50}, {"LaunchConditions", nil, 100}, {"ValidateProductID", nil, 700},
			{"CostInitialize", nil, 800}, {"FileCost", nil, 900}, {"CostFinalize", nil, 1000},
			{"MigrateFeatureStates", nil, 1200}, {"InstallValidate", nil, 1400}, {"ArtenSetzen", nil, 1450},
			{"InstallInitialize", nil, 1500},
			{"RemoveExistingProducts", nil, 1501}, {"ProcessComponents", nil, 1600}, {"UnpublishFeatures", nil, 1800},
			{"StopServices", "VersionNT", 1900},
			{"PaketEntfernen", "REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE", 1910},
			{"RemoveFiles", nil, 3500}, {"RemoveFolders", nil, 3600}, {"CreateFolders", nil, 3700},
			{"InstallFiles", nil, 4000}, {"RegisterUser", nil, 6000}, {"RegisterProduct", nil, 6100},
			{"PublishFeatures", nil, 6300}, {"PublishProduct", nil, 6400},
			{"PaketZurueck", "NOT Installed AND NOT OW_ALTE AND NOT REMOVE~=\"ALL\"", 6490},
			{"PaketEinrichten", "NOT REMOVE~=\"ALL\"", 6500},
			{"InstallFinalize", nil, 6600},
		}},
		{name: "InstallUISequence", cols: []msiCol{{"Action", cK(72)}, {"Condition", cSN(255)}, {"Sequence", cI2N()}}, rows: [][]any{
			{"FindRelatedProducts", nil, 25}, {"AppSearch", nil, 50}, {"LaunchConditions", nil, 100}, {"ValidateProductID", nil, 700},
			{"CostInitialize", nil, 800}, {"FileCost", nil, 900}, {"CostFinalize", nil, 1000},
			{"MigrateFeatureStates", nil, 1200},
			{"WillkommenDlg", "NOT Installed", 1230}, {"WartungDlg", "Installed AND NOT Preselected", 1250},
			{"ProgressDlg", nil, 1280}, {"ExecuteAction", nil, 1300},
			{"ExitDlg", nil, -1}, {"UserExitDlg", nil, -2}, {"FatalErrorDlg", nil, -3},
		}},
	}...)
}

// buildMSI baut openwacht-agent_<version>_<arch>.msi aus dem Windows-Binary.
func buildMSI(out, binName, goarch, ver string, mtime time.Time) (string, error) {
	exe, err := os.ReadFile(filepath.Join(out, binName))
	if err != nil {
		return "", err
	}
	data, err := msiPackage(exe, goarch, ver, mtime)
	if err != nil {
		return "", err
	}
	name := msiFileName(ver, goarch)
	fmt.Printf("baue %-40s (Windows Installer)\n", name)
	return name, os.WriteFile(filepath.Join(out, name), data, 0o644)
}

func msiFileName(ver, goarch string) string {
	return fmt.Sprintf("openwacht-agent_%s_%s.msi", ver, goarch)
}

// msiPackage: das MSI als Bytes (getrennt von buildMSI, damit Tests es lesen können).
func msiPackage(exe []byte, goarch, ver string, mtime time.Time) ([]byte, error) {
	template, err := msiArch(goarch)
	if err != nil {
		return nil, err
	}
	if _, err := msiVersion(ver); err != nil {
		return nil, err
	}
	if len(exe) > 1<<30 {
		return nil, errors.New("MSI: Agent zu groß")
	}
	streams, err := encodeDB(msiTables(goarch, ver, len(exe)))
	if err != nil {
		return nil, err
	}
	cab, err := cabinet("AgentExe", exe, mtime)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(exe)
	streams = append(streams,
		cfbStream{name: msiStreamName("agent.cab", false), data: cab},
		cfbStream{name: cfbName(summaryStream), data: summaryInfo([]summaryProp{
			{pidCodepage, int16(1252)},
			{pidTitle, "Installation Database"},
			{pidSubject, "OpenWacht-Agent " + ver},
			{pidAuthor, "OpenWacht"},
			{pidKeywords, "Installer, OpenWacht, Agent"},
			{pidComments, "Sendet Messwerte an die OpenWacht-Zentrale."},
			{pidTemplate, template},
			// Paketkennung: je Inhalt eindeutig (Version, Plattform, Agent).
			{pidRevision, msiGUID(fmt.Sprintf("agent package %s %s %x", goarch, ver, sum))},
			{pidCreated, mtime},
			{pidSaved, mtime},
			{pidPageCount, int32(500)}, // Windows Installer 5.0 (x64/Arm64)
			{pidWordCount, int32(2)},   // lange Namen, komprimierte Quelle (Cabinet)
			{pidAppName, "OpenWacht tools/build"},
			{pidSecurity, int32(2)}, // schreibgeschützt empfohlen
		})})
	return writeCFB(streams, msiCLSID)
}
