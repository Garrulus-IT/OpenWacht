// SPDX-License-Identifier: AGPL-3.0-only

package sbom

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const fontListe = `{"schriften":[{"name":"D-DIN","version":"1.00","lizenz":"OFL-1.1","quelle":"https://example.org/d-din","urheber":"Datto Inc.","dateien":["B.woff2","A.woff2"]}]}`

func fontFS(liste string) fstest.MapFS {
	return fstest.MapFS{
		"schriften.json": {Data: []byte(liste)},
		"A.woff2":        {Data: []byte("a")},
		"B.woff2":        {Data: []byte("b")},
		"LIESMICH.md":    {Data: []byte("x")},
	}
}

func TestLoadFonts(t *testing.T) {
	fonts, err := LoadFonts(fontFS(fontListe))
	if err != nil {
		t.Fatal(err)
	}
	if len(fonts) != 2 || fonts[0].File != "A.woff2" || fonts[1].File != "B.woff2" {
		t.Fatalf("Reihenfolge oder Anzahl falsch: %+v", fonts)
	}
	// SHA-256 von "a"
	if fonts[0].SHA256 != "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" {
		t.Fatalf("Prüfsumme falsch: %s", fonts[0].SHA256)
	}
	if fonts[0].License != "OFL-1.1" || fonts[0].Name != "D-DIN" || fonts[0].Author != "Datto Inc." {
		t.Fatalf("Felder falsch: %+v", fonts[0])
	}
}

func TestLoadFontsFehler(t *testing.T) {
	ersetze := func(alt, neu string) string { return strings.Replace(fontListe, alt, neu, 1) }
	faelle := map[string]fstest.MapFS{
		"GPL":              fontFS(ersetze(`"OFL-1.1"`, `"GPL-3.0-only"`)),
		"Apache":           fontFS(ersetze(`"OFL-1.1"`, `"Apache-2.0"`)),
		"http":             fontFS(ersetze(`https://`, `http://`)),
		"Pfad":             fontFS(ersetze(`"A.woff2"`, `"../A.woff2"`)),
		"doppelt":          fontFS(ersetze(`"A.woff2"`, `"B.woff2"`)),
		"fehlt im Ordner":  fontFS(ersetze(`"A.woff2"`, `"C.woff2"`)),
		"unbekanntes Feld": fontFS(ersetze(`"name"`, `"extra":1,"name"`)),
		"keine Dateien":    fontFS(ersetze(`["B.woff2","A.woff2"]`, `[]`)),
		"Version":          fontFS(ersetze(`"1.00"`, `"<b>"`)),
	}
	// Datei im Ordner, aber nicht in der Liste
	extra := fontFS(fontListe)
	extra["Neu.woff2"] = &fstest.MapFile{Data: []byte("n")}
	faelle["nicht eingetragen"] = extra
	ohneListe := fontFS(fontListe)
	delete(ohneListe, "schriften.json")
	faelle["ohne Liste"] = ohneListe
	for name, fsys := range faelle {
		if _, err := LoadFonts(fsys); err == nil {
			t.Errorf("%s: kein Fehler", name)
		}
	}
}

func TestGenerateMitSchriften(t *testing.T) {
	fonts, err := LoadFonts(fontFS(fontListe))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(Input{
		Version: "1.0.0", Time: time.Unix(0, 0),
		GoMod: []byte("module x\n\ngo 1.25\n"), Fonts: fonts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Components []struct {
			Type     string `json:"type"`
			BOMRef   string `json:"bom-ref"`
			Scope    string `json:"scope"`
			Hashes   []struct{ Alg, Content string }
			Licenses []struct{ Expression string }
		}
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	gefunden := 0
	for _, c := range b.Components {
		if strings.HasPrefix(c.BOMRef, "openwacht-schrift:") {
			gefunden++
			if c.Type != "file" || c.Scope != "required" || len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || c.Licenses[0].Expression != "OFL-1.1" {
				t.Errorf("Komponente falsch: %+v", c)
			}
		}
	}
	if gefunden != 2 {
		t.Fatalf("%d Schrift-Komponenten statt 2", gefunden)
	}
	// Eine manipulierte Liste (falsche Lizenz) wird auch in Generate abgelehnt.
	fonts[0].License = "GPL-3.0-only"
	if _, err := Generate(Input{Version: "1.0.0", GoMod: []byte("module x\n\ngo 1.25\n"), Fonts: fonts}); err == nil {
		t.Fatal("falsche Lizenz nicht abgelehnt")
	}
}

// Die echte Liste im Repository muss zu den Dateien passen.
func TestEchteSchriftliste(t *testing.T) {
	for _, dir := range []string{"../../web/src/schriften", "../../internal/desktop/schriften"} {
		fonts, err := LoadFonts(os.DirFS(dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(fonts) == 0 {
			t.Fatal("keine Schriften in " + dir)
		}
	}
}
