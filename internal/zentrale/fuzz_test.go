// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Fuzz-Ziel für den CSV-Import von Geräten (Befund M3). Die Datei kommt
// von Mandanten-Admins; jede Zeile muss im Rahmen der Grenzen bleiben.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParseImportCSV(f *testing.F) {
	f.Add("name;adresse;gruppe;profil;vorlage\nsrv-file01;10.10.0.10;Server/Datei;SNMP Standard;Ping\n")
	f.Add("\ufeffname,adresse\n\"sw-core01\",10.10.0.2\n\n,\n")
	f.Add("name\n\"offen")
	f.Fuzz(func(t *testing.T, text string) {
		rows, err := parseImportCSV(text)
		if err != nil {
			return
		}
		if len(rows) == 0 || len(rows) > maxImportRows {
			t.Fatalf("%d Zeilen angenommen", len(rows))
		}
		last := 1
		for _, r := range rows {
			if r.line <= last {
				t.Fatalf("Zeilennummer %d nach %d", r.line, last)
			}
			last = r.line
			for _, v := range []string{r.name, r.addr, r.group, r.profile, r.template} {
				if !utf8.ValidString(v) || v != strings.TrimSpace(v) {
					t.Fatalf("Feld ungeprüft: %q", v)
				}
			}
		}
	})
}
