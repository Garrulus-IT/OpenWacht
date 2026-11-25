// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import "testing"

// Zeilen, die Excel als ein Feld in Anführungszeichen gespeichert hat (1.0.3).
func TestParseImportCSVExcelZeilen(t *testing.T) {
	excel := "\ufeff\"name;adresse;gruppe;profil;vorlage\"\r\n\"srv-a;10.20.0.1;Server;;\"\r\n\"srv-b;10.20.0.2;Server;\"\"Profil A\"\";std-ping\"\r\n"
	rows, err := parseImportCSV(excel)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].name != "srv-a" || rows[0].addr != "10.20.0.1" || rows[0].group != "Server" ||
		rows[1].profile != "Profil A" || rows[1].template != "std-ping" {
		t.Errorf("Zeilen: %+v", rows)
	}
	// Mit Komma getrennt geht es genauso.
	if rows, err := parseImportCSV("\"name,adresse\"\n\"srv-c,10.20.0.3\"\n"); err != nil || len(rows) != 1 || rows[0].addr != "10.20.0.3" {
		t.Errorf("Komma: %+v %v", rows, err)
	}
	for name, text := range map[string]string{
		// normale Dateien bleiben unverändert
		"nur Name in Anführungszeichen": "\"name\"\n\"srv;d\"\n",
		"gemischt":                      "\"name;adresse\"\nsrv-e;10.20.0.5\n",
	} {
		rows, err := parseImportCSV(text)
		switch name {
		case "nur Name in Anführungszeichen":
			if err != nil || len(rows) != 1 || rows[0].name != "srv;d" {
				t.Errorf("%s: %+v %v", name, rows, err)
			}
		case "gemischt":
			// nur die Kopfzeile in Anführungszeichen: wird genauso gelesen
			if err != nil || len(rows) != 1 || rows[0].addr != "10.20.0.5" {
				t.Errorf("%s: %+v %v", name, rows, err)
			}
		}
	}
}
