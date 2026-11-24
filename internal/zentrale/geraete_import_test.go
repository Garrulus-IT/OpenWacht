// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func importCSV(t *testing.T, user, tenant, csv string, preview bool) response {
	t.Helper()
	return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/geraete/import", map[string]any{"csv": csv, "nur_pruefen": preview})
}

func deviceCount(t *testing.T, tenant, prefix string) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.devices WHERE tenant_id = $1 AND name LIKE $2 || '%'`,
		ids[tenant], prefix).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func rowErrors(r response) map[float64]string {
	out := map[float64]string{}
	rows, _ := r.body["zeilen"].([]any)
	for _, x := range rows {
		e := x.(map[string]any)
		if e["ok"] != true {
			out[e["zeile"].(float64)], _ = e["fehler"].(string)
		}
	}
	return out
}

func TestGeraeteImport(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	// Gruppen der Fertigung: Wachen/Nord
	r := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/gruppen", map[string]any{"name": "GI Wachen"})
	expectStatus(t, "Gruppe", r, 201)
	top := r.body["id"].(string)
	r = as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/gruppen", map[string]any{"name": "Nord", "eltern_id": top})
	expectStatus(t, "Untergruppe", r, 201)
	sub := r.body["id"].(string)
	r = newProfile(t, "v_fw", "Fertigung", "GI Switches", nil)
	expectStatus(t, "Profil", r, 201)
	prof := r.body["id"].(string)
	r = newProfile(t, "v_it", "IT", "GI IT-Profil", nil)
	expectStatus(t, "IT-Profil", r, 201)
	expectStatus(t, "vorhandenes Gerät", newDevice(t, "v_fw", "Fertigung", "GI Alt", ""), 201)

	good := "\ufeffname;adresse;gruppe;profil;vorlage\n" +
		"GI Switch 1;sw1.lan;GI Wachen/Nord;GI Switches;std-ping\n" +
		"GI Switch 2;sw2.lan;gi wachen;;Synology Temperatur\n" + // SNMP-Vorlage ohne Profil: Fehler
		"\n" +
		"GI Drucker;;;;\n"
	r = importCSV(t, "v_fw", "Fertigung", good, true)
	expectStatus(t, "Vorschau", r, 200)
	errs := rowErrors(r)
	if len(errs) != 1 || !strings.Contains(errs[3], "braucht SNMP") {
		t.Fatalf("Fehler je Zeile: %v (%s)", errs, r.raw)
	}
	if n := deviceCount(t, "Fertigung", "GI "); n != 1 {
		t.Fatalf("Vorschau hat angelegt: %d", n)
	}
	// Mit Fehlern: nichts angelegt.
	r = importCSV(t, "v_fw", "Fertigung", good, false)
	expectStatus(t, "Import mit Fehler", r, 422)
	if n := deviceCount(t, "Fertigung", "GI "); n != 1 || r.body["angelegt"] != 0.0 {
		t.Fatalf("trotz Fehler angelegt: %d %s", n, r.raw)
	}

	// Fehler je Zeile.
	bad := "name,adresse,gruppe,profil,vorlage\n" +
		"GI Alt,,,,\n" + // 2 schon vorhanden
		"GI X,,Gibtsnicht,,\n" + // 3 Gruppe fehlt
		"GI Y,,,Kein Profil,\n" + // 4 Profil fehlt
		"GI Z,,,GI Switches,\n" + // 5 Profil ohne Adresse
		"GI A,a.lan,,,Dienst SSH (Linux)\n" + // 6 Agent-Vorlage
		"GI B,,,,std-ping\n" + // 7 Vorlage braucht Adresse
		"GI C,http://x,,,\n" + // 8 Adresse ungültig
		"GI D,d.lan,,,Gibtsnicht\n" + // 9 Vorlage fehlt
		"gi d,,,,\n" + // 10 doppelt in der Datei
		"GI E,,,GI IT-Profil,\n" + // 11 Profil der Eltern unsichtbar
		"GI F,10.0.0.1,,GI Switches,\n" // 12 Adresse nicht freigegeben
	r = importCSV(t, "v_fw", "Fertigung", bad, true)
	expectStatus(t, "Vorschau Fehler", r, 200)
	errs = rowErrors(r)
	want := map[float64]string{2: "gibt es im Mandanten schon", 3: "Gruppe", 4: "Profil", 5: "Adresse", 6: "Agent", 7: "Adresse",
		8: "Adresse", 9: "Vorlage", 10: "Zeile 9", 11: "Profil", 12: "nicht freigegeben"}
	for line, sub := range want {
		if !strings.Contains(errs[line], sub) {
			t.Errorf("Zeile %v: %q, erwartet %q", line, errs[line], sub)
		}
	}
	if len(errs) != len(want) {
		t.Errorf("Fehler: %v", errs)
	}

	// Erfolg: Gerät, Gruppe, SNMP-Quelle mit Profil, Sensor aus Vorlage.
	ok := "name;adresse;gruppe;profil;vorlage\n" +
		"GI Switch 1;sw1.lan;GI Wachen/Nord;gi switches;std-ping\n" +
		"\"GI Switch; 2\";sw2.lan;gi wachen;GI Switches;Synology Temperatur\n" +
		"GI Drucker\n"
	r = importCSV(t, "v_fw", "Fertigung", ok, false)
	expectStatus(t, "Import", r, 201)
	if r.body["angelegt"] != 3.0 {
		t.Fatalf("angelegt: %s", r.raw)
	}
	var group, snmpProf, version string
	var checks int
	if err := owner.QueryRow(ctx, `SELECT d.group_id::text, s.profile_id::text, s.version,
			(SELECT count(*) FROM openwacht.checks c WHERE c.device_id = d.id)::int
		FROM openwacht.devices d JOIN openwacht.snmp_sources s ON s.device_id = d.id WHERE d.name = 'GI Switch 1'`).
		Scan(&group, &snmpProf, &version, &checks); err != nil {
		t.Fatal(err)
	}
	if group != sub || snmpProf != prof || version != "2c" || checks != 1 {
		t.Errorf("Gerät 1: Gruppe %s, Profil %s, Version %s, Sensoren %d", group, snmpProf, version, checks)
	}
	var sid string
	owner.QueryRow(ctx, `SELECT s.id::text FROM openwacht.snmp_sources s JOIN openwacht.devices d ON d.id = s.device_id
		WHERE d.name = 'GI Switch; 2'`).Scan(&sid)
	if sec, _ := sourceSecret(t, sid); sec.Community != profCommunity {
		t.Errorf("Kopie der Zugangsdaten: %+v", sec)
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'geraete.importiert' AND tenant_id = $1`, ids["Fertigung"]).Scan(&audits)
	if audits != 1 {
		t.Errorf("Audit: %d", audits)
	}
	// Zweiter Import derselben Datei: alles doppelt, nichts angelegt.
	r = importCSV(t, "v_fw", "Fertigung", ok, false)
	expectStatus(t, "doppelter Import", r, 422)
	if n := deviceCount(t, "Fertigung", "GI "); n != 4 {
		t.Errorf("Geräte nach doppeltem Import: %d", n)
	}
}

func TestGeraeteImportDatei(t *testing.T) {
	verwaltungSetup(t)
	many := "name\n"
	for i := 0; i < 501; i++ {
		many += fmt.Sprintf("GD %d\n", i)
	}
	for name, csv := range map[string]string{
		"leer":              "",
		"nur Kopf":          "name;adresse\n",
		"ohne name":         "adresse;gruppe\nx;y\n",
		"unbekannte Spalte": "name;passwort\nx;y\n",
		"Spalte doppelt":    "name;name\nx;y\n",
		"zu viele Felder":   "name;adresse\nx;y;z\n",
		"Anführungszeichen": "name\n\"x\n",
		"501 Zeilen":        many,
	} {
		r := importCSV(t, "v_fw", "Fertigung", csv, true)
		expectStatus(t, name, r, 400)
	}
	// 500 Zeilen gehen (Vorschau).
	five := "name\n"
	for i := 0; i < 500; i++ {
		five += fmt.Sprintf("GD %d\n", i)
	}
	r := importCSV(t, "v_fw", "Fertigung", five, true)
	expectStatus(t, "500 Zeilen", r, 200)
	if r.body["fehlerhaft"] != 0.0 || len(r.body["zeilen"].([]any)) != 500 {
		t.Errorf("500 Zeilen: %v", r.body["fehlerhaft"])
	}
	if n := deviceCount(t, "Fertigung", "GD "); n != 0 {
		t.Errorf("Vorschau legt an: %d", n)
	}
}

func TestGeraeteImportMandantentrennung(t *testing.T) {
	lz := lzAdmin(t)
	csv := "name\nGT Gerät\n"
	expectStatus(t, "Geschwister", importCSV(t, "v_oa", "Fertigung", csv, false), 404)
	expectStatus(t, "Kind bei Eltern", importCSV(t, "v_fw", "IT", csv, false), 404)
	expectStatus(t, "Untermandant bei Eltern", importCSV(t, lz, "Fertigung", csv, false), 404)
	expectStatus(t, "Leser", importCSV(t, "v_lz", "Lager Nord", csv, false), 403)
	expectStatus(t, "Leser Vorschau", importCSV(t, "v_lz", "Lager Nord", csv, true), 403)
	if n := deviceCount(t, "Fertigung", "GT "); n != 0 {
		t.Fatalf("angelegt: %d", n)
	}
	r := importCSV(t, "v_it", "Lager Nord", "name;profil;adresse\nGT LZ;GT IT;lz.lan\n", true)
	expectStatus(t, "Eltern bei Kind (Profil fehlt)", r, 200)
	if r.body["fehlerhaft"] != 1.0 {
		t.Errorf("Profil sollte fehlen: %s", r.raw)
	}
	expectStatus(t, "IT-Profil", newProfile(t, "v_it", "IT", "GT IT", nil), 201)
	expectStatus(t, "Eltern mit eigenem Profil beim Kind", importCSV(t, "v_it", "Lager Nord", "name;profil;adresse\nGT LZ;GT IT;lz.lan\n", false), 201)
	// Das Profil der Eltern kennt der Untermandant nicht.
	r = importCSV(t, lz, "Lager Nord", "name;profil;adresse\nGT LZ 2;GT IT;lz.lan\n", true)
	if errs := rowErrors(r); !strings.Contains(errs[2], "Profil") {
		t.Errorf("Untermandant nutzt Eltern-Profil: %s", r.raw)
	}
	// Operator darf importieren, aber kein Profil zuordnen (nur Admins sehen Profile).
	_, _, op := wartungZiele(t, "GTOP")
	r = importCSV(t, op, "Lager Nord", "name;adresse;vorlage\nGT OP;op.lan;std-ping\n", false)
	expectStatus(t, "Operator", r, 201)
}
