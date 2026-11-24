// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/auth"
)

// Anmeldung über AD (Etappe 22a) gegen den OpenLDAP der Sandbox
// (OPENWACHT_TEST_LDAPS, OPENWACHT_TEST_LDAP_CA).

const (
	tgAdmins = "cn=GG-OpenWacht-Admins,ou=gruppen,dc=firma,dc=test"
	tgOps    = "cn=GG-OpenWacht-Operatoren,ou=gruppen,dc=firma,dc=test"
	tSvcDN   = "cn=svc-openwacht,ou=dienst,dc=firma,dc=test"
)

func ldapEnv(t *testing.T) (url, ca string) {
	t.Helper()
	url = os.Getenv("OPENWACHT_TEST_LDAPS")
	if url == "" {
		if os.Getenv("OPENWACHT_REQUIRE_LDAP") != "" {
			t.Fatal("OPENWACHT_TEST_LDAPS fehlt")
		}
		t.Skip("OPENWACHT_TEST_LDAPS nicht gesetzt")
	}
	b, err := os.ReadFile(os.Getenv("OPENWACHT_TEST_LDAP_CA"))
	if err != nil {
		t.Fatal(err)
	}
	return url, string(b)
}

func cleanDirectories(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM openwacht.sessions WHERE user_id IN (SELECT id FROM openwacht.users WHERE directory_id IS NOT NULL)`,
		`DELETE FROM openwacht.role_assignments WHERE user_id IN (SELECT id FROM openwacht.users WHERE directory_id IS NOT NULL)`,
		`DELETE FROM openwacht.users WHERE directory_id IS NOT NULL`,
		`DELETE FROM openwacht.directories`,
		`UPDATE openwacht.settings SET mfa_policy = NULL`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
}

// approveDir gibt Domänen und NetBIOS-Namen einer Anbindung frei (wie der
// Betreiber, Etappe 30).
func approveDir(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `UPDATE openwacht.directory_domains SET status = 'freigegeben' WHERE directory_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.directories SET netbios_status = 'freigegeben' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func dirBody(url, ca string) map[string]any {
	return map[string]any{
		"mandant": ids["Fertigung"], "name": "AD Firma", "url": url, "ca": ca, "bind_dn": tSvcDN,
		"passwort": "dienst-pass-123", "base_dn": "dc=firma,dc=test", "netbios": "FIRMA", "domaenen": []string{"firma.test"},
		"verschachtelt": false, // OpenLDAP kennt die AD-Regel für verschachtelte Gruppen nicht
		"gruppen": []map[string]any{
			{"gruppe": tgAdmins, "mandant": ids["Lager Nord"], "rolle": "admin"},
			{"gruppe": tgOps, "mandant": ids["Fertigung"], "rolle": "operator"},
		},
	}
}

func dirLogin(t *testing.T, srv *httptest.Server, login, pass string) (*client, response) {
	t.Helper()
	c := newClient(t, srv)
	r := c.do("POST", "/api/v1/sitzung", map[string]string{"email": login, "passwort": pass})
	if s, ok := r.body["csrf"].(string); ok {
		c.csrf = s
	}
	return c, r
}

func dirUser(t *testing.T, email string) (id string, disabled bool, roles string) {
	t.Helper()
	err := owner.QueryRow(context.Background(), `SELECT u.id::text, u.disabled,
		coalesce((SELECT string_agg(t.name || ':' || r.role, ',' ORDER BY t.name) FROM openwacht.role_assignments r
		          JOIN openwacht.tenants t ON t.id = r.tenant_id WHERE r.user_id = u.id), '')
		FROM openwacht.users u WHERE u.email = $1 AND u.directory_id IS NOT NULL`, email).Scan(&id, &disabled, &roles)
	if err != nil {
		t.Fatalf("Konto %s: %v", email, err)
	}
	return
}

func TestVerzeichnisAnbindungUndAnmeldung(t *testing.T) {
	url, ca := ldapEnv(t)
	s, srv := settingsServer(t, Config{})
	resetSettings(t)
	cleanDirectories(t)
	t.Cleanup(func() { cleanDirectories(t); resetSettings(t) })
	ctx := context.Background()

	fw := loginOn(t, srv, "v_fw")
	body := dirBody(url, ca)
	body["code"] = freshCode(t, "v_fw")
	// Verzeichnis liegt nicht in der Netzfreigabe: abgelehnt.
	r := fw.do("POST", "/api/v1/verzeichnisse", body)
	expectStatus(t, "ohne Netzfreigabe", r, 502)
	if !strings.Contains(r.raw, "Netzfreigabe") {
		t.Errorf("Hinweis fehlt: %s", r.raw)
	}
	s.ldapDialOverride = (&net.Dialer{}).DialContext

	// Rechte: Geschwister und Leser legen nichts an, Ziel nur im eigenen Teilbaum.
	oa := loginOn(t, srv, "v_oa")
	body["code"] = freshCode(t, "v_oa")
	expectStatus(t, "Geschwister legt an", oa.do("POST", "/api/v1/verzeichnisse", body), 403)
	lz := loginOn(t, srv, "v_lz")
	expectStatus(t, "Leser legt an", lz.do("POST", "/api/v1/verzeichnisse", body), 403)
	bad := dirBody(url, ca)
	bad["gruppen"] = []map[string]any{{"gruppe": tgAdmins, "mandant": ids["Organisation"], "rolle": "admin"}}
	bad["code"] = freshCode(t, "v_fw")
	if r := fw.do("POST", "/api/v1/verzeichnisse", bad); r.status < 400 || r.status >= 500 {
		t.Errorf("Gruppe auf Geschwister: %d %s", r.status, r.raw)
	}
	bad = dirBody(url, ca)
	bad["gruppen"] = []map[string]any{{"gruppe": tgAdmins, "mandant": ids["IT"], "rolle": "admin"}}
	bad["code"] = freshCode(t, "v_fw")
	if r := fw.do("POST", "/api/v1/verzeichnisse", bad); r.status < 400 || r.status >= 500 {
		t.Errorf("Gruppe auf Eltern: %d %s", r.status, r.raw)
	}
	// Eingaben und Dienstkonto
	for name, mod := range map[string]func(m map[string]any){
		"Klartext-LDAP":     func(m map[string]any) { m["url"] = "ldap://127.0.0.1:389" },
		"falsches Passwort": func(m map[string]any) { m["passwort"] = "falsch" },
		"ohne Domäne":       func(m map[string]any) { m["domaenen"] = []string{}; m["netbios"] = "" },
		"kein DN":           func(m map[string]any) { m["base_dn"] = "firma" },
		"ohne CA":           func(m map[string]any) { m["ca"] = "" },
	} {
		b := dirBody(url, ca)
		mod(b)
		b["code"] = freshCode(t, "v_fw")
		if r := fw.do("POST", "/api/v1/verzeichnisse", b); r.status < 400 {
			t.Errorf("%s angenommen: %s", name, r.raw)
		}
	}
	body["code"] = "000000"
	expectStatus(t, "falscher Code", fw.do("POST", "/api/v1/verzeichnisse", body), 403)
	body["code"] = freshCode(t, "v_fw")
	r = fw.do("POST", "/api/v1/verzeichnisse", body)
	expectStatus(t, "anlegen", r, 201)
	dirID, _ := r.body["id"].(string)
	// Fertigung ist Untermandant: Domäne und NetBIOS-Name warten auf den Betreiber.
	if _, r := dirLogin(t, srv, "anna@firma.test", "anna-pass-123"); r.status != 401 {
		t.Errorf("Anmeldung vor der Freigabe: %d", r.status)
	}
	if _, r := dirLogin(t, srv, `FIRMA\anna`, "anna-pass-123"); r.status != 401 {
		t.Errorf("NetBIOS vor der Freigabe: %d", r.status)
	}
	approveDir(t, dirID)

	// Eine freigegebene Domäne gilt nur für eine Anbindung: Ein zweiter
	// Antrag (hier Geschwister) bleibt beantragt und sperrt die erste nicht.
	dup := dirBody(url, ca)
	dup["mandant"], dup["gruppen"], dup["netbios"], dup["code"] = ids["Organisation"], nil, "", freshCode(t, "v_oa")
	dup["name"] = "AD Organisation"
	if r := oa.do("POST", "/api/v1/verzeichnisse", dup); r.status != 201 {
		t.Errorf("Antrag Geschwister: %s", r.raw)
	}
	var pending int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.directory_domains WHERE domain = 'firma.test' AND status = 'beantragt'`).Scan(&pending)
	if pending != 1 {
		t.Errorf("Antrag des Geschwisters: %d beantragt", pending)
	}

	// Sichtbarkeit: Fertigung und Eltern ja, Geschwister nein; Passwort nie.
	for u, want := range map[string]int{"v_fw": 1, "v_it": 2, "v_oa": 1} {
		c := fw
		if u != "v_fw" {
			c = loginOn(t, srv, u)
		}
		r := c.do("GET", "/api/v1/verzeichnisse", nil)
		if u == "v_oa" || u == "v_it" {
			expectStatus(t, u+" Liste", r, 200)
		}
		if l, _ := r.body["verzeichnisse"].([]any); len(l) != want {
			t.Errorf("%s sieht %d Anbindungen, erwartet %d", u, len(l), want)
		}
		if strings.Contains(r.raw, "dienst-pass") {
			t.Errorf("%s: Passwort in der Liste", u)
		}
		if u == "v_oa" && strings.Contains(r.raw, dirID) {
			t.Error("Geschwister sieht die Anbindung der Fertigung")
		}
	}
	var enc []byte
	owner.QueryRow(ctx, `SELECT bind_pass_enc FROM openwacht.directories WHERE id = $1`, dirID).Scan(&enc)
	if len(enc) == 0 || strings.Contains(string(enc), "dienst-pass") {
		t.Error("Passwort nicht verschlüsselt")
	}
	expectStatus(t, "Test", fw.do("POST", "/api/v1/verzeichnisse/"+dirID+"/test", nil), 200)
	expectStatus(t, "Geschwister testet", oa.do("POST", "/api/v1/verzeichnisse/"+dirID+"/test", nil), 404)

	// Anmeldung: Gruppen ergeben Mandant und Rolle.
	anna, r := dirLogin(t, srv, "anna@firma.test", "anna-pass-123")
	expectStatus(t, "Anna", r, 200)
	if r.body["zwei_faktor_einrichten"] != false {
		t.Errorf("AD ohne 2FA-Pflicht: %v", r.body)
	}
	me := anna.do("GET", "/api/v1/ich", nil)
	if me.body["quelle"] != "ldap" {
		t.Errorf("Quelle: %v", me.body["quelle"])
	}
	annaID, _, roles := dirUser(t, "anna@firma.test")
	if roles != "Lager Nord:admin" {
		t.Errorf("Anna Rollen: %s", roles)
	}
	expectStatus(t, "Anna liest Mandanten", anna.do("GET", "/api/v1/mandanten", nil), 200)
	_, r = dirLogin(t, srv, `FIRMA\otto`, "otto-pass-123")
	expectStatus(t, "Otto (NetBIOS)", r, 200)
	ottoID, _, roles := dirUser(t, "otto@firma.test")
	if roles != "Fertigung:operator" {
		t.Errorf("Otto Rollen: %s", roles)
	}
	// Negativfälle
	for _, x := range [][2]string{
		{"anna@firma.test", "falsch"}, {"anna@firma.test", ""}, {"gustav@firma.test", "gustav-pass-123"},
		{"niemand@firma.test", "x-pass-123"}, {"anna@fremd.test", "anna-pass-123"}, {`FREMD\anna`, "anna-pass-123"},
	} {
		if _, r := dirLogin(t, srv, x[0], x[1]); r.status != 401 && !(x[1] == "" && r.status == 400) {
			t.Errorf("%s/%q: Status %d", x[0], x[1], r.status)
		}
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.users WHERE email = 'gustav@firma.test'`).Scan(&n)
	if n != 0 {
		t.Error("gesperrtes AD-Konto angelegt")
	}
	owner.Exec(ctx, `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1) UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, annaID)

	// Rechte und Passwort von AD-Konten nur aus dem Verzeichnis.
	expectStatus(t, "Rolle von Hand", fw.do("PUT", "/api/v1/benutzer/"+ottoID+"/rollen/"+ids["Fertigung"],
		map[string]any{"rolle": "admin"}), 400)
	if r := fw.do("PUT", "/api/v1/benutzer/"+ottoID+"/passwort", map[string]any{"passwort": "Neues-Passwort-123", "code": freshCode(t, "v_fw")}); r.status < 400 {
		t.Errorf("Passwort für AD-Konto gesetzt: %s", r.raw)
	}

	// Adressen nur aus den Domänen der Anbindung (sonst könnte ein AD fremde Adressen vergeben).
	dom := dirBody(url, ca)
	delete(dom, "passwort")
	dom["domaenen"], dom["code"] = []string{"anders.test"}, freshCode(t, "v_fw")
	expectStatus(t, "Domäne ändern", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, dom), 200)
	if _, r := dirLogin(t, srv, `FIRMA\anna`, "anna-pass-123"); r.status != 401 {
		t.Errorf("UPN außerhalb der Domänen: %d", r.status)
	}
	dom["domaenen"], dom["code"] = []string{"firma.test"}, freshCode(t, "v_fw")
	expectStatus(t, "Domäne zurück", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, dom), 200)
	approveDir(t, dirID)
	owner.Exec(ctx, `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1) UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, annaID)

	// Bestätigung ohne 2FA mit dem AD-Passwort.
	expectStatus(t, "Anna bestätigt falsch", anna.do("DELETE", "/api/v1/verzeichnisse/"+dirID, map[string]any{"code": "falsch"}), 403)
	expectStatus(t, "Anna bestätigt, sieht aber nichts", anna.do("DELETE", "/api/v1/verzeichnisse/"+dirID,
		map[string]any{"code": "anna-pass-123"}), 404)

	// Abgleich: Gruppe entfernt -> gesperrt, Sitzung weg; wieder da -> frei.
	upd := dirBody(url, ca)
	delete(upd, "passwort")
	upd["gruppen"] = []map[string]any{{"gruppe": tgOps, "mandant": ids["Fertigung"], "rolle": "operator"}}
	upd["code"] = freshCode(t, "v_fw")
	expectStatus(t, "Gruppen ändern ohne Passwort", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, upd), 200)
	s.SyncDirectories(ctx)
	if _, dis, roles := dirUser(t, "anna@firma.test"); !dis || roles != "" {
		t.Errorf("Anna nach Abgleich: gesperrt=%v Rollen=%q", dis, roles)
	}
	expectStatus(t, "Annas Sitzung", anna.do("GET", "/api/v1/ich", nil), 401)
	upd["gruppen"] = dirBody(url, ca)["gruppen"]
	upd["code"] = freshCode(t, "v_fw")
	expectStatus(t, "Gruppen zurück", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, upd), 200)
	s.SyncDirectories(ctx)
	if _, dis, roles := dirUser(t, "anna@firma.test"); dis || roles != "Lager Nord:admin" {
		t.Errorf("Anna wieder: gesperrt=%v Rollen=%q", dis, roles)
	}
	// Von Hand gesperrt bleibt gesperrt.
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, ottoID)
	s.SyncDirectories(ctx)
	if _, dis, _ := dirUser(t, "otto@firma.test"); !dis {
		t.Error("Abgleich hebt Sperre von Hand auf")
	}
	if _, r := dirLogin(t, srv, `FIRMA\otto`, "otto-pass-123"); r.status != 401 {
		t.Errorf("gesperrter Otto meldet sich an: %d", r.status)
	}
	// Aus dem Verzeichnis verschwunden.
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = false, external_id = '00112233445566778899aabbccddeeff' WHERE id = $1`, ottoID)
	s.SyncDirectories(ctx)
	if _, dis, _ := dirUser(t, "otto@firma.test"); !dis {
		t.Error("verschwundenes Konto nicht gesperrt")
	}

	// Neue Adresse ohne Passwort: abgelehnt (Passwort geht an keinen anderen Server).
	upd["url"], upd["code"] = strings.Replace(url, "127.0.0.1", "localhost", 1), freshCode(t, "v_fw")
	expectStatus(t, "neue Adresse ohne Passwort", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, upd), 400)
	upd["url"], upd["ca"], upd["code"] = url, "", freshCode(t, "v_fw")
	expectStatus(t, "neue CA ohne Passwort", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, upd), 400)
	upd["ca"] = ca

	// 2FA-Pflicht der Anbindung
	upd["zwei_faktor"], upd["code"] = true, freshCode(t, "v_fw")
	expectStatus(t, "2FA-Pflicht an", fw.do("PUT", "/api/v1/verzeichnisse/"+dirID, upd), 200)
	anna, r = dirLogin(t, srv, "anna@firma.test", "anna-pass-123")
	expectStatus(t, "Anna mit Pflicht", r, 200)
	if r.body["zwei_faktor_einrichten"] != true {
		t.Errorf("Pflicht nicht gemeldet: %v", r.body)
	}
	expectStatus(t, "Anna ohne 2FA", anna.do("GET", "/api/v1/mandanten", nil), 403)

	// Löschen sperrt die Konten.
	expectStatus(t, "Geschwister löscht", oa.do("DELETE", "/api/v1/verzeichnisse/"+dirID, map[string]any{"code": freshCode(t, "v_oa")}), 404)
	expectStatus(t, "löschen", fw.do("DELETE", "/api/v1/verzeichnisse/"+dirID, map[string]any{"code": freshCode(t, "v_fw")}), 200)
	var dis bool
	var hash *string
	owner.QueryRow(ctx, `SELECT disabled, password_hash FROM openwacht.users WHERE id = $1`, annaID).Scan(&dis, &hash)
	if !dis || hash != nil {
		t.Errorf("Konto nach Löschen der Anbindung: gesperrt=%v Passwort=%v", dis, hash != nil)
	}
	if _, r := dirLogin(t, srv, "anna@firma.test", "anna-pass-123"); r.status != 401 {
		t.Errorf("Anmeldung nach Löschen: %d", r.status)
	}
}

func TestZweiFaktorPflichtEinstellung(t *testing.T) {
	_, srv := settingsServer(t, Config{})
	resetSettings(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = NULL`)
		owner.Exec(ctx, `DELETE FROM openwacht.sessions WHERE user_id = $1`, ids["v_mfa"])
		owner.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1`, ids["v_mfa"])
		owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, ids["v_mfa"])
		resetSettings(t)
	})
	it := loginOn(t, srv, "v_it")
	put := func(c *client, v, code string) response {
		return c.do("PUT", "/api/v1/einstellungen/anmeldung", map[string]any{"zwei_faktor": v, "code": code})
	}
	expectStatus(t, "Nicht-Betreiber", put(it, "freiwillig", freshCode(t, "v_it")), 403)
	setOperator(t, "v_it", true)
	expectStatus(t, "ungültig", put(it, "nie", freshCode(t, "v_it")), 400)
	expectStatus(t, "ohne Code", put(it, "freiwillig", ""), 403)
	fw := loginOn(t, srv, "v_fw")
	expectStatus(t, "Fertigung-Admin", put(fw, "freiwillig", freshCode(t, "v_fw")), 403)

	// eigener Admin ohne 2FA in Lager Nord
	hash, _ := auth.HashPassword(testPassword, testParams)
	var mid string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
		VALUES ($1, 'v_mfa@test.invalid', 'v_mfa', $2) RETURNING id::text`, ids["Lager Nord"], hash).Scan(&mid); err != nil {
		t.Fatal(err)
	}
	ids["v_mfa"] = mid
	owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, mid, ids["Lager Nord"])
	check := func(what string, wantBlocked bool, user string) *client {
		t.Helper()
		c := newClient(t, srv)
		r := c.login(user)
		expectStatus(t, what+" Anmeldung", r, 200)
		if r.body["zwei_faktor_einrichten"] != wantBlocked {
			t.Errorf("%s: zwei_faktor_einrichten = %v", what, r.body["zwei_faktor_einrichten"])
		}
		want := 200
		if wantBlocked {
			want = 403
		}
		expectStatus(t, what+" Zugriff", c.do("GET", "/api/v1/mandanten", nil), want)
		return c
	}
	check("Standard: Admin", true, "v_mfa")
	check("Standard: Leser", false, "v_lz")
	expectStatus(t, "freiwillig", put(it, "freiwillig", freshCode(t, "v_it")), 200)
	adm := check("freiwillig: Admin", false, "v_mfa")
	// Bestätigung ohne 2FA mit dem eigenen Passwort
	expectStatus(t, "Bestätigung falsches Passwort", adm.do("DELETE", "/api/v1/verzeichnisse/00000000-0000-4000-8000-000000000000",
		map[string]any{"code": "falsch-falsch"}), 403)
	expectStatus(t, "Bestätigung leer", adm.do("DELETE", "/api/v1/verzeichnisse/00000000-0000-4000-8000-000000000000",
		map[string]any{"code": ""}), 403)
	expectStatus(t, "Bestätigung Passwort", adm.do("DELETE", "/api/v1/verzeichnisse/00000000-0000-4000-8000-000000000000",
		map[string]any{"code": testPassword}), 404)
	// Mit 2FA zählt nur der Code, nicht das Passwort.
	expectStatus(t, "Passwort statt Code", fw.do("DELETE", "/api/v1/verzeichnisse/00000000-0000-4000-8000-000000000000",
		map[string]any{"code": testPassword}), 403)
	expectStatus(t, "alle", put(it, "alle", freshCode(t, "v_it")), 200)
	check("alle: Leser", true, "v_lz")
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'einstellungen.zwei_faktor'`).Scan(&audits)
	if audits < 2 {
		t.Errorf("Audit: %d", audits)
	}
}
