// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Pflicht-Tests zur Mandantentrennung für jeden Verwaltungs-Endpunkt:
// kein Zugriff auf Geschwister oder Eltern, Zugriff von Eltern auf Kinder.
//
// Baum (zusätzlich zu den Daten aus zentrale_test.go):
//
//	IT ─┬─ Fertigung ── Lager Nord
//	    └─ Organisation

import (
	"context"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
)

var (
	vOnce    sync.Once
	vErr     error
	vSrv     *httptest.Server
	vServer  *Server
	vClients = map[string]*client{}
	vSecrets = map[string][]byte{}
	vMu      sync.Mutex
	// vNtfy: nachgebauter ntfy-Server, als Alarmziel des gemeinsamen Servers freigegeben.
	vNtfy *fakeNtfy
)

// Benutzer der Verwaltungstests: Name -> (Heimatmandant, Rolle, 2FA)
var vUsers = []struct {
	name, tenant, role string
	totp               bool
}{
	{"v_it", "IT", "admin", true},
	{"v_fw", "Fertigung", "admin", true},
	{"v_lz", "Lager Nord", "leser", false},
	{"v_lz2", "Lager Nord", "leser", false},
	{"v_oa", "Organisation", "admin", true},
	{"v_oa_user", "Organisation", "leser", false},
}

func verwaltungSetup(t *testing.T) {
	t.Helper()
	vOnce.Do(func() {
		ctx := context.Background()
		for _, tn := range []struct{ name, parent string }{{"Lager Nord", "Fertigung"}, {"Organisation", "IT"}} {
			var id string
			if vErr = owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2) RETURNING id::text`,
				ids[tn.parent], tn.name).Scan(&id); vErr != nil {
				return
			}
			ids[tn.name] = id
		}
		hash, _ := auth.HashPassword(testPassword, testParams)
		box := deriveKey(testKey, "openwacht secretbox v1")
		for _, u := range vUsers {
			var id string
			if vErr = owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
				VALUES ($1, $2, $3, $4) RETURNING id::text`, ids[u.tenant], u.name+"@test.invalid", u.name, hash).Scan(&id); vErr != nil {
				return
			}
			ids[u.name] = id
			if _, vErr = owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
				id, ids[u.tenant], u.role); vErr != nil {
				return
			}
			if u.totp {
				secret, _ := auth.GenerateTOTPSecret()
				enc, _ := auth.Seal(box, secret, []byte(id))
				vSecrets[u.name] = secret
				if _, vErr = owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2, totp_enabled = true WHERE id = $1`,
					id, enc); vErr != nil {
					return
				}
			}
		}
		vServer, vSrv = newTestServerNoCleanup()
	})
	if vErr != nil {
		t.Fatal(vErr)
	}
}

// newTestServerNoCleanup: ein gemeinsamer Server für alle Verwaltungstests,
// damit jeder Benutzer sich nur einmal anmelden muss (TOTP-Codes gelten nur einmal).
func newTestServerNoCleanup() (*Server, *httptest.Server) {
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	u := mustURL(srv.URL)
	vNtfy = newFakeNtfy()
	s, err := New(Config{BaseURL: u, PasswordParams: &testParams, LoginsPerMinutePerIP: 1000,
		AlertTargets: alarm.NewTargets(vNtfy.URL, "https://ntfy.test.invalid", "http://127.0.0.1:9")}, pool, testKey)
	if err != nil {
		panic(err)
	}
	srv.Config.Handler = s.Handler()
	return s, srv
}

// as liefert einen angemeldeten Client für den Benutzer (einmal je Benutzer).
func as(t *testing.T, user string) *client {
	t.Helper()
	verwaltungSetup(t)
	vMu.Lock()
	defer vMu.Unlock()
	if c := vClients[user]; c != nil {
		c.t = t
		return c
	}
	c := newClient(t, vSrv)
	r := c.login(user)
	if r.status != 200 {
		t.Fatalf("Anmeldung %s: %d %s", user, r.status, r.raw)
	}
	if r.body["zweiter_faktor"] == true {
		code := auth.TOTPCode(vSecrets[user], auth.TOTPStep(time.Now()))
		r = c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": code})
		if r.status != 200 {
			t.Fatalf("2FA %s: %d %s", user, r.status, r.raw)
		}
		c.csrf, _ = r.body["csrf"].(string)
	}
	vClients[user] = c
	return c
}

func tenantNames(t *testing.T, c *client) map[string]string {
	t.Helper()
	r := c.do("GET", "/api/v1/mandanten", nil)
	expectStatus(t, "Mandanten", r, 200)
	out := map[string]string{}
	list, _ := r.body["mandanten"].([]any)
	for _, x := range list {
		m := x.(map[string]any)
		out[m["name"].(string)] = m["rolle"].(string)
	}
	return out
}

func keys(m map[string]string) string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return strings.Join(k, ",")
}

func TestVerwaltungMandantenSichtbarkeit(t *testing.T) {
	it := tenantNames(t, as(t, "v_it"))
	for _, n := range []string{"IT", "Fertigung", "Lager Nord", "Organisation"} {
		if it[n] != "admin" {
			t.Errorf("v_it: %s mit Rolle %q, erwartet admin", n, it[n])
		}
	}
	fw := tenantNames(t, as(t, "v_fw"))
	if keys(fw) != "Fertigung,Lager Nord" || fw["Lager Nord"] != "admin" {
		t.Errorf("v_fw sieht %v", fw)
	}
	if lz := tenantNames(t, as(t, "v_lz")); keys(lz) != "Lager Nord" || lz["Lager Nord"] != "leser" {
		t.Errorf("v_lz sieht %v", lz)
	}
	if oa := tenantNames(t, as(t, "v_oa")); keys(oa) != "Organisation" {
		t.Errorf("v_oa sieht %v", oa)
	}
}

func TestVerwaltungMandantAnlegenUmbenennenLoeschen(t *testing.T) {
	create := func(user, parent, name string) response {
		return as(t, user).do("POST", "/api/v1/mandanten", map[string]string{"uebergeordnet_id": ids[parent], "name": name})
	}
	expectStatus(t, "v_fw legt unter Fertigung an (nur IT darf)", create("v_fw", "Fertigung", "LZ Süd"), 403)
	expectStatus(t, "v_oa legt unter Fertigung an", create("v_oa", "Fertigung", "LZ Süd"), 403)
	expectStatus(t, "v_lz legt an", create("v_lz", "Lager Nord", "X"), 403)
	expectStatus(t, "leerer Name", create("v_it", "Fertigung", "  "), 400)
	r := create("v_it", "Fertigung", "LZ Süd")
	expectStatus(t, "v_it legt unter Fertigung an", r, 201)
	newID, _ := r.body["id"].(string)
	expectStatus(t, "doppelter Name", create("v_it", "Fertigung", "lz süd"), 409)

	rename := func(user, id, name string) response {
		return as(t, user).do("PATCH", "/api/v1/mandanten/"+id, map[string]string{"name": name})
	}
	expectStatus(t, "v_fw benennt neuen Lager um", rename("v_fw", newID, "Lager Süd"), 204)
	expectStatus(t, "v_fw benennt eigenen Knoten um", rename("v_fw", ids["Fertigung"], "Fertigung"), 204)
	expectStatus(t, "v_fw benennt Organisation um", rename("v_fw", ids["Organisation"], "gekapert"), 404)
	expectStatus(t, "v_fw benennt IT um", rename("v_fw", ids["IT"], "gekapert"), 404)
	expectStatus(t, "v_lz benennt Lager um", rename("v_lz", ids["Lager Nord"], "X"), 404)

	del := func(user, id string) response { return as(t, user).do("DELETE", "/api/v1/mandanten/"+id, nil) }
	expectStatus(t, "v_oa löscht Lager Süd", del("v_oa", newID), 404)
	expectStatus(t, "v_fw löscht eigenen Knoten", del("v_fw", ids["Fertigung"]), 404)
	expectStatus(t, "v_fw löscht Lager Nord mit Benutzern", del("v_fw", ids["Lager Nord"]), 409)
	expectStatus(t, "v_fw löscht leeren Lager Süd", del("v_fw", newID), 204)
	expectStatus(t, "ungültige ID", del("v_fw", "kein-uuid"), 400)

	// Audit: Anlegen am Elternknoten, mit handelnder Person.
	var actor string
	owner.QueryRow(context.Background(), `SELECT actor_user_id::text FROM openwacht.audit_log
		WHERE action = 'mandant.angelegt' AND tenant_id = $1 ORDER BY chain_seq DESC LIMIT 1`, ids["Fertigung"]).Scan(&actor)
	if actor != ids["v_it"] {
		t.Errorf("Audit mandant.angelegt: actor %q", actor)
	}
}

func userEmails(t *testing.T, c *client, query string) []string {
	t.Helper()
	r := c.do("GET", "/api/v1/benutzer"+query, nil)
	expectStatus(t, "Benutzer", r, 200)
	var out []string
	list, _ := r.body["benutzer"].([]any)
	for _, x := range list {
		out = append(out, x.(map[string]any)["email"].(string))
	}
	sort.Strings(out)
	return out
}

func TestVerwaltungBenutzerSichtbarkeit(t *testing.T) {
	fw := strings.Join(userEmails(t, as(t, "v_fw"), ""), ",")
	for _, want := range []string{"v_fw@", "v_lz@", "leser@"} {
		if !strings.Contains(fw, want) {
			t.Errorf("v_fw sieht %s nicht: %s", want, fw)
		}
	}
	for _, not := range []string{"v_oa", "v_it@", "admin@"} {
		if strings.Contains(fw, not) {
			t.Errorf("v_fw sieht fremden Benutzer %s: %s", not, fw)
		}
	}
	// Filter auf einen fremden Mandanten liefert nichts.
	if got := userEmails(t, as(t, "v_fw"), "?mandant="+ids["Organisation"]); len(got) != 0 {
		t.Errorf("v_fw mit Filter Organisation: %v", got)
	}
	expectStatus(t, "ungültiger Filter", as(t, "v_fw").do("GET", "/api/v1/benutzer?mandant=x", nil), 400)
}

func TestVerwaltungBenutzerAnlegenUndAendern(t *testing.T) {
	create := func(user, tenant, email string) response {
		return as(t, user).do("POST", "/api/v1/benutzer", map[string]string{
			"mandant_id": ids[tenant], "email": email, "anzeigename": "Neu", "passwort": "ein-neues-passwort"})
	}
	expectStatus(t, "v_fw legt im Organisation an", create("v_fw", "Organisation", "x1@test.invalid"), 403)
	expectStatus(t, "v_lz legt an", create("v_lz", "Lager Nord", "x2@test.invalid"), 403)
	expectStatus(t, "zu kurzes Passwort", as(t, "v_fw").do("POST", "/api/v1/benutzer", map[string]string{
		"mandant_id": ids["Lager Nord"], "email": "x3@test.invalid", "anzeigename": "Neu", "passwort": "kurz"}), 400)
	r := create("v_fw", "Lager Nord", "Neu.Mitglied@Test.invalid")
	expectStatus(t, "v_fw legt im Lager an", r, 201)
	if r.body["email"] != "neu.mitglied@test.invalid" {
		t.Errorf("E-Mail nicht normalisiert: %v", r.body["email"])
	}
	newID, _ := r.body["id"].(string)
	expectStatus(t, "doppelte E-Mail", create("v_fw", "Lager Nord", "neu.mitglied@test.invalid"), 409)

	// Der neue Benutzer kann sich anmelden.
	nc := newClient(t, vSrv)
	r = nc.do("POST", "/api/v1/sitzung", map[string]string{"email": "neu.mitglied@test.invalid", "passwort": "ein-neues-passwort"})
	expectStatus(t, "Anmeldung neuer Benutzer", r, 200)
	nc.csrf, _ = r.body["csrf"].(string)

	patch := func(user, id string, body map[string]any) response {
		return as(t, user).do("PATCH", "/api/v1/benutzer/"+id, body)
	}
	expectStatus(t, "v_oa ändert Fertigung-Benutzer", patch("v_oa", newID, map[string]any{"anzeigename": "gekapert"}), 404)
	expectStatus(t, "v_lz ändert Benutzer", patch("v_lz", newID, map[string]any{"anzeigename": "gekapert"}), 404)
	expectStatus(t, "v_fw deaktiviert sich selbst", patch("v_fw", ids["v_fw"], map[string]any{"deaktiviert": true}), 400)
	expectStatus(t, "v_fw deaktiviert neuen Benutzer", patch("v_fw", newID, map[string]any{"deaktiviert": true}), 204)
	// Deaktivieren beendet laufende Sitzungen sofort.
	expectStatus(t, "Sitzung nach Deaktivierung", nc.do("GET", "/api/v1/ich", nil), 401)
	expectStatus(t, "v_it ändert Fertigung-Benutzer (Elternknoten)", patch("v_it", newID, map[string]any{"anzeigename": "Von der IT"}), 204)
}

func TestVerwaltungPasswortSetzen(t *testing.T) {
	set := func(user, target string, body map[string]string) response {
		return as(t, user).do("PUT", "/api/v1/benutzer/"+ids[target]+"/passwort", body)
	}
	expectStatus(t, "v_oa setzt Passwort in Fertigung", set("v_oa", "v_lz2", map[string]string{"passwort": "neues-passwort-123"}), 404)
	expectStatus(t, "v_lz setzt fremdes Passwort", set("v_lz", "v_lz2", map[string]string{"passwort": "neues-passwort-123"}), 404)
	expectStatus(t, "v_fw setzt Passwort im Lager", set("v_fw", "v_lz2", map[string]string{"passwort": "neues-passwort-123"}), 204)
	nc := newClient(t, vSrv)
	expectStatus(t, "Anmeldung mit neuem Passwort", nc.do("POST", "/api/v1/sitzung",
		map[string]string{"email": "v_lz2@test.invalid", "passwort": "neues-passwort-123"}), 200)
}

func TestVerwaltungRollen(t *testing.T) {
	put := func(user, target, tenant, role string) response {
		return as(t, user).do("PUT", "/api/v1/benutzer/"+ids[target]+"/rollen/"+ids[tenant], map[string]string{"rolle": role})
	}
	expectStatus(t, "v_fw gibt v_lz Operator im Lager", put("v_fw", "v_lz", "Lager Nord", "operator"), 204)
	expectStatus(t, "v_fw vergibt Rolle auf Organisation", put("v_fw", "v_lz", "Organisation", "leser"), 403)
	expectStatus(t, "v_fw vergibt Rolle auf IT", put("v_fw", "v_lz", "IT", "admin"), 403)
	expectStatus(t, "v_fw vergibt Rolle an unsichtbaren Benutzer", put("v_fw", "v_oa_user", "Fertigung", "leser"), 403)
	expectStatus(t, "v_lz vergibt Rolle", put("v_lz", "v_lz2", "Lager Nord", "admin"), 403)
	expectStatus(t, "eigene Rolle ändern", put("v_fw", "v_fw", "Lager Nord", "leser"), 400)
	expectStatus(t, "unbekannte Rolle", put("v_fw", "v_lz", "Lager Nord", "superuser"), 400)

	if r := tenantNames(t, as(t, "v_lz")); r["Lager Nord"] != "operator" {
		t.Errorf("v_lz effektive Rolle nach Vergabe: %v", r)
	}
	del := func(user, target, tenant string) response {
		return as(t, user).do("DELETE", "/api/v1/benutzer/"+ids[target]+"/rollen/"+ids[tenant], nil)
	}
	expectStatus(t, "v_oa entzieht Rolle im Lager", del("v_oa", "v_lz", "Lager Nord"), 404)
	expectStatus(t, "v_fw entzieht Rolle im Lager", del("v_fw", "v_lz", "Lager Nord"), 204)
	expectStatus(t, "erneut entziehen", del("v_fw", "v_lz", "Lager Nord"), 404)
	put("v_fw", "v_lz", "Lager Nord", "leser")
}

func TestVerwaltungZugangsschutz(t *testing.T) {
	verwaltungSetup(t)
	anon := newClient(t, vSrv)
	expectStatus(t, "ohne Anmeldung", anon.do("GET", "/api/v1/mandanten", nil), 401)

	// Admin ohne 2FA kommt nicht an die Verwaltung.
	admin := newClient(t, vSrv)
	admin.login("admin")
	r := admin.do("GET", "/api/v1/mandanten", nil)
	expectStatus(t, "Admin ohne 2FA", r, 403)
	if r.body["zwei_faktor_einrichten"] != true {
		t.Errorf("Hinweis auf 2FA fehlt: %s", r.raw)
	}

	// Ohne CSRF-Token keine Änderung.
	c := as(t, "v_it")
	csrf := c.csrf
	c.csrf = ""
	expectStatus(t, "ohne CSRF", c.do("POST", "/api/v1/mandanten",
		map[string]string{"uebergeordnet_id": ids["IT"], "name": "ohne-csrf"}), 403)
	c.csrf = csrf
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
