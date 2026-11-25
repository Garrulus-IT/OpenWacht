// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Schnelle Argon2-Kosten für Tests; das Verfahren ist dasselbe.
var testParams = auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const testPassword = "ein-langes-test-passwort"

var (
	owner   *pgx.Conn
	pool    *pgxpool.Pool
	testKey = bytes.Repeat([]byte{42}, auth.KeySize)
	ids     = map[string]string{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := func() int {
		defer tdb.Close()
		if owner, err = pgx.ConnectConfig(ctx, tdb.OwnerCfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer owner.Close(ctx)
		if _, err := db.Migrate(ctx, owner); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		pcfg, _ := pgxpool.ParseConfig("")
		pcfg.ConnConfig = tdb.AppCfg.Copy()
		if pool, err = pgxpool.NewWithConfig(ctx, pcfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer pool.Close()
		if err := seed(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "Testdaten:", err)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

func seed(ctx context.Context) error {
	hash, err := auth.HashPassword(testPassword, testParams)
	if err != nil {
		return err
	}
	var it, fw string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`).Scan(&it); err != nil {
		return err
	}
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, 'Fertigung') RETURNING id::text`,
		it).Scan(&fw); err != nil {
		return err
	}
	ids["IT"], ids["Fertigung"] = it, fw
	users := []struct{ name, tenant, role string }{
		{"admin", "IT", "admin"},
		{"leser", "Fertigung", "leser"},
		{"sperre", "Fertigung", "leser"},
		{"gesperrt", "Fertigung", "leser"},
		{"zweifa", "IT", "admin"},
		{"altehash", "Fertigung", "leser"},
	}
	for _, u := range users {
		h := hash
		if u.name == "altehash" {
			h, _ = auth.HashPassword(testPassword, auth.Params{Memory: 32, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16})
		}
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash, disabled)
			VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			ids[u.tenant], u.name+"@test.invalid", u.name, h, u.name == "gesperrt").Scan(&id); err != nil {
			return err
		}
		ids[u.name] = id
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			id, ids[u.tenant], u.role); err != nil {
			return err
		}
	}
	return nil
}

// --- Testclient ---------------------------------------------------------------
// Cookies verwaltet der Client selbst: Go's Cookie-Jar sendet Secure-Cookies
// nicht über http, der Testserver läuft aber ohne TLS.

type client struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
	csrf    string
	origin  string
	xff     string // X-Forwarded-For (nur mit vertrauenswürdigem Proxy wirksam)
}

func newTestServer(t *testing.T, mod func(*Config)) (*Server, *httptest.Server) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	u, _ := url.Parse(srv.URL)
	// Sammeln (1.0.1) aus: Die übrigen Tests erwarten den Versand im selben Durchlauf.
	cfg := Config{BaseURL: u, PasswordParams: &testParams, LoginsPerMinutePerIP: 1000, UserRequestsPerMinute: 1 << 30, AlertCollect: -1}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s.Handler()
	t.Cleanup(srv.Close)
	return s, srv
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	return &client{t: t, base: srv.URL, cookies: map[string]*http.Cookie{}, origin: srv.URL}
}

type response struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

func (c *client) do(method, path string, body any) response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.origin != "" && method != http.MethodGet {
		req.Header.Set("Origin", c.origin)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.xff != "" {
		req.Header.Set("X-Forwarded-For", c.xff)
	}
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	r := response{status: resp.StatusCode, header: resp.Header, raw: string(raw)}
	json.Unmarshal(raw, &r.body)
	return r
}

func (c *client) login(user string) response {
	c.t.Helper()
	r := c.do("POST", "/api/v1/sitzung", map[string]string{"email": user + "@test.invalid", "passwort": testPassword})
	if s, ok := r.body["csrf"].(string); ok {
		c.csrf = s
	}
	return r
}

func expectStatus(t *testing.T, what string, r response, want int) {
	t.Helper()
	if r.status != want {
		t.Errorf("%s: Status %d, erwartet %d (%s)", what, r.status, want, strings.TrimSpace(r.raw))
	}
}

// --- Tests --------------------------------------------------------------------

func TestSicherheitsHeader(t *testing.T) {
	_, srv := newTestServer(t, nil)
	r := newClient(t, srv).do("GET", "/api/v1/gesund", nil)
	expectStatus(t, "gesund", r, 200)
	for h, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	} {
		if !strings.Contains(r.header.Get(h), want) {
			t.Errorf("Header %s = %q, erwartet %q", h, r.header.Get(h), want)
		}
	}
}

func TestAnmeldungUndSitzung(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	r := c.login("leser")
	expectStatus(t, "Anmeldung", r, 200)
	ck := c.cookies[sessionCookie]
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
		t.Fatalf("Sitzungscookie unsicher oder fehlt: %+v", ck)
	}
	if c.csrf == "" {
		t.Fatal("kein CSRF-Token")
	}
	me := c.do("GET", "/api/v1/ich", nil)
	expectStatus(t, "ich", me, 200)
	if me.body["email"] != "leser@test.invalid" || me.body["csrf"] != c.csrf {
		t.Errorf("ich: %s", me.raw)
	}
	if me.body["version"] != version.Version || me.body["commit"] != version.Commit {
		t.Errorf("ich: Version fehlt: %s", me.raw)
	}
	roles, _ := me.body["rollen"].([]any)
	if len(roles) != 1 || roles[0].(map[string]any)["mandant"] != "Fertigung" {
		t.Errorf("Rollen: %v", roles)
	}

	// Audit: Erfolg mit handelnder Person.
	var actor string
	owner.QueryRow(context.Background(), `SELECT actor_user_id::text FROM openwacht.audit_log
		WHERE action = 'anmeldung.erfolg' ORDER BY chain_seq DESC LIMIT 1`).Scan(&actor)
	if actor != ids["leser"] {
		t.Errorf("Audit-Eintrag: actor %q", actor)
	}

	// Abmelden nur mit CSRF-Token.
	csrf := c.csrf
	c.csrf = ""
	expectStatus(t, "Abmelden ohne CSRF", c.do("DELETE", "/api/v1/sitzung", nil), 403)
	c.csrf = "falsch"
	expectStatus(t, "Abmelden mit falschem CSRF", c.do("DELETE", "/api/v1/sitzung", nil), 403)
	c.csrf = csrf
	old := c.cookies[sessionCookie].Value
	expectStatus(t, "Abmelden", c.do("DELETE", "/api/v1/sitzung", nil), 204)
	c.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: old}
	expectStatus(t, "alte Sitzung nach Abmeldung", c.do("GET", "/api/v1/ich", nil), 401)
}

func TestFehlerVerratenNichts(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	wrong := c.do("POST", "/api/v1/sitzung", map[string]string{"email": "leser@test.invalid", "passwort": "falsches-passwort-1"})
	unknown := c.do("POST", "/api/v1/sitzung", map[string]string{"email": "niemand@test.invalid", "passwort": "falsches-passwort-1"})
	disabled := c.do("POST", "/api/v1/sitzung", map[string]string{"email": "gesperrt@test.invalid", "passwort": testPassword})
	for name, r := range map[string]response{"falsches Passwort": wrong, "unbekannte E-Mail": unknown, "deaktiviert": disabled} {
		expectStatus(t, name, r, 401)
		if r.body["fehler"] != msgLoginFailed {
			t.Errorf("%s: andere Meldung: %s", name, r.raw)
		}
	}
	owner.Exec(context.Background(), `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1) UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, ids["leser"])
}

func TestKontosperre(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	defer owner.Exec(context.Background(), `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1) UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, ids["sperre"])
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/v1/sitzung", map[string]string{"email": "sperre@test.invalid", "passwort": "falsches-passwort-1"})
	}
	r := c.login("sperre")
	expectStatus(t, "richtiges Passwort bei gesperrtem Konto", r, 401)
	if c.cookies[sessionCookie] != nil {
		t.Error("Sitzung trotz Sperre")
	}
}

func TestFremderUrsprungAbgelehnt(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	c.origin = "https://boese.example"
	expectStatus(t, "fremder Origin", c.login("leser"), 403)
}

func TestUngueltigeAnfragen(t *testing.T) {
	_, srv := newTestServer(t, nil)
	post := func(ct, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sitzung", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := post("application/x-www-form-urlencoded", "email=a"); s != 415 {
		t.Errorf("Formular statt JSON: %d", s)
	}
	if s := post("application/json", `{"email":"a@b.de","passwort":"x","admin":true}`); s != 400 {
		t.Errorf("unbekanntes Feld: %d", s)
	}
	if s := post("application/json", `{"email":"a@b.de","passwort":"`+strings.Repeat("x", 20000)+`"}`); s != 400 {
		t.Errorf("zu großer Body: %d", s)
	}
	if s := post("application/json", `{"email":"a@b.de","passwort":"x"} {"zweites":1}`); s != 400 {
		t.Errorf("zwei JSON-Objekte: %d", s)
	}
}

func TestRateLimitJeAdresse(t *testing.T) {
	_, srv := newTestServer(t, func(c *Config) { c.LoginsPerMinutePerIP = 3 })
	c := newClient(t, srv)
	for i := 0; i < 3; i++ {
		c.do("POST", "/api/v1/sitzung", map[string]string{"email": "niemand@test.invalid", "passwort": "falsches-passwort-1"})
	}
	expectStatus(t, "4. Versuch", c.login("leser"), 429)
}

func TestAdminOhneZweiFaktorEingeschraenkt(t *testing.T) {
	s, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	r := c.login("admin")
	expectStatus(t, "Anmeldung Admin", r, 200)
	if r.body["zwei_faktor_einrichten"] != true {
		t.Errorf("Hinweis auf 2FA-Pflicht fehlt: %s", r.raw)
	}
	expectStatus(t, "ich ohne 2FA", c.do("GET", "/api/v1/ich", nil), 200)

	// Alle normalen Endpunkte (requireSession(false)) sind ohne 2FA gesperrt.
	protected := s.requireSession(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest("GET", "/geschuetzt", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookies[sessionCookie].Value})
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "zwei_faktor_einrichten") {
		t.Errorf("Admin ohne 2FA kommt durch: %d %s", rec.Code, rec.Body.String())
	}

	// Leser ohne 2FA dürfen (keine Pflicht).
	l := newClient(t, srv)
	l.login("leser")
	req = httptest.NewRequest("GET", "/geschuetzt", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: l.cookies[sessionCookie].Value})
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Errorf("Leser ohne 2FA abgewiesen: %d", rec.Code)
	}
}

func TestZweiFaktorEinrichtenUndAnmelden(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	expectStatus(t, "Anmeldung", c.login("zweifa"), 200)
	oldSession := c.cookies[sessionCookie].Value

	r := c.do("POST", "/api/v1/zwei-faktor/einrichten", nil)
	expectStatus(t, "einrichten", r, 200)
	secretText, _ := r.body["geheimnis"].(string)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretText)
	if err != nil || len(secret) != 20 {
		t.Fatalf("Geheimnis: %q %v", secretText, err)
	}
	if uri, _ := r.body["uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI: %q", uri)
	}
	// Das Geheimnis liegt verschlüsselt in der Datenbank, nicht im Klartext.
	var stored []byte
	owner.QueryRow(context.Background(), `SELECT totp_secret_enc FROM openwacht.users WHERE id = $1`, ids["zweifa"]).Scan(&stored)
	if len(stored) == 0 || bytes.Contains(stored, secret) {
		t.Fatal("TOTP-Geheimnis nicht verschlüsselt gespeichert")
	}

	expectStatus(t, "falscher Code", c.do("POST", "/api/v1/zwei-faktor/bestaetigen", map[string]string{"code": "000000"}), 400)
	code := auth.TOTPCode(secret, auth.TOTPStep(time.Now()))
	r = c.do("POST", "/api/v1/zwei-faktor/bestaetigen", map[string]string{"code": code})
	expectStatus(t, "bestätigen", r, 200)
	c.csrf, _ = r.body["csrf"].(string)
	if c.cookies[sessionCookie].Value == oldSession {
		t.Error("Sitzung nach Einrichten nicht erneuert")
	}
	stale := newClient(t, srv)
	stale.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: oldSession}
	expectStatus(t, "alte Sitzung nach 2FA-Einrichtung", stale.do("GET", "/api/v1/ich", nil), 401)
	expectStatus(t, "erneut einrichten", c.do("POST", "/api/v1/zwei-faktor/einrichten", nil), 409)
	expectStatus(t, "abmelden", c.do("DELETE", "/api/v1/sitzung", nil), 204)

	// Anmeldung mit zweitem Faktor.
	c2 := newClient(t, srv)
	r = c2.login("zweifa")
	expectStatus(t, "Passwortschritt", r, 200)
	if r.body["zweiter_faktor"] != true || c2.cookies[sessionCookie] != nil || c2.cookies[pendingCookie] == nil {
		t.Fatalf("Passwortschritt darf nur eine Zwischen-Sitzung liefern: %s", r.raw)
	}
	// Die Zwischen-Sitzung ist keine volle Sitzung.
	fake := newClient(t, srv)
	fake.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: c2.cookies[pendingCookie].Value}
	expectStatus(t, "Zwischen-Sitzung als volle Sitzung", fake.do("GET", "/api/v1/ich", nil), 401)

	expectStatus(t, "falscher Code", c2.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": "123456"}), 401)
	// Der beim Einrichten verbrauchte Code gilt nicht noch einmal (Replay).
	expectStatus(t, "verbrauchter Code", c2.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": code}), 401)
	next := auth.TOTPCode(secret, auth.TOTPStep(time.Now())+1)
	r = c2.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": next})
	expectStatus(t, "richtiger Code", r, 200)
	if c2.cookies[sessionCookie] == nil || c2.cookies[pendingCookie] != nil {
		t.Error("nach zweitem Faktor: volle Sitzung erwartet, Zwischen-Sitzung entfernt")
	}
	c2.csrf, _ = r.body["csrf"].(string)
	me := c2.do("GET", "/api/v1/ich", nil)
	if me.body["zwei_faktor_aktiv"] != true || me.body["zwei_faktor_einrichten"] != false {
		t.Errorf("ich nach 2FA: %s", me.raw)
	}
	owner.Exec(context.Background(), `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1) UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, ids["zweifa"])
}

func TestHashWirdErneuert(t *testing.T) {
	_, srv := newTestServer(t, nil)
	var before, after string
	owner.QueryRow(context.Background(), `SELECT password_hash FROM openwacht.users WHERE id = $1`, ids["altehash"]).Scan(&before)
	expectStatus(t, "Anmeldung", newClient(t, srv).login("altehash"), 200)
	owner.QueryRow(context.Background(), `SELECT password_hash FROM openwacht.users WHERE id = $1`, ids["altehash"]).Scan(&after)
	if before == after || !strings.Contains(after, "m=64,") {
		t.Errorf("Hash nicht auf aktuelle Kosten erneuert: %s", after)
	}
}

func TestClientAdresseHinterProxy(t *testing.T) {
	u, _ := url.Parse("https://openwacht.test")
	s, err := New(Config{BaseURL: u, PasswordParams: &testParams,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}, nil, testKey)
	if err != nil {
		t.Fatal(err)
	}
	ip := func(remote, xff string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return s.clientIP(r).String()
	}
	if got := ip("10.0.0.1:1234", "1.2.3.4, 5.6.7.8"); got != "5.6.7.8" {
		t.Errorf("hinter vertrauenswürdigem Proxy: %s", got)
	}
	if got := ip("192.0.2.9:1234", "1.2.3.4"); got != "192.0.2.9" {
		t.Errorf("gefälschtes X-Forwarded-For übernommen: %s", got)
	}
}

func TestNurHTTPSAusserLokal(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://openwacht.test": true, "http://localhost:8080": true,
		"http://127.0.0.1:8080": true, "http://openwacht.test": false,
	} {
		u, _ := url.Parse(raw)
		_, err := New(Config{BaseURL: u, PasswordParams: &testParams}, nil, testKey)
		if (err == nil) != ok {
			t.Errorf("%s: Fehler %v", raw, err)
		}
	}
}

func TestStartVerweigertFalscheRolle(t *testing.T) {
	ctx := context.Background()
	if err := CheckAppRole(ctx, pool); err != nil {
		t.Fatalf("Anwendungsrolle abgelehnt: %v", err)
	}
	ocfg, _ := pgxpool.ParseConfig("")
	ocfg.ConnConfig = owner.Config().Copy()
	op, err := pgxpool.NewWithConfig(ctx, ocfg)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if err := CheckAppRole(ctx, op); err == nil {
		t.Fatal("Start als Eigentümer nicht verweigert")
	}
}

func TestEinrichtungNurEinmal(t *testing.T) {
	ctx := context.Background()
	err := Bootstrap(ctx, owner, "Zweite", "neu@test.invalid", "Neu", testPassword, testParams)
	if !errors.Is(err, ErrAlreadySetUp) {
		t.Fatalf("zweite Einrichtung: %v", err)
	}
	// Frische Installation: Einrichtung klappt, Admin kann sich anmelden.
	tdb, err := dbtest.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	o, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(ctx)
	if _, err := db.Migrate(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := Bootstrap(ctx, o, "IT", "Chef@Test.invalid", "Chef", "kurz", testParams); err == nil {
		t.Fatal("zu kurzes Passwort akzeptiert")
	}
	if err := Bootstrap(ctx, o, "IT", "Chef@Test.invalid", "Chef", testPassword, testParams); err != nil {
		t.Fatal(err)
	}
	pcfg, _ := pgxpool.ParseConfig("")
	pcfg.ConnConfig = tdb.AppCfg.Copy()
	p, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s, err := New(Config{BaseURL: u, PasswordParams: &testParams}, p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s.Handler()
	c := newClient(t, srv)
	r := c.do("POST", "/api/v1/sitzung", map[string]string{"email": "chef@test.invalid", "passwort": testPassword})
	expectStatus(t, "Anmeldung des ersten Admins", r, 200)
	if r.body["zwei_faktor_einrichten"] != true {
		t.Error("erster Admin muss 2FA einrichten")
	}
}

func TestOberflaecheAusliefern(t *testing.T) {
	s, srv := newTestServer(t, nil)
	s.ui = fstest.MapFS{
		"index.html":             {Data: []byte("<!doctype html><title>OpenWacht</title>")},
		"assets/app-abc123.js":   {Data: []byte("console.log(1)")},
		"thema.js":               {Data: []byte("(function(){})();")},
		"manifest.json":          {Data: []byte(`{"name":"OpenWacht"}`)},
		"apple-touch-icon.png":   {Data: []byte("\x89PNG\r\n\x1a\n")},
		"assets/D-DIN-abc.woff2": {Data: []byte("wOF2")},
		"lizenzen/OFL-D-DIN.txt": {Data: []byte("SIL OPEN FONT LICENSE")},
	}
	srv.Config.Handler = s.Handler()
	get := func(p string) *http.Response {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := get("/"); r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-cache" || r.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("/: %d %v", r.StatusCode, r.Header)
	}
	if r := get("/mandanten/irgendwas"); r.StatusCode != 200 {
		t.Errorf("Browser-Route liefert nicht index.html: %d", r.StatusCode)
	}
	if r := get("/assets/app-abc123.js"); r.StatusCode != 200 || !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("Asset: %d %s", r.StatusCode, r.Header.Get("Cache-Control"))
	}
	// Darstellung (Etappe 16): vor dem ersten Zeichnen geladen, nicht dauerhaft
	// zwischengespeichert, sonst greift eine geänderte Logik erst Tage später.
	if r := get("/thema.js"); r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-cache" ||
		!strings.Contains(r.Header.Get("Content-Type"), "javascript") {
		t.Errorf("/thema.js: %d %v", r.StatusCode, r.Header)
	}
	// App-Icon und Manifest (Corporate Design): mit passendem Typ, nicht als index.html.
	if r := get("/manifest.json"); r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "json") {
		t.Errorf("/manifest.json: %d %v", r.StatusCode, r.Header)
	}
	if r := get("/apple-touch-icon.png"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/png" {
		t.Errorf("/apple-touch-icon.png: %d %v", r.StatusCode, r.Header)
	}
	// Schriften (Corporate Design): als Schrift, lange zwischengespeichert;
	// der Lizenztext wird mit ausgeliefert.
	if r := get("/assets/D-DIN-abc.woff2"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "font/woff2" ||
		!strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("Schrift: %d %v", r.StatusCode, r.Header)
	}
	if r := get("/lizenzen/OFL-D-DIN.txt"); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("Lizenztext: %d %v", r.StatusCode, r.Header)
	}
	if r := get("/assets/fehlt.js"); r.StatusCode != 404 {
		t.Errorf("fehlende Datei: %d", r.StatusCode)
	}
	if r := get("/../../etc/passwd"); r.StatusCode == 200 && r.ContentLength > 100 {
		t.Errorf("Pfad außerhalb ausgeliefert")
	}
	if r := get("/api/v1/unbekannt"); r.StatusCode != 404 {
		t.Errorf("API-Pfad fällt nicht auf die Oberfläche zurück: %d", r.StatusCode)
	}
	// Ohne gebaute Oberfläche: verständliche Meldung statt leerer Seite.
	s.ui = fstest.MapFS{"LIESMICH.txt": {Data: []byte("x")}}
	srv.Config.Handler = s.Handler()
	if r := get("/"); r.StatusCode != 503 {
		t.Errorf("ohne Oberfläche: %d", r.StatusCode)
	}
}
