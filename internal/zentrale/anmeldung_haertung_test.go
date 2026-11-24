// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Etappe 30: Härtung der Anmeldung (M1, M4, M8, N5, I2).

import (
	"context"
	"encoding/base32"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
)

// quellenServer: eigener Server, der X-Forwarded-For von 127.0.0.1 annimmt,
// damit Tests verschiedene Quellen simulieren können. Wartezeiten werden nur
// aufgezeichnet.
func quellenServer(t *testing.T) (*Server, *httptest.Server, *[]time.Duration) {
	t.Helper()
	s, srv := settingsServer(t, Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	var mu sync.Mutex
	waits := []time.Duration{}
	s.loginWait = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		waits = append(waits, d)
		return nil
	}
	return s, srv, &waits
}

func resetLogin(t *testing.T, user string) {
	t.Helper()
	owner.Exec(context.Background(), `WITH d AS (DELETE FROM openwacht.login_sources WHERE user_id = $1)
		UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, ids[user])
}

func from(t *testing.T, srv *httptest.Server, addr string) *client {
	c := newClient(t, srv)
	c.xff = addr
	return c
}

func TestSperreNurJeKontoUndQuelle(t *testing.T) {
	_, srv, waits := quellenServer(t)
	kontoMitRollen(t, "q_konto", "Fertigung", map[string]string{"Fertigung": "leser"}, false, false)
	resetLogin(t, "q_konto")
	t.Cleanup(func() { resetLogin(t, "q_konto") })

	// Bekannte Quelle: angemeldet, Sitzung läuft.
	home := from(t, srv, "198.51.100.7")
	expectStatus(t, "Anmeldung von zu Hause", home.login("q_konto"), 200)

	// Angreifer: fünf Fehlversuche aus einer anderen Quelle.
	bad := from(t, srv, "203.0.113.5")
	for i := 0; i < 5; i++ {
		r := bad.do("POST", "/api/v1/sitzung", map[string]string{"email": "q_konto@test.invalid", "passwort": "falsches-passwort-1"})
		expectStatus(t, "Fehlversuch", r, 401)
	}
	r := bad.login("q_konto")
	expectStatus(t, "richtiges Passwort aus gesperrter Quelle", r, 401)
	if r.body["fehler"] != msgLoginFailed {
		t.Errorf("Meldung bei Sperre verrät etwas: %s", r.raw)
	}
	// Die laufende Sitzung bleibt, die bekannte Quelle meldet sich ohne Wartezeit an.
	expectStatus(t, "Sitzung nach Fehlversuchen", home.do("GET", "/api/v1/ich", nil), 200)
	if len(*waits) != 0 {
		t.Errorf("Wartezeit für die bekannte Quelle oder den Angreifer: %v", *waits)
	}

	// Unbekannte IPv6-Quelle: ein Fehlversuch, danach wartet dasselbe /64.
	v6 := from(t, srv, "2001:db8:1:2::1")
	expectStatus(t, "IPv6 falsch", v6.do("POST", "/api/v1/sitzung", map[string]string{"email": "q_konto@test.invalid", "passwort": "falsches-passwort-1"}), 401)
	v6b := from(t, srv, "2001:db8:1:2:ffff::9")
	expectStatus(t, "IPv6 gleiches /64 richtig", v6b.login("q_konto"), 200)
	if len(*waits) != 1 || (*waits)[0] < 500*time.Millisecond || (*waits)[0] > 1100*time.Millisecond {
		t.Errorf("Wartezeit für unbekannte Quelle: %v", *waits)
	}
	// Erfolg hebt die Wartezeit auf; das /64 gilt jetzt als bekannt.
	expectStatus(t, "von zu Hause erneut", from(t, srv, "198.51.100.7").login("q_konto"), 200)

	// Die gesperrte Quelle bleibt gesperrt, auch für den zweiten Faktor eines anderen Kontos nicht relevant.
	expectStatus(t, "gesperrte Quelle weiter gesperrt", from(t, srv, "203.0.113.5").login("q_konto"), 401)

	// Leitprinzip 5: Adressen stehen nicht in der Datenbank.
	var raw string
	owner.QueryRow(context.Background(), `SELECT string_agg(encode(source_hash, 'escape'), '') FROM openwacht.login_sources WHERE user_id = $1`, ids["q_konto"]).Scan(&raw)
	if strings.Contains(raw, "203.0.113.5") || strings.Contains(raw, "198.51.100.7") {
		t.Error("Adresse im Klartext gespeichert")
	}
}

func TestRateLimitIPv6JeSechzigVier(t *testing.T) {
	l := newIPLimiter(2, time.Minute)
	now := time.Now()
	for i, a := range []string{"2001:db8::1", "2001:db8::2"} {
		if !l.allow(netip.MustParseAddr(a), now) {
			t.Fatalf("Versuch %d abgelehnt", i)
		}
	}
	if l.allow(netip.MustParseAddr("2001:db8::ffff:3"), now) {
		t.Error("drittes Mal im selben /64 erlaubt")
	}
	if !l.allow(netip.MustParseAddr("2001:db8:0:1::1"), now) {
		t.Error("anderes /64 abgelehnt")
	}
	if !l.allow(netip.MustParseAddr("192.0.2.1"), now) || !l.allow(netip.MustParseAddr("192.0.2.2"), now) || !l.allow(netip.MustParseAddr("192.0.2.3"), now) {
		t.Error("IPv4-Adressen werden zusammengefasst")
	}
	if got := limitKey(netip.MustParseAddr("::ffff:192.0.2.9")); got != netip.MustParseAddr("192.0.2.9") {
		t.Errorf("IPv4 in IPv6: %v", got)
	}
}

var recoveryRe = regexp.MustCompile(`^[a-hjkmnp-z2-9]{5}-[a-hjkmnp-z2-9]{5}$`)

func TestWiederherstellungscodesAPI(t *testing.T) {
	_, srv, _ := quellenServer(t)
	kontoMitRollen(t, "q_codes", "Fertigung", map[string]string{"Fertigung": "leser"}, false, false)
	t.Cleanup(func() { resetLogin(t, "q_codes") })
	c := newClient(t, srv)
	expectStatus(t, "Anmeldung", c.login("q_codes"), 200)
	expectStatus(t, "Codes ohne 2FA", c.do("POST", "/api/v1/zwei-faktor/codes", map[string]string{"code": "123456"}), 409)
	r := c.do("POST", "/api/v1/zwei-faktor/einrichten", nil)
	expectStatus(t, "einrichten", r, 200)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.body["geheimnis"].(string))
	step := auth.TOTPStep(time.Now())
	r = c.do("POST", "/api/v1/zwei-faktor/bestaetigen", map[string]string{"code": auth.TOTPCode(secret, step)})
	expectStatus(t, "bestätigen", r, 200)
	list, _ := r.body["wiederherstellungscodes"].([]any)
	if len(list) != 10 {
		t.Fatalf("Codes: %s", r.raw)
	}
	codes := make([]string, len(list))
	seen := map[string]bool{}
	for i, x := range list {
		codes[i], _ = x.(string)
		if !recoveryRe.MatchString(codes[i]) || seen[codes[i]] {
			t.Errorf("Code %q", codes[i])
		}
		seen[codes[i]] = true
	}
	c.csrf, _ = r.body["csrf"].(string)
	if me := c.do("GET", "/api/v1/ich", nil); me.body["wiederherstellungscodes_offen"] != float64(10) {
		t.Errorf("ich: %s", me.raw)
	}
	// Klartext liegt nicht in der Datenbank.
	var stored string
	owner.QueryRow(context.Background(), `SELECT string_agg(encode(code_hash, 'hex'), ',') FROM openwacht.recovery_codes WHERE user_id = $1`, ids["q_codes"]).Scan(&stored)
	if strings.Contains(stored, strings.ReplaceAll(codes[0], "-", "")) {
		t.Error("Code im Klartext gespeichert")
	}

	secondStep := func(code string) response {
		t.Helper()
		d := newClient(t, srv)
		r := d.login("q_codes")
		if r.body["zweiter_faktor"] != true {
			t.Fatalf("kein zweiter Faktor: %s", r.raw)
		}
		return d.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": code})
	}
	// Groß geschrieben und ohne Bindestrich geht auch.
	r = secondStep(" " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", " ")) + " ")
	expectStatus(t, "mit Wiederherstellungscode", r, 200)
	if r.body["wiederherstellungscodes_offen"] != float64(9) {
		t.Errorf("offen: %s", r.raw)
	}
	expectStatus(t, "Code zweimal", secondStep(codes[0]), 401)
	expectStatus(t, "falscher Code", secondStep("abcde-fghjk"), 401)
	expectStatus(t, "Unsinn", secondStep(strings.Repeat("x", 500)), 401)

	// Neue Codes nur mit frischem Code aus der App; die alten verfallen.
	expectStatus(t, "neue Codes ohne Code", c.do("POST", "/api/v1/zwei-faktor/codes", map[string]string{"code": ""}), 403)
	owner.Exec(context.Background(), `UPDATE openwacht.users SET totp_last_step = 0 WHERE id = $1`, ids["q_codes"])
	r = c.do("POST", "/api/v1/zwei-faktor/codes", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(time.Now()))})
	expectStatus(t, "neue Codes", r, 200)
	if l, _ := r.body["wiederherstellungscodes"].([]any); len(l) != 10 {
		t.Errorf("neue Codes: %s", r.raw)
	}
	resetLogin(t, "q_codes")
	expectStatus(t, "alter Code nach Erneuerung", secondStep(codes[1]), 401)

	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('zweifaktor.code_verwendet', 'zweifaktor.codes_erzeugt')
		AND details IS NOT NULL AND tenant_id = $1 AND at > now() - interval '5 minutes'`, ids["Fertigung"]).Scan(&n)
	if n < 2 {
		t.Errorf("Audit-Einträge: %d", n)
	}
}

func TestBetreiberImmerMitZweiFaktor(t *testing.T) {
	_, srv, _ := quellenServer(t)
	resetSettings(t)
	t.Cleanup(func() {
		resetSettings(t)
		owner.Exec(context.Background(), `UPDATE openwacht.settings SET mfa_policy = NULL`)
	})
	owner.Exec(context.Background(), `UPDATE openwacht.settings SET mfa_policy = 'freiwillig'`)
	kontoMitRollen(t, "q_betr", "IT", map[string]string{"IT": "admin"}, false, false)
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.users SET platform_operator = true WHERE id = $1`, ids["q_betr"]); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv)
	r := c.login("q_betr")
	expectStatus(t, "Anmeldung", r, 200)
	if r.body["zwei_faktor_einrichten"] != true {
		t.Errorf("Betreiber ohne 2FA-Pflicht: %s", r.raw)
	}
	expectStatus(t, "Einstellungen ohne 2FA", c.do("GET", "/api/v1/einstellungen", nil), 403)
	if me := c.do("GET", "/api/v1/ich", nil); me.body["betreiber"] == true {
		t.Error("Betreiber ohne TOTP wirksam")
	}
}

func TestBestaetigungZaehltFehlversuche(t *testing.T) {
	_, srv, _ := quellenServer(t)
	t.Cleanup(func() { owner.Exec(context.Background(), `UPDATE openwacht.settings SET mfa_policy = NULL`) })
	owner.Exec(context.Background(), `UPDATE openwacht.settings SET mfa_policy = 'freiwillig'`)
	kontoMitRollen(t, "q_best", "Fertigung", map[string]string{"Fertigung": "admin"}, false, false)
	t.Cleanup(func() { resetLogin(t, "q_best") })
	c := from(t, srv, "203.0.113.20")
	expectStatus(t, "Anmeldung", c.login("q_best"), 200)
	body := func(code string) map[string]any {
		return map[string]any{"mandant": ids["Fertigung"], "name": "Test", "rolle": "leser", "tage": 1, "code": code}
	}
	for i := 0; i < 5; i++ {
		expectStatus(t, "falsches Passwort", c.do("POST", "/api/v1/api-tokens", body("falsches-passwort-1")), 403)
	}
	r := c.do("POST", "/api/v1/api-tokens", body(testPassword))
	expectStatus(t, "richtiges Passwort nach fünf Fehlversuchen", r, 403)
	if !strings.Contains(r.raw, "Zu viele Fehlversuche") {
		t.Errorf("Meldung: %s", r.raw)
	}
	expectStatus(t, "Anmeldung aus derselben Quelle", from(t, srv, "203.0.113.20").login("q_best"), 401)
	d := from(t, srv, "198.51.100.20")
	expectStatus(t, "Anmeldung aus anderer Quelle", d.login("q_best"), 200)
	expectStatus(t, "Bestätigung aus anderer Quelle", d.do("POST", "/api/v1/api-tokens", body(testPassword)), 201)
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'bestaetigung.fehlgeschlagen' AND tenant_id = $1
		AND at > now() - interval '5 minutes'`, ids["Fertigung"]).Scan(&n)
	if n < 5 {
		t.Errorf("Audit „bestaetigung.fehlgeschlagen“: %d (ging bis 0.29 verloren)", n)
	}
	owner.Exec(context.Background(), `DELETE FROM openwacht.api_tokens WHERE tenant_id = $1 AND name = 'Test'`, ids["Fertigung"])
}

func TestAnmeldeDomaenenNurNachFreigabe(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	setOperator(t, "v_it", true)
	t.Cleanup(func() {
		setOperator(t, "v_it", false)
		owner.Exec(ctx, `DELETE FROM openwacht.directories WHERE name LIKE 'M1 %'`)
	})
	mk := func(tenant, name, netbios, dom string) string {
		t.Helper()
		var id string
		var nb *string
		if netbios != "" {
			nb = &netbios
		}
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.directories (tenant_id, name, url, bind_dn, bind_pass_enc, base_dn, netbios)
			VALUES ($1, $2, 'ldaps://dc.example.com', 'cn=svc,dc=x', $3, 'dc=x', $4) RETURNING id::text`,
			ids[tenant], name, make([]byte, 40), nb).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.directory_domains (domain, directory_id, tenant_id) VALUES ($1, $2, $3)`, dom, id, ids[tenant]); err != nil {
			t.Fatal(err)
		}
		return id
	}
	fwDir := mk("Fertigung", "M1 FW", "M1FW", "m1-fw.example")
	oaDir := mk("Organisation", "M1 OA", "", "m1-fw.example")
	fw := as(t, "v_fw")
	it := as(t, "v_it")
	oa := as(t, "v_oa")

	r := fw.do("GET", "/api/v1/verzeichnisse", nil)
	if !strings.Contains(r.raw, `"m1-fw.example":"beantragt"`) || !strings.Contains(r.raw, `"netbios_status":"beantragt"`) {
		t.Errorf("Liste zeigt den Antrag nicht: %s", r.raw)
	}
	for u, c := range map[string]*client{"v_fw": fw, "v_oa": oa} {
		expectStatus(t, u+" liest Anträge", c.do("GET", "/api/v1/einstellungen/anmeldedomaenen", nil), 403)
	}
	r = it.do("GET", "/api/v1/einstellungen/anmeldedomaenen", nil)
	expectStatus(t, "Betreiber liest Anträge", r, 200)
	if !strings.Contains(r.raw, fwDir) || !strings.Contains(r.raw, oaDir) || !strings.Contains(r.raw, "M1FW") {
		t.Errorf("Anträge: %s", r.raw)
	}
	decide := func(c *client, dir, kind, value string, ok bool, code string) response {
		return c.do("POST", "/api/v1/einstellungen/anmeldedomaenen", map[string]any{
			"verzeichnis": dir, "art": kind, "wert": value, "freigeben": ok, "code": code})
	}
	expectStatus(t, "Untermandant gibt sich selbst frei", decide(fw, fwDir, "domaene", "m1-fw.example", true, freshCode(t, "v_fw")), 403)
	expectStatus(t, "Geschwister gibt frei", decide(oa, fwDir, "domaene", "m1-fw.example", true, freshCode(t, "v_oa")), 403)
	expectStatus(t, "Betreiber ohne Code", decide(it, fwDir, "domaene", "m1-fw.example", true, ""), 403)
	expectStatus(t, "ungültige Art", decide(it, fwDir, "egal", "m1-fw.example", true, freshCode(t, "v_it")), 400)
	expectStatus(t, "unbekannter Antrag", decide(it, fwDir, "domaene", "gibt-es-nicht.example", true, freshCode(t, "v_it")), 404)
	expectStatus(t, "Betreiber gibt frei", decide(it, fwDir, "domaene", "m1-fw.example", true, freshCode(t, "v_it")), 200)
	expectStatus(t, "Betreiber gibt NetBIOS frei", decide(it, fwDir, "netbios", "m1fw", true, freshCode(t, "v_it")), 200)
	expectStatus(t, "zweite Freigabe derselben Domäne", decide(it, oaDir, "domaene", "m1-fw.example", true, freshCode(t, "v_it")), 409)
	expectStatus(t, "Ablehnung", decide(it, oaDir, "domaene", "m1-fw.example", false, freshCode(t, "v_it")), 200)
	var id string
	pool.QueryRow(ctx, `SELECT id::text FROM openwacht.directory_for_login('m1-fw.example', NULL)`).Scan(&id)
	if id != fwDir {
		t.Errorf("Anmeldung landet bei %q", id)
	}
	r = oa.do("GET", "/api/v1/verzeichnisse", nil)
	if !strings.Contains(r.raw, `"m1-fw.example":"abgelehnt"`) || strings.Contains(r.raw, fwDir) {
		t.Errorf("Organisation sieht: %s", r.raw)
	}
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'anmeldedomaene.entschieden' AND at > now() - interval '5 minutes'`).Scan(&audits)
	if audits != 3 {
		t.Errorf("Audit beim Betreiber: %d", audits)
	}
}

func TestSitzungsdauerJeAnbindung(t *testing.T) {
	s, _, _ := quellenServer(t)
	ctx := context.Background()
	kontoMitRollen(t, "q_sso", "Fertigung", map[string]string{"Fertigung": "leser"}, false, false)
	var dir string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.directories (tenant_id, name, url, bind_dn, bind_pass_enc, base_dn, session_hours)
		VALUES ($1, 'I2 Test', 'ldaps://dc.example.com', 'cn=svc,dc=x', $2, 'dc=x', 2) RETURNING id::text`,
		ids["Fertigung"], make([]byte, 40)).Scan(&dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.users SET directory_id = NULL WHERE id = $1`, ids["q_sso"])
		owner.Exec(ctx, `DELETE FROM openwacht.directories WHERE id = $1`, dir)
	})
	src := make([]byte, 32)
	lifetime := func() (time.Duration, int) {
		t.Helper()
		rec := httptest.NewRecorder()
		if _, err := s.newSession(ctx, rec, ids["q_sso"], src); err != nil {
			t.Fatal(err)
		}
		var secs float64
		owner.QueryRow(ctx, `SELECT extract(epoch FROM expires_at - created_at) FROM openwacht.sessions WHERE user_id = $1
			ORDER BY created_at DESC LIMIT 1`, ids["q_sso"]).Scan(&secs)
		maxAge := 0
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookie {
				maxAge = c.MaxAge
			}
		}
		return time.Duration(secs) * time.Second, maxAge
	}
	if d, m := lifetime(); d != 12*time.Hour || m != 12*3600 {
		t.Errorf("lokales Konto: %v / %d", d, m)
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET directory_id = $2 WHERE id = $1`, ids["q_sso"], dir)
	if d, m := lifetime(); d != 2*time.Hour || m != 2*3600 {
		t.Errorf("Konto der Anbindung: %v / %d", d, m)
	}
}
