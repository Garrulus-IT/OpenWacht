// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// freshInstall: eigene, leere Datenbank (die gemeinsame hat schon einen
// Hauptmandanten) mit Eigentümer-Verbindung und App-Pool.
func freshInstall(t *testing.T) (*pgx.Conn, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tdb.Close)
	o, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close(ctx) })
	if _, err := db.Migrate(ctx, o); err != nil {
		t.Fatal(err)
	}
	pcfg, _ := pgxpool.ParseConfig("")
	pcfg.ConnConfig = tdb.AppCfg.Copy()
	p, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return o, p
}

// setupToken legt wie `einrichtungslink` ein Token an (als Eigentümer).
func setupToken(t *testing.T, o *pgx.Conn) string {
	t.Helper()
	raw, hash, err := NewSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(context.Background(), `UPDATE openwacht.setup_state SET token_hash = $1, expires_at = now() + interval '2 hours'`, hash); err != nil {
		t.Fatal(err)
	}
	return raw
}

func setupServer(t *testing.T, p *pgxpool.Pool) (*Setup, *client) {
	t.Helper()
	s, err := NewSetup(p, testKey, &testParams)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, newClient(t, srv)
}

func totpNow(t *testing.T, geheimnis string) string {
	t.Helper()
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(geheimnis)
	if err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCode(sec, auth.TOTPStep(time.Now()))
}

func finishBody(email string) map[string]any {
	return map[string]any{
		"mandant":   "IT",
		"admin":     map[string]any{"name": "Erika Mustermann", "email": email, "passwort": "ein-sehr-langes-passwort-42"},
		"adressen":  []string{"openwacht.example.com", "10.10.0.5"},
		"zeitzone":  "Europe/Berlin",
		"netze":     []string{"10.10.0.0/16"},
		"sicherung": map[string]int{"uhr": 2, "tage": 21},
	}
}

func TestEinrichtungAblauf(t *testing.T) {
	ctx := context.Background()
	o, p := freshInstall(t)
	if open, err := SetupOpen(ctx, p); err != nil || !open {
		t.Fatalf("Einrichtung offen: %v %v", open, err)
	}
	// Vorläufiges Zertifikat: einmal angelegt, nicht überschrieben.
	if err := EnsureSetupCert(ctx, p, testKey, []string{"openwacht", "10.10.0.5"}); err != nil {
		t.Fatal(err)
	}
	h1, err := LoadHTTPS(ctx, p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureSetupCert(ctx, p, testKey, []string{"anders"}); err != nil {
		t.Fatal(err)
	}
	h2, _ := LoadHTTPS(ctx, p, testKey)
	if h1.info()["fingerabdruck"] != h2.info()["fingerabdruck"] {
		t.Fatal("vorläufiges Zertifikat überschrieben")
	}

	raw := setupToken(t, o)
	s, c := setupServer(t, p)

	// Ohne Token, mit falschem Token, ohne Cookie: kein Zugang.
	expectStatus(t, "ohne Cookie", c.do("GET", "/api/v1/einrichtung", nil), 403)
	expectStatus(t, "falsches Token", c.do("POST", "/api/v1/einrichtung/start", map[string]string{"token": raw[:len(raw)-2] + "xx"}), 403)
	expectStatus(t, "andere API", c.do("GET", "/api/v1/ich", nil), 503)
	// Fremder Ursprung
	c.origin = "https://boese.example"
	expectStatus(t, "fremder Ursprung", c.do("POST", "/api/v1/einrichtung/start", map[string]string{"token": raw}), 403)
	c.origin = c.base

	r := c.do("POST", "/api/v1/einrichtung/start", map[string]string{"token": raw})
	expectStatus(t, "Start", r, 200)
	if c.cookies[setupCookie] == nil || !c.cookies[setupCookie].HttpOnly {
		t.Fatal("kein HttpOnly-Cookie")
	}
	expectStatus(t, "Zustand", c.do("GET", "/api/v1/einrichtung", nil), 200)

	// Fertig ohne 2FA und Zertifikat geht nicht.
	expectStatus(t, "Fertig ohne 2FA", c.do("POST", "/api/v1/einrichtung/fertig", finishBody("erika@example.com")), 400)

	r = c.do("POST", "/api/v1/einrichtung/zwei-faktor", map[string]string{"email": "Erika@Example.com"})
	expectStatus(t, "2FA beginnen", r, 200)
	geheimnis, _ := r.body["geheimnis"].(string)
	expectStatus(t, "falscher Code", c.do("POST", "/api/v1/einrichtung/zwei-faktor/pruefen", map[string]string{"code": "000000"}), 400)
	code := totpNow(t, geheimnis)
	expectStatus(t, "Code", c.do("POST", "/api/v1/einrichtung/zwei-faktor/pruefen", map[string]string{"code": code}), 200)

	// Andere E-Mail als die mit 2FA: abgelehnt.
	expectStatus(t, "andere E-Mail", c.do("POST", "/api/v1/einrichtung/fertig", finishBody("jemand@example.com")), 400)

	expectStatus(t, "HTTPS falsche Adresse", c.do("POST", "/api/v1/einrichtung/https",
		map[string]any{"art": "eigene-ca", "adressen": []string{"*.example.com"}}), 400)
	r = c.do("POST", "/api/v1/einrichtung/https", map[string]any{"art": "eigene-ca", "adressen": []string{"openwacht.example.com"}})
	expectStatus(t, "HTTPS", r, 200)
	// Zertifikat für andere Adressen als in „Fertig“: abgelehnt.
	expectStatus(t, "Zertifikat passt nicht", c.do("POST", "/api/v1/einrichtung/fertig", finishBody("erika@example.com")), 400)
	r = c.do("POST", "/api/v1/einrichtung/https", map[string]any{"art": "eigene-ca", "adressen": []string{"openwacht.example.com", "10.10.0.5"}})
	expectStatus(t, "HTTPS", r, 200)
	caFP, _ := r.body["ca_fingerabdruck"].(string)

	// Zu kurzes Passwort
	b := finishBody("erika@example.com")
	b["admin"].(map[string]any)["passwort"] = "kurz"
	expectStatus(t, "kurzes Passwort", c.do("POST", "/api/v1/einrichtung/fertig", b), 400)
	// Ungültige Mail-Einstellung
	b = finishBody("erika@example.com")
	b["mail"] = map[string]any{"server": "smtp.example.com", "port": 587, "tls": "keine", "absender": "ow@example.com"}
	expectStatus(t, "Klartext-Mail", c.do("POST", "/api/v1/einrichtung/fertig", b), 400)

	b = finishBody("erika@example.com")
	b["mail"] = map[string]any{"server": "smtp.example.com", "port": 587, "tls": "starttls", "absender": "ow@example.com",
		"benutzer": "ow", "passwort": "geheim-smtp"}
	r = c.do("POST", "/api/v1/einrichtung/fertig", b)
	expectStatus(t, "Fertig", r, 200)
	if r.body["adresse"] != "https://openwacht.example.com" {
		t.Fatalf("Adresse %v", r.body["adresse"])
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done nicht geschlossen")
	}

	// Danach: Link tot, Assistent liefert 410.
	expectStatus(t, "zweiter Start", c.do("POST", "/api/v1/einrichtung/start", map[string]string{"token": raw}), 410)
	expectStatus(t, "Fertig nochmal", c.do("POST", "/api/v1/einrichtung/fertig", b), 410)
	if open, _ := SetupOpen(ctx, p); open {
		t.Fatal("Einrichtung noch offen")
	}

	// Inhalt der Datenbank
	var totp, op bool
	var role, tenant string
	var last int64
	if err := o.QueryRow(ctx, `SELECT u.totp_enabled, u.platform_operator, ra.role, t.name, u.totp_last_step
		FROM openwacht.users u JOIN openwacht.role_assignments ra ON ra.user_id = u.id JOIN openwacht.tenants t ON t.id = u.tenant_id
		WHERE u.email = 'erika@example.com'`).Scan(&totp, &op, &role, &tenant, &last); err != nil {
		t.Fatal(err)
	}
	if !totp || !op || role != "admin" || tenant != "IT" || last == 0 {
		t.Fatalf("Admin: totp=%v betreiber=%v rolle=%s mandant=%s schritt=%d", totp, op, role, tenant, last)
	}
	var base, tz, kind string
	var hour, days int16
	var names []string
	var nets []string
	var smtpPass []byte
	if err := o.QueryRow(ctx, `SELECT s.base_url, s.timezone, s.backup_hour, s.backup_days, s.names, s.check_nets::text[], s.smtp_pass_enc, h.kind
		FROM openwacht.settings s, openwacht.https_material h`).Scan(&base, &tz, &hour, &days, &names, &nets, &smtpPass, &kind); err != nil {
		t.Fatal(err)
	}
	if base != "https://openwacht.example.com" || tz != "Europe/Berlin" || hour != 2 || days != 21 || strings.Join(names, ",") != "openwacht.example.com,10.10.0.5" ||
		strings.Join(nets, ",") != "10.10.0.0/16" || len(smtpPass) == 0 || kind != "eigene-ca" {
		t.Fatalf("Einstellungen: %s %s %d %d %v %v %d %s", base, tz, hour, days, names, nets, len(smtpPass), kind)
	}
	var tok []byte
	var done *time.Time
	o.QueryRow(ctx, `SELECT token_hash, done_at FROM openwacht.setup_state`).Scan(&tok, &done)
	if tok != nil || done == nil {
		t.Fatal("Token nicht gelöscht oder nicht abgeschlossen")
	}
	var audit int
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'installation.eingerichtet'`).Scan(&audit)
	if audit != 1 {
		t.Fatalf("Audit %d", audit)
	}

	// Gespeichertes Zertifikat: eigene CA mit Beschränkung, Schlüssel lesbar.
	h, err := LoadHTTPS(ctx, p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if h.info()["ca_fingerabdruck"] != caFP || h.ca.Cert.PermittedDNSDomains[0] != "openwacht.example.com" {
		t.Fatal("CA nicht die aus dem Assistenten")
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	if _, err := h.cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.10.0.5"}); err != nil {
		t.Fatalf("Serverzertifikat: %v", err)
	}
	// Mit falschem Hauptschlüssel nicht lesbar.
	other := make([]byte, auth.KeySize)
	if _, err := LoadHTTPS(ctx, p, other); err == nil {
		t.Fatal("Zertifikat mit falschem Schlüssel geladen")
	}

	// Erneuerung erst kurz vor Ablauf.
	if ok, err := h.RenewIfDue(ctx); err != nil || ok {
		t.Fatalf("zu früh erneuert: %v %v", ok, err)
	}
	old := h.info()["fingerabdruck"]
	h.now = func() time.Time { return time.Now().Add(pki.HTTPSLeafValidity - 10*24*time.Hour) }
	if ok, err := h.RenewIfDue(ctx); err != nil || !ok {
		t.Fatalf("nicht erneuert: %v %v", ok, err)
	}
	if h.info()["fingerabdruck"] == old || h.info()["ca_fingerabdruck"] != caFP {
		t.Fatal("Erneuerung falsch (neues Serverzertifikat, gleiche CA erwartet)")
	}
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'https.erneuert'`).Scan(&audit)
	if audit != 1 {
		t.Fatalf("Audit Erneuerung %d", audit)
	}
	// Nach der Einrichtung kein vorläufiges Zertifikat mehr.
	if _, err := p.Exec(ctx, `SELECT openwacht.https_setup_init('x', '\x00', '{a}')`); !isCode(err, "42501") {
		t.Fatalf("https_setup_init nach Fertig: %v", err)
	}
}

func isCode(err error, code string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == code
}

// Die Datenbank schützt selbst: ohne gültiges Token kein setup_finish, kein
// Zugriff der App-Rolle auf die Tabellen, https_put nur für Betreiber.
func TestEinrichtungDatenbank(t *testing.T) {
	ctx := context.Background()
	o, p := freshInstall(t)
	raw := setupToken(t, o)
	call := func(hash []byte) error {
		_, err := p.Exec(ctx, `SELECT openwacht.setup_finish($1, gen_random_uuid(), 'IT', 'a@example.com', 'A', 'x', NULL, 0,
			'https://a.example.com', '{a.example.com}', 'Europe/Berlin', '{}', NULL, NULL, NULL, NULL, NULL, NULL, 0::smallint, 14::smallint,
			'hochgeladen', repeat('x', 200), repeat('y', 40)::bytea, NULL, NULL)`, hash)
		return err
	}
	if err := call(setupHash("falsch")); !isCode(err, "42501") {
		t.Fatalf("falsches Token: %v", err)
	}
	if _, err := o.Exec(ctx, `UPDATE openwacht.setup_state SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := call(setupHash(raw)); !isCode(err, "42501") {
		t.Fatalf("abgelaufenes Token: %v", err)
	}
	var ok bool
	p.QueryRow(ctx, `SELECT openwacht.setup_check($1)`, setupHash(raw)).Scan(&ok)
	if ok {
		t.Fatal("abgelaufenes Token gilt")
	}
	raw = setupToken(t, o)
	if err := call(setupHash(raw)); err != nil {
		t.Fatalf("gültiges Token: %v", err)
	}
	if err := call(setupHash(raw)); !isCode(err, "42501") {
		t.Fatalf("zweimal: %v", err)
	}
	for _, q := range []string{`SELECT * FROM openwacht.setup_state`, `SELECT * FROM openwacht.https_material`,
		`UPDATE openwacht.setup_state SET done_at = NULL`} {
		if _, err := p.Exec(ctx, q); !isCode(err, "42501") {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := p.Exec(ctx, `SELECT openwacht.https_put('hochgeladen', repeat('x', 200), repeat('y', 40)::bytea, NULL, NULL, '{a}')`); !isCode(err, "42501") {
		t.Fatalf("https_put ohne Betreiber: %v", err)
	}
	// Erneuerung nur bei eigener CA
	if _, err := p.Exec(ctx, `SELECT openwacht.https_renew(repeat('x', 200), repeat('z', 200), repeat('y', 40)::bytea)`); err != nil {
		t.Fatal(err)
	}
	var cert string
	o.QueryRow(ctx, `SELECT cert_pem FROM openwacht.https_material`).Scan(&cert)
	if !strings.HasPrefix(cert, "xxx") {
		t.Fatal("hochgeladenes Zertifikat durch Erneuerung ersetzt")
	}
}

// Wer mit `einrichten` (Shell) einrichtet, schließt den Assistenten.
func TestEinrichtungPerShellSchliesst(t *testing.T) {
	ctx := context.Background()
	o, p := freshInstall(t)
	raw := setupToken(t, o)
	if err := Bootstrap(ctx, o, "IT", "a@example.com", "A", "ein-sehr-langes-passwort-42", testParams); err != nil {
		t.Fatal(err)
	}
	var ok bool
	p.QueryRow(ctx, `SELECT openwacht.setup_check($1)`, setupHash(raw)).Scan(&ok)
	if ok {
		t.Fatal("Token gilt nach der Einrichtung per Shell")
	}
	if open, _ := SetupOpen(ctx, p); open {
		t.Fatal("Einrichtung offen")
	}
}

func TestAssistentNachEinrichtungTot(t *testing.T) {
	_, srv := newTestServer(t, nil)
	c := newClient(t, srv)
	expectStatus(t, "Start", c.do("POST", "/api/v1/einrichtung/start", map[string]string{"token": "x"}), 410)
	expectStatus(t, "Wurzel ohne eigene CA", c.do("GET", "/openwacht-wurzel.crt", nil), 404)
}
