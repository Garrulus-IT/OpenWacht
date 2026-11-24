// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/webauthn/webauthntest"
)

// passkeyServer: eigener Server mit DNS-Namen als Basisadresse (localhost),
// denn eine IP-Adresse ist als RP-ID nicht erlaubt.
func passkeyServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	verwaltungSetup(t)
	var origin string
	_, srv := newTestServer(t, func(c *Config) {
		origin = "http://localhost:" + c.BaseURL.Port()
		c.BaseURL = mustURL(origin)
	})
	return srv, origin
}

// pkKonto legt ein Konto an; mit totp ein eingerichtetes Geheimnis (geliefert).
func pkKonto(t *testing.T, name, home string, totp bool) []byte {
	t.Helper()
	kontoMitRollen(t, name, home, map[string]string{home: "admin"}, false, false)
	if !totp {
		return nil
	}
	secret, _ := auth.GenerateTOTPSecret()
	enc, _ := auth.Seal(deriveKey(testKey, "openwacht secretbox v1"), secret, []byte(ids[name]))
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.users SET totp_secret_enc = $2, totp_enabled = true WHERE id = $1`,
		ids[name], enc); err != nil {
		t.Fatal(err)
	}
	return secret
}

// pkCode: gültiger App-Code; setzt den Schutz gegen Wiederverwendung zurück.
func pkCode(t *testing.T, name string, secret []byte) string {
	t.Helper()
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.users SET totp_last_step = 0 WHERE id = $1`, ids[name]); err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCode(secret, auth.TOTPStep(time.Now()))
}

func pkClient(t *testing.T, srv *httptest.Server, origin string) *client {
	c := newClient(t, srv)
	c.origin = origin
	return c
}

// pkPending: Passwort richtig, zweiter Schritt offen.
func pkPending(t *testing.T, srv *httptest.Server, origin, name string) (*client, response) {
	t.Helper()
	c := pkClient(t, srv, origin)
	r := c.login(name)
	if r.status != 200 || r.body["zweiter_faktor"] != true {
		t.Fatalf("Anmeldung %s: %d %s", name, r.status, r.raw)
	}
	return c, r
}

func pkLogin(t *testing.T, srv *httptest.Server, origin, name string, secret []byte) *client {
	t.Helper()
	c, _ := pkPending(t, srv, origin, name)
	r := c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": pkCode(t, name, secret)})
	if r.status != 200 {
		t.Fatalf("2FA %s: %d %s", name, r.status, r.raw)
	}
	c.csrf, _ = r.body["csrf"].(string)
	return c
}

func challengeOf(t *testing.T, r response) []byte {
	t.Helper()
	s, _ := r.body["challenge"].(string)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("Challenge: %s", r.raw)
	}
	return b
}

func registerPasskey(t *testing.T, c *client, name string, secret []byte, a *webauthntest.Authenticator) response {
	t.Helper()
	r := c.do("POST", "/api/v1/passkeys/optionen", nil)
	if r.status != 200 {
		t.Fatalf("Optionen: %d %s", r.status, r.raw)
	}
	cd, att := a.Register(challengeOf(t, r))
	return c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop", "code": pkCode(t, name, secret),
		"client_data": cd, "attestation": att})
}

// passkeyLogin: kompletter zweiter Schritt mit Passkey.
func passkeyLogin(t *testing.T, c *client, a *webauthntest.Authenticator) response {
	t.Helper()
	r := c.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	if r.status != 200 {
		return r
	}
	return c.do("POST", "/api/v1/sitzung/passkey", a.Assert(challengeOf(t, r)))
}

func auditCount(t *testing.T, user, action, grund string) int {
	t.Helper()
	var n int
	// Fehlversuche stehen ohne Akteur im Log, deshalb über den Heimatmandanten.
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log
		WHERE tenant_id = (SELECT tenant_id FROM openwacht.users WHERE id = $1) AND action = $2
		AND ($3 = '' OR details->>'grund' = $3) AND at > now() - interval '5 minutes'`, ids[user], action, grund).Scan(&n)
	return n
}

func TestPasskeyRegistrierenUndAnmelden(t *testing.T) {
	srv, origin := passkeyServer(t)
	secret := pkKonto(t, "pk_anna", "Organisation", true)
	c := pkLogin(t, srv, origin, "pk_anna", secret)

	r := c.do("GET", "/api/v1/passkeys", nil)
	if r.status != 200 || r.body["moeglich"] != true || len(r.body["passkeys"].([]any)) != 0 {
		t.Fatalf("Liste: %d %s", r.status, r.raw)
	}
	r = c.do("POST", "/api/v1/passkeys/optionen", nil)
	if rp, _ := r.body["rp"].(map[string]any); rp["id"] != "localhost" || r.body["attestation"] != "none" {
		t.Fatalf("Optionen: %s", r.raw)
	}
	a := webauthntest.New("localhost", origin)
	cd, att := a.Register(challengeOf(t, r))
	// Ohne bzw. mit falschem App-Code: abgelehnt (heikle Änderung).
	expectStatus(t, "ohne Code", c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop", "client_data": cd, "attestation": att}), 403)
	expectStatus(t, "falscher Code", c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop", "code": "000000",
		"client_data": cd, "attestation": att}), 403)
	resetLogin(t, "pk_anna")
	expectStatus(t, "leerer Name", c.do("POST", "/api/v1/passkeys", map[string]string{"name": " ", "code": pkCode(t, "pk_anna", secret),
		"client_data": cd, "attestation": att}), 400)
	expectStatus(t, "registrieren", c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop", "code": pkCode(t, "pk_anna", secret),
		"client_data": cd, "attestation": att}), 201)
	// Dieselbe Challenge ein zweites Mal: verbraucht.
	expectStatus(t, "Challenge zweimal", c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop 2", "code": pkCode(t, "pk_anna", secret),
		"client_data": cd, "attestation": att}), 400)
	// Derselbe Authenticator noch einmal: steht in excludeCredentials und wird abgelehnt.
	r = c.do("POST", "/api/v1/passkeys/optionen", nil)
	if ex, _ := r.body["excludeCredentials"].([]any); len(ex) != 1 {
		t.Errorf("excludeCredentials: %s", r.raw)
	}
	cd, att = a.Register(challengeOf(t, r))
	expectStatus(t, "doppelt", c.do("POST", "/api/v1/passkeys", map[string]string{"name": "Laptop", "code": pkCode(t, "pk_anna", secret),
		"client_data": cd, "attestation": att}), 409)
	// Falscher Ursprung bei der Registrierung
	evil := webauthntest.New("localhost", "http://localhost.evil.example")
	expectStatus(t, "fremder Ursprung", registerPasskey(t, c, "pk_anna", secret, evil), 400)
	if auditCount(t, "pk_anna", "passkey.angelegt", "") != 1 {
		t.Error("Audit passkey.angelegt fehlt")
	}

	// Anmeldung mit Passkey
	p, lr := pkPending(t, srv, origin, "pk_anna")
	if lr.body["passkey"] != true {
		t.Errorf("Anmeldung bietet keinen Passkey an: %s", lr.raw)
	}
	r = p.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	if al, _ := r.body["allowCredentials"].([]any); len(al) != 1 || r.body["rpId"] != "localhost" {
		t.Fatalf("Anmelde-Optionen: %s", r.raw)
	}
	assertion := a.Assert(challengeOf(t, r))
	r = p.do("POST", "/api/v1/sitzung/passkey", assertion)
	if r.status != 200 || r.body["csrf"] == nil {
		t.Fatalf("Anmeldung mit Passkey: %d %s", r.status, r.raw)
	}
	p.csrf = r.body["csrf"].(string)
	expectStatus(t, "angemeldet", p.do("GET", "/api/v1/ich", nil), 200)
	if auditCount(t, "pk_anna", "anmeldung.passkey", "") != 1 {
		t.Error("Audit anmeldung.passkey fehlt")
	}
	// Wiederholung derselben Antwort in einer neuen Anmeldung: andere Challenge.
	p2, _ := pkPending(t, srv, origin, "pk_anna")
	p2.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	expectStatus(t, "wiederholte Antwort", p2.do("POST", "/api/v1/sitzung/passkey", assertion), 401)
	// Challenge gilt nur einmal, auch nach einem Fehlversuch mit falscher Signatur.
	r = p2.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	ch := challengeOf(t, r)
	bad := a.Assert(ch)
	bad["signature"] = a.Assert(mustOther(ch))["signature"]
	expectStatus(t, "falsche Signatur", p2.do("POST", "/api/v1/sitzung/passkey", bad), 401)
	expectStatus(t, "danach richtige Signatur, gleiche Challenge", p2.do("POST", "/api/v1/sitzung/passkey", a.Assert(ch)), 401)
	resetLogin(t, "pk_anna")
	// Zähler sinkt: Hinweis auf kopierten Schlüssel.
	a.Count = 0
	expectStatus(t, "Zähler gesunken", passkeyLogin(t, p2, a), 401)
	if auditCount(t, "pk_anna", "anmeldung.fehlgeschlagen", "passkey_zaehler") != 1 {
		t.Error("Audit passkey_zaehler fehlt")
	}
	a.Count = 100
	// Abgelaufene Challenge
	r = p2.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	owner.Exec(context.Background(), `UPDATE openwacht.webauthn_challenges SET expires_at = now() - interval '1 second' WHERE user_id = $1`, ids["pk_anna"])
	expectStatus(t, "abgelaufen", p2.do("POST", "/api/v1/sitzung/passkey", a.Assert(challengeOf(t, r))), 401)
	// Passkey auf einer anderen Seite (Phishing): Ursprung passt nicht.
	phish := *a
	phish.Origin = "http://localhost:1"
	expectStatus(t, "anderer Ursprung", passkeyLogin(t, p2, &phish), 401)
	// Ohne halbe Sitzung
	expectStatus(t, "ohne Anmeldung", pkClient(t, srv, origin).do("POST", "/api/v1/sitzung/passkey/optionen", nil), 401)
	resetLogin(t, "pk_anna")
	// Nach den Fehlversuchen geht es mit richtigem Passkey weiter.
	p3, _ := pkPending(t, srv, origin, "pk_anna")
	expectStatus(t, "danach richtig", passkeyLogin(t, p3, a), 200)

	// Fremder Passkey: Konto B nimmt den Passkey von A.
	secretB := pkKonto(t, "pk_bert", "Organisation", true)
	pb, lb := pkPending(t, srv, origin, "pk_bert")
	if lb.body["passkey"] != false {
		t.Errorf("Konto ohne Passkey: %s", lb.raw)
	}
	expectStatus(t, "Optionen ohne Passkey", pb.do("POST", "/api/v1/sitzung/passkey/optionen", nil), 409)
	cb := pkLogin(t, srv, origin, "pk_bert", secretB)
	b := webauthntest.New("localhost", origin)
	expectStatus(t, "B registriert", registerPasskey(t, cb, "pk_bert", secretB, b), 201)
	pb, _ = pkPending(t, srv, origin, "pk_bert")
	r = pb.do("POST", "/api/v1/sitzung/passkey/optionen", nil)
	expectStatus(t, "Passkey von A für B", pb.do("POST", "/api/v1/sitzung/passkey", a.Assert(challengeOf(t, r))), 401)
	resetLogin(t, "pk_bert")

	// Sichtbarkeit und Löschen: nur eigene (RLS), Schlüssel nie lesbar.
	var aID string
	owner.QueryRow(context.Background(), `SELECT id::text FROM openwacht.webauthn_credentials WHERE user_id = $1`, ids["pk_anna"]).Scan(&aID)
	expectStatus(t, "B löscht Passkey von A", cb.do("DELETE", "/api/v1/passkeys/"+aID, nil), 404)
	err := asDB(t, "pk_bert", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.webauthn_credentials`).Scan(&n); err != nil || n != 1 {
			t.Errorf("B sieht %d Passkeys (%v)", n, err)
		}
		_, err := tx.Exec(context.Background(), `SELECT public_key FROM openwacht.webauthn_credentials`)
		return err
	})
	if !isDenied(err) {
		t.Errorf("App liest public_key: %v", err)
	}
	if err := asDB(t, "pk_bert", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `SELECT * FROM openwacht.webauthn_challenges`)
		return err
	}); !isDenied(err) {
		t.Errorf("App liest Challenges: %v", err)
	}
	if err := asDB(t, "pk_bert", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `SELECT openwacht.webauthn_register_begin($1, $2)`, ids["pk_anna"], make([]byte, 32))
		return err
	}); !isDenied(err) {
		t.Errorf("Challenge für fremdes Konto: %v", err)
	}
	expectStatus(t, "A löscht eigenen", c.do("DELETE", "/api/v1/passkeys/"+aID, nil), 204)
	p4, lr4 := pkPending(t, srv, origin, "pk_anna")
	if lr4.body["passkey"] != false {
		t.Errorf("nach dem Löschen noch Passkey angeboten")
	}
	expectStatus(t, "gelöschter Passkey", passkeyLogin(t, p4, a), 409)

	// App zurückgesetzt (z. B. zweifaktor-zuruecksetzen): Passkeys verfallen.
	owner.Exec(context.Background(), `UPDATE openwacht.users SET totp_enabled = false WHERE id = $1`, ids["pk_bert"])
	var left int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.webauthn_credentials WHERE user_id = $1`, ids["pk_bert"]).Scan(&left)
	if left != 0 {
		t.Errorf("nach Zurücksetzen der App noch %d Passkeys", left)
	}
}

func TestPasskeyOhneAppUndOhneDNSName(t *testing.T) {
	srv, origin := passkeyServer(t)
	pkKonto(t, "pk_cora", "Organisation", false)
	c := pkClient(t, srv, origin)
	if r := c.login("pk_cora"); r.status != 200 {
		t.Fatalf("Anmeldung: %s", r.raw)
	}
	expectStatus(t, "ohne App", c.do("POST", "/api/v1/passkeys/optionen", nil), 409)
	// Basisadresse mit IP (gemeinsamer Testserver): keine Passkeys.
	r := as(t, "v_oa").do("GET", "/api/v1/passkeys", nil)
	if r.status != 200 || r.body["moeglich"] != false {
		t.Errorf("IP-Adresse: %s", r.raw)
	}
	expectStatus(t, "Optionen bei IP", as(t, "v_oa").do("POST", "/api/v1/passkeys/optionen", nil), 409)
	if strings.Contains(newClient(t, vSrv).login("v_oa").raw, `"passkey":true`) {
		t.Error("Passkey bei IP-Adresse angeboten")
	}
}

func mustOther(ch []byte) []byte {
	o := append([]byte(nil), ch...)
	o[0] ^= 0xff
	return o
}
