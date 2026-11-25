// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6: Meldungen bei verdächtigen Anmeldungen und kontoweite Bremse für den
// zweiten Faktor (H5).

import (
	"context"
	"encoding/base32"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm/smtptest"
	"github.com/garrulus-it/openwacht/internal/auth"
)

func noticeKinds(t *testing.T, user string) []string {
	t.Helper()
	rows, err := owner.Query(context.Background(), `SELECT kind FROM openwacht.auth_notices WHERE user_id = $1 ORDER BY id`, ids[user])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		rows.Scan(&k)
		out = append(out, k)
	}
	return out
}

// totpEinrichten richtet für ein Konto die App ein und liefert das Geheimnis.
func totpEinrichten(t *testing.T, c *client) []byte {
	t.Helper()
	r := c.do("POST", "/api/v1/zwei-faktor/einrichten", nil)
	expectStatus(t, "einrichten", r, 200)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.body["geheimnis"].(string))
	r = c.do("POST", "/api/v1/zwei-faktor/bestaetigen", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(time.Now()))})
	expectStatus(t, "bestätigen", r, 200)
	return secret
}

func TestZweiterFaktorKontoweiteBremse(t *testing.T) {
	_, srv, _ := quellenServer(t)
	ctx := context.Background()
	kontoMitRollen(t, "h5_konto", "Fertigung", map[string]string{"Fertigung": "leser"}, false, false)
	resetLogin(t, "h5_konto")
	t.Cleanup(func() {
		resetLogin(t, "h5_konto")
		owner.Exec(ctx, `DELETE FROM openwacht.auth_notices WHERE user_id = $1`, ids["h5_konto"])
	})
	home := from(t, srv, "198.51.100.20")
	expectStatus(t, "Anmeldung", home.login("h5_konto"), 200)
	secret := totpEinrichten(t, home)

	wrong := func(addr string) response {
		t.Helper()
		// Wartezeit unbekannter Quellen ausblenden: hier zählt nur der Code.
		owner.Exec(ctx, `UPDATE openwacht.users SET login_next_slot = NULL WHERE id = $1`, ids["h5_konto"])
		c := from(t, srv, addr)
		r := c.login("h5_konto")
		if r.body["zweiter_faktor"] != true {
			t.Fatalf("%s: kein zweiter Faktor: %s", addr, r.raw)
		}
		return c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": "000000"})
	}
	// Je Quelle ein falscher Code: die Sperre je Quelle greift nicht.
	for i := 1; i <= 9; i++ {
		expectStatus(t, fmt.Sprintf("falscher Code %d", i), wrong(fmt.Sprintf("203.0.113.%d", i)), 401)
	}
	var locked bool
	owner.QueryRow(ctx, `SELECT openwacht.auth_mfa_locked($1)`, ids["h5_konto"]).Scan(&locked)
	if locked {
		t.Fatal("nach 9 falschen Codes schon gesperrt")
	}
	expectStatus(t, "falscher Code 10", wrong("203.0.113.10"), 401)
	owner.QueryRow(ctx, `SELECT openwacht.auth_mfa_locked($1)`, ids["h5_konto"]).Scan(&locked)
	if !locked {
		t.Fatal("nach 10 falschen Codes aus 10 Quellen nicht gesperrt")
	}
	// Jetzt hilft auch der richtige Code von einer neuen Quelle nicht, und die
	// Meldung verrät nichts.
	owner.Exec(ctx, `UPDATE openwacht.users SET login_next_slot = NULL, totp_last_step = 0 WHERE id = $1`, ids["h5_konto"])
	c := from(t, srv, "192.0.2.77")
	expectStatus(t, "Passwort", c.login("h5_konto"), 200)
	r := c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(time.Now()))})
	expectStatus(t, "richtiger Code während der Sperre", r, 401)
	if r.body["fehler"] != msgLoginFailed {
		t.Errorf("Meldung verrät die Sperre: %s", r.raw)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'zweifaktor.gesperrt' AND details->>'benutzer' = $1`, ids["h5_konto"]).Scan(&n)
	if n != 1 {
		t.Errorf("Audit zweifaktor.gesperrt: %d", n)
	}
	if k := noticeKinds(t, "h5_konto"); !slices.Contains(k, "zweifaktor_gesperrt") {
		t.Errorf("Meldungen: %v", k)
	}
	// entsperren hebt auch diese Sperre auf.
	var m *int
	owner.QueryRow(ctx, `SELECT openwacht.auth_unlock('h5_konto@test.invalid')`).Scan(&m)
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_last_step = 0 WHERE id = $1`, ids["h5_konto"])
	c = from(t, srv, "192.0.2.78")
	expectStatus(t, "Passwort nach entsperren", c.login("h5_konto"), 200)
	r = c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(time.Now()))})
	expectStatus(t, "richtiger Code nach entsperren", r, 200)
	// Eine erfolgreiche Anmeldung setzt den Zähler zurück.
	var f int
	owner.QueryRow(ctx, `SELECT mfa_failures FROM openwacht.users WHERE id = $1`, ids["h5_konto"]).Scan(&f)
	if f != 0 {
		t.Errorf("Zähler nach Erfolg: %d", f)
	}
}

func TestAnmeldeMeldungen(t *testing.T) {
	s, srv, _ := quellenServer(t)
	ctx := context.Background()
	smtp := smtptest.Start(t, false, "relay", "relay-pass")
	enc, _ := auth.Seal(s.smtpKey(), []byte("relay-pass"), smtpAAD("127.0.0.1", "relay"))
	if _, err := owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = '127.0.0.1', smtp_port = $1, smtp_tls = 'starttls',
		smtp_from = 'openwacht@test.invalid', smtp_user = 'relay', smtp_pass_enc = $2, smtp_ca = $3`, smtp.Port, enc, smtp.CAPEM); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET smtp_host = NULL, smtp_port = NULL, smtp_tls = NULL, smtp_from = NULL,
			smtp_user = NULL, smtp_pass_enc = NULL, smtp_ca = NULL`)
	})
	if err := s.ReloadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	kontoMitRollen(t, "mel_konto", "Fertigung", map[string]string{"Fertigung": "leser"}, false, false)
	kontoMitRollen(t, "mel_betreiber", "IT", map[string]string{"IT": "admin"}, false, false)
	owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true, totp_enabled = true WHERE id = $1`, ids["mel_betreiber"])
	for _, u := range []string{"mel_konto", "mel_betreiber"} {
		resetLogin(t, u)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = false WHERE id = $1`, ids["mel_betreiber"])
		owner.Exec(ctx, `DELETE FROM openwacht.auth_notices WHERE user_id = $1`, ids["mel_konto"])
		resetLogin(t, "mel_konto")
	})

	// Erste Anmeldung überhaupt: keine Meldung.
	expectStatus(t, "erste Anmeldung", from(t, srv, "198.51.100.30").login("mel_konto"), 200)
	expectStatus(t, "gleiche Quelle", from(t, srv, "198.51.100.30").login("mel_konto"), 200)
	if k := noticeKinds(t, "mel_konto"); len(k) != 0 {
		t.Fatalf("Meldung ohne Grund: %v", k)
	}
	// Neue Quelle: eine Meldung, eine zweite neue Quelle binnen einer Stunde nicht noch einmal.
	expectStatus(t, "neue Quelle", from(t, srv, "203.0.113.40").login("mel_konto"), 200)
	expectStatus(t, "noch eine neue Quelle", from(t, srv, "203.0.113.41").login("mel_konto"), 200)
	if k := noticeKinds(t, "mel_konto"); !slices.Equal(k, []string{"neue_quelle"}) {
		t.Fatalf("Meldungen nach neuer Quelle: %v", k)
	}
	// Fünf falsche Passwörter aus einer Quelle: Sperre, gemeldet einmal.
	bad := from(t, srv, "192.0.2.50")
	for i := 0; i < 7; i++ {
		owner.Exec(ctx, `UPDATE openwacht.users SET login_next_slot = NULL WHERE id = $1`, ids["mel_konto"])
		bad.do("POST", "/api/v1/sitzung", map[string]string{"email": "mel_konto@test.invalid", "passwort": "falsches-passwort-1"})
	}
	if k := noticeKinds(t, "mel_konto"); !slices.Equal(k, []string{"neue_quelle", "quelle_gesperrt"}) {
		t.Fatalf("Meldungen nach Sperre: %v", k)
	}

	s.sendAuthNotices(ctx)
	msgs := smtp.Messages()
	if len(msgs) != 2 {
		t.Fatalf("Mails: %d", len(msgs))
	}
	for _, m := range msgs {
		if !slices.Contains(m.To, "mel_konto@test.invalid") {
			t.Errorf("nicht an das Konto: %v", m.To)
		}
		for _, addr := range []string{"203.0.113.40", "192.0.2.50", "198.51.100.30"} {
			if strings.Contains(m.Data, addr) {
				t.Errorf("Adresse %s in der Mail", addr)
			}
		}
	}
	// Neue Quelle nur an das Konto, Sperre auch an den Betreiber.
	if slices.Contains(msgs[0].To, "mel_betreiber@test.invalid") || !strings.Contains(msgs[0].Data, "neuen Rechner") {
		t.Errorf("neue Quelle: %v", msgs[0].To)
	}
	if !slices.Contains(msgs[1].To, "mel_betreiber@test.invalid") {
		t.Errorf("Sperre nicht an den Betreiber: %v", msgs[1].To)
	}
	// Verschickt: kein zweites Mal.
	s.sendAuthNotices(ctx)
	if len(smtp.Messages()) != 2 {
		t.Errorf("doppelt verschickt: %d", len(smtp.Messages()))
	}

	// Shell-Befehle melden sich ebenfalls.
	owner.Exec(ctx, `DELETE FROM openwacht.auth_notices WHERE user_id = $1`, ids["mel_konto"])
	owner.Exec(ctx, `SELECT openwacht.auth_2fa_reset('mel_konto@test.invalid')`)
	hash, _ := auth.HashPassword(testPassword, testParams)
	owner.Exec(ctx, `SELECT openwacht.auth_password_set_shell('mel_konto@test.invalid', $1)`, hash)
	if k := noticeKinds(t, "mel_konto"); !slices.Equal(k, []string{"zweifaktor_zurueckgesetzt", "passwort_gesetzt"}) {
		t.Errorf("Meldungen der Shell: %v", k)
	}
}

// Die App-Rolle kommt an den Ausgang nur über die Funktionen.
func TestAnmeldeMeldungenNurUeberFunktionen(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT count(*) FROM openwacht.auth_notices`); err == nil {
		t.Error("App-Rolle liest auth_notices direkt")
	}
	if _, err := pool.Exec(ctx, `SELECT openwacht.auth_notice_add($1, 'neue_quelle')`, ids["admin"]); err == nil {
		t.Error("App-Rolle legt Meldungen selbst an")
	}
}
