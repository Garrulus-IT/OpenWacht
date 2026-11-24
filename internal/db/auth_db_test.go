// SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const validHash = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

// Etappe 30 (M4): Sperre je Konto und Quelle, für andere Quellen nur Wartezeit.
func TestKontosperreJeQuelle(t *testing.T) {
	ctx := context.Background()
	uid := env.users["lz_leser"]
	reset := func() {
		env.owner.Exec(ctx, `DELETE FROM openwacht.login_sources WHERE user_id = $1`, uid)
		env.owner.Exec(ctx, `UPDATE openwacht.users SET failed_logins = 0, locked_until = NULL, login_next_slot = NULL WHERE id = $1`, uid)
	}
	reset()
	defer reset()
	src := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	a, b, known := src("a"), src("b"), src("bekannt")
	gate := func(s []byte) int {
		t.Helper()
		var w int
		if err := env.app.QueryRow(ctx, `SELECT openwacht.auth_login_gate($1, $2)`, uid, s).Scan(&w); err != nil {
			t.Fatal(err)
		}
		return w
	}
	lockedUntil := func(s []byte) *time.Time {
		var l *time.Time
		env.owner.QueryRow(ctx, `SELECT locked_until FROM openwacht.login_sources WHERE user_id = $1 AND source_hash = $2`, uid, s).Scan(&l)
		return l
	}
	if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_login_succeeded($1, $2)`, uid, known); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_login_failed($1, $2)`, uid, a); err != nil {
			t.Fatal(err)
		}
		l := lockedUntil(a)
		if i < 5 && l != nil {
			t.Fatalf("nach %d Fehlversuchen schon gesperrt", i)
		}
		if i >= 5 && (l == nil || time.Until(*l) <= 0) {
			t.Fatalf("nach %d Fehlversuchen nicht gesperrt", i)
		}
		if i == 6 {
			if d := time.Until(*l); d < 90*time.Second || d > 130*time.Second {
				t.Errorf("Sperrdauer nach 6 Fehlversuchen %v, erwartet etwa 2 Minuten", d)
			}
		}
	}
	if w := gate(a); w != -1 {
		t.Errorf("gesperrte Quelle: %d", w)
	}
	// Das Konto selbst ist nicht gesperrt: keine Sperre am Konto, Sitzungen bleiben.
	var accLocked *time.Time
	env.owner.QueryRow(ctx, `SELECT locked_until FROM openwacht.users WHERE id = $1`, uid).Scan(&accLocked)
	if accLocked != nil {
		t.Error("Konto gesperrt statt nur der Quelle")
	}
	// Bekannte Quelle: ohne Wartezeit
	for i := 0; i < 3; i++ {
		if w := gate(known); w != 0 {
			t.Errorf("bekannte Quelle wartet %d ms", w)
		}
	}
	// Unbekannte Quelle: Zeitschlitze nacheinander (2 s je Versuch nach 6 Fehlern)
	w1, w2, w3 := gate(b), gate(b), gate(b)
	if w1 != 0 || w2 < 1500 || w2 > 2100 || w3 < 3500 || w3 > 4100 {
		t.Errorf("Wartezeiten %d, %d, %d ms", w1, w2, w3)
	}
	// Über 30 s Rückstand: abgelehnt statt warten
	env.owner.Exec(ctx, `UPDATE openwacht.users SET login_next_slot = now() + interval '40 seconds' WHERE id = $1`, uid)
	if w := gate(b); w != -2 {
		t.Errorf("Rückstau: %d", w)
	}
	if w := gate(known); w != 0 {
		t.Errorf("bekannte Quelle bei Rückstau: %d", w)
	}
	// Erfolg von a hebt Sperre und Zähler auf
	if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_login_succeeded($1, $2)`, uid, a); err != nil {
		t.Fatal(err)
	}
	if lockedUntil(a) != nil || gate(b) != 0 {
		t.Error("Sperre bzw. Wartezeit nach Erfolg nicht aufgehoben")
	}
	// Ungültige Quelle
	if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_login_failed($1, $2)`, uid, []byte("kurz")); err == nil {
		t.Error("kurze Quelle angenommen")
	}
	// Anwendung sieht die Tabelle nicht
	expectDenied(t, "login_sources lesen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.login_sources`)
		return err
	}))
	// Entsperren nur für den Eigentümer
	if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_unlock('lz_leser@test.invalid')`); sqlState(err) != "42501" {
		t.Errorf("App entsperrt: %v", err)
	}
	for i := 0; i < 5; i++ {
		env.app.Exec(ctx, `SELECT openwacht.auth_login_failed($1, $2)`, uid, b)
	}
	var n *int
	if err := env.owner.QueryRow(ctx, `SELECT openwacht.auth_unlock('LZ_Leser@test.invalid ')`).Scan(&n); err != nil || n == nil || *n != 1 {
		t.Fatalf("entsperren: %v %v", n, err)
	}
	if gate(b) != 0 {
		t.Error("nach Entsperren weiter gesperrt")
	}
	if err := env.owner.QueryRow(ctx, `SELECT openwacht.auth_unlock('niemand@test.invalid')`).Scan(&n); err != nil || n != nil {
		t.Errorf("unbekanntes Konto: %v %v", n, err)
	}
}

func TestSitzungenNurUeberFunktionen(t *testing.T) {
	ctx := context.Background()
	expectDenied(t, "Sitzungstabelle lesen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.sessions`)
		return err
	}))
	tok := sha256.Sum256([]byte(randHex(16)))
	uid := env.users["fw_leser"]
	if _, err := env.app.Exec(ctx, `SELECT openwacht.session_create($1, $2, 'voll', '30 minutes', '12 hours')`, uid, tok[:]); err != nil {
		t.Fatal(err)
	}
	get := func() (string, bool) {
		var u string
		err := env.app.QueryRow(ctx, `SELECT user_id::text FROM openwacht.session_get($1)`, tok[:]).Scan(&u)
		return u, err == nil
	}
	if u, ok := get(); !ok || u != uid {
		t.Fatal("frische Sitzung nicht gefunden")
	}
	// Leerlauf überschritten.
	env.owner.Exec(ctx, `UPDATE openwacht.sessions SET last_seen = now() - interval '31 minutes' WHERE token_hash = $1`, tok[:])
	if _, ok := get(); ok {
		t.Error("Sitzung trotz Leerlauf gültig")
	}
	// Absolute Laufzeit überschritten, obwohl aktiv.
	env.owner.Exec(ctx, `UPDATE openwacht.sessions SET last_seen = now(), expires_at = now() - interval '1 second' WHERE token_hash = $1`, tok[:])
	if _, ok := get(); ok {
		t.Error("Sitzung trotz Ablauf gültig")
	}
	// Deaktivierter Benutzer.
	env.owner.Exec(ctx, `UPDATE openwacht.sessions SET expires_at = now() + interval '1 hour' WHERE token_hash = $1`, tok[:])
	env.owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, uid)
	defer env.owner.Exec(ctx, `UPDATE openwacht.users SET disabled = false WHERE id = $1`, uid)
	if _, ok := get(); ok {
		t.Error("Sitzung eines deaktivierten Benutzers gültig")
	}
}

func TestNurEigeneZweiFaktorDaten(t *testing.T) {
	ctx := context.Background()
	expectDenied(t, "fremdes TOTP lesen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.auth_totp_get($1)`, env.users["fw_admin"])
		return err
	}))
	expectDenied(t, "fremdes TOTP setzen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_begin($1, '\x01')`, env.users["fw_admin"])
		return err
	}))
	expectDenied(t, "TOTP ohne Kontext", asUser(t, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.auth_totp_get($1)`, env.users["fw_admin"])
		return err
	}))
	// Eigener Ablauf mit Replay-Schutz.
	err := asUser(t, "fw_leser", func(tx pgx.Tx) error {
		uid := env.users["fw_leser"]
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_begin($1, '\x01')`, uid); err != nil {
			return err
		}
		var first, second bool
		tx.QueryRow(ctx, `SELECT openwacht.auth_totp_use_step($1, 100)`, uid).Scan(&first)
		tx.QueryRow(ctx, `SELECT openwacht.auth_totp_use_step($1, 100)`, uid).Scan(&second)
		if !first || second {
			t.Errorf("Replay-Schutz: erster=%v zweiter=%v", first, second)
		}
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_enable($1)`, uid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_begin($1, '\x02')`, uid)
		if err == nil {
			t.Error("Geheimnis bei aktivem 2FA überschrieben")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPasswortSetzenNurBerechtigt(t *testing.T) {
	ctx := context.Background()
	set := func(user, target, hash string) error {
		return asUser(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, env.users[target], hash)
			return err
		})
	}
	expectOK(t, "eigenes Passwort", set("fw_leser", "fw_leser", validHash))
	expectOK(t, "Admin setzt Passwort im eigenen Mandanten", set("fw_admin", "fw_leser", validHash))
	expectDenied(t, "Admin setzt Passwort in fremdem Mandanten", set("fw_admin", "oa_admin", validHash))
	expectDenied(t, "Leser setzt fremdes Passwort", set("fw_leser", "fw_admin", validHash))
	if err := set("fw_leser", "fw_leser", "klartext"); err == nil {
		t.Error("Klartext als Hash akzeptiert")
	}
}

func TestAnmeldeAuditOhneHandelnden(t *testing.T) {
	ctx := context.Background()
	if _, err := env.app.Exec(ctx, `SELECT openwacht.audit_auth($1, 'anmeldung.fehlgeschlagen', '{}')`, env.users["oa_admin"]); err != nil {
		t.Fatal(err)
	}
	var actor *string
	var tenant string
	if err := env.owner.QueryRow(ctx, `SELECT actor_user_id::text, tenant_id::text FROM openwacht.audit_log
		WHERE action = 'anmeldung.fehlgeschlagen' ORDER BY chain_seq DESC LIMIT 1`).Scan(&actor, &tenant); err != nil {
		t.Fatal(err)
	}
	if actor != nil || tenant != env.tenants["Organisation"] {
		t.Errorf("Fehlversuch: actor=%v tenant=%s", actor, tenant)
	}
	if _, err := env.app.Exec(ctx, `SELECT openwacht.audit_auth($1, 'mandant.geloescht', '{}')`, env.users["oa_admin"]); err == nil {
		t.Error("beliebige Aktion über audit_auth möglich")
	}
}
