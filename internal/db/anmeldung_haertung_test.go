// SPDX-License-Identifier: AGPL-3.0-only

package db

// Etappe 30: Wiederherstellungscodes (N5), Betreiber mit 2FA (M8),
// Freigabe von Anmelde-Domänen (M1), Sitzungsdauer je Anbindung (I2).

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

func hashes(prefix string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, i)))
		out[i] = h[:]
	}
	return out
}

func TestWiederherstellungscodes(t *testing.T) {
	ctx := context.Background()
	uid := env.users["fw_leser"]
	env.owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = false WHERE id = $1`, uid)
	defer env.owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = false WHERE id = $1`, uid)
	defer env.owner.Exec(ctx, `DELETE FROM openwacht.recovery_codes WHERE user_id = $1`, uid)
	set := func(user string, h [][]byte) error {
		return asUser(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT openwacht.auth_recovery_set($1, $2)`, uid, h)
			return err
		})
	}
	if err := set("fw_leser", hashes("a", 10)); sqlState(err) != "55000" {
		t.Errorf("ohne 2FA: %v", err)
	}
	env.owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = true WHERE id = $1`, uid)
	expectDenied(t, "Codes für fremdes Konto (Admin)", set("fw_admin", hashes("a", 10)))
	if err := set("fw_leser", hashes("a", 9)); sqlState(err) != "22023" {
		t.Errorf("neun Codes: %v", err)
	}
	dup := hashes("a", 10)
	dup[9] = dup[0]
	if err := set("fw_leser", dup); sqlState(err) != "22023" {
		t.Errorf("doppelter Code: %v", err)
	}
	// Dauerhaft anlegen (eigene Transaktion mit Commit)
	tx, _ := env.app.Begin(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, uid)
	if _, err := tx.Exec(ctx, `SELECT openwacht.auth_recovery_set($1, $2)`, uid, hashes("a", 10)); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)

	use := func(user string, h []byte) (int, error) {
		var left int
		err := asUserCommit(t, user, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT openwacht.auth_recovery_use($1, $2)`, uid, h).Scan(&left)
		})
		return left, err
	}
	h := hashes("a", 10)
	if _, err := use("fw_admin", h[0]); sqlState(err) != "42501" {
		t.Errorf("fremdes Konto verbraucht Code: %v", err)
	}
	if n, err := use("fw_leser", h[0]); err != nil || n != 9 {
		t.Errorf("erster Code: %d %v", n, err)
	}
	if n, _ := use("fw_leser", h[0]); n != -1 {
		t.Errorf("Code zweimal: %d", n)
	}
	if n, _ := use("fw_leser", hashes("b", 1)[0]); n != -1 {
		t.Errorf("fremder Code: %d", n)
	}
	expectDenied(t, "Codes lesen", asUser(t, "fw_leser", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.recovery_codes`)
		return err
	}))

	// Zurücksetzen nur durch den Eigentümer: Geheimnis, Codes und Sitzungen weg.
	tok := sha256.Sum256([]byte(randHex(16)))
	env.app.Exec(ctx, `SELECT openwacht.session_create($1, $2, 'voll', '30 minutes', '12 hours')`, uid, tok[:])
	if _, err := env.app.Exec(ctx, `SELECT openwacht.auth_2fa_reset('fw_leser@test.invalid')`); sqlState(err) != "42501" {
		t.Errorf("App setzt 2FA zurück: %v", err)
	}
	var had *bool
	if err := env.owner.QueryRow(ctx, `SELECT openwacht.auth_2fa_reset('fw_leser@test.invalid')`).Scan(&had); err != nil || had == nil || !*had {
		t.Fatalf("zurücksetzen: %v %v", had, err)
	}
	var enabled bool
	var codes, sessions int
	env.owner.QueryRow(ctx, `SELECT totp_enabled, (SELECT count(*) FROM openwacht.recovery_codes WHERE user_id = $1),
		(SELECT count(*) FROM openwacht.sessions WHERE user_id = $1) FROM openwacht.users WHERE id = $1`, uid).Scan(&enabled, &codes, &sessions)
	if enabled || codes != 0 || sessions != 0 {
		t.Errorf("nach Zurücksetzen: 2FA %v, Codes %d, Sitzungen %d", enabled, codes, sessions)
	}
	var audit int
	env.owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'zweifaktor.zurueckgesetzt' AND details->>'benutzer' = $1`, uid).Scan(&audit)
	if audit != 1 {
		t.Errorf("Audit-Einträge: %d", audit)
	}
}

// asUserCommit wie asUser, aber mit Commit.
func asUserCommit(t *testing.T, user string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	return pgx.BeginFunc(ctx, env.app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, env.users[user]); err != nil {
			return err
		}
		return fn(tx)
	})
}

func TestBetreiberBrauchtZweiFaktor(t *testing.T) {
	ctx := context.Background()
	uid := env.users["it_admin"]
	defer env.owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = false, totp_enabled = false WHERE id = $1`, uid)
	env.owner.Exec(ctx, `INSERT INTO openwacht.settings DEFAULT VALUES ON CONFLICT DO NOTHING`)
	env.owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = 'freiwillig'`)
	defer env.owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = NULL`)
	env.owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true, totp_enabled = false WHERE id = $1`, uid)
	var req, op bool
	env.app.QueryRow(ctx, `SELECT openwacht.mfa_required_for($1)`, uid).Scan(&req)
	if !req {
		t.Error("Betreiber ohne 2FA-Pflicht bei „freiwillig“")
	}
	asUser(t, "it_admin", func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT openwacht.is_platform_operator()`).Scan(&op) })
	if op {
		t.Error("Betreiber ohne TOTP wirksam")
	}
	env.owner.Exec(ctx, `UPDATE openwacht.users SET totp_enabled = true WHERE id = $1`, uid)
	asUser(t, "it_admin", func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT openwacht.is_platform_operator()`).Scan(&op) })
	if !op {
		t.Error("Betreiber mit TOTP nicht wirksam")
	}
	// Andere Admins bleiben bei „freiwillig“ ohne Pflicht.
	env.app.QueryRow(ctx, `SELECT openwacht.mfa_required_for($1)`, env.users["fw_admin"]).Scan(&req)
	if req {
		t.Error("„freiwillig“ wirkt nicht mehr für andere")
	}
}

func TestAnmeldeDomaenenFreigabe(t *testing.T) {
	ctx := context.Background()
	op := env.users["it_admin"]
	env.owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = true, totp_enabled = true WHERE id = $1`, op)
	defer env.owner.Exec(ctx, `UPDATE openwacht.users SET platform_operator = false, totp_enabled = false WHERE id = $1`, op)
	defer env.owner.Exec(ctx, `DELETE FROM openwacht.directories`)
	mk := func(tenant, name, netbios string) string {
		t.Helper()
		var id string
		if err := env.owner.QueryRow(ctx, `INSERT INTO openwacht.directories (tenant_id, name, url, bind_dn, bind_pass_enc, base_dn, netbios, netbios_status)
			VALUES ($1, $2, 'ldaps://dc.example.com', 'cn=svc,dc=x', $3, 'dc=x', $4, 'freigegeben') RETURNING id::text`,
			env.tenants[tenant], name, make([]byte, 40), netbios).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	root := mk("IT", "Haupt", "HAUPT")
	sub := mk("Fertigung", "FW", "FIRMA")
	addDom := func(user, dir, tenant, dom string) error {
		return asUserCommit(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO openwacht.directory_domains (domain, directory_id, tenant_id) VALUES ($1, $2, $3)`,
				dom, dir, env.tenants[tenant])
			return err
		})
	}
	expectOK(t, "Domäne im Hauptmandanten", addDom("it_admin", root, "IT", "beispiel.example"))
	expectOK(t, "Domäne im Untermandanten", addDom("fw_admin", sub, "Fertigung", "fw.example"))
	// Untermandant beansprucht die Domäne des Hauptmandanten: Antrag, kein Konflikt
	expectOK(t, "fremde Domäne beantragen", addDom("fw_admin", sub, "Fertigung", "beispiel.example"))
	status := func(dir, dom string) string {
		var s string
		env.owner.QueryRow(ctx, `SELECT status FROM openwacht.directory_domains WHERE directory_id = $1 AND domain = $2`, dir, dom).Scan(&s)
		return s
	}
	if status(root, "beispiel.example") != "freigegeben" || status(sub, "fw.example") != "beantragt" || status(sub, "beispiel.example") != "beantragt" {
		t.Errorf("Zustände: %s %s %s", status(root, "beispiel.example"), status(sub, "fw.example"), status(sub, "beispiel.example"))
	}
	var nb string
	env.owner.QueryRow(ctx, `SELECT netbios_status FROM openwacht.directories WHERE id = $1`, sub).Scan(&nb)
	if nb != "beantragt" {
		t.Errorf("NetBIOS im Untermandanten: %s (Eigentümer setzte freigegeben, der Trigger muss gewinnen)", nb)
	}
	login := func(dom, netbios any) string {
		var id string
		env.app.QueryRow(ctx, `SELECT id::text FROM openwacht.directory_for_login($1, $2)`, dom, netbios).Scan(&id)
		return id
	}
	if login("beispiel.example", nil) != root {
		t.Error("beispiel.example führt nicht zur Anbindung des Hauptmandanten")
	}
	if login("fw.example", nil) != "" || login(nil, "FIRMA") != "" {
		t.Error("beantragte Domäne bzw. NetBIOS-Name leitet Anmeldungen")
	}
	// Die Anwendung kann den Zustand nicht selbst setzen.
	expectDenied(t, "Zustand per UPDATE", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.directory_domains SET status = 'freigegeben' WHERE directory_id = $1`, sub)
		return err
	}))
	expectDenied(t, "Zustand beim Anlegen", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.directory_domains (domain, directory_id, tenant_id, status) VALUES ('x.example', $1, $2, 'freigegeben')`,
			sub, env.tenants["Fertigung"])
		return err
	}))
	expectDenied(t, "NetBIOS-Zustand per UPDATE", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.directories SET netbios_status = 'freigegeben' WHERE id = $1`, sub)
		return err
	}))
	// Geschwister sehen den Antrag nicht, Eltern schon.
	countDom := func(user string) int {
		var n int
		asUser(t, user, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.directory_domains WHERE directory_id = $1`, sub).Scan(&n)
		})
		return n
	}
	if countDom("oa_admin") != 0 || countDom("it_admin") != 2 {
		t.Errorf("Sichtbarkeit: Geschwister %d, Eltern %d", countDom("oa_admin"), countDom("it_admin"))
	}
	// Nur der Betreiber entscheidet.
	decide := func(user, kind, value string, ok bool) error {
		return asUserCommit(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT openwacht.login_claim_decide($1, $2, $3, $4)`, sub, kind, value, ok)
			return err
		})
	}
	expectDenied(t, "Admin des Untermandanten gibt frei", decide("fw_admin", "domaene", "fw.example", true))
	expectDenied(t, "Geschwister gibt frei", decide("oa_admin", "domaene", "fw.example", true))
	expectDenied(t, "Anträge lesen ohne Betreiber", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM openwacht.login_claims()`)
		return err
	}))
	var claims int
	asUser(t, "it_admin", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.login_claims() WHERE status = 'beantragt'`).Scan(&claims)
	})
	if claims != 3 {
		t.Errorf("Anträge: %d, erwartet 3", claims)
	}
	expectOK(t, "Betreiber gibt frei", decide("it_admin", "domaene", "fw.example", true))
	expectOK(t, "Betreiber gibt NetBIOS frei", decide("it_admin", "netbios", "firma", true))
	if login("fw.example", nil) != sub || login(nil, "firma") != sub {
		t.Error("nach Freigabe keine Anmeldung")
	}
	// Doppelte Freigabe scheitert an der Eindeutigkeit.
	if err := decide("it_admin", "domaene", "beispiel.example", true); sqlState(err) != "23505" {
		t.Errorf("zweite Freigabe derselben Domäne: %v", err)
	}
	expectOK(t, "Betreiber lehnt ab", decide("it_admin", "domaene", "beispiel.example", false))
	if status(sub, "beispiel.example") != "abgelehnt" {
		t.Error("Ablehnung nicht gespeichert")
	}
	// Neuer NetBIOS-Name: wieder beantragt; unveränderter Name bleibt frei.
	asUserCommit(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.directories SET name = 'FW neu' WHERE id = $1`, sub)
		return err
	})
	env.owner.QueryRow(ctx, `SELECT netbios_status FROM openwacht.directories WHERE id = $1`, sub).Scan(&nb)
	if nb != "freigegeben" {
		t.Errorf("Name geändert, NetBIOS gleich: %s", nb)
	}
	asUserCommit(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.directories SET netbios = 'ANDERS' WHERE id = $1`, sub)
		return err
	})
	env.owner.QueryRow(ctx, `SELECT netbios_status FROM openwacht.directories WHERE id = $1`, sub).Scan(&nb)
	if nb != "beantragt" {
		t.Errorf("neuer NetBIOS-Name: %s", nb)
	}
	var audits int
	env.owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('domaene.beantragt', 'domaene.freigegeben', 'domaene.abgelehnt', 'netbios.beantragt', 'netbios.freigegeben')`).Scan(&audits)
	if audits < 6 {
		t.Errorf("Audit-Einträge: %d", audits)
	}

	// I2: Höchstdauer der Sitzung je Anbindung
	env.owner.Exec(ctx, `UPDATE openwacht.directories SET session_hours = 2 WHERE id = $1`, sub)
	env.owner.Exec(ctx, `UPDATE openwacht.users SET directory_id = $2 WHERE id = $1`, env.users["fw_leser"], sub)
	defer env.owner.Exec(ctx, `UPDATE openwacht.users SET directory_id = NULL WHERE id = $1`, env.users["fw_leser"])
	var hours *float64
	env.app.QueryRow(ctx, `SELECT extract(epoch FROM openwacht.session_max_for($1)) / 3600`, env.users["fw_leser"]).Scan(&hours)
	if hours == nil || *hours != 2 {
		t.Errorf("Höchstdauer: %v", hours)
	}
	env.app.QueryRow(ctx, `SELECT extract(epoch FROM openwacht.session_max_for($1)) / 3600`, env.users["fw_admin"]).Scan(&hours)
	if hours != nil {
		t.Errorf("lokales Konto mit Höchstdauer %v", *hours)
	}
	if _, err := env.owner.Exec(ctx, `UPDATE openwacht.directories SET session_hours = 13 WHERE id = $1`, sub); err == nil {
		t.Error("13 Stunden angenommen")
	}
}
