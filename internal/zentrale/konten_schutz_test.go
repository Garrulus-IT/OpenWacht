// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Befund H2 (Etappe 29): Ein Admin darf Passwort, Sperre, Anzeigename,
// Sitzungen und das Konto selbst nur ändern, wenn jede Rolle des Kontos auf
// einem Mandanten liegt, den er administriert. Baum wie in verwaltung_test.go:
//
//	IT ─┬─ Fertigung ── Lager Nord
//	    └─ Organisation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/auth"
)

// kontoMitRollen legt ein Konto im Heimatmandanten home an, mit Rollen
// (Mandant → Rolle). Mit pending bekommt es ein unbestätigtes TOTP-Geheimnis,
// mit enabled ein eingerichtetes.
func kontoMitRollen(t *testing.T, name, home string, roles map[string]string, pending, enabled bool) string {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword(testPassword, testParams)
	var id string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
		VALUES ($1, $2, $3, $4) RETURNING id::text`, ids[home], name+"@test.invalid", name, hash).Scan(&id); err != nil {
		t.Fatal(err)
	}
	ids[name] = id
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.sessions WHERE user_id = $1`, id)
		owner.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1`, id)
		owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true, email = 'weg-'||id||'@test.invalid' WHERE id = $1`, id)
	})
	for tn, role := range roles {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			id, ids[tn], role); err != nil {
			t.Fatal(err)
		}
	}
	if pending || enabled {
		secret, _ := auth.GenerateTOTPSecret()
		enc, _ := auth.Seal(deriveKey(testKey, "openwacht secretbox v1"), secret, []byte(id))
		if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2, totp_enabled = $3 WHERE id = $1`,
			id, enc, enabled); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// asDB führt fn in einer Transaktion der App-Rolle als Benutzer user aus und
// rollt danach zurück.
func asDB(t *testing.T, user string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids[user]); err != nil {
		t.Fatal(err)
	}
	return fn(tx)
}

func isDenied(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501"
}

func TestKontoMitFremdenRollen(t *testing.T) {
	ctx := context.Background()
	// Das Konto aus dem Review: Heimat Lager, Operator in IT und Organisation.
	ext := kontoMitRollen(t, "k_ext", "Lager Nord",
		map[string]string{"Lager Nord": "leser", "IT": "operator", "Organisation": "operator"}, true, false)
	// Admin-Rolle außerhalb, noch ohne TOTP (Angreifer könnte es sonst selbst einrichten).
	extAdm := kontoMitRollen(t, "k_extchef", "Lager Nord",
		map[string]string{"Lager Nord": "leser", "Organisation": "admin"}, false, false)
	// Ohne fremde Rollen, mit unbestätigtem TOTP.
	plain := kontoMitRollen(t, "k_plain", "Lager Nord", map[string]string{"Lager Nord": "leser"}, true, false)
	// Rolle beim Elternknoten Fertigung: liegt im Bereich von v_fw.
	parent := kontoMitRollen(t, "k_eltern", "Lager Nord",
		map[string]string{"Lager Nord": "leser", "Fertigung": "operator"}, false, false)
	// Nur eine Rolle außerhalb des Heimatmandanten (Organisation).
	onlyForeign := kontoMitRollen(t, "k_nurfremd", "Lager Nord", map[string]string{"Organisation": "operator"}, false, false)
	// Mit eingerichteter 2FA: bleibt beim Reset erhalten.
	twofa := kontoMitRollen(t, "k_zweif", "Lager Nord", map[string]string{"Lager Nord": "leser"}, false, true)

	setPw := func(user, target, pw string) response {
		return as(t, user).do("PUT", "/api/v1/benutzer/"+target+"/passwort", map[string]string{"passwort": pw})
	}
	patch := func(user, target string, body map[string]any) response {
		return as(t, user).do("PATCH", "/api/v1/benutzer/"+target, body)
	}

	// --- Der Angriff aus dem Review: jetzt 403 mit Meldung -----------------
	r := setPw("v_fw", ext, "uebernahme-passwort-1")
	expectStatus(t, "v_fw setzt Passwort eines Kontos mit Rollen in IT und Organisation", r, 403)
	if !strings.Contains(r.raw, "nicht verwaltest") {
		t.Errorf("Meldung fehlt: %s", r.raw)
	}
	if lr := newClient(t, vSrv).do("POST", "/api/v1/sitzung",
		map[string]string{"email": "k_ext@test.invalid", "passwort": "uebernahme-passwort-1"}); lr.status == 200 {
		t.Error("Anmeldung mit dem gesetzten Passwort möglich")
	}
	expectStatus(t, "v_fw setzt Passwort (Admin-Rolle außerhalb, ohne TOTP)", setPw("v_fw", extAdm, "uebernahme-passwort-2"), 403)
	// Admin des fremden Mandanten, aber nicht des Heimatmandanten: wie bisher 404.
	expectStatus(t, "v_oa setzt Passwort (nicht Admin des Heimatmandanten)", setPw("v_oa", extAdm, "uebernahme-passwort-3"), 404)
	expectStatus(t, "v_oa setzt Passwort im Lager (Geschwister)", setPw("v_oa", plain, "uebernahme-passwort-4"), 404)
	expectStatus(t, "v_lz (Leser) setzt Passwort", setPw("v_lz", plain, "uebernahme-passwort-5"), 404)

	// Sperren, Entsperren, Anzeigename
	expectStatus(t, "v_fw sperrt Konto mit fremden Rollen", patch("v_fw", ext, map[string]any{"deaktiviert": true}), 403)
	expectStatus(t, "v_fw benennt Konto mit fremden Rollen um", patch("v_fw", ext, map[string]any{"anzeigename": "gekapert"}), 403)
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = true WHERE id = $1`, extAdm)
	expectStatus(t, "v_fw entsperrt Konto mit fremder Admin-Rolle", patch("v_fw", extAdm, map[string]any{"deaktiviert": false}), 403)
	var disabled bool
	var name string
	owner.QueryRow(ctx, `SELECT disabled FROM openwacht.users WHERE id = $1`, extAdm).Scan(&disabled)
	owner.QueryRow(ctx, `SELECT display_name FROM openwacht.users WHERE id = $1`, ext).Scan(&name)
	if !disabled || name != "k_ext" {
		t.Errorf("trotz 403 geändert: gesperrt=%v Name=%q", disabled, name)
	}
	owner.Exec(ctx, `UPDATE openwacht.users SET disabled = false WHERE id = $1`, extAdm)

	// --- Dieselbe Regel in der Datenbank (ohne API) --------------------------
	hash, _ := auth.HashPassword("db-direkt-passwort-1", testParams)
	if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, ext, hash)
		return err
	}); !isDenied(err) {
		t.Errorf("DB: auth_set_password durch v_fw: %v", err)
	}
	if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT openwacht.session_delete_user($1)`, ext)
		return err
	}); !isDenied(err) {
		t.Errorf("DB: session_delete_user durch v_fw: %v", err)
	}
	for what, sql := range map[string]string{
		"sperren":    `UPDATE openwacht.users SET disabled = true WHERE id = $1`,
		"umbenennen": `UPDATE openwacht.users SET display_name = 'x' WHERE id = $1`,
		"löschen":    `DELETE FROM openwacht.users WHERE id = $1`,
	} {
		var n int64
		if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
			ct, err := tx.Exec(ctx, sql, ext)
			n = ct.RowsAffected()
			return err
		}); err != nil || n != 0 {
			t.Errorf("DB: %s durch v_fw: %d Zeilen, %v", what, n, err)
		}
	}
	// Positivfall in der DB: v_fw darf das Konto ohne fremde Rollen ändern.
	if err := asDB(t, "v_fw", func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE openwacht.users SET display_name = 'ok' WHERE id = $1`, plain)
		if err == nil && ct.RowsAffected() != 1 {
			err = errors.New("keine Zeile geändert")
		}
		return err
	}); err != nil {
		t.Errorf("DB: v_fw ändert Konto ohne fremde Rollen: %v", err)
	}
	// Admin aller Rollen-Mandanten, aber nicht des Heimatmandanten: nein.
	if err := asDB(t, "v_oa", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, onlyForeign, hash)
		return err
	}); !isDenied(err) {
		t.Errorf("DB: auth_set_password durch Admin des Rollen-, nicht des Heimatmandanten: %v", err)
	}
	expectStatus(t, "v_oa setzt Passwort (nur Rolle im Organisation)", setPw("v_oa", onlyForeign, "uebernahme-passwort-6"), 404)
	// user_manageable verrät nichts über Konten außerhalb des eigenen Bereichs.
	var m *bool
	asDB(t, "v_oa", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT openwacht.user_manageable($1)`, plain).Scan(&m)
	})
	if m == nil || *m {
		t.Errorf("user_manageable für Geschwister: %v", m)
	}

	// --- Erlaubt bleibt --------------------------------------------------------
	// Admin des Hauptmandanten verwaltet alle Mandanten des Kontos.
	expectStatus(t, "v_it setzt Passwort des Kontos mit fremden Rollen", setPw("v_it", ext, "neues-passwort-von-it"), 204)
	expectStatus(t, "Anmeldung danach", newClient(t, vSrv).do("POST", "/api/v1/sitzung",
		map[string]string{"email": "k_ext@test.invalid", "passwort": "neues-passwort-von-it"}), 200)
	expectStatus(t, "v_it benennt um", patch("v_it", ext, map[string]any{"anzeigename": "Konto ext"}), 204)
	// Rolle beim Elternknoten innerhalb des eigenen Bereichs.
	expectStatus(t, "v_fw setzt Passwort (Rolle bei Fertigung)", setPw("v_fw", parent, "neues-passwort-eltern"), 204)

	// Konto ohne fremde Rollen: Reset beendet Sitzungen und verwirft das
	// unbestätigte TOTP-Geheimnis.
	pc := newClient(t, vSrv)
	expectStatus(t, "k_plain meldet sich an", pc.login("k_plain"), 200)
	expectStatus(t, "v_fw setzt Passwort ohne fremde Rollen", setPw("v_fw", plain, "neues-passwort-plain"), 204)
	expectStatus(t, "alte Sitzung nach Reset", pc.do("GET", "/api/v1/ich", nil), 401)
	var pendingLeft bool
	owner.QueryRow(ctx, `SELECT totp_secret_enc IS NOT NULL FROM openwacht.users WHERE id = $1`, plain).Scan(&pendingLeft)
	if pendingLeft {
		t.Error("unbestätigtes TOTP-Geheimnis nach Admin-Reset noch vorhanden")
	}
	// Eingerichtete 2FA bleibt.
	expectStatus(t, "v_fw setzt Passwort (2FA eingerichtet)", setPw("v_fw", twofa, "neues-passwort-zweif"), 204)
	var enabled, kept bool
	owner.QueryRow(ctx, `SELECT totp_enabled, totp_secret_enc IS NOT NULL FROM openwacht.users WHERE id = $1`, twofa).Scan(&enabled, &kept)
	if !enabled || !kept {
		t.Errorf("eingerichtete 2FA nach Reset: aktiv=%v Geheimnis=%v", enabled, kept)
	}

	// Das Konto selbst ändert sein Passwort weiter (mit dem bisherigen); ein
	// unbestätigtes Geheimnis bleibt dabei.
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = '\x01'::bytea WHERE id = $1`, ext)
	sc := newClient(t, vSrv)
	lr := sc.do("POST", "/api/v1/sitzung", map[string]string{"email": "k_ext@test.invalid", "passwort": "neues-passwort-von-it"})
	expectStatus(t, "k_ext meldet sich an", lr, 200)
	sc.csrf, _ = lr.body["csrf"].(string)
	expectStatus(t, "k_ext ändert eigenes Passwort", sc.do("PUT", "/api/v1/benutzer/"+ext+"/passwort",
		map[string]string{"passwort": "eigenes-neues-passwort", "altes_passwort": "neues-passwort-von-it"}), 204)
	owner.QueryRow(ctx, `SELECT totp_secret_enc IS NOT NULL FROM openwacht.users WHERE id = $1`, ext).Scan(&pendingLeft)
	if !pendingLeft {
		t.Error("eigener Passwortwechsel hat das unbestätigte Geheimnis verworfen")
	}
}

// Das bisherige Passwort lässt sich beim Ändern nicht beliebig oft raten:
// Fehlversuche zählen wie bei der Anmeldung auf Konto und Quelle. Nach fünf
// Fehlversuchen wird auch das richtige Passwort aus dieser Quelle abgelehnt;
// aus einer anderen Quelle bleibt das Konto benutzbar.
func TestEigenesPasswortNichtRatbar(t *testing.T) {
	verwaltungSetup(t)
	_, srv, _ := quellenServer(t)
	resetLogin(t, "v_oa_user")
	t.Cleanup(func() { resetLogin(t, "v_oa_user") })
	c := from(t, srv, "198.51.100.77")
	expectStatus(t, "Anmeldung", c.login("v_oa_user"), 200)
	path := "/api/v1/benutzer/" + ids["v_oa_user"] + "/passwort"
	for i := range 5 {
		r := c.do("PUT", path, map[string]string{"passwort": "ganz-neues-passwort-1", "altes_passwort": fmt.Sprintf("geraten-%02d-geraten", i)})
		expectStatus(t, "falsches altes Passwort", r, 400)
	}
	r := c.do("PUT", path, map[string]string{"passwort": "ganz-neues-passwort-1", "altes_passwort": testPassword})
	if r.status != 403 {
		t.Fatalf("nach fünf Fehlversuchen: Status %d, erwartet 403 (%s)", r.status, r.raw)
	}
	var fails int
	if err := owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log
		WHERE actor_user_id = $1 AND action = 'bestaetigung.fehlgeschlagen' AND details->>'grund' = 'passwort_aendern'`,
		ids["v_oa_user"]).Scan(&fails); err != nil || fails != 5 {
		t.Errorf("Audit: %d Einträge (%v), erwartet 5", fails, err)
	}
	// Andere Quelle: nicht gesperrt, das Passwort ist unverändert.
	d := from(t, srv, "198.51.100.78")
	expectStatus(t, "Anmeldung aus anderer Quelle mit altem Passwort", d.login("v_oa_user"), 200)
}
