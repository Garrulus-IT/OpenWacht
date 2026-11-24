// SPDX-License-Identifier: AGPL-3.0-only

package db

// Pflicht-Tests zur Mandantentrennung gegen ein echtes PostgreSQL.
//
// Testdatenbank und Rollen stellt das Paket dbtest bereit (OPENWACHT_TEST_DSN).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/dbtest"
)

type testEnv struct {
	super, owner, app *pgx.Conn
	appCfg            *pgx.ConnConfig
	tenants           map[string]string // Name -> ID
	users             map[string]string // Kurzname -> ID
}

var env *testEnv

func TestMain(m *testing.M) {
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Testumgebung:", err)
		os.Exit(1)
	}
	e, err := setup(ctx, tdb)
	if err != nil {
		tdb.Close()
		fmt.Fprintln(os.Stderr, "Testumgebung:", err)
		os.Exit(1)
	}
	env = e
	code := m.Run()
	for _, c := range []*pgx.Conn{e.app, e.owner, e.super} {
		c.Close(ctx)
	}
	tdb.Close()
	os.Exit(code)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func setup(ctx context.Context, tdb *dbtest.DB) (*testEnv, error) {
	e := &testEnv{appCfg: tdb.AppCfg, tenants: map[string]string{}, users: map[string]string{}}
	var err error
	if e.super, err = pgx.ConnectConfig(ctx, tdb.SuperCfg); err != nil {
		return nil, err
	}
	if e.owner, err = pgx.ConnectConfig(ctx, tdb.OwnerCfg); err != nil {
		return nil, err
	}
	if _, err := Migrate(ctx, e.owner); err != nil {
		return nil, err
	}
	if e.app, err = pgx.ConnectConfig(ctx, tdb.AppCfg); err != nil {
		return nil, err
	}
	if err := seed(ctx, e); err != nil {
		return nil, fmt.Errorf("Testdaten: %w", err)
	}
	return e, nil
}

// Testbaum:
//
//	IT (Hauptmandant)
//	├── Fertigung
//	│   └── Lager Nord
//	└── Organisation
func seed(ctx context.Context, e *testEnv) error {
	tenants := []struct{ name, parent string }{
		{"IT", ""}, {"Fertigung", "IT"}, {"Lager Nord", "Fertigung"}, {"Organisation", "IT"},
	}
	for _, t := range tenants {
		var parent any
		if t.parent != "" {
			parent = e.tenants[t.parent]
		}
		var id string
		if err := e.owner.QueryRow(ctx,
			`INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2) RETURNING id::text`,
			parent, t.name).Scan(&id); err != nil {
			return err
		}
		e.tenants[t.name] = id
	}
	users := []struct{ short, tenant, role, roleAt string }{
		{"it_admin", "IT", "admin", "IT"},
		{"fw_admin", "Fertigung", "admin", "Fertigung"},
		{"fw_leser", "Fertigung", "leser", "Fertigung"},
		{"lz_leser", "Lager Nord", "leser", "Lager Nord"},
		{"oa_admin", "Organisation", "admin", "Organisation"},
		{"ohne_rolle", "IT", "", ""},
		{"gesperrt", "IT", "admin", "IT"},
	}
	for _, u := range users {
		var id string
		if err := e.owner.QueryRow(ctx,
			`INSERT INTO openwacht.users (tenant_id, email, display_name, disabled)
			 VALUES ($1, $2, $3, $4) RETURNING id::text`,
			e.tenants[u.tenant], u.short+"@test.invalid", u.short, u.short == "gesperrt").Scan(&id); err != nil {
			return err
		}
		e.users[u.short] = id
		if u.role != "" {
			if _, err := e.owner.Exec(ctx,
				`INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
				id, e.tenants[u.roleAt], u.role); err != nil {
				return err
			}
		}
	}
	return nil
}

// asUser führt fn in einer Transaktion der Anwendungsrolle mit gesetztem
// Benutzerkontext aus und rollt danach immer zurück. user == "" bedeutet: kein Kontext.
func asUser(t *testing.T, user string, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := env.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if user != "" {
		id, ok := env.users[user]
		if !ok {
			t.Fatalf("unbekannter Testbenutzer %q", user)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, id); err != nil {
			t.Fatal(err)
		}
	}
	return fn(tx)
}

func visibleTenantNames(t *testing.T, user string) []string {
	t.Helper()
	var names []string
	err := asUser(t, user, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT name FROM openwacht.tenants`)
		if err != nil {
			return err
		}
		names, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	return names
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// expectDenied prüft, dass err eine Rechte- oder RLS-Verletzung ist (SQLSTATE 42501).
func expectDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: erwartet abgelehnt, war aber erlaubt", what)
		return
	}
	if sqlState(err) != "42501" {
		t.Errorf("%s: erwartet SQLSTATE 42501, bekommen: %v", what, err)
	}
}

func expectOK(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: erwartet erlaubt, Fehler: %v", what, err)
	}
}

// --- Sichtbarkeit -----------------------------------------------------------

func TestOhneKontextIstNichtsSichtbar(t *testing.T) {
	for _, table := range []string{"tenants", "users", "role_assignments", "audit_log"} {
		err := asUser(t, "", func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.`+table).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return fmt.Errorf("%d Zeilen sichtbar", n)
			}
			return nil
		})
		if err != nil {
			t.Errorf("%s ohne Kontext: %v", table, err)
		}
	}
}

func TestSichtbarkeitImMandantenbaum(t *testing.T) {
	cases := map[string][]string{
		"it_admin":   {"Fertigung", "IT", "Lager Nord", "Organisation"},
		"fw_admin":   {"Fertigung", "Lager Nord"},
		"fw_leser":   {"Fertigung", "Lager Nord"},
		"lz_leser":   {"Lager Nord"},
		"oa_admin":   {"Organisation"},
		"ohne_rolle": nil,
		"gesperrt":   nil,
	}
	for user, want := range cases {
		got := visibleTenantNames(t, user)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s sieht %v, erwartet %v", user, got, want)
		}
	}
}

func TestBenutzerSichtbarkeit(t *testing.T) {
	err := asUser(t, "fw_admin", func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT display_name FROM openwacht.users ORDER BY 1`)
		if err != nil {
			return err
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if want := "fw_admin,fw_leser,lz_leser"; strings.Join(got, ",") != want {
			return fmt.Errorf("sieht %v, erwartet %s", got, want)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	// Ohne Rolle sieht man nur sich selbst.
	err = asUser(t, "ohne_rolle", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.users`).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("sieht %d Benutzer, erwartet 1 (sich selbst)", n)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestUngueltigerKontextIstFehler(t *testing.T) {
	ctx := context.Background()
	tx, err := env.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	tx.Exec(ctx, `SELECT set_config('app.user_id', 'kein-uuid', true)`)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.tenants`).Scan(&n); err == nil {
		t.Errorf("ungültiger Kontext muss ein Fehler sein, sah %d Zeilen", n)
	}
}

// --- Schreibrechte ----------------------------------------------------------

func insertTenant(tx pgx.Tx, parent, name string) error {
	_, err := tx.Exec(context.Background(),
		`INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2)`, env.tenants[parent], name)
	return err
}

func TestMandantAnlegen(t *testing.T) {
	expectOK(t, "it_admin unter Fertigung", asUser(t, "it_admin", func(tx pgx.Tx) error {
		return insertTenant(tx, "Fertigung", "Lager Süd")
	}))
	// Untermandanten nur mit Freigabe der IT: Fertigung-Admin darf nicht selbst anlegen.
	expectDenied(t, "fw_admin unter Fertigung", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		return insertTenant(tx, "Fertigung", "Lager Süd")
	}))
	expectDenied(t, "fw_admin unter IT", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		return insertTenant(tx, "IT", "Neu")
	}))
	expectDenied(t, "lz_leser unter Lager", asUser(t, "lz_leser", func(tx pgx.Tx) error {
		return insertTenant(tx, "Lager Nord", "Neu")
	}))
	expectDenied(t, "it_admin neuer Hauptmandant", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO openwacht.tenants (parent_id, name) VALUES (NULL, 'Zweite Wurzel')`)
		return err
	}))
}

func TestMandantUmbenennenUndLoeschen(t *testing.T) {
	ctx := context.Background()
	expectOK(t, "fw_admin benennt Lager um", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE openwacht.tenants SET name = 'LZ Nord' WHERE id = $1`, env.tenants["Lager Nord"])
		if err == nil && ct.RowsAffected() != 1 {
			err = fmt.Errorf("%d Zeilen geändert", ct.RowsAffected())
		}
		return err
	}))
	// Fremde Knoten sind für UPDATE unsichtbar: 0 Zeilen, kein Fehler.
	err := asUser(t, "fw_admin", func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE openwacht.tenants SET name = 'gekapert' WHERE id = $1`, env.tenants["Organisation"])
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 0 {
			return fmt.Errorf("fremden Mandanten umbenannt")
		}
		return nil
	})
	expectOK(t, "fw_admin kann Organisation nicht umbenennen", err)

	expectDenied(t, "Elternknoten per UPDATE ändern", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.tenants SET parent_id = $1 WHERE id = $2`,
			env.tenants["Organisation"], env.tenants["Lager Nord"])
		return err
	}))

	// Löschen nur durch Admin des Elternknotens: fw_admin darf "Fertigung" selbst nicht löschen.
	err = asUser(t, "fw_admin", func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM openwacht.tenants WHERE id = $1`, env.tenants["Fertigung"])
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 0 {
			return fmt.Errorf("eigenen Knoten gelöscht")
		}
		return nil
	})
	expectOK(t, "fw_admin löscht eigenen Knoten nicht", err)
}

func TestVerschiebenAuchFuerEigentuemerGesperrt(t *testing.T) {
	_, err := env.owner.Exec(context.Background(), `UPDATE openwacht.tenants SET parent_id = $1 WHERE id = $2`,
		env.tenants["Organisation"], env.tenants["Lager Nord"])
	if err == nil || !strings.Contains(err.Error(), "verschieben") {
		t.Errorf("Verschieben muss abgelehnt werden, Fehler: %v", err)
	}
}

func TestNurEinHauptmandant(t *testing.T) {
	_, err := env.owner.Exec(context.Background(), `INSERT INTO openwacht.tenants (parent_id, name) VALUES (NULL, 'Zweite Wurzel')`)
	if sqlState(err) != "23505" {
		t.Errorf("zweiter Hauptmandant muss an Eindeutigkeit scheitern, Fehler: %v", err)
	}
}

func TestRollenVergeben(t *testing.T) {
	ctx := context.Background()
	grant := func(user, target, tenant, role string) error {
		return asUser(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
				env.users[target], env.tenants[tenant], role)
			return err
		})
	}
	expectOK(t, "fw_admin: fw_leser wird Admin im Lager", grant("fw_admin", "fw_leser", "Lager Nord", "admin"))
	expectDenied(t, "fw_admin: Rolle auf IT", grant("fw_admin", "fw_leser", "IT", "admin"))
	expectDenied(t, "fw_admin: Rolle auf Organisation", grant("fw_admin", "fw_leser", "Organisation", "leser"))
	expectDenied(t, "fw_admin: Rolle für unsichtbaren Benutzer", grant("fw_admin", "ohne_rolle", "Fertigung", "leser"))
	expectDenied(t, "fw_leser: vergibt sich selbst Admin", grant("fw_leser", "fw_leser", "Fertigung", "admin"))
	expectDenied(t, "oa_admin: Rolle in Fertigung", grant("oa_admin", "oa_admin", "Fertigung", "admin"))

	// Rollen entziehen nur im eigenen Teilbaum.
	err := asUser(t, "fw_admin", func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1`, env.users["it_admin"])
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 0 {
			return fmt.Errorf("Rolle der IT entzogen")
		}
		return nil
	})
	expectOK(t, "fw_admin entzieht it_admin nichts", err)
}

func TestBenutzerAnlegen(t *testing.T) {
	create := func(user, tenant string) error {
		return asUser(t, user, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, $2, 'Neu')`,
				env.tenants[tenant], "neu-"+randHex(3)+"@test.invalid")
			return err
		})
	}
	expectOK(t, "fw_admin legt Benutzer im Lager an", create("fw_admin", "Lager Nord"))
	expectDenied(t, "fw_admin legt Benutzer im Organisation an", create("fw_admin", "Organisation"))
	expectDenied(t, "fw_leser legt Benutzer an", create("fw_leser", "Fertigung"))
}

// --- Spalten- und Tabellenrechte -------------------------------------------

func TestPasswortHashNichtLesbar(t *testing.T) {
	expectDenied(t, "password_hash lesen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `SELECT password_hash FROM openwacht.users`)
		return err
	}))
	expectDenied(t, "password_hash setzen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE openwacht.users SET password_hash = 'x'`)
		return err
	}))
}

func TestAbschlusstabelleGesperrt(t *testing.T) {
	expectDenied(t, "tenant_closure lesen", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `SELECT * FROM openwacht.tenant_closure`)
		return err
	}))
}

func TestAnwendungsrolleUmgehtKeinRLS(t *testing.T) {
	ctx := context.Background()
	var super, bypass bool
	if err := env.app.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		t.Fatal(err)
	}
	if super || bypass {
		t.Fatal("Anwendungsrolle darf weder SUPERUSER noch BYPASSRLS haben")
	}
	var owned int
	if err := env.app.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'openwacht' AND pg_has_role(current_user, tableowner, 'USAGE')`).Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned != 0 {
		t.Fatalf("Anwendungsrolle besitzt %d Tabellen und würde RLS umgehen", owned)
	}
	var withoutRLS []string
	rows, err := env.owner.Query(ctx,
		`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'openwacht' AND c.relkind = 'r' AND NOT c.relrowsecurity
		    AND has_table_privilege('openwacht_app', c.oid, 'SELECT')`)
	if err != nil {
		t.Fatal(err)
	}
	withoutRLS, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutRLS) != 0 {
		t.Fatalf("Tabellen ohne RLS, die die Anwendung lesen darf: %v", withoutRLS)
	}
}

// --- Audit-Log --------------------------------------------------------------

func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	write := func(user, tenant string) error {
		return asUser(t, user, func(tx pgx.Tx) error {
			var tid any
			if tenant != "" {
				tid = env.tenants[tenant]
			}
			_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details)
				VALUES ($1, 'test.eintrag', '{"x":1}')`, tid)
			if err != nil {
				return err
			}
			return tx.Commit(ctx)
		})
	}
	expectOK(t, "fw_admin schreibt für Fertigung", write("fw_admin", "Fertigung"))
	expectDenied(t, "fw_admin schreibt für Organisation", write("fw_admin", "Organisation"))
	expectDenied(t, "fw_admin schreibt ohne Mandant", write("fw_admin", ""))
	expectOK(t, "it_admin schreibt ohne Mandant", write("it_admin", ""))
	expectDenied(t, "ohne Kontext schreiben", asUser(t, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action) VALUES ($1, 'x')`, env.tenants["IT"])
		return err
	}))

	// Handelnde Person bestimmt die Datenbank, nicht die Anfrage.
	expectDenied(t, "actor_user_id selbst setzen", asUser(t, "fw_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, actor_user_id) VALUES ($1, 'x', $2)`,
			env.tenants["Fertigung"], env.users["it_admin"])
		return err
	}))
	var actor string
	if err := env.owner.QueryRow(ctx,
		`SELECT actor_user_id::text FROM openwacht.audit_log WHERE tenant_id = $1 ORDER BY chain_seq DESC LIMIT 1`,
		env.tenants["Fertigung"]).Scan(&actor); err != nil || actor != env.users["fw_admin"] {
		t.Errorf("actor_user_id = %q (%v), erwartet fw_admin", actor, err)
	}

	// Sichtbarkeit: Organisation sieht keine Fertigung-Einträge.
	err := asUser(t, "oa_admin", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id IS DISTINCT FROM $1`,
			env.tenants["Organisation"]).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("sieht %d fremde Einträge", n)
		}
		return nil
	})
	expectOK(t, "oa_admin sieht keine fremden Einträge", err)

	// Unveränderlich: für die Anwendung keine Rechte, für den Eigentümer ein Trigger.
	expectDenied(t, "Anwendung ändert Audit-Log", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE openwacht.audit_log SET action = 'weg'`)
		return err
	}))
	expectDenied(t, "Anwendung löscht Audit-Log", asUser(t, "it_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM openwacht.audit_log`)
		return err
	}))
	for _, stmt := range []string{
		`UPDATE openwacht.audit_log SET action = 'weg'`,
		`DELETE FROM openwacht.audit_log`,
		`TRUNCATE openwacht.audit_log`,
	} {
		if _, err := env.owner.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "unveränderlich") {
			t.Errorf("Eigentümer: %s muss scheitern, Fehler: %v", stmt, err)
		}
	}
}

func TestAuditKetteUndManipulation(t *testing.T) {
	ctx := context.Background()
	// Gleichzeitige Schreiber dürfen die Kette nicht zerreißen.
	appCfg := env.appCfg
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := pgx.ConnectConfig(ctx, appCfg)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close(ctx)
			for i := 0; i < 15; i++ {
				err := pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, env.users["it_admin"]); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action) VALUES ($1, 'test.parallel')`,
						env.tenants["IT"])
					return err
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var bad *int64
	if err := env.owner.QueryRow(ctx, `SELECT openwacht.audit_verify()`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != nil {
		t.Fatalf("Kette nach parallelem Schreiben defekt ab chain_seq %d", *bad)
	}

	// Ein Superuser kann Trigger abschalten; die Hash-Kette deckt das auf.
	tx, err := env.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, s := range []string{
		`ALTER TABLE openwacht.audit_log DISABLE TRIGGER audit_no_update`,
		`UPDATE openwacht.audit_log SET details = '{"x":2}' WHERE chain_seq = 2`,
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.QueryRow(ctx, `SELECT openwacht.audit_verify()`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad == nil || *bad != 2 {
		t.Fatalf("Manipulation nicht erkannt, audit_verify = %v", bad)
	}
}

// --- Migrationen ------------------------------------------------------------

func TestMigrationIdempotentUndGeschuetzt(t *testing.T) {
	ctx := context.Background()
	n, err := Migrate(ctx, env.owner)
	if err != nil || n != 0 {
		t.Fatalf("zweiter Lauf: %d neu, Fehler %v", n, err)
	}
	tx, err := env.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = '\x00' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		migs, _ := Migrations()
		env.owner.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = 1`, migs[0].Checksum[:])
	}()
	if _, err := Migrate(ctx, env.owner); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("veränderte Migration nicht erkannt: %v", err)
	}
}

func TestBenutzerAendernNurImEigenenTeilbaum(t *testing.T) {
	ctx := context.Background()
	upd := func(user, target string) (int64, error) {
		var n int64
		err := asUser(t, user, func(tx pgx.Tx) error {
			ct, err := tx.Exec(ctx, `UPDATE openwacht.users SET display_name = 'geändert' WHERE id = $1`, env.users[target])
			n = ct.RowsAffected()
			return err
		})
		return n, err
	}
	if n, err := upd("fw_admin", "oa_admin"); err != nil || n != 0 {
		t.Errorf("fw_admin ändert Benutzer im Organisation: %d Zeilen, %v", n, err)
	}
	if n, err := upd("fw_leser", "fw_admin"); err != nil || n != 0 {
		t.Errorf("fw_leser ändert Benutzer: %d Zeilen, %v", n, err)
	}
	if n, err := upd("it_admin", "lz_leser"); err != nil || n != 1 {
		t.Errorf("it_admin ändert Benutzer im Lager: %d Zeilen, %v", n, err)
	}
	if n, err := upd("fw_admin", "lz_leser"); err != nil || n != 1 {
		t.Errorf("fw_admin ändert Benutzer im Lager: %d Zeilen, %v", n, err)
	}
}
