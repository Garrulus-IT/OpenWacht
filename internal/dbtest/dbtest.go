// SPDX-License-Identifier: AGPL-3.0-only

// Package dbtest stellt für Tests eine frische PostgreSQL-Datenbank bereit:
// eigene Datenbank, eigene Login-Rollen (Eigentümer und Anwendung) mit
// zufälligen Namen und Passwörtern, damit parallel laufende Testpakete sich
// nicht in die Quere kommen. Nach dem Test wird alles entfernt.
//
// Voraussetzung: OPENWACHT_TEST_DSN mit einem Superuser. Ist die Variable nicht
// gesetzt, wird übersprungen, außer OPENWACHT_REQUIRE_DB=1 (CI): dann Fehler.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

// ErrSkip bedeutet: keine Testdatenbank konfiguriert, Tests überspringen.
var ErrSkip = errors.New("OPENWACHT_TEST_DSN nicht gesetzt: Datenbanktests werden übersprungen")

// DB ist eine Testdatenbank mit Verbindungsdaten für drei Rollen.
type DB struct {
	Name     string
	SuperCfg *pgx.ConnConfig // Superuser, verbunden mit der Testdatenbank
	OwnerCfg *pgx.ConnConfig // Eigentümer: führt Migrationen aus
	AppCfg   *pgx.ConnConfig // Anwendung: Mitglied von openwacht_app, für sie gilt RLS
	TrapsCfg *pgx.ConnConfig // Trap-Dienst: Mitglied von openwacht_traps

	adminCfg                      *pgx.ConnConfig
	ownerRole, appRole, trapsRole string
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// New legt Rollen und Datenbank an. Bei ErrSkip soll der Aufrufer überspringen.
func New(ctx context.Context) (*DB, error) {
	dsn := os.Getenv("OPENWACHT_TEST_DSN")
	if dsn == "" {
		if os.Getenv("OPENWACHT_REQUIRE_DB") == "1" {
			return nil, errors.New("OPENWACHT_TEST_DSN fehlt, Datenbanktests sind aber Pflicht (OPENWACHT_REQUIRE_DB=1)")
		}
		return nil, ErrSkip
	}
	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		return nil, err
	}
	defer admin.Close(ctx)

	suffix := randHex(4)
	d := &DB{
		Name:      "openwacht_test_" + suffix,
		adminCfg:  adminCfg,
		ownerRole: "openwacht_t_" + suffix + "_owner",
		appRole:   "openwacht_t_" + suffix + "_app",
		trapsRole: "openwacht_t_" + suffix + "_traps",
	}
	ownerPW, appPW, trapsPW := randHex(16), randHex(16), randHex(16)
	stmts := []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openwacht_app') THEN CREATE ROLE openwacht_app NOLOGIN; END IF; END $$`,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, d.ownerRole, ownerPW),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' IN ROLE openwacht_app`, d.appRole, appPW),
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openwacht_traps') THEN CREATE ROLE openwacht_traps NOLOGIN; END IF; END $$`,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' IN ROLE openwacht_traps`, d.trapsRole, trapsPW),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, d.Name, d.ownerRole),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, d.Name),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, d.Name, d.appRole, d.trapsRole),
	}
	for _, s := range stmts {
		if _, err := admin.Exec(ctx, s); err != nil {
			d.Close()
			return nil, fmt.Errorf("Testdatenbank anlegen: %w", err)
		}
	}
	with := func(user, pw string) *pgx.ConnConfig {
		c := adminCfg.Copy()
		c.Database = d.Name
		if user != "" {
			c.User, c.Password = user, pw
		}
		return c
	}
	d.SuperCfg = with("", "")
	d.OwnerCfg = with(d.ownerRole, ownerPW)
	d.AppCfg = with(d.appRole, appPW)
	d.TrapsCfg = with(d.trapsRole, trapsPW)
	return d, nil
}

// Close entfernt Datenbank und Login-Rollen. Fehler werden ignoriert.
func (d *DB) Close() {
	ctx := context.Background()
	admin, err := pgx.ConnectConfig(ctx, d.adminCfg)
	if err != nil {
		return
	}
	defer admin.Close(ctx)
	admin.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, d.Name))
	admin.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, d.appRole))
	admin.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, d.trapsRole))
	admin.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, d.ownerRole))
}
