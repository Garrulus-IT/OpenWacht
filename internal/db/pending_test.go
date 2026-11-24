// SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"context"
	"errors"
	"testing"

	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/jackc/pgx/v5"
)

// TestPending: leere Datenbank, Stand 0.20.1 (Migration 25) und aktuell.
// Pending darf nichts anlegen (läuft vor der Sicherung eines Updates).
func TestPending(t *testing.T) {
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	owner, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	migs, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}

	n, fresh, err := Pending(ctx, owner)
	if err != nil || !fresh || n != len(migs) {
		t.Fatalf("leere DB: n=%d fresh=%v err=%v", n, fresh, err)
	}
	var schema bool
	owner.QueryRow(ctx, `SELECT to_regnamespace('openwacht') IS NOT NULL`).Scan(&schema)
	if schema {
		t.Fatal("Pending hat das Schema angelegt")
	}

	if _, err := owner.Exec(ctx, `CREATE SCHEMA openwacht; CREATE TABLE openwacht.schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum bytea NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migs[:25] {
		if _, err := owner.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			m.Version, m.Name, m.Checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	if n, fresh, err = Pending(ctx, owner); err != nil || fresh || n != len(migs)-25 {
		t.Fatalf("Stand 25: n=%d fresh=%v err=%v", n, fresh, err)
	}
	if _, err := Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if n, fresh, err = Pending(ctx, owner); err != nil || fresh || n != 0 {
		t.Fatalf("aktuell: n=%d fresh=%v err=%v", n, fresh, err)
	}
}
