// SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/jackc/pgx/v5"
)

// TestErsetztePruefsumme: Eine Datenbank, die 0044 mit dem Text vor 0.99.0
// angewendet hat, wird stillschweigend auf die neue Prüfsumme umgestellt.
// Jede andere Abweichung bleibt ErrChecksumMismatch.
func TestErsetztePruefsumme(t *testing.T) {
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
	if _, err := Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}

	alt, _ := hex.DecodeString(replacedChecksums[44][0])
	if _, err := owner.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = 44`, alt); err != nil {
		t.Fatal(err)
	}
	if n, err := Migrate(ctx, owner); err != nil || n != 0 {
		t.Fatalf("alter Stand von 0044: n=%d err=%v", n, err)
	}
	var sum []byte
	owner.QueryRow(ctx, `SELECT checksum FROM openwacht.schema_migrations WHERE version = 44`).Scan(&sum)
	if hex.EncodeToString(sum) == replacedChecksums[44][0] {
		t.Fatal("Prüfsumme wurde nicht nachgeführt")
	}

	fremd := make([]byte, 32)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = 44`, fremd); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, owner); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("fremde Prüfsumme: err=%v, erwartet ErrChecksumMismatch", err)
	}
	// Nur 0044 und 0046 haben einen Ersatz; die alte Prüfsumme von 0044 gilt nicht für 0045.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = 44`, sum); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = 45`, alt); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, owner); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("alte Prüfsumme an falscher Migration: err=%v", err)
	}
}
