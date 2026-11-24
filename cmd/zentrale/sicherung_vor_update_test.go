// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/jackc/pgx/v5"
)

// TestSicherungVorUpdate: Stand 0.20.1 (Migration 25, ohne backup_log und
// settings.backup_hour) wird gesichert; aktuell und leer nicht.
func TestSicherungVorUpdate(t *testing.T) {
	if _, err := exec.LookPath("pg_dump"); err != nil {
		t.Skip("pg_dump fehlt")
	}
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
	dsn := tdb.OwnerCfg.ConnString()
	run := func() (string, []backupFile) {
		t.Helper()
		dir := t.TempDir()
		var out bytes.Buffer
		if err := backupBeforeUpdate(ctx, owner, dsn, dir, &out); err != nil {
			t.Fatal(err)
		}
		files, err := listBackups(dir)
		if err != nil {
			t.Fatal(err)
		}
		return out.String(), files
	}

	if out, files := run(); len(files) != 0 || !strings.Contains(out, "Neue Datenbank") {
		t.Fatalf("leer: %q %v", out, files)
	}

	migs, err := db.Migrations()
	if err != nil {
		t.Fatal(err)
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
	out, files := run()
	if len(files) != 1 || !strings.Contains(out, "Vor dem Update gesichert ("+strconv.Itoa(len(migs)-25)+" Migration") {
		t.Fatalf("Stand 25: %q %v", out, files)
	}

	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if out, files := run(); len(files) != 0 || !strings.Contains(out, "Keine ausstehenden") {
		t.Fatalf("aktuell: %q %v", out, files)
	}
	// Ab 0027 steht der Lauf im Protokoll: eine ausstehende Migration erzwingen.
	if _, err := owner.Exec(ctx, `DELETE FROM openwacht.schema_migrations WHERE version = $1`, len(migs)); err != nil {
		t.Fatal(err)
	}
	if _, files := run(); len(files) != 1 {
		t.Fatalf("mit Protokoll: %v", files)
	}
	var msg string
	if err := owner.QueryRow(ctx, `SELECT message FROM openwacht.backup_log WHERE ok ORDER BY started_at DESC LIMIT 1`).Scan(&msg); err != nil || msg != "vor dem Update" {
		t.Fatalf("Protokoll: %q %v", msg, err)
	}
}

// TestSicherungenAbgleichen: Dateien ohne Eintrag (Sicherung vor einem Update
// von 0.20.1, fehlender Eintrag nach einer Rücksicherung) kommen in die Liste,
// Einträge ohne Datei gelten als entfernt; ein zweiter Lauf ändert nichts.
func TestSicherungenAbgleichen(t *testing.T) {
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
	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, n := range []string{"openwacht-20261122T145624Z.dump", "openwacht-20261122T150958Z.dump", "fremd.dump"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.backup_log (started_at, file, size_bytes, ok) VALUES
		('2026-11-22T15:09:58Z', 'openwacht-20261122T150958Z.dump', 1, true),
		('2026-11-21T00:05:00Z', 'openwacht-20261121T000500Z.dump', 1, true)`); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := syncBackupLog(ctx, owner, dir, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 nachgetragen, 1 als entfernt") {
		t.Errorf("Ausgabe: %q", out.String())
	}
	var added, removed, total int
	owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE message = 'nachgetragen' AND file = 'openwacht-20261122T145624Z.dump'
			AND started_at = '2026-11-22T14:56:24Z'),
		count(*) FILTER (WHERE removed_at IS NOT NULL AND file = 'openwacht-20261121T000500Z.dump'), count(*)
		FROM openwacht.backup_log`).Scan(&added, &removed, &total)
	if added != 1 || removed != 1 || total != 3 {
		t.Errorf("nachgetragen %d, entfernt %d, gesamt %d", added, removed, total)
	}
	out.Reset()
	if err := syncBackupLog(ctx, owner, dir, &out); err != nil || out.Len() != 0 {
		t.Errorf("zweiter Lauf: %v %q", err, out.String())
	}
}
