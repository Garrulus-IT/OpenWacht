// SPDX-License-Identifier: AGPL-3.0-only

// Package db enthält das Datenbankschema (Migrationen) und den Zugriff auf
// PostgreSQL. Die Mandantentrennung erzwingt die Datenbank selbst per
// Row-Level Security; siehe migrations/0001_mandanten.sql.
package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Migration ist eine eingebettete SQL-Datei.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum [32]byte
}

// Migrations liefert alle eingebetteten Migrationen in aufsteigender Reihenfolge.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var res []Migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("ungültiger Migrationsname %q", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		res = append(res, Migration{Version: v, Name: e.Name(), SQL: string(b), Checksum: sha256.Sum256(b)})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Version < res[j].Version })
	for i, m := range res {
		if m.Version != i+1 {
			return nil, fmt.Errorf("Migrationen müssen lückenlos ab 0001 nummeriert sein, %s passt nicht", m.Name)
		}
	}
	return res, nil
}

// replacedChecksums: frühere Prüfsummen von Migrationen, deren Text sich nur
// in Kommentaren geändert hat (0.99.0 und 0.99.3: Namen aus Kommentaren entfernt). Eine
// Datenbank mit dem alten Stand wird dabei auf die neue Prüfsumme umgestellt;
// jede andere Abweichung bleibt ein Fehler.
var replacedChecksums = map[int][]string{
	44: {"f64d600a1b93d0211c90cd236d0ef2a77be2e38b041ea6e29b0ffe9e1ac61abd"},
	46: {"af7d06e96b1590bc8f40450bf17fc2d06e8252bebbbdff4b0402fefc84c09193"},
	25: {"e4b863f0c6be70c0bda000b4788ab5f037ee296fc040343262fdbc0bd0af905a"},
	29: {"c6911331eeb139a369ac06af9a23db871f049a955f2f787931d2e5ead59a8330"},
	31: {"33c9d829fa4529d11ec8f573f34c31c94237ead098201eb2492a9a940898fdfa"},
	47: {"cf05514ae4bb7b1d9e8cc3f5c17b5dd557d93ac5adf14c7e16d32f56caf9149e"},
}

func replacedChecksum(version int, sum []byte) bool {
	h := hex.EncodeToString(sum)
	for _, old := range replacedChecksums[version] {
		if h == old {
			return true
		}
	}
	return false
}

// ErrChecksumMismatch meldet, dass eine bereits angewendete Migration
// nachträglich verändert wurde.
var ErrChecksumMismatch = errors.New("bereits angewendete Migration wurde verändert")

// Migrate wendet alle ausstehenden Migrationen an. Die Verbindung muss als
// Eigentümer-Rolle angemeldet sein, nie als Anwendungsrolle. Gleichzeitige
// Aufrufe werden über eine Advisory-Sperre serialisiert. Jede Migration läuft
// in einer eigenen Transaktion. Liefert die Zahl der neu angewendeten Migrationen.
func Migrate(ctx context.Context, conn *pgx.Conn) (int, error) {
	migs, err := Migrations()
	if err != nil {
		return 0, err
	}
	const lockKey = 0x77616563 // fester, historischer Wert; nie ändern, sonst schützt die Sperre nicht über ein Update hinweg
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return 0, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey)

	if _, err := conn.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS openwacht;
		CREATE TABLE IF NOT EXISTS openwacht.schema_migrations (
			version    integer PRIMARY KEY,
			name       text NOT NULL,
			checksum   bytea NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("Migrationstabelle anlegen: %w", err)
	}

	applied := map[int][]byte{}
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM openwacht.schema_migrations`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var v int
		var sum []byte
		if err := rows.Scan(&v, &sum); err != nil {
			rows.Close()
			return 0, err
		}
		applied[v] = sum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	n := 0
	for _, m := range migs {
		if sum, ok := applied[m.Version]; ok {
			if string(sum) != string(m.Checksum[:]) {
				if !replacedChecksum(m.Version, sum) {
					return n, fmt.Errorf("%w: %s", ErrChecksumMismatch, m.Name)
				}
				if _, err := conn.Exec(ctx, `UPDATE openwacht.schema_migrations SET checksum = $1 WHERE version = $2`,
					m.Checksum[:], m.Version); err != nil {
					return n, fmt.Errorf("Prüfsumme von %s nachführen: %w", m.Name, err)
				}
			}
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO openwacht.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
				m.Version, m.Name, m.Checksum[:])
			return err
		})
		if err != nil {
			return n, fmt.Errorf("Migration %s: %w", m.Name, err)
		}
		n++
	}
	return n, nil
}

// Pending liefert die Zahl der noch nicht angewendeten Migrationen. Gibt es
// die Migrationstabelle noch nicht (leere Datenbank), ist fresh wahr.
// Ändert nichts an der Datenbank (für die Sicherung vor einem Update).
func Pending(ctx context.Context, conn *pgx.Conn) (n int, fresh bool, err error) {
	migs, err := Migrations()
	if err != nil {
		return 0, false, err
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('openwacht.schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, false, err
	}
	if !exists {
		return len(migs), true, nil
	}
	applied := map[int]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM openwacht.schema_migrations`)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return 0, false, err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	for _, m := range migs {
		if !applied[m.Version] {
			n++
		}
	}
	return n, false, nil
}
