// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

var testParams = auth.Params{Memory: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

// passwort-setzen: setzt den Hash, hebt Sperren auf, beendet Sitzungen,
// schreibt das Audit; lehnt Konten aus AD/SSO, fehlende Konten und zu kurze
// Passwörter ab, ohne etwas zu ändern.
func TestPasswortSetzen(t *testing.T) {
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
	if err := zentrale.Bootstrap(ctx, owner, "IT", "admin@beispiel.example", "Admin", "altes-passwort-1234", testParams); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET failed_logins = 7, locked_until = now() + interval '1 hour'
		WHERE email = 'admin@beispiel.example'`); err != nil {
		t.Fatal(err)
	}
	hashOf := func() string {
		var h string
		if err := owner.QueryRow(ctx, `SELECT password_hash FROM openwacht.users WHERE email = 'admin@beispiel.example'`).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	before := hashOf()

	// zu kurz: nichts ändert sich
	var out bytes.Buffer
	if err := passwordSet(ctx, owner, "admin@beispiel.example", strings.NewReader("kurz\n"), &out, testParams); err == nil {
		t.Fatal("zu kurzes Passwort angenommen")
	}
	if hashOf() != before {
		t.Fatal("Hash trotz Fehler geändert")
	}
	// unbekanntes Konto
	if err := passwordSet(ctx, owner, "niemand@beispiel.example", strings.NewReader("neues-passwort-5678\n"), &out, testParams); err == nil ||
		!strings.Contains(err.Error(), "kein Benutzer") {
		t.Fatalf("unbekanntes Konto: %v", err)
	}
	// Großschreibung und Leerzeichen in der Adresse wie bei den anderen Befehlen
	out.Reset()
	if err := passwordSet(ctx, owner, " Admin@Beispiel.example ", strings.NewReader("neues-passwort-5678\n"), &out, testParams); err != nil {
		t.Fatalf("setzen: %v\n%s", err, out.String())
	}
	ok, _, err := auth.VerifyPassword("neues-passwort-5678", hashOf(), testParams)
	if err != nil || !ok {
		t.Fatalf("neues Passwort passt nicht: %v", err)
	}
	var failed int
	var locked *string
	owner.QueryRow(ctx, `SELECT failed_logins, locked_until::text FROM openwacht.users WHERE email = 'admin@beispiel.example'`).Scan(&failed, &locked)
	if failed != 0 || locked != nil {
		t.Fatalf("Sperre nicht aufgehoben: %d %v", failed, locked)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'passwort.gesetzt' AND details->>'quelle' = 'shell'`).Scan(&n)
	if n != 1 {
		t.Fatalf("Audit-Einträge: %d", n)
	}

	// Konto aus dem AD: abgelehnt, Hash unverändert
	if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET auth_source = 'ldap' WHERE email = 'admin@beispiel.example'`); err != nil {
		t.Fatal(err)
	}
	h := hashOf()
	if err := passwordSet(ctx, owner, "admin@beispiel.example", strings.NewReader("drittes-passwort-9012\n"), &out, testParams); err == nil ||
		!strings.Contains(err.Error(), "AD") {
		t.Fatalf("AD-Konto: %v", err)
	}
	if hashOf() != h {
		t.Fatal("AD-Konto geändert")
	}
	// auch direkt über die Funktion nicht
	var res *string
	owner.QueryRow(ctx, `SELECT openwacht.auth_password_set_shell('admin@beispiel.example', $1)`, before).Scan(&res)
	if res == nil || *res != "ldap" || hashOf() != h {
		t.Fatalf("Funktion setzt AD-Konto: %v", res)
	}
}

// Die App-Rolle darf die Funktion nicht aufrufen.
func TestPasswortSetzenNurEigentuemer(t *testing.T) {
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
	app, err := pgx.ConnectConfig(ctx, tdb.AppCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)
	_, err = app.Exec(ctx, `SELECT openwacht.auth_password_set_shell('a@beispiel.example', 'x')`)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("App-Rolle darf passwort-setzen: %v", err)
	}
}
