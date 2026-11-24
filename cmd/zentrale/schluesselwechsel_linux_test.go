// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/traps"
)

// Der Befehl schluessel-wechseln tauscht nach der Datenbank die Dateien:
// alter Schlüssel als .alt-<zeit>, neuer an seiner Stelle mit denselben
// Rechten, Trap-Schlüssel neu abgeleitet. -nur-pruefen ändert nichts.
func TestSchluesselWechselnBefehl(t *testing.T) {
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
	oc := tdb.OwnerCfg
	t.Setenv("OPENWACHT_DB_EIGENTUEMER", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		oc.Host, oc.Port, oc.User, oc.Password, oc.Database))

	dir := t.TempDir()
	oldText, _ := auth.GenerateKeyText()
	newText, _ := auth.GenerateKeyText()
	keyFile, newFile, trapFile := filepath.Join(dir, "schluessel"), filepath.Join(dir, "schluessel.neu"), filepath.Join(t.TempDir(), "trap")
	os.WriteFile(keyFile, []byte(oldText+"\n"), 0o400)
	os.WriteFile(newFile, []byte(newText+"\n"), 0o600)
	oldKey, _ := auth.LoadKeyFile(keyFile)
	newKey, _ := auth.LoadKeyFile(newFile)
	os.WriteFile(trapFile, []byte(base64.StdEncoding.EncodeToString(traps.DeriveKey(oldKey))+"\n"), 0o400)
	// Ein Geheimnis: TOTP eines Kontos.
	var tenant, user string
	owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`).Scan(&tenant)
	owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, 'a@example.com', 'A') RETURNING id::text`, tenant).Scan(&user)
	boxOld := deriveTestBox(oldKey)
	box, _ := auth.Seal(boxOld, []byte("totp"), []byte(user))
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2 WHERE id = $1`, user, box)

	args := []string{"-schluessel", keyFile, "-neu", newFile, "-trap-schluessel", trapFile}
	var out bytes.Buffer
	if err := cmdRekey(ctx, append(args, "-nur-pruefen"), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Nichts geändert") {
		t.Errorf("Ausgabe: %s", out.String())
	}
	if b, _ := os.ReadFile(keyFile); strings.TrimSpace(string(b)) != oldText {
		t.Fatal("-nur-pruefen hat den Schlüssel getauscht")
	}
	var cur []byte
	owner.QueryRow(ctx, `SELECT totp_secret_enc FROM openwacht.users WHERE id = $1`, user).Scan(&cur)
	if !bytes.Equal(cur, box) {
		t.Fatal("-nur-pruefen hat die Datenbank geändert")
	}
	// Gleicher Schlüssel und anderer Ordner: abgelehnt.
	if err := cmdRekey(ctx, []string{"-schluessel", keyFile, "-neu", keyFile}, &out); err == nil {
		t.Error("gleicher Schlüssel")
	}
	other := filepath.Join(t.TempDir(), "neu")
	os.WriteFile(other, []byte(newText+"\n"), 0o600)
	if err := cmdRekey(ctx, []string{"-schluessel", keyFile, "-neu", other}, &out); err == nil || !strings.Contains(err.Error(), "Ordner") {
		t.Errorf("anderer Ordner: %v", err)
	}

	out.Reset()
	if err := cmdRekey(ctx, args, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if b, _ := os.ReadFile(keyFile); strings.TrimSpace(string(b)) != newText {
		t.Fatal("neuer Schlüssel nicht an seiner Stelle")
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o400 {
		t.Errorf("Rechte des neuen Schlüssels: %v", fi.Mode().Perm())
	}
	alt, _ := filepath.Glob(keyFile + ".alt-*")
	if len(alt) != 1 {
		t.Fatalf("alter Schlüssel nicht aufbewahrt: %v", alt)
	}
	if b, _ := os.ReadFile(alt[0]); strings.TrimSpace(string(b)) != oldText {
		t.Error("aufbewahrter Schlüssel falsch")
	}
	if _, err := os.Stat(newFile); err == nil {
		t.Error("schluessel.neu liegt noch")
	}
	tk, _ := os.ReadFile(trapFile)
	if strings.TrimSpace(string(tk)) != base64.StdEncoding.EncodeToString(traps.DeriveKey(newKey)) {
		t.Error("Trap-Schlüssel nicht neu abgeleitet")
	}
	if fi, _ := os.Stat(trapFile); fi.Mode().Perm() != 0o400 {
		t.Errorf("Rechte des Trap-Schlüssels: %v", fi.Mode().Perm())
	}
	owner.QueryRow(ctx, `SELECT totp_secret_enc FROM openwacht.users WHERE id = $1`, user).Scan(&cur)
	if pt, err := auth.Open(deriveTestBox(newKey), cur, []byte(user)); err != nil || string(pt) != "totp" {
		t.Fatalf("Geheimnis mit neuem Schlüssel: %v", err)
	}
	if !strings.Contains(out.String(), "systemctl start") {
		t.Errorf("Ausgabe: %s", out.String())
	}
}

// deriveTestBox: wie die Zentrale (HMAC-SHA256 mit Zweck).
func deriveTestBox(master []byte) []byte {
	return deriveForTest(master, "openwacht secretbox v1")
}

func deriveForTest(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}
