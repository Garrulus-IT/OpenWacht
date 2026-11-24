// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/update"
)

func TestSignieren(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "test.key")
	if err := run([]string{"-neu", "-schluessel", key}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-neu", "-schluessel", key}); err == nil {
		t.Fatal("Schlüssel überschrieben")
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Errorf("Rechte %v", fi.Mode().Perm())
	}
	bin := filepath.Join(dir, "openwacht-agent_linux_amd64")
	os.WriteFile(bin, []byte("binary"), 0o755)
	if err := run([]string{"-schluessel", key, "-version", "0.23.0", bin}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(bin + ".sig")
	s, err := update.ParseSigned(raw)
	if err != nil || s.OS != "linux" || s.Arch != "amd64" || s.Version != "0.23.0" {
		t.Fatalf("%+v %v", s, err)
	}
	if err := run([]string{"-schluessel", key, "-version", "0.23.0", filepath.Join(dir, "anders")}); err == nil ||
		!strings.Contains(err.Error(), "Name") {
		t.Errorf("falscher Name: %v", err)
	}
	if err := run([]string{"-schluessel", key, "-version", "x", bin}); err == nil {
		t.Error("ungültige Version")
	}
	// Widerruf mitsigniert
	if err := run([]string{"-schluessel", key, "-version", "0.24.0", "-widerrufen", "00000000000000aa", bin}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(bin + ".sig")
	if s, err := update.ParseSigned(raw); err != nil || len(s.Revoked) != 1 || s.Revoked[0] != "00000000000000aa" {
		t.Errorf("Widerruf: %+v %v", s, err)
	}
	if err := run([]string{"-schluessel", key, "-version", "0.24.0", "-widerrufen", "kaputt", bin}); err == nil {
		t.Error("ungültige Kennung")
	}
	// Prüfsummen
	sums := filepath.Join(dir, "SHA256SUMS")
	os.WriteFile(sums, []byte("abc  datei\n"), 0o644)
	if err := run([]string{"-schluessel", key, "-summen", sums}); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(sums + ".sig")
	ss, err := update.ParseSumsSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	seedRaw, _ := os.ReadFile(key)
	seed, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedRaw)))
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := update.SingleKey(pub).VerifySums([]byte("abc  datei\n"), ss); err != nil {
		t.Errorf("Prüfsummen-Signatur: %v", err)
	}
	if err := run([]string{"-schluessel", key, "-summen", sums, bin}); err == nil {
		t.Error("-summen mit Binarys")
	}
}

// -zeigen gibt nur den öffentlichen Teil aus, nie den privaten Schlüssel.
func TestZeigen(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	if err := run([]string{"-neu", "-schluessel", key}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(key)
	out := captureStdout(t, func() {
		if err := run([]string{"-zeigen", "-schluessel", key}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "ed25519:") || !strings.Contains(out, "Kennung: ") || strings.Contains(out, strings.TrimSpace(string(raw))) {
		t.Errorf("Ausgabe: %q", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}
