// SPDX-License-Identifier: AGPL-3.0-only

package safe

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func capture(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestRecoverSetztFehlerUndZaehlt(t *testing.T) {
	ResetForTest()
	log := capture(t)
	f := func(b []byte) (err error) {
		defer Recover("test", &err)
		_ = b[len(b)+3] // Laufzeitfehler
		return nil
	}
	if err := f([]byte("geheim-paket")); !errors.Is(err, ErrPanic) {
		t.Fatalf("Fehler: %v", err)
	}
	if Counts()["test"] != 1 || Total() != 1 || len(Areas()) != 1 {
		t.Fatalf("Zähler: %v", Counts())
	}
	out := log.String()
	if !strings.Contains(out, "bereich=test") || !strings.Contains(out, "safe_test.go") || !strings.Contains(out, "index out of range") {
		t.Fatalf("Logzeile: %s", out)
	}
	if strings.Contains(out, "geheim") {
		t.Fatal("Inhalt im Log")
	}
}

// Eine Panik mit eigenem Wert (kann Daten von außen enthalten) erscheint
// nur mit ihrem Typ im Log.
func TestPanikwertNichtImLog(t *testing.T) {
	ResetForTest()
	log := capture(t)
	if !Run("traps", func() { panic("community=geheim-test") }) {
		t.Fatal("Panik nicht gemeldet")
	}
	if Run("traps", func() {}) {
		t.Fatal("ohne Panik gemeldet")
	}
	if strings.Contains(log.String(), "geheim") || !strings.Contains(log.String(), "art=string") {
		t.Fatalf("Logzeile: %s", log.String())
	}
	if Counts()["traps"] != 1 {
		t.Fatalf("Zähler: %v", Counts())
	}
}

func TestOhnePanikNichts(t *testing.T) {
	ResetForTest()
	f := func() (err error) {
		defer Recover("x", &err)
		return errors.New("normal")
	}
	if err := f(); err == nil || errors.Is(err, ErrPanic) {
		t.Fatalf("Fehler verändert: %v", err)
	}
	if Total() != 0 {
		t.Fatal("ohne Panik gezählt")
	}
}
