// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// prepareDir auf ein schon bestehendes Verzeichnis mit Datei (zweite
// Registrierung, abgebrochene erste): darf nicht abstürzen (0.99.0: Panic in
// ACLFromEntries) und muss die Datei danach nur erben lassen.
func TestPrepareDirBestehend(t *testing.T) {
	if !IsAdmin() {
		t.Skip("braucht Administratorrechte")
	}
	dir := filepath.Join(t.TempDir(), "agent")
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyACL(t *testing.T) {
	a := emptyACL()
	h := (*[8]byte)(unsafe.Pointer(a))
	if h[0] != 2 || h[2] != 8 || h[4] != 0 {
		t.Fatalf("ACL-Kopf % x", h[:])
	}
}
