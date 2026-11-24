// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/update"
)

func TestPruefeSignatur(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fpub, fpriv, _ := ed25519.GenerateKey(rand.Reader)
	keys := filepath.Join(dir, "update-schluessel.pub")
	os.WriteFile(keys, []byte("ed25519:"+base64.StdEncoding.EncodeToString(pub)+" aktiv\n"), 0o644)
	sums := filepath.Join(dir, "SHA256SUMS")
	os.WriteFile(sums, []byte("abc  paket.deb\n"), 0o644)
	sig, _ := update.SignSums(priv, []byte("abc  paket.deb\n"))
	os.WriteFile(sums+".sig", sig, 0o644)
	id := update.KeyID(pub)
	call := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		rc := run(append([]string{"pruefe-signatur"}, args...), strings.NewReader(""), &out, &errb)
		return rc, out.String() + errb.String()
	}
	if rc, out := call("-summen", sums, "-schluessel-datei", keys, "-abdruck", id); rc != 0 || !strings.Contains(out, "in Ordnung") {
		t.Fatalf("gültig: %d %s", rc, out)
	}
	// Schlüsseldatei aus dem Paket allein beweist nichts.
	if rc, out := call("-summen", sums, "-schluessel-datei", keys); rc == 0 || !strings.Contains(out, "-abdruck") {
		t.Errorf("ohne Abdruck: %d %s", rc, out)
	}
	if rc, _ := call("-summen", sums, "-schluessel-datei", keys, "-abdruck", update.KeyID(fpub)); rc == 0 {
		t.Error("fremder Abdruck angenommen")
	}
	// Eingebettete Schlüssel: im Repository leer, also „kein Schlüssel“ (Rückgabe 3).
	if _, err := update.Keys(); err != nil {
		if rc, _ := call("-summen", sums); rc != exitNoKey {
			t.Errorf("ohne eingebetteten Schlüssel: %d", rc)
		}
	}
	// Geänderte Prüfsummen, fremde Signatur, kaputte Signaturdatei.
	os.WriteFile(sums, []byte("abd  paket.deb\n"), 0o644)
	if rc, _ := call("-summen", sums, "-schluessel-datei", keys, "-abdruck", id); rc == 0 {
		t.Error("geänderte Prüfsummen angenommen")
	}
	os.WriteFile(sums, []byte("abc  paket.deb\n"), 0o644)
	fsig, _ := update.SignSums(fpriv, []byte("abc  paket.deb\n"))
	os.WriteFile(sums+".sig", fsig, 0o644)
	if rc, _ := call("-summen", sums, "-schluessel-datei", keys, "-abdruck", id); rc == 0 {
		t.Error("fremde Signatur angenommen")
	}
	os.WriteFile(sums+".sig", []byte("kaputt"), 0o644)
	if rc, _ := call("-summen", sums, "-schluessel-datei", keys, "-abdruck", id); rc == 0 {
		t.Error("kaputte Signaturdatei angenommen")
	}
	if rc, _ := call(); rc == 0 {
		t.Error("ohne -summen")
	}
}
