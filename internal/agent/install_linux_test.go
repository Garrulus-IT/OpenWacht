// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fileOwner(t *testing.T, p string) int {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Sys().(*syscall.Stat_t).Uid)
}

// TestHandOverNurImVerzeichnis (Befund N4): root übergibt nur, was im
// Verzeichnis liegt; Links nach außen und harte Links bleiben unberührt.
func TestHandOverNurImVerzeichnis(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("braucht root (chown)")
	}
	const uid, gid = 54321, 54321
	base := t.TempDir()
	dir, outside := filepath.Join(base, "agent"), filepath.Join(base, "system")
	os.MkdirAll(filepath.Join(dir, "unter"), 0o700)
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "unter", "a"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(outside, "shadow"), []byte("x"), 0o600)
	os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(dir, "link"))
	os.Symlink(outside, filepath.Join(dir, "ordnerlink"))

	if err := HandOver(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".", "config.json", "unter", "unter/a", "link", "ordnerlink"} {
		if got := fileOwner(t, filepath.Join(dir, p)); got != uid {
			t.Errorf("%s: Besitzer %d, erwartet %d", p, got, uid)
		}
	}
	for _, p := range []string{outside, filepath.Join(outside, "shadow")} {
		if got := fileOwner(t, p); got != 0 {
			t.Errorf("außerhalb übergeben: %s gehört %d", p, got)
		}
	}

	// Harter Link auf eine Datei außerhalb: Abbruch, Datei bleibt bei root.
	if err := os.Link(filepath.Join(outside, "shadow"), filepath.Join(dir, "hart")); err != nil {
		t.Fatal(err)
	}
	if err := HandOver(dir, uid, gid); err == nil || !strings.Contains(err.Error(), "harte Links") {
		t.Errorf("harter Link: %v", err)
	}
	if got := fileOwner(t, filepath.Join(outside, "shadow")); got != 0 {
		t.Errorf("Ziel des harten Links übergeben: gehört %d", got)
	}
}

// TestHandOverLinkTausch: Der Dienstbenutzer tauscht während der Übergabe
// ein Unterverzeichnis gegen einen Link nach außen. Nichts außerhalb darf
// dabei den Besitzer wechseln.
func TestHandOverLinkTausch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("braucht root (chown)")
	}
	const uid, gid = 54322, 54322
	base := t.TempDir()
	dir, outside := filepath.Join(base, "agent"), filepath.Join(base, "system")
	os.MkdirAll(filepath.Join(dir, "echt"), 0o700)
	os.MkdirAll(outside, 0o755)
	for i := range 20 {
		os.WriteFile(filepath.Join(dir, "echt", "f"+string(rune('a'+i))), nil, 0o644)
		os.WriteFile(filepath.Join(outside, "f"+string(rune('a'+i))), nil, 0o600)
	}
	os.Symlink(outside, filepath.Join(dir, "link"))
	sub := filepath.Join(dir, "sub")
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Rename(filepath.Join(dir, "echt"), sub)
			os.Rename(sub, filepath.Join(dir, "echt"))
			os.Rename(filepath.Join(dir, "link"), sub)
			os.Rename(sub, filepath.Join(dir, "link"))
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = HandOver(dir, uid, gid) // Fehler durch den Tausch sind erlaubt
	}
	close(stop)
	<-done
	entries, _ := os.ReadDir(outside)
	for _, e := range append([]os.DirEntry{nil}, entries...) {
		p := outside
		if e != nil {
			p = filepath.Join(outside, e.Name())
		}
		if got := fileOwner(t, p); got != 0 {
			t.Fatalf("außerhalb übergeben: %s gehört %d", p, got)
		}
	}
}
