// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// paketPfade lenkt die Pfade der Paket-Erkennung in ein Testverzeichnis.
func paketPfade(t *testing.T) (etc, pkg, old string) {
	t.Helper()
	base := t.TempDir()
	etc, pkg, old = filepath.Join(base, "etc"), filepath.Join(base, "lib"), filepath.Join(base, "alt")
	for _, d := range []string{etc, pkg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oe, op, oo := etcUnitDir, pkgUnitDir, oldUnitsDir
	etcUnitDir, pkgUnitDir, oldUnitsDir = etc, pkg, old
	t.Cleanup(func() { etcUnitDir, pkgUnitDir, oldUnitsDir = oe, op, oo })
	return etc, pkg, old
}

func TestPaketErkennung(t *testing.T) {
	_, pkg, _ := paketPfade(t)
	if Packaged(PackagedBinary, PackagedDir) {
		t.Fatal("ohne Unit des Pakets gilt die Installation nicht als Paket")
	}
	if err := os.WriteFile(filepath.Join(pkg, "openwacht-agent.service"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Packaged(PackagedBinary, PackagedDir) || !Packaged(PackagedBinary, PackagedDir+"/") {
		t.Fatal("Paket nicht erkannt")
	}
	for _, c := range [][2]string{{"/usr/local/bin/openwacht-agent", PackagedDir}, {PackagedBinary, "/srv/agent"}} {
		if Packaged(c[0], c[1]) {
			t.Errorf("%v gilt fälschlich als Paket", c)
		}
	}
}

func TestAlteUnitsVerschieben(t *testing.T) {
	etc, _, old := paketPfade(t)
	units, err := PackageUnits()
	if err != nil {
		t.Fatal(err)
	}
	// eigene Unit einer früheren Einrichtung von Hand und eine fremde
	own, _ := RenderUnit("/usr/local/bin/openwacht-agent", PackagedDir)
	os.WriteFile(filepath.Join(etc, "openwacht-agent.service"), []byte(own), 0o644)
	os.WriteFile(filepath.Join(etc, "openwacht-agent-update.path"), []byte("[Unit]\n# vom Admin\n"), 0o644)
	os.Symlink("/dev/null", filepath.Join(etc, "openwacht-agent-update.service"))
	moved, foreign, err := RetireOldUnits()
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 1 || !strings.HasSuffix(moved[0], "openwacht-agent.service") {
		t.Fatalf("verschoben: %v", moved)
	}
	if len(foreign) != 2 {
		t.Fatalf("fremde Units (auch ein Link gilt als fremd): %v", foreign)
	}
	b, err := os.ReadFile(filepath.Join(old, "openwacht-agent.service"))
	if err != nil || string(b) != own {
		t.Fatalf("alte Unit nicht aufbewahrt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(etc, "openwacht-agent.service")); !os.IsNotExist(err) {
		t.Fatal("alte Unit liegt noch in /etc")
	}
	// zweiter Lauf mit erneut geschriebener Unit überschreibt die Aufbewahrung nicht
	os.WriteFile(filepath.Join(etc, "openwacht-agent.service"), []byte(own), 0o644)
	if _, _, err := RetireOldUnits(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(old, "openwacht-agent.service.1")); err != nil {
		t.Fatal("zweite Aufbewahrung fehlt")
	}
	// Units im Paket haben feste Pfade und die Markierung
	for n, u := range units {
		if !strings.HasPrefix(u, generatedMark) || !strings.Contains(u, PackagedDir) {
			t.Errorf("%s: unerwarteter Inhalt", n)
		}
	}
	if !strings.Contains(units["openwacht-agent.service"], "ReadWritePaths="+PackagedDir) {
		t.Error("Unit des Pakets schreibt nicht nur ins Agent-Verzeichnis")
	}
}
