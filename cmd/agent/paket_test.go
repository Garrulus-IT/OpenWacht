// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/agent"
)

// Freigaben aus dem Assistenten des MSI (1.0.6): Leere Teile aus den
// Kästchen fallen weg, ohne Angabe bleibt alles, wie es ist, und eine
// ungültige Angabe bricht die Installation nicht ab.
func TestReleaseFromPackage(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := releaseFromPackage(packageOptions{dir: dir}, &out); err != nil || out.Len() != 0 {
		t.Fatalf("ohne Angaben: %v %q", err, out.String())
	}
	if rel, _ := agent.ReadSensorConfig(dir); rel != nil {
		t.Fatal("Freigabe ohne Angabe geschrieben")
	}
	o := packageOptions{dir: dir, arten: ",dienst,,prozess,,datei,", ordner: "/var/log ", netze: "10.20.0.0/16"}
	if err := releaseFromPackage(o, &out); err != nil {
		t.Fatal(err)
	}
	rel, err := agent.ReadSensorConfig(dir)
	if err != nil || rel == nil || strings.Join(rel.Kinds, ",") != "dienst,prozess,datei" || len(rel.Folders) != 1 {
		t.Fatalf("Freigabe: %+v %v", rel, err)
	}
	if nets, err := agent.ReadCollectorConfig(dir); err != nil || len(nets) != 1 {
		t.Fatalf("Sammler: %v %v", nets, err)
	}
	out.Reset()
	if err := releaseFromPackage(packageOptions{dir: dir, arten: "datei"}, &out); err != nil {
		t.Fatalf("ungültige Angabe bricht ab: %v", err)
	}
	if !strings.Contains(out.String(), "nicht freigegeben") {
		t.Fatalf("Meldung fehlt: %q", out.String())
	}
	if rel, _ := agent.ReadSensorConfig(dir); rel == nil || len(rel.Kinds) != 3 {
		t.Fatal("ungültige Angabe hat die Freigabe verändert")
	}
}
