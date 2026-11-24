// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	got, err := parseTargets("stufe1")
	if err != nil || len(got) != len(tier1) {
		t.Fatalf("stufe1: %v, %v", got, err)
	}
	all, _ := parseTargets("alle")
	if len(all) != len(tier1)+len(tier2) {
		t.Fatalf("alle: %d Ziele", len(all))
	}
	one, err := parseTargets("linux/armv7, linux/armv7,windows/amd64")
	if err != nil || len(one) != 2 || one[0].arm != "7" {
		t.Fatalf("Liste: %v, %v", one, err)
	}
	for _, bad := range []string{"", "plan9/amd64", "linux/arm"} {
		if _, err := parseTargets(bad); err == nil {
			t.Errorf("parseTargets(%q) sollte fehlschlagen", bad)
		}
	}
}

func TestOutputName(t *testing.T) {
	cases := map[target]string{
		{"windows", "amd64", ""}: "openwacht-agent_windows_amd64.exe",
		{"linux", "arm", "7"}:    "openwacht-agent_linux_armv7",
		{"linux", "arm64", ""}:   "openwacht-agent_linux_arm64",
	}
	for tg, want := range cases {
		if got := outputName("openwacht-agent", tg); got != want {
			t.Errorf("outputName(%v) = %q, erwartet %q", tg, got, want)
		}
	}
}

func TestSafeValue(t *testing.T) {
	for _, ok := range []string{"0.1.0", "dev", "1.2.3-rc.1", "abc123def456-dirty"} {
		if !safeValue.MatchString(ok) {
			t.Errorf("%q sollte erlaubt sein", ok)
		}
	}
	for _, bad := range []string{"", "1.0 -X evil=1", "a;b", "-flag", strings.Repeat("a", 70)} {
		if safeValue.MatchString(bad) {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
}

func TestLdflagsEnthaeltVersion(t *testing.T) {
	f := ldflags("0.1.0", "abc")
	if !strings.Contains(f, "version.Version=0.1.0") || !strings.Contains(f, "version.Commit=abc") {
		t.Errorf("ldflags = %q", f)
	}
}

func TestReadVersionFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/VERSION"
	if err := os.WriteFile(p, []byte(" 0.16.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := readVersionFile(p); err != nil || v != "0.16.0" {
		t.Fatalf("readVersionFile = %q, %v", v, err)
	}
	for _, bad := range []string{"", "0.16.0 -X evil", "$(id)", "0.1\n0.2"} {
		if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if v, err := readVersionFile(p); err == nil {
			t.Errorf("readVersionFile(%q) = %q, erwartet Fehler", bad, v)
		}
	}
	if _, err := readVersionFile(dir + "/fehlt"); err == nil {
		t.Error("fehlende Datei: erwartet Fehler")
	}
}

func TestVersionDateiImRepository(t *testing.T) {
	v, err := readVersionFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if v == "dev" {
		t.Error("VERSION darf nicht dev sein")
	}
}

func TestDebReproduzierbar(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bin"), []byte("#!binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	mt := time.Unix(1763769600, 0).UTC()
	read := func() []byte {
		name, err := buildDeb(dir, "bin", "amd64", "0.21.0-dev", mt)
		if err != nil {
			t.Fatal(err)
		}
		if name != "openwacht-zentrale_0.21.0~dev_amd64.deb" {
			t.Fatalf("Name %s", name)
		}
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return b
	}
	a, b := read(), read()
	if !bytes.Equal(a, b) {
		t.Fatal("zwei Läufe, verschiedene Pakete")
	}
	if !bytes.HasPrefix(a, []byte("!<arch>\ndebian-binary   ")) {
		t.Fatal("kein ar-Archiv mit debian-binary zuerst")
	}
	if p, err := exec.LookPath("dpkg-deb"); err == nil {
		out, err := exec.Command(p, "--info", filepath.Join(dir, "openwacht-zentrale_0.21.0~dev_amd64.deb")).CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("Package: openwacht-zentrale")) {
			t.Fatalf("dpkg-deb: %v\n%s", err, out)
		}
	}
}
