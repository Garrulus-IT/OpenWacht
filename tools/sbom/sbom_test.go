// SPDX-License-Identifier: AGPL-3.0-only

package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testGoMod = `module example.org/x

go 1.27.0

toolchain go1.27.4

tool golang.org/x/vuln/cmd/govulncheck

require (
	github.com/a/b v1.2.3
	golang.org/x/sys v0.50.0
)

require golang.org/x/vuln v1.10.0 // indirect

require (
	github.com/c/d v2.0.0+incompatible // indirect
)
`

func TestParseGoMod(t *testing.T) {
	mods, gv, err := ParseGoMod([]byte(testGoMod))
	if err != nil {
		t.Fatal(err)
	}
	if gv != "go1.27.4" {
		t.Errorf("Toolchain %q", gv)
	}
	want := map[string]GoModule{
		"github.com/a/b":    {Version: "v1.2.3"},
		"golang.org/x/sys":  {Version: "v0.50.0"},
		"golang.org/x/vuln": {Version: "v1.10.0", Indirect: true},
		"github.com/c/d":    {Version: "v2.0.0+incompatible", Indirect: true},
	}
	if len(mods) != len(want) {
		t.Fatalf("Module: %v", mods)
	}
	for k, v := range want {
		if mods[k] != v {
			t.Errorf("%s: %+v, erwartet %+v", k, mods[k], v)
		}
	}
	// Ohne toolchain-Zeile zählt die go-Zeile.
	_, gv, _ = ParseGoMod([]byte("module m\n\ngo 1.26.1\n"))
	if gv != "go1.26.1" {
		t.Errorf("go-Zeile: %q", gv)
	}
}

func TestParseGoModFehler(t *testing.T) {
	cases := map[string]string{
		"replace":           "module m\nreplace a/b => ../b\n",
		"replace-block":     "module m\nreplace (\n\ta/b v1.0.0 => c/d v1.0.0\n)\n",
		"offener Block":     "module m\nrequire (\n\ta/b v1.0.0\n",
		"ohne Version":      "module m\nrequire a/b\n",
		"falsche Version":   "module m\nrequire a/b 1.0.0\n",
		"doppelt":           "module m\nrequire a/b v1.0.0\nrequire a/b v1.1.0\n",
		"Steuerzeichen":     "module m\nrequire a/b\x01 v1.0.0\n",
		"zu viele Felder":   "module m\nrequire a/b v1.0.0 x\n",
		"Pfad mit Leerlauf": "module m\nrequire (\n\t../b v1.0.0\n)\n",
	}
	for name, in := range cases {
		if _, _, err := ParseGoMod([]byte(in)); err == nil {
			t.Errorf("%s: kein Fehler", name)
		}
	}
}

// Ein kleiner Lockfile mit Scope, verschachteltem Paket, dev und Link.
const testLock = `{
  "name": "web", "lockfileVersion": 3,
  "packages": {
    "": {"name": "web", "dependencies": {"react": "1.0.0"}, "devDependencies": {"@types/x": "2.0.0"}},
    "node_modules/react": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/react/-/react-1.0.0.tgz",
      "integrity": "sha512-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==",
      "license": "MIT", "dependencies": {"loose": "^1", "scheduler": "^3"}},
    "node_modules/scheduler": {"version": "3.0.0", "license": {"type": "ISC"}},
    "node_modules/react/node_modules/scheduler": {"version": "2.0.0+build.1", "license": "SEE LICENSE IN x"},
    "node_modules/@types/x": {"version": "2.0.0", "dev": true, "optional": true, "license": "MIT OR Apache-2.0",
      "integrity": "sha1-AAECAwQFBgcICQoLDA0ODxAREhM= sha256-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
    "node_modules/a-alias": {"name": "zzz", "version": "1.0.0"},
    "node_modules/local": {"resolved": "../local", "link": true}
  }
}`

func TestParseLock(t *testing.T) {
	comps, deps, top, err := parseLock([]byte(testLock))
	if err != nil {
		t.Fatal(err)
	}
	byRef := map[string]component{}
	for _, c := range comps {
		byRef[c.BOMRef] = c
	}
	if len(comps) != 5 {
		t.Fatalf("%d Komponenten, erwartet 5 (Link zählt nicht): %v", len(comps), byRef)
	}
	if a, ok := byRef["pkg:npm/zzz@1.0.0"]; !ok || a.Name != "zzz" {
		t.Errorf("Alias: der echte Name zählt: %+v", byRef)
	}
	r, ok := byRef["pkg:npm/react@1.0.0"]
	if !ok || r.Scope != "required" || r.Licenses[0].Expression != "MIT" {
		t.Fatalf("react: %+v", r)
	}
	if len(r.Hashes) != 1 || r.Hashes[0].Alg != "SHA-512" ||
		r.Hashes[0].Content != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" {
		t.Errorf("Hash react: %+v", r.Hashes)
	}
	if len(r.ExternalReferences) != 1 || r.ExternalReferences[0].Type != "distribution" {
		t.Errorf("Quelle react: %+v", r.ExternalReferences)
	}
	ty, ok := byRef["pkg:npm/%40types/x@2.0.0"]
	if !ok || ty.Group != "@types" || ty.Name != "x" || ty.Scope != "excluded" {
		t.Fatalf("@types/x: %+v", ty)
	}
	if ty.Hashes[0].Alg != "SHA-256" {
		t.Errorf("stärkster Hash: %+v", ty.Hashes)
	}
	if ty.Licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("Lizenz: %+v", ty.Licenses)
	}
	if byRef["pkg:npm/scheduler@3.0.0"].Licenses[0].Expression != "ISC" {
		t.Error("altes Lizenzobjekt nicht gelesen")
	}
	nested, ok := byRef["pkg:npm/scheduler@2.0.0%2Bbuild.1"]
	if !ok || nested.Licenses != nil {
		t.Fatalf("verschachteltes Paket: %+v (Lizenz 'SEE LICENSE' soll fehlen)", nested)
	}
	// react hängt vom eigenen, verschachtelten scheduler ab, nicht vom oberen;
	// "loose" fehlt im Lockfile und wird übergangen.
	for _, d := range deps {
		if d.Ref == "pkg:npm/react@1.0.0" {
			if len(d.DependsOn) != 1 || d.DependsOn[0] != nested.BOMRef {
				t.Errorf("Auflösung react: %v", d.DependsOn)
			}
		}
	}
	if strings.Join(top, ",") != "pkg:npm/%40types/x@2.0.0,pkg:npm/react@1.0.0" {
		t.Errorf("direkte Abhängigkeiten: %v", top)
	}
}

func TestParseLockGleicheVersionZweimal(t *testing.T) {
	lock := `{"lockfileVersion": 3, "packages": {"": {},
	  "node_modules/a": {"version": "1.0.0"},
	  "node_modules/b": {"version": "1.0.0"},
	  "node_modules/b/node_modules/a": {"version": "1.0.0"}}}`
	comps, _, _, err := parseLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range comps {
		if seen[c.BOMRef] {
			t.Fatalf("bom-ref doppelt: %s", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
	if !seen["pkg:npm/a@1.0.0#node_modules/b/node_modules/a"] {
		t.Errorf("zweites a ohne eindeutige Referenz: %v", seen)
	}
}

func TestParseLockFehler(t *testing.T) {
	cases := map[string]string{
		"kein JSON":         `{`,
		"Version 1":         `{"lockfileVersion": 1, "packages": {"": {}}}`,
		"ohne Wurzel":       `{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}`,
		"fremder Schlüssel": `{"lockfileVersion": 3, "packages": {"": {}, "../a": {"version": "1.0.0"}}}`,
		"Schlüssel innen":   `{"lockfileVersion": 3, "packages": {"": {}, "x/node_modules/a": {"version": "1.0.0"}}}`,
		"Name groß":         `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/A b": {"version": "1.0.0"}}}`,
		"ohne Version":      `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {}}}`,
		"Version mit /":     `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1/2"}}}`,
		"Integrity kurz":    `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "integrity": "sha512-AAEC"}}}`,
		"Integrity md5":     `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "integrity": "md5-AAECAwQFBgcICQoLDA0ODw=="}}}`,
		"Alias ungültig":    `{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"name": "B C", "version": "1.0.0"}}}`,
	}
	for name, in := range cases {
		if _, _, _, err := parseLock([]byte(in)); err == nil {
			t.Errorf("%s: kein Fehler", name)
		}
	}
}

func TestPURL(t *testing.T) {
	if got := goPURL("github.com/c/d", "v2.0.0+incompatible"); got != "pkg:golang/github.com/c/d@v2.0.0%2Bincompatible" {
		t.Errorf("goPURL: %s", got)
	}
	if got := purlEscape("@a b/c~"); got != "%40a%20b%2Fc~" {
		t.Errorf("purlEscape: %s", got)
	}
	if programName("openwacht-agent_windows_amd64.exe") != "openwacht-agent" || programName("prog") != "prog" {
		t.Error("programName")
	}
}

// testBinary baut testdata/prog (linkt golang.org/x/sys) und liefert den Pfad.
func testBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("baut ein Binary")
	}
	out := filepath.Join(t.TempDir(), "probe_linux_amd64")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/prog")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func realInput(t *testing.T, bin string) Input {
	t.Helper()
	goMod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	goSum, _ := os.ReadFile("../../go.sum")
	return Input{
		Version: "0.28.0", Commit: "abc123", Time: time.Date(2026, 11, 22, 10, 0, 0, 0, time.FixedZone("x", 3600)),
		GoMod: goMod, GoSum: goSum, Lock: []byte(testLock), Binaries: []string{bin},
	}
}

func TestGenerate(t *testing.T) {
	bin := testBinary(t)
	in := realInput(t, bin)
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		BOMFormat, SpecVersion, SerialNumber string
		Metadata                             struct {
			Timestamp string
			Component component
		}
		Components   []component
		Dependencies []dependency
	}
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if b.BOMFormat != "CycloneDX" || b.SpecVersion != "1.6" {
		t.Errorf("Kopf: %s %s", b.BOMFormat, b.SpecVersion)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(b.SerialNumber) {
		t.Errorf("serialNumber %q", b.SerialNumber)
	}
	if b.Metadata.Timestamp != "2026-11-22T09:00:00Z" {
		t.Errorf("Zeit %q (UTC erwartet)", b.Metadata.Timestamp)
	}
	if b.Metadata.Component.Name != "OpenWacht" || b.Metadata.Component.Version != "0.28.0" {
		t.Errorf("Wurzel: %+v", b.Metadata.Component)
	}
	scope := map[string]component{}
	for _, c := range b.Components {
		scope[c.Name] = c
	}
	sys := scope["golang.org/x/sys"]
	if sys.Scope != "required" || sys.Properties[0].Value != "probe" {
		t.Errorf("x/sys steckt im Binary: %+v", sys)
	}
	if !strings.HasPrefix(propValue(sys, "openwacht:go-sum"), "h1:") {
		t.Errorf("x/sys ohne go.sum-Prüfsumme: %+v", sys.Properties)
	}
	if v := scope["golang.org/x/vuln"]; v.Scope != "excluded" {
		t.Errorf("x/vuln ist nur Werkzeug: %+v", v)
	}
	if p := scope["github.com/jackc/pgx/v5"]; p.Scope != "excluded" {
		t.Errorf("pgx steckt nicht im Testbinary: %+v", p)
	}
	if s := scope["stdlib"]; s.Scope != "required" || !strings.HasPrefix(s.Version, "1.") {
		t.Errorf("stdlib: %+v", s)
	}
	if scope["react"].Scope != "required" {
		t.Error("npm fehlt")
	}
	var rootDeps []string
	for _, d := range b.Dependencies {
		if d.Ref == b.Metadata.Component.BOMRef {
			rootDeps = d.DependsOn
		}
	}
	joined := strings.Join(rootDeps, " ")
	if !strings.Contains(joined, "pkg:golang/github.com/go-ldap/ldap/v3@") || strings.Contains(joined, "x/vuln") {
		t.Errorf("direkte Abhängigkeiten der Wurzel: %v", rootDeps)
	}
	// Sortiert und eindeutig.
	for i := 1; i < len(b.Components); i++ {
		if b.Components[i-1].BOMRef >= b.Components[i].BOMRef {
			t.Fatalf("nicht sortiert: %s vor %s", b.Components[i-1].BOMRef, b.Components[i].BOMRef)
		}
	}

	// Reproduzierbar: gleiche Eingabe, gleiche Bytes; andere Eingabe, andere Nummer.
	again, _ := Generate(in)
	if !bytes.Equal(out, again) {
		t.Error("zweiter Lauf liefert andere Bytes")
	}
	in.Version = "0.28.1"
	other, _ := Generate(in)
	var b2 struct{ SerialNumber string }
	_ = json.Unmarshal(other, &b2)
	if b2.SerialNumber == b.SerialNumber {
		t.Error("serialNumber hängt nicht vom Inhalt ab")
	}
}

func propValue(c component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func TestGenerateFehler(t *testing.T) {
	bin := testBinary(t)

	in := realInput(t, bin)
	in.Version = ""
	if _, err := Generate(in); err == nil {
		t.Error("ohne Version")
	}

	// Binary enthält x/sys, go.mod nennt eine andere Version.
	in = realInput(t, bin)
	in.GoMod = []byte(strings.Replace(string(in.GoMod), "golang.org/x/sys v", "golang.org/x/sys v9.9.9-alt-", 1))
	if _, err := Generate(in); err == nil || !strings.Contains(err.Error(), "go.mod nennt") {
		t.Errorf("Versionsabweichung: %v", err)
	}

	// Binary enthält ein Modul, das go.mod nicht kennt.
	in = realInput(t, bin)
	in.GoMod = []byte("module m\n\ngo 1.27.0\n")
	if _, err := Generate(in); err == nil || !strings.Contains(err.Error(), "nicht in go.mod") {
		t.Errorf("unbekanntes Modul: %v", err)
	}

	// Keine Go-Datei.
	in = realInput(t, bin)
	in.Binaries = []string{"../../go.mod"}
	if _, err := Generate(in); err == nil {
		t.Error("Datei ohne Build-Info angenommen")
	}

	in = realInput(t, bin)
	in.Lock = []byte(`{"lockfileVersion": 1}`)
	if _, err := Generate(in); err == nil {
		t.Error("kaputter Lockfile angenommen")
	}
}

// Der echte Lockfile des Projekts muss sich lesen lassen; Laufzeitpakete der
// Oberfläche sind "required", Bauwerkzeuge "excluded".
func TestEchterLockfile(t *testing.T) {
	data, err := os.ReadFile("../../web/package-lock.json")
	if err != nil {
		t.Skip("kein web/package-lock.json")
	}
	comps, _, top, err := parseLock(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) == 0 || len(comps) == 0 {
		t.Fatal("leer")
	}
	for _, c := range comps {
		if c.Name == "react" && c.Group == "" && c.Scope != "required" {
			t.Errorf("react: %s", c.Scope)
		}
		if c.Name == "vite" && c.Scope != "excluded" {
			t.Errorf("vite: %s", c.Scope)
		}
	}
}
