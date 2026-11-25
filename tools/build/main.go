// SPDX-License-Identifier: AGPL-3.0-only

// Build-Werkzeug für OpenWacht: baut Zentrale und Agent für alle
// Zielplattformen und schreibt Prüfsummen. Aufruf aus dem Repository-Wurzelordner:
//
//	go run ./tools/build                     # Stufe 1 (Standard)
//	go run ./tools/build -ziele alle         # Stufe 1 und 2
//	go run ./tools/build -ziele linux/amd64  # einzelne Ziele, kommagetrennt
//	go run ./tools/build -version 0.1.0      # Versionsnummer setzen (sonst aus VERSION)
//	go run ./tools/build -ohne-web           # Oberfläche nicht neu bauen
//
// Für jede Zielplattform der Zentrale entsteht zusätzlich ein Debian-Paket
// openwacht-zentrale_<version>_<arch>.deb (siehe deb.go), dazu bei jedem Lauf
// die Stückliste openwacht-<version>.cdx.json (CycloneDX, tools/sbom).
//
// Vor den Go-Binaries wird die Web-Oberfläche gebaut (npm ci, npm run build)
// und landet in internal/webui/dist, von wo die Zentrale sie einbettet.
//
// Die Binaries sind statisch (CGO_ENABLED=0) und so weit wie möglich
// reproduzierbar gebaut: -trimpath, ohne Build-ID, ohne VCS-Stempel.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/tools/sbom"
)

// target ist eine Zielplattform. arm ist nur für GOARCH=arm gesetzt (GOARM).
type target struct {
	os, arch, arm string
}

func (t target) String() string {
	if t.arm != "" {
		return t.os + "/" + t.arch + "v" + t.arm
	}
	return t.os + "/" + t.arch
}

// Stufe 1: bei jedem Release getestet. Stufe 2: gebaut, aber ohne Gewähr.
// Hintergrund: Sicherheitskonzept im Handbuch, Kapitel 17.
var (
	tier1 = []target{
		{"linux", "amd64", ""}, {"linux", "arm64", ""},
		{"windows", "amd64", ""}, {"windows", "arm64", ""},
	}
	tier2 = []target{
		{"linux", "arm", "7"},
		{"darwin", "amd64", ""}, {"darwin", "arm64", ""},
		{"freebsd", "amd64", ""},
	}
	// Die Zentrale läuft nur auf Linux-Servern.
	zentraleTargets = []target{{"linux", "amd64", ""}, {"linux", "arm64", ""}}
	// Agent-Pakete (.deb, .rpm) gibt es für Stufe 1 unter Linux.
	agentPackageTargets = []target{{"linux", "amd64", ""}, {"linux", "arm64", ""}}
	// MSI für Windows (Stufe 1).
	msiTargets = []target{{"windows", "amd64", ""}, {"windows", "arm64", ""}}
	// Desktop-App für den Infobereich (1.0.4), nur Windows.
	desktopTargets = []target{{"windows", "amd64", ""}, {"windows", "arm64", ""}}
)

const modulePath = "github.com/garrulus-it/openwacht"

// Nur harmlose Zeichen, damit nichts Fremdes in die ldflags gelangt.
var safeValue = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	ziele := fs.String("ziele", "stufe1", `"stufe1", "alle" oder kommagetrennte Liste wie "linux/amd64,linux/armv7"`)
	ver := fs.String("version", "", "Versionsnummer, z. B. 0.1.0 (Standard: Inhalt der Datei VERSION)")
	out := fs.String("out", "dist", "Ausgabeordner")
	noWeb := fs.Bool("ohne-web", false, "Web-Oberfläche nicht bauen (vorhandenen Stand einbetten)")
	msiNew := fs.Bool("msi-neu", false, "nach dem Authenticode-Signieren: MSI aus den (signierten) Agents im Ausgabeordner neu bauen, dann SHA256SUMS neu")
	sumsNew := fs.Bool("summen-neu", false, "nur SHA256SUMS für die dort genannten Dateien neu berechnen (nach dem Signieren der MSI)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ver == "" {
		v, err := readVersionFile("VERSION")
		if err != nil {
			return err
		}
		*ver = v
	}
	if !safeValue.MatchString(*ver) {
		return fmt.Errorf("ungültige Version %q", *ver)
	}
	if *msiNew || *sumsNew {
		return afterSigning(*out, *ver, *msiNew)
	}
	targets, err := parseTargets(*ziele)
	if err != nil {
		return err
	}
	commit := gitCommit()
	mtime := commitTime()
	if !*noWeb {
		if err := buildWeb(); err != nil {
			return fmt.Errorf("Web-Oberfläche: %w", err)
		}
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	var built []string
	for _, t := range targets {
		name, err := build(*out, "agent", "openwacht-agent", t, *ver, commit)
		if err != nil {
			return err
		}
		built = append(built, name)
		if slices.Contains(msiTargets, t) {
			if _, err := msiVersion(*ver); err != nil {
				fmt.Printf("kein MSI für %s: %v\n", t, err)
			} else {
				msi, err := buildMSI(*out, name, t.arch, *ver, mtime)
				if err != nil {
					return fmt.Errorf("MSI für %s: %w", t, err)
				}
				built = append(built, msi)
			}
		}
		if slices.Contains(desktopTargets, t) {
			name, err := buildWith(*out, "desktop", "openwacht-desktop", t, *ver, commit, "-H windowsgui")
			if err != nil {
				return err
			}
			built = append(built, name)
		}
		if slices.Contains(agentPackageTargets, t) {
			pkgs, err := buildAgentPackages(*out, name, t.arch, *ver, mtime)
			if err != nil {
				return fmt.Errorf("Agent-Pakete für %s: %w", t, err)
			}
			built = append(built, pkgs...)
		}
		if slices.Contains(zentraleTargets, t) {
			name, err := build(*out, "zentrale", "openwacht-zentrale", t, *ver, commit)
			if err != nil {
				return err
			}
			built = append(built, name)
			deb, err := buildDeb(*out, name, t.arch, *ver, mtime)
			if err != nil {
				return fmt.Errorf("Debian-Paket für %s: %w", t, err)
			}
			built = append(built, deb)
		}
	}
	sb, err := writeSBOM(*out, built, *ver, commit, mtime)
	if err != nil {
		return err
	}
	built = append(built, sb)
	return writeChecksums(*out, built)
}

// writeSBOM schreibt die Stückliste (CycloneDX, tools/sbom) neben
// SHA256SUMS. Sie nennt die Go-Module aus go.mod (mit Kennzeichen, welche
// in den gebauten Binaries stecken), die npm-Pakete und die Schriften der
// Oberfläche.
func writeSBOM(out string, built []string, ver, commit string, mtime time.Time) (string, error) {
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	goSum, err := os.ReadFile("go.sum")
	if err != nil {
		return "", err
	}
	lock, err := os.ReadFile("web/package-lock.json")
	if err != nil {
		return "", err
	}
	fonts, err := sbom.LoadFonts(os.DirFS("web/src/schriften"))
	if err != nil {
		return "", err
	}
	var bins []string
	for _, n := range built {
		if !isPackage(n) {
			bins = append(bins, filepath.Join(out, n))
		}
	}
	data, err := sbom.Generate(sbom.Input{
		Version: ver, Commit: commit, Time: mtime,
		GoMod: goMod, GoSum: goSum, Lock: lock, Binaries: bins, Fonts: fonts,
	})
	if err != nil {
		return "", err
	}
	name := sbomName(ver)
	fmt.Printf("Stückliste: %s\n", filepath.Join(out, name))
	return name, os.WriteFile(filepath.Join(out, name), data, 0o644)
}

func sbomName(ver string) string { return "openwacht-" + ver + ".cdx.json" }

func parseTargets(spec string) ([]target, error) {
	switch spec {
	case "stufe1":
		return tier1, nil
	case "alle":
		return append(slices.Clone(tier1), tier2...), nil
	}
	known := append(slices.Clone(tier1), tier2...)
	var res []target
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(s)
		i := slices.IndexFunc(known, func(t target) bool { return t.String() == s })
		if i < 0 {
			return nil, fmt.Errorf("unbekanntes Ziel %q", s)
		}
		if !slices.Contains(res, known[i]) {
			res = append(res, known[i])
		}
	}
	if len(res) == 0 {
		return nil, errors.New("keine Ziele angegeben")
	}
	return res, nil
}

// readVersionFile liest die Versionsnummer aus der Datei VERSION im
// Wurzelordner. Eine Zeile, Leerraum drumherum zählt nicht.
func readVersionFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("Versionsdatei: %w (aus dem Repository-Wurzelordner starten oder -version angeben)", err)
	}
	v := strings.TrimSpace(string(b))
	if !safeValue.MatchString(v) {
		return "", fmt.Errorf("ungültige Version %q in %s", v, path)
	}
	return v, nil
}

func ldflags(ver, commit string) string {
	return strings.Join([]string{
		"-s", "-w", "-buildid=",
		"-X", modulePath + "/internal/version.Version=" + ver,
		"-X", modulePath + "/internal/version.Commit=" + commit,
	}, " ")
}

func outputName(prog string, t target) string {
	arch := t.arch
	if t.arm != "" {
		arch += "v" + t.arm
	}
	name := fmt.Sprintf("%s_%s_%s", prog, t.os, arch)
	if t.os == "windows" {
		name += ".exe"
	}
	return name
}

func build(out, pkg, prog string, t target, ver, commit string) (string, error) {
	return buildWith(out, pkg, prog, t, ver, commit, "")
}

// buildWith: wie build, mit zusätzlichen Linker-Optionen (Desktop-App: -H windowsgui,
// damit Windows kein Konsolenfenster öffnet).
func buildWith(out, pkg, prog string, t target, ver, commit, extra string) (string, error) {
	name := outputName(prog, t)
	lf := ldflags(ver, commit)
	if extra != "" {
		lf = extra + " " + lf
	}
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", lf,
		"-o", filepath.Join(out, name), "./cmd/"+pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+t.os, "GOARCH="+t.arch, "GOARM="+t.arm)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Printf("baue %-40s (%s)\n", name, t)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s für %s: %w", prog, t, err)
	}
	return name, nil
}

func gitCommit() string {
	outp, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	c := strings.TrimSpace(string(outp))
	if st, err := exec.Command("git", "status", "--porcelain").Output(); err == nil && len(st) > 0 {
		c += "-dirty"
	}
	if !safeValue.MatchString(c) {
		return "unknown"
	}
	return c
}

func writeChecksums(out string, names []string) error {
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		f, err := os.Open(filepath.Join(out, n))
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), n)
	}
	fmt.Printf("Prüfsummen: %s\n", filepath.Join(out, "SHA256SUMS"))
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(b.String()), 0o644)
}

// buildWeb baut die SPA. Installationsskripte von Paketen bleiben aus
// (web/.npmrc: ignore-scripts), die Versionen kommen aus package-lock.json.
func buildWeb() error {
	const distDir = "internal/webui/dist"
	entries, err := os.ReadDir(distDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "LIESMICH.txt" {
			if err := os.RemoveAll(filepath.Join(distDir, e.Name())); err != nil {
				return err
			}
		}
	}
	steps := [][]string{{"npm", "ci", "--no-audit"}, {"npm", "run", "build"}}
	for _, st := range steps {
		cmd := exec.Command(st[0], st[1:]...)
		cmd.Dir = "web"
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		fmt.Printf("web: %s\n", strings.Join(st, " "))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(st, " "), err)
		}
	}
	return nil
}

// isPackage: Pakete und Installer (keine Go-Binaries für die Stückliste).
func isPackage(name string) bool {
	for _, ext := range []string{".deb", ".rpm", ".msi"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// afterSigning: Schritte nach dem Authenticode-Signieren (Handbuch Kapitel 15).
// Mit msi: MSI aus den signierten Agents neu bauen. Danach SHA256SUMS für
// alle Dateien, die schon drinstehen (plus neue MSI), neu berechnen. Die
// Signatur von SHA256SUMS (tools/signieren) kommt erst danach.
func afterSigning(out, ver string, msi bool) error {
	old, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("SHA256SUMS im Ausgabeordner: %w", err)
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(string(old)), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			names = append(names, f[1])
		}
	}
	if msi {
		mtime := commitTime()
		for _, t := range msiTargets {
			exe := outputName("openwacht-agent", t)
			if _, err := os.Stat(filepath.Join(out, exe)); err != nil {
				continue
			}
			name, err := buildMSI(out, exe, t.arch, ver, mtime)
			if err != nil {
				return err
			}
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(out, "SHA256SUMS.sig")); err == nil {
		fmt.Println("Hinweis: SHA256SUMS.sig gilt für die alten Prüfsummen; nach diesem Schritt neu signieren (tools/signieren).")
	}
	return writeChecksums(out, names)
}
