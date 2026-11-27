// SPDX-License-Identifier: AGPL-3.0-only

// Package sbom schreibt eine Software-Stückliste (SBOM) im Format
// CycloneDX 1.6 (JSON) für OpenWacht, nur mit der Standardbibliothek.
//
// Quellen:
//   - go.mod: alle Go-Module, die das Projekt verlangt (auch indirekte und
//     reine Werkzeuge wie govulncheck).
//   - die gebauten Binaries: debug/buildinfo sagt, welche Module wirklich
//     hineingelinkt sind. Nur diese bekommen scope "required", die übrigen
//     "excluded" (nicht ausgeliefert). Weicht eine Version von go.mod ab,
//     bricht der Generator ab.
//   - web/package-lock.json (lockfileVersion 2 oder 3): alle npm-Pakete.
//     Pakete mit "dev": true sind Bauwerkzeuge (Vite, TypeScript) und
//     landen nicht in der Oberfläche, also "excluded".
//   - web/src/schriften/schriften.json und internal/desktop/schriften/
//     schriften.json: die mitgelieferten Schriftdateien (LoadFonts), mit
//     SHA-256 und Lizenz.
//
// Die Ausgabe ist reproduzierbar: feste Sortierung, Zeitstempel = Commit-Zeit,
// serialNumber aus dem SHA-256 des Inhalts. Ein zweiter Lauf auf demselben
// Commit ergibt dieselben Bytes.
package sbom

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Input sind die Eingaben für Generate.
type Input struct {
	Version  string    // Version von OpenWacht, z. B. 0.28.0
	Commit   string    // Commit (kurz), steht als Eigenschaft im Kopf
	Time     time.Time // Zeitpunkt (Commit-Zeit), für metadata.timestamp
	GoMod    []byte    // Inhalt von go.mod
	GoSum    []byte    // Inhalt von go.sum (optional, liefert h1-Prüfsummen)
	Lock     []byte    // Inhalt von web/package-lock.json (optional)
	Binaries []string  // Pfade der gebauten Go-Binaries
	Fonts    []Font    // Schriftdateien der Oberfläche (optional, LoadFonts)
}

// Grenzen gegen kaputte oder fremde Eingaben.
const (
	maxComponents = 5000
	maxField      = 512
)

// Generate liefert die SBOM als eingerücktes JSON mit abschließendem Zeilenumbruch.
func Generate(in Input) ([]byte, error) {
	if in.Version == "" {
		return nil, errors.New("sbom: Version fehlt")
	}
	mods, goVer, err := ParseGoMod(in.GoMod)
	if err != nil {
		return nil, err
	}
	sums := parseGoSum(in.GoSum)

	// Welche Module stecken in welchem Programm?
	used := map[string][]string{} // Modulpfad -> Programme
	toolchain := ""
	for _, p := range in.Binaries {
		bi, err := buildinfo.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("sbom: Build-Info aus %s: %w", filepath.Base(p), err)
		}
		prog := programName(filepath.Base(p))
		if toolchain == "" {
			toolchain = bi.GoVersion
		} else if toolchain != bi.GoVersion {
			return nil, fmt.Errorf("sbom: Binaries mit verschiedenen Go-Versionen (%s, %s)", toolchain, bi.GoVersion)
		}
		for _, d := range bi.Deps {
			if d.Replace != nil {
				return nil, fmt.Errorf("sbom: Modul %s ist ersetzt (replace); das unterstützt der Generator nicht", d.Path)
			}
			m, ok := mods[d.Path]
			if !ok {
				return nil, fmt.Errorf("sbom: %s enthält %s, das nicht in go.mod steht", filepath.Base(p), d.Path)
			}
			if m.Version != d.Version {
				return nil, fmt.Errorf("sbom: %s enthält %s %s, go.mod nennt %s", filepath.Base(p), d.Path, d.Version, m.Version)
			}
			if !slices.Contains(used[d.Path], prog) {
				used[d.Path] = append(used[d.Path], prog)
			}
		}
	}

	root := component{
		Type:     "application",
		BOMRef:   "pkg:generic/openwacht@" + purlEscape(in.Version),
		Supplier: &entity{Name: "OpenWacht"},
		Name:     "OpenWacht",
		Version:  in.Version,
		Licenses: []license{{Expression: "AGPL-3.0-only"}},
		PURL:     "pkg:generic/openwacht@" + purlEscape(in.Version),
	}
	if in.Commit != "" {
		root.Properties = append(root.Properties, property{"openwacht:commit", in.Commit})
	}

	var comps []component
	var rootDeps []string

	// Go-Module.
	for _, path := range sortedKeys(mods) {
		m := mods[path]
		c := component{
			Type:    "library",
			BOMRef:  goPURL(path, m.Version),
			Name:    path,
			Version: m.Version,
			PURL:    goPURL(path, m.Version),
		}
		if progs := used[path]; len(progs) > 0 {
			sort.Strings(progs)
			c.Scope = "required"
			c.Properties = append(c.Properties, property{"openwacht:enthalten-in", strings.Join(progs, ", ")})
		} else {
			c.Scope = "excluded"
			c.Properties = append(c.Properties, property{"openwacht:verwendung", "nur Entwicklung und Werkzeuge, nicht ausgeliefert"})
		}
		if m.Indirect {
			c.Properties = append(c.Properties, property{"openwacht:go-indirekt", "true"})
		} else {
			rootDeps = append(rootDeps, c.BOMRef)
		}
		if h := sums[path+" "+m.Version]; h != "" {
			c.Properties = append(c.Properties, property{"openwacht:go-sum", h})
		}
		comps = append(comps, c)
	}
	// Go selbst (Standardbibliothek und Laufzeit) steckt in jedem Binary.
	if toolchain == "" {
		toolchain = goVer
	}
	if toolchain != "" {
		v := strings.TrimPrefix(toolchain, "go")
		c := component{
			Type: "library", BOMRef: "pkg:golang/stdlib@" + purlEscape(v), Name: "stdlib", Version: v,
			PURL: "pkg:golang/stdlib@" + purlEscape(v), Scope: "required",
			Licenses:   []license{{Expression: "BSD-3-Clause"}},
			Properties: []property{{"openwacht:verwendung", "Go-Standardbibliothek und Laufzeit in allen Binaries"}},
		}
		comps = append(comps, c)
		rootDeps = append(rootDeps, c.BOMRef)
	}

	var deps []dependency
	if len(in.Lock) > 0 {
		npmComps, npmDeps, top, err := parseLock(in.Lock)
		if err != nil {
			return nil, err
		}
		comps = append(comps, npmComps...)
		deps = append(deps, npmDeps...)
		rootDeps = append(rootDeps, top...)
	}
	if len(in.Fonts) > 0 {
		fontComps, refs, err := fontComponents(in.Fonts)
		if err != nil {
			return nil, err
		}
		comps = append(comps, fontComps...)
		rootDeps = append(rootDeps, refs...)
	}
	if len(comps) > maxComponents {
		return nil, fmt.Errorf("sbom: zu viele Komponenten (%d)", len(comps))
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	for i := 1; i < len(comps); i++ {
		if comps[i].BOMRef == comps[i-1].BOMRef {
			return nil, fmt.Errorf("sbom: Komponente doppelt: %s", comps[i].BOMRef)
		}
	}
	sort.Strings(rootDeps)
	deps = append(deps, dependency{Ref: root.BOMRef, DependsOn: rootDeps})
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })

	b := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: metadata{
			Timestamp: in.Time.UTC().Format(time.RFC3339),
			Tools: tools{Components: []component{{
				Type: "application", Name: "openwacht-sbom", Version: in.Version,
				Description: "eigener Generator, tools/sbom",
			}}},
			Component: root,
		},
		Components:   comps,
		Dependencies: deps,
	}
	// serialNumber: aus dem Inhalt ohne serialNumber abgeleitet (reproduzierbar).
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	b.SerialNumber = "urn:uuid:" + contentUUID(raw)
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// programName macht aus "openwacht-agent_linux_amd64.exe" "openwacht-agent".
func programName(file string) string {
	if i := strings.IndexByte(file, '_'); i > 0 {
		return file[:i]
	}
	return file
}

// GoModule ist ein Eintrag aus go.mod.
type GoModule struct {
	Version  string
	Indirect bool
}

var (
	modPathRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~/-]{0,250}$`)
	modVerRe  = regexp.MustCompile(`^v[0-9][0-9A-Za-z.+-]{0,100}$`)
)

// ParseGoMod liest die require-Einträge aus go.mod. Ein replace bricht ab
// (die SBOM würde sonst eine falsche Quelle nennen). Zurück kommen die
// Module und die Toolchain (oder, ohne toolchain-Zeile, die go-Zeile).
func ParseGoMod(data []byte) (map[string]GoModule, string, error) {
	mods := map[string]GoModule{}
	goVer, toolchain := "", ""
	block := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		text, comment, _ := strings.Cut(raw, "//")
		f := strings.Fields(text)
		if len(f) == 0 {
			continue
		}
		if block != "" {
			if f[0] == ")" {
				block = ""
				continue
			}
			if block == "require" {
				if err := addRequire(mods, f, comment, line); err != nil {
					return nil, "", err
				}
			}
			if block == "replace" {
				return nil, "", fmt.Errorf("go.mod Zeile %d: replace wird nicht unterstützt", line)
			}
			continue
		}
		switch f[0] {
		case "module", "exclude", "retract", "godebug", "tool", "ignore":
			if len(f) == 2 && f[1] == "(" {
				block = f[0]
			}
		case "go":
			if len(f) == 2 {
				goVer = "go" + f[1]
			}
		case "toolchain":
			if len(f) == 2 {
				toolchain = f[1]
			}
		case "require":
			if len(f) == 2 && f[1] == "(" {
				block = "require"
				continue
			}
			if err := addRequire(mods, f[1:], comment, line); err != nil {
				return nil, "", err
			}
		case "replace":
			return nil, "", fmt.Errorf("go.mod Zeile %d: replace wird nicht unterstützt", line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	if block != "" {
		return nil, "", fmt.Errorf("go.mod: Block %q nicht geschlossen", block)
	}
	if toolchain != "" {
		goVer = toolchain
	}
	return mods, goVer, nil
}

func addRequire(mods map[string]GoModule, f []string, comment string, line int) error {
	if len(f) != 2 {
		return fmt.Errorf("go.mod Zeile %d: require erwartet Modul und Version", line)
	}
	if !modPathRe.MatchString(f[0]) || !modVerRe.MatchString(f[1]) {
		return fmt.Errorf("go.mod Zeile %d: ungültiges Modul %q %q", line, f[0], f[1])
	}
	if _, dup := mods[f[0]]; dup {
		return fmt.Errorf("go.mod Zeile %d: %s doppelt", line, f[0])
	}
	mods[f[0]] = GoModule{Version: f[1], Indirect: strings.TrimSpace(comment) == "indirect"}
	return nil
}

// parseGoSum liefert "modul version" -> "h1:…" (nur der Modulinhalt,
// nicht die go.mod-Zeilen).
func parseGoSum(data []byte) map[string]string {
	res := map[string]string{}
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && !strings.HasSuffix(f[1], "/go.mod") && strings.HasPrefix(f[2], "h1:") && len(f[2]) <= 100 {
			res[f[0]+" "+f[1]] = f[2]
		}
	}
	return res
}

// lockFile ist der Teil von package-lock.json, den der Generator liest.
type lockFile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	License              json.RawMessage   `json:"license"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

var (
	npmNameRe = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~][a-z0-9._~-]*$`)
	npmVerRe  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,100}$`)
)

// parseLock liest package-lock.json und liefert Komponenten, Abhängigkeiten
// zwischen ihnen und die Pakete, von denen die Oberfläche direkt abhängt.
func parseLock(data []byte) ([]component, []dependency, []string, error) {
	var lf lockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, nil, nil, fmt.Errorf("package-lock.json: %w", err)
	}
	if lf.LockfileVersion < 2 || lf.LockfileVersion > 3 {
		return nil, nil, nil, fmt.Errorf("package-lock.json: lockfileVersion %d wird nicht unterstützt (2 oder 3)", lf.LockfileVersion)
	}
	if len(lf.Packages) > maxComponents {
		return nil, nil, nil, errors.New("package-lock.json: zu viele Pakete")
	}
	rootPkg, ok := lf.Packages[""]
	if !ok {
		return nil, nil, nil, errors.New("package-lock.json: Eintrag für das Projekt selbst fehlt")
	}
	refs := map[string]string{} // Schlüssel (node_modules/…) -> bom-ref
	var comps []component
	for _, key := range sortedKeys(lf.Packages) {
		if key == "" {
			continue
		}
		p := lf.Packages[key]
		if p.Link {
			continue // Verweis auf einen Ordner im Projekt, kein Paket
		}
		name, err := lockName(key)
		if err != nil {
			return nil, nil, nil, err
		}
		if p.Name != "" && p.Name != name {
			// Alias (npm:anderes@…): der echte Name zählt.
			name = p.Name
			if !npmNameRe.MatchString(name) {
				return nil, nil, nil, fmt.Errorf("package-lock.json: ungültiger Name %q", name)
			}
		}
		if !npmVerRe.MatchString(p.Version) {
			return nil, nil, nil, fmt.Errorf("package-lock.json: ungültige Version %q bei %s", p.Version, key)
		}
		group, short := "", name
		if strings.HasPrefix(name, "@") {
			group, short, _ = strings.Cut(name, "/")
		}
		purl := "pkg:npm/" + purlEscape(name) + "@" + purlEscape(p.Version)
		if group != "" {
			purl = "pkg:npm/" + purlEscape(group) + "/" + purlEscape(short) + "@" + purlEscape(p.Version)
		}
		ref := purl
		// Dieselbe Version an zwei Stellen im Baum: Pfad anhängen, damit
		// bom-ref eindeutig bleibt.
		for _, other := range refs {
			if other == ref {
				ref = purl + "#" + key
				break
			}
		}
		refs[key] = ref
		c := component{Type: "library", BOMRef: ref, Group: group, Name: short, Version: p.Version, PURL: purl}
		if p.Dev {
			c.Scope = "excluded"
			c.Properties = append(c.Properties, property{"openwacht:verwendung", "nur zum Bauen der Oberfläche, nicht ausgeliefert"})
		} else {
			c.Scope = "required"
			c.Properties = append(c.Properties, property{"openwacht:enthalten-in", "openwacht-zentrale (Web-Oberfläche)"})
		}
		if p.Optional {
			c.Properties = append(c.Properties, property{"openwacht:npm-optional", "true"})
		}
		if h, err := integrityHash(p.Integrity); err != nil {
			return nil, nil, nil, fmt.Errorf("package-lock.json: %s: %w", key, err)
		} else if h != nil {
			c.Hashes = []hash{*h}
		}
		if lic := licenseOf(p.License); lic != "" {
			c.Licenses = []license{{Expression: lic}}
		}
		if p.Resolved != "" && len(p.Resolved) <= maxField && strings.HasPrefix(p.Resolved, "https://") {
			c.ExternalReferences = []extRef{{Type: "distribution", URL: p.Resolved}}
		}
		comps = append(comps, c)
	}
	// Abhängigkeiten wie Node auflösen: erst im eigenen node_modules, dann
	// die Ordner darüber.
	var deps []dependency
	for _, key := range sortedKeys(refs) {
		p := lf.Packages[key]
		var on []string
		for _, n := range depNames(p, false) {
			if r, ok := resolve(refs, key, n); ok && !slices.Contains(on, r) {
				on = append(on, r)
			}
		}
		sort.Strings(on)
		deps = append(deps, dependency{Ref: refs[key], DependsOn: on})
	}
	var top []string
	for _, n := range depNames(rootPkg, true) {
		if r, ok := refs["node_modules/"+n]; ok && !slices.Contains(top, r) {
			top = append(top, r)
		}
	}
	return comps, deps, top, nil
}

func depNames(p lockPackage, withDev bool) []string {
	var names []string
	for _, m := range []map[string]string{p.Dependencies, p.OptionalDependencies, p.PeerDependencies} {
		for n := range m {
			names = append(names, n)
		}
	}
	if withDev {
		for n := range p.DevDependencies {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return slices.Compact(names)
}

// resolve sucht ein Paket so, wie Node es täte: from/node_modules/name,
// dann eine Ebene höher, bis zur Wurzel.
func resolve(refs map[string]string, from, name string) (string, bool) {
	dir := from
	for {
		if r, ok := refs[dir+"/node_modules/"+name]; ok {
			return r, true
		}
		i := strings.LastIndex(dir, "/node_modules/")
		if i < 0 {
			r, ok := refs["node_modules/"+name]
			return r, ok
		}
		dir = dir[:i]
	}
}

// lockName holt den Paketnamen aus dem Schlüssel "node_modules/a/node_modules/@s/b".
func lockName(key string) (string, error) {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 || (i > 0 && key[i-1] != '/') || !strings.HasPrefix(key, "node_modules/") {
		return "", fmt.Errorf("package-lock.json: unerwarteter Eintrag %q", key)
	}
	name := key[i+len("node_modules/"):]
	if !npmNameRe.MatchString(name) {
		return "", fmt.Errorf("package-lock.json: ungültiger Paketname in %q", key)
	}
	return name, nil
}

// integrityHash wandelt "sha512-<base64>" in einen CycloneDX-Hash (hex).
// Mehrere Werte (durch Leerzeichen getrennt): der stärkste zählt.
func integrityHash(s string) (*hash, error) {
	if s == "" {
		return nil, nil
	}
	var best *hash
	rank := map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
	names := map[string]string{"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
	sizes := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
	bestRank := 0
	for _, part := range strings.Fields(s) {
		alg, val, ok := strings.Cut(part, "-")
		if !ok || rank[alg] == 0 {
			return nil, fmt.Errorf("unbekanntes Integrity-Format %q", part)
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil || len(raw) != sizes[alg] {
			return nil, fmt.Errorf("ungültiger Integrity-Wert für %s", alg)
		}
		if rank[alg] > bestRank {
			bestRank = rank[alg]
			best = &hash{Alg: names[alg], Content: hex.EncodeToString(raw)}
		}
	}
	return best, nil
}

var licenseRe = regexp.MustCompile(`^[A-Za-z0-9.+() -]{1,100}$`)

// licenseOf liest das Feld "license" (Text oder altes Objekt {"type": …})
// und gibt einen SPDX-Ausdruck zurück, oder "" wenn unbrauchbar.
func licenseOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var o struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &o) != nil {
			return ""
		}
		s = o.Type
	}
	s = strings.TrimSpace(s)
	if !licenseRe.MatchString(s) || strings.HasPrefix(strings.ToUpper(s), "SEE LICENSE") {
		return ""
	}
	return s
}

func goPURL(path, version string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = purlEscape(s)
	}
	return "pkg:golang/" + strings.Join(segs, "/") + "@" + purlEscape(version)
}

// purlEscape kodiert alles außer den ungeschützten Zeichen nach RFC 3986
// (package-url: "+" in Versionen wird zu %2B).
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// contentUUID baut eine UUID (Version 8, RFC 9562) aus dem SHA-256 des Inhalts.
func contentUUID(data []byte) string {
	sum := sha256.Sum256(data)
	u := sum[:16]
	u[6] = (u[6] & 0x0f) | 0x80
	u[8] = (u[8] & 0x3f) | 0x80
	h := hex.EncodeToString(u)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CycloneDX-Struktur (nur die benutzten Felder).
type bom struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     tools     `json:"tools"`
	Component component `json:"component"`
}

type tools struct {
	Components []component `json:"components"`
}

type entity struct {
	Name string `json:"name"`
}

type component struct {
	Type               string     `json:"type"`
	BOMRef             string     `json:"bom-ref,omitempty"`
	Supplier           *entity    `json:"supplier,omitempty"`
	Group              string     `json:"group,omitempty"`
	Name               string     `json:"name"`
	Version            string     `json:"version,omitempty"`
	Description        string     `json:"description,omitempty"`
	Scope              string     `json:"scope,omitempty"`
	Hashes             []hash     `json:"hashes,omitempty"`
	Licenses           []license  `json:"licenses,omitempty"`
	PURL               string     `json:"purl,omitempty"`
	ExternalReferences []extRef   `json:"externalReferences,omitempty"`
	Properties         []property `json:"properties,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type license struct {
	License    *licenseItem `json:"license,omitempty"`
	Expression string       `json:"expression,omitempty"`
}

type licenseItem struct {
	Name string `json:"name"`
}

type extRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}
