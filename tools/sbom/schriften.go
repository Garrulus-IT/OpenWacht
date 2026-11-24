// SPDX-License-Identifier: AGPL-3.0-only

package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Font ist eine ausgelieferte Schriftdatei der Oberfläche.
type Font struct {
	Name    string // Schriftname, z. B. "D-DIN"
	Version string
	License string // SPDX, nur OFL-1.1 erlaubt (Ausnahme in CONTRIBUTING.md)
	Source  string // Herkunft (https)
	Author  string
	File    string // Dateiname, z. B. "D-DIN.woff2"
	SHA256  string // hex
}

// Nur Schriftdateien mit dieser Lizenz dürfen ins Projekt (CONTRIBUTING.md).
var allowedFontLicenses = map[string]bool{"OFL-1.1": true}

var (
	fontFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.woff2$`)
	fontTextRe = regexp.MustCompile(`^[\p{L}\p{N} .,()&-]{1,120}$`)
	fontVerRe  = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,30}$`)
)

// LoadFonts liest die Liste schriften.json aus dir und prüft sie gegen die
// Dateien im selben Verzeichnis: Jede .woff2-Datei muss genau einmal
// eingetragen sein und jeder Eintrag muss existieren. Zurück kommen die
// Dateien mit SHA-256, sortiert nach Dateiname.
func LoadFonts(dir fs.FS) ([]Font, error) {
	raw, err := fs.ReadFile(dir, "schriften.json")
	if err != nil {
		return nil, fmt.Errorf("sbom: Schriftliste: %w", err)
	}
	var m struct {
		Schriften []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			Lizenz  string   `json:"lizenz"`
			Quelle  string   `json:"quelle"`
			Urheber string   `json:"urheber"`
			Dateien []string `json:"dateien"`
		} `json:"schriften"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("sbom: Schriftliste: %w", err)
	}
	listed := map[string]bool{}
	var out []Font
	for _, s := range m.Schriften {
		switch {
		case !fontTextRe.MatchString(s.Name):
			return nil, fmt.Errorf("sbom: Schriftliste: ungültiger Name %q", s.Name)
		case !fontVerRe.MatchString(s.Version):
			return nil, fmt.Errorf("sbom: Schriftliste: %s: ungültige Version %q", s.Name, s.Version)
		case !allowedFontLicenses[s.Lizenz]:
			return nil, fmt.Errorf("sbom: Schriftliste: %s: Lizenz %q ist nicht erlaubt (nur OFL-1.1)", s.Name, s.Lizenz)
		case !strings.HasPrefix(s.Quelle, "https://") || len(s.Quelle) > maxField:
			return nil, fmt.Errorf("sbom: Schriftliste: %s: Quelle muss eine https-Adresse sein", s.Name)
		case !fontTextRe.MatchString(s.Urheber):
			return nil, fmt.Errorf("sbom: Schriftliste: %s: ungültiger Urheber %q", s.Name, s.Urheber)
		case len(s.Dateien) == 0:
			return nil, fmt.Errorf("sbom: Schriftliste: %s: keine Dateien", s.Name)
		}
		for _, f := range s.Dateien {
			if !fontFileRe.MatchString(f) {
				return nil, fmt.Errorf("sbom: Schriftliste: ungültiger Dateiname %q", f)
			}
			if listed[f] {
				return nil, fmt.Errorf("sbom: Schriftliste: %s steht doppelt", f)
			}
			listed[f] = true
			data, err := fs.ReadFile(dir, f)
			if err != nil {
				return nil, fmt.Errorf("sbom: Schriftliste: %w", err)
			}
			sum := sha256.Sum256(data)
			out = append(out, Font{
				Name: s.Name, Version: s.Version, License: s.Lizenz, Source: s.Quelle,
				Author: s.Urheber, File: f, SHA256: hex.EncodeToString(sum[:]),
			})
		}
	}
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(path.Ext(e.Name()), ".woff2") && !listed[e.Name()] {
			return nil, fmt.Errorf("sbom: Schriftdatei %s fehlt in schriften.json", e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

var hexSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fontComponents macht aus den Schriftdateien SBOM-Komponenten (Typ "file").
func fontComponents(fonts []Font) ([]component, []string, error) {
	var comps []component
	var refs []string
	for _, f := range fonts {
		if !fontFileRe.MatchString(f.File) || !hexSHA256Re.MatchString(f.SHA256) || !allowedFontLicenses[f.License] {
			return nil, nil, fmt.Errorf("sbom: ungültige Schriftdatei %q", f.File)
		}
		ref := "openwacht-schrift:" + f.File
		comps = append(comps, component{
			Type:               "file",
			BOMRef:             ref,
			Supplier:           &entity{Name: f.Author},
			Name:               f.File,
			Version:            f.Version,
			Scope:              "required",
			Hashes:             []hash{{Alg: "SHA-256", Content: f.SHA256}},
			Licenses:           []license{{Expression: f.License}},
			ExternalReferences: []extRef{{Type: "distribution", URL: f.Source}},
			Properties: []property{
				{"openwacht:schrift", f.Name},
				{"openwacht:verwendung", "Schrift der Web-Oberfläche"},
			},
		})
		refs = append(refs, ref)
	}
	return comps, refs, nil
}
