// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Seite „Downloads“ (1.0.14): Agents, MSI, Desktop-App und Agent-Pakete
// liegen auf der Zentrale selbst, nicht im Netz. Sie kommen mit dem Paket der
// Zentrale (tools/build, usr/share/openwacht/downloads) und werden mit jedem
// Update der Zentrale mit erneuert; so geht der Download auch ohne Internet.
//
// Aufbau des Ordners (Config.Downloads): je Betriebssystem ein Ordner
// (linux, windows, darwin, freebsd) mit den Dateien und einer SHA256SUMS.
// Angeboten wird nur, was in SHA256SUMS steht und dazu passt; die Prüfsumme
// rechnet die Zentrale einmal je Datei (bis sich Größe oder Zeit ändern).

// downloadSysteme: Reihenfolge auf der Seite.
var downloadSysteme = []string{"windows", "linux", "darwin", "freebsd"}

// downloadName: nur einfache Dateinamen aus SHA256SUMS (kein Pfad).
var downloadName = regexp.MustCompile(`^openwacht-(agent|desktop)[0-9A-Za-z._-]{1,120}$`)

// downloadDatei: ein Eintrag der Seite.
type downloadDatei struct {
	Name     string `json:"name"`
	Art      string `json:"art"`
	Arch     string `json:"arch,omitempty"`
	Groesse  int64  `json:"groesse"`
	SHA256   string `json:"sha256"`
	Signatur string `json:"signatur,omitempty"` // zugehörige .sig (Agent-Update), falls vorhanden
}

type downloadSystem struct {
	OS      string          `json:"os"`
	Dateien []downloadDatei `json:"dateien"`
}

// downloadPruefung: berechnete Prüfsummen je Datei (Pfad → Größe, Zeit, Summe).
type downloadPruefung struct {
	mu   sync.Mutex
	summ map[string]downloadSumme
}

type downloadSumme struct {
	size int64
	mod  time.Time
	sum  string
}

// sumOf: SHA-256 einer Datei, zwischengespeichert bis sich Größe oder Zeit ändern.
func (p *downloadPruefung) sumOf(path string, fi os.FileInfo) (string, error) {
	p.mu.Lock()
	if c, ok := p.summ[path]; ok && c.size == fi.Size() && c.mod.Equal(fi.ModTime()) {
		p.mu.Unlock()
		return c.sum, nil
	}
	p.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	p.mu.Lock()
	if p.summ == nil {
		p.summ = map[string]downloadSumme{}
	}
	p.summ[path] = downloadSumme{fi.Size(), fi.ModTime(), sum}
	p.mu.Unlock()
	return sum, nil
}

// downloadArt: Art und Architektur aus dem Dateinamen.
func downloadArt(name string) (art, arch string) {
	switch {
	case strings.HasSuffix(name, ".sig"):
		art = "signatur"
	case strings.HasSuffix(name, ".msi"):
		art = "msi"
	case strings.HasSuffix(name, ".deb"):
		art = "deb"
	case strings.HasSuffix(name, ".rpm"):
		art = "rpm"
	case strings.HasPrefix(name, "openwacht-desktop"):
		art = "desktop"
	default:
		art = "agent"
	}
	for _, a := range []string{"amd64", "x86_64", "arm64", "aarch64", "armv7"} {
		if strings.Contains(name, a) {
			arch = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[a]
			if arch == "" {
				arch = a
			}
			break
		}
	}
	return art, arch
}

// readSums: Einträge von SHA256SUMS (Name → Summe), nur gültige Zeilen.
func readSums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 2 || len(fs[0]) != 64 {
			continue
		}
		name := strings.TrimPrefix(fs[1], "*")
		if _, err := hex.DecodeString(fs[0]); err != nil || !downloadName.MatchString(name) {
			continue
		}
		out[name] = strings.ToLower(fs[0])
	}
	return out, sc.Err()
}

// downloadListe: alle angebotenen Dateien. Was nicht zur SHA256SUMS passt,
// fehlt (mit Warnung im Log).
func (s *Server) downloadListe() []downloadSystem {
	dir := s.cfg.Downloads
	if dir == "" {
		return nil
	}
	var out []downloadSystem
	for _, o := range downloadSysteme {
		sums, err := readSums(filepath.Join(dir, o, "SHA256SUMS"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				slog.Warn("Downloads: SHA256SUMS nicht lesbar", "system", o, "fehler", err)
			}
			continue
		}
		names := make([]string, 0, len(sums))
		for n := range sums {
			names = append(names, n)
		}
		sort.Strings(names)
		sys := downloadSystem{OS: o, Dateien: []downloadDatei{}}
		for _, n := range names {
			d, ok := s.downloadPruefen(o, n, sums[n])
			if !ok {
				continue
			}
			sys.Dateien = append(sys.Dateien, d)
		}
		// Signaturen gehören zu ihrem Agent und stehen dort, nicht für sich.
		var rest []downloadDatei
		sig := map[string]bool{}
		for _, d := range sys.Dateien {
			if d.Art == "signatur" {
				sig[strings.TrimSuffix(d.Name, ".sig")] = true
			}
		}
		for _, d := range sys.Dateien {
			if d.Art == "signatur" {
				continue
			}
			if sig[d.Name] {
				d.Signatur = d.Name + ".sig"
			}
			rest = append(rest, d)
		}
		sys.Dateien = rest
		if len(sys.Dateien) > 0 {
			out = append(out, sys)
		}
	}
	return out
}

// downloadPruefen: Datei vorhanden und Prüfsumme wie in SHA256SUMS?
func (s *Server) downloadPruefen(o, name, want string) (downloadDatei, bool) {
	path := filepath.Join(s.cfg.Downloads, o, name)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			slog.Warn("Downloads: Datei nicht lesbar", "datei", o+"/"+name, "fehler", err)
		}
		return downloadDatei{}, false
	}
	sum, err := s.downloads.sumOf(path, fi)
	if err != nil {
		slog.Warn("Downloads: Datei nicht lesbar", "datei", o+"/"+name, "fehler", err)
		return downloadDatei{}, false
	}
	if sum != want {
		slog.Warn("Downloads: Prüfsumme passt nicht zu SHA256SUMS, Datei wird nicht angeboten", "datei", o+"/"+name)
		return downloadDatei{}, false
	}
	art, arch := downloadArt(name)
	return downloadDatei{Name: name, Art: art, Arch: arch, Groesse: fi.Size(), SHA256: sum}, true
}

// handleDownloadsList: GET /api/v1/downloads (alle angemeldeten Benutzer).
func (s *Server) handleDownloadsList(w http.ResponseWriter, r *http.Request) {
	liste := s.downloadListe()
	if liste == nil {
		liste = []downloadSystem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version.Version, "systeme": liste})
}

// handleDownloadFile: GET /api/v1/downloads/{os}/{name}.
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	o, name := r.PathValue("os"), r.PathValue("name")
	known := false
	for _, x := range downloadSysteme {
		known = known || x == o
	}
	if !known || !downloadName.MatchString(name) || s.cfg.Downloads == "" {
		writeError(w, http.StatusNotFound, "Diese Datei gibt es hier nicht.")
		return
	}
	sums, err := readSums(filepath.Join(s.cfg.Downloads, o, "SHA256SUMS"))
	if err != nil || sums[name] == "" {
		writeError(w, http.StatusNotFound, "Diese Datei gibt es hier nicht.")
		return
	}
	if _, ok := s.downloadPruefen(o, name, sums[name]); !ok {
		writeError(w, http.StatusNotFound, "Diese Datei gibt es hier nicht (Prüfsumme passt nicht).")
		return
	}
	f, err := os.Open(filepath.Join(s.cfg.Downloads, o, name))
	if err != nil {
		writeError(w, http.StatusNotFound, "Diese Datei gibt es hier nicht.")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Datei nicht lesbar.")
		return
	}
	// Große Dateien über langsame Leitungen: mehr als die 30 Sekunden des Servers.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Minute))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-cache")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// MitgelieferteAgentUpdates legt die signierten Agents aus dem
// Downloads-Ordner unter „Agent-Updates“ ab (1.0.14), damit nach einem Update
// der Zentrale die passenden Agents bereitstehen, ohne Hochladen von Hand.
// Geprüft wird wie beim Hochladen: Prüfsumme aus SHA256SUMS, Signatur gegen
// die eingebetteten Schlüssel ohne widerrufene, Plattform aus dem Dateinamen.
// Was es schon gibt, bleibt. Freigegeben wird nichts (Freigabe von Hand oder
// „Automatisch übernehmen“). Rückgabe: Zahl neu abgelegter Pakete.
func (s *Server) MitgelieferteAgentUpdates(ctx context.Context) (int, error) {
	if s.cfg.Downloads == "" {
		return 0, nil
	}
	keys, err := s.updateKeys(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	if !keys.Usable() {
		slog.Info("Downloads: kein Update-Schlüssel im Build; mitgelieferte Agents stehen nur auf der Seite Downloads")
		return 0, nil
	}
	neu := 0
	for _, o := range []string{"linux", "windows"} {
		sums, err := readSums(filepath.Join(s.cfg.Downloads, o, "SHA256SUMS"))
		if err != nil {
			continue
		}
		for _, arch := range []string{"amd64", "arm64"} {
			name := "openwacht-agent_" + o + "_" + arch
			if o == "windows" {
				name += ".exe"
			}
			if sums[name] == "" || sums[name+".sig"] == "" {
				continue
			}
			if _, ok := s.downloadPruefen(o, name, sums[name]); !ok {
				continue
			}
			if _, ok := s.downloadPruefen(o, name+".sig", sums[name+".sig"]); !ok {
				continue
			}
			rawSig, err := os.ReadFile(filepath.Join(s.cfg.Downloads, o, name+".sig"))
			if err != nil {
				continue
			}
			bin, err := os.ReadFile(filepath.Join(s.cfg.Downloads, o, name))
			if err != nil {
				continue
			}
			signed, err := update.ParseSigned(rawSig)
			if err == nil && (signed.OS != o || signed.Arch != arch) {
				err = errors.New("Plattform passt nicht zum Dateinamen")
			}
			if err == nil {
				err = keys.VerifySigned(signed)
			}
			if err == nil {
				err = keys.Verify(signed, bin)
			}
			if err != nil {
				slog.Warn("Downloads: mitgelieferter Agent nicht als Update übernommen", "datei", o+"/"+name, "fehler", err)
				continue
			}
			var added bool
			if err := s.pool.QueryRow(ctx, `SELECT openwacht.agent_update_mitliefern($1, $2, $3, $4, $5, $6, $7, $8)`,
				signed.Version, signed.OS, signed.Arch, signed.SHA256, signed.Size, string(rawSig), bin, signed.KeyID).Scan(&added); err != nil {
				return neu, fmt.Errorf("Agent-Update %s/%s %s: %w", o, arch, signed.Version, err)
			}
			if added {
				neu++
				slog.Info("Downloads: mitgelieferter Agent als Update abgelegt", "version", signed.Version, "plattform", o+"/"+arch)
			}
		}
	}
	return neu, nil
}
