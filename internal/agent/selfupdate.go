// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Signierte Updates (Etappe 23). Der Agent (ohne Root) lädt eine freigegebene
// Version, prüft die Offline-Signatur und legt sie in <dir>/update ab. Das
// Installieren übernimmt ein eigener Dienst mit Root- bzw. SYSTEM-Rechten
// („update-installieren“), der wieder selbst prüft: Der Agent-Dienst kann
// sein eigenes Binary nicht ändern, und ein übernommener Agent kann nur
// signierte, neuere Versionen derselben Plattform anstoßen.

const (
	updateDir    = "update"
	updateBin    = "openwacht-agent.neu"
	updateSig    = "openwacht-agent.sig"
	updateReady  = "bereit"
	updateFailed = "fehler"
)

// Platform: GOOS/GOARCH dieses Agents.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// updateState des Runners.
type updateState struct {
	key   *update.Keyring // nil = Updates aus (kein Schlüssel im Build)
	offer *agentproto.UpdateOffer
	tried map[string]time.Time
}

// RevokedFile: Widerrufe von Update-Schlüsseln (Etappe 32) neben dem
// Binary. Nur der Installationsdienst (root bzw. SYSTEM) schreibt sie; der
// Agent-Dienst liest sie nur und kann sie nicht löschen.
func RevokedFile(exe string) string { return exe + ".widerrufen" }

// loadRevoked ergänzt den Schlüsselbund um die gespeicherten Widerrufe.
func loadRevoked(k *update.Keyring, exe string) error {
	b, err := os.ReadFile(RevokedFile(exe))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	k.Revoke(update.ParseRevoked(b)...)
	return nil
}

func defaultUpdateKey() *update.Keyring {
	k, err := update.Keys()
	if err != nil {
		return nil
	}
	if exe, err := os.Executable(); err == nil {
		if err := loadRevoked(k, exe); err != nil {
			slog.Warn("Widerrufe der Update-Schlüssel nicht lesbar", "fehler", err)
		}
	}
	return k
}

// readUpdateError: letzte Meldung des Installationsdienstes (für die Oberfläche).
func readUpdateError(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, updateDir, updateFailed))
	if err != nil {
		return ""
	}
	return cleanMessage(string(b))
}

func cleanMessage(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 290 {
		s = string(r[:290]) + "…"
	}
	return s
}

func postRaw(ctx context.Context, c *http.Client, url string, in any, limit int64) ([]byte, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Zentrale: HTTP %d", resp.StatusCode)
	}
	if int64(len(data)) > limit {
		return nil, errors.New("Antwort der Zentrale zu groß")
	}
	return data, nil
}

// maybeUpdate lädt eine angebotene Version, wenn sie neuer und gültig signiert ist.
func (r *Runner) maybeUpdate(ctx context.Context) {
	o := r.upd.offer
	r.upd.offer = nil
	if o == nil || r.upd.key == nil || !update.Newer(o.Version, version.Version) {
		return
	}
	if t, ok := r.upd.tried[o.Version]; ok && r.now().Sub(t) < 6*time.Hour {
		return
	}
	r.upd.tried[o.Version] = r.now()
	if err := r.fetchUpdate(ctx, o); err != nil {
		slog.Warn("Agent-Update nicht geladen", "version", o.Version, "fehler", err)
		return
	}
	slog.Info("Agent-Update geprüft und bereitgelegt", "version", o.Version)
}

func (r *Runner) fetchUpdate(ctx context.Context, o *agentproto.UpdateOffer) error {
	req := map[string]string{"version": o.Version, "plattform": Platform()}
	raw, err := postRaw(ctx, r.client, r.zentrale.String()+agentproto.PathUpdateSignature, req, 4096)
	if err != nil {
		return err
	}
	s, err := update.ParseSigned(raw)
	if err != nil {
		return err
	}
	if err := r.upd.key.VerifySigned(s); err != nil {
		return err
	}
	if s.Version != o.Version || s.OS+"/"+s.Arch != Platform() || s.SHA256 != o.SHA256 {
		return errors.New("Signatur passt nicht zum Angebot")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	bin, err := postRaw(ctx, r.client, r.zentrale.String()+agentproto.PathUpdateBinary, req, s.Size)
	if err != nil {
		return err
	}
	if err := r.upd.key.Verify(s, bin); err != nil {
		return err
	}
	ud := filepath.Join(r.dir, updateDir)
	if err := os.MkdirAll(ud, 0o755); err != nil {
		return err
	}
	os.Remove(filepath.Join(ud, updateFailed))
	if err := writeFileAtomic(filepath.Join(ud, updateBin), bin, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(ud, updateSig), raw, 0o644); err != nil {
		return err
	}
	// Zuletzt die Marke: Sie löst den Installationsdienst aus.
	return writeFileAtomic(filepath.Join(ud, updateReady), []byte(s.Version+"\n"), 0o644)
}

// --- Installation (Root bzw. SYSTEM) ----------------------------------------------

// Installer ersetzt das Agent-Binary durch ein geprüftes Update.
type Installer struct {
	Dir     string          // Verzeichnis des Agents
	Key     *update.Keyring // eingebettete Schlüssel des installierten Binarys
	Current string          // installierte Version
	Exe     string          // Pfad des installierten Binarys
	Replace func(exe string, bin []byte) error
	Restart func() error
}

// ErrNothing: keine Marke, nichts zu tun.
var ErrNothing = errors.New("kein Update bereit")

// Run prüft und installiert. Fehler stehen danach in <dir>/update/fehler.
// Das Update-Verzeichnis gehört dem Agent-Benutzer: Zugriffe laufen über
// os.Root, damit Verknüpfungen nicht aus dem Verzeichnis herausführen.
func (in Installer) Run() error {
	base, err := os.OpenRoot(in.Dir)
	if err != nil {
		return err
	}
	defer base.Close()
	root, err := base.OpenRoot(updateDir)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNothing
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(updateReady); errors.Is(err, fs.ErrNotExist) {
		return ErrNothing
	}
	err = in.install(root)
	// Marke und Dateien immer entfernen, damit der Dienst nicht in einer Schleife läuft.
	for _, f := range []string{updateReady, updateBin, updateSig} {
		root.Remove(f)
	}
	if err != nil {
		writeFailed(root, time.Now().UTC().Format(time.RFC3339)+" "+cleanMessage(err.Error())+"\n")
		return err
	}
	root.Remove(updateFailed)
	return nil
}

// writeFailed legt die Fehlermeldung als neue Datei an. Das Verzeichnis
// gehört dem Agent-Benutzer: Eine vorhandene Datei könnte ein harter Link auf
// eine fremde Datei sein, die der Installationsdienst (root bzw. SYSTEM) dann
// überschriebe. Deshalb erst entfernen (löscht nur den Eintrag), dann
// ausschließlich neu anlegen; kommt jemand dazwischen, bleibt die Meldung aus.
func writeFailed(root *os.Root, msg string) {
	root.Remove(updateFailed)
	f, err := root.OpenFile(updateFailed, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		slog.Warn("Fehlermeldung des Updates nicht gespeichert", "fehler", err)
		return
	}
	defer f.Close()
	f.WriteString(msg)
}

func readRoot(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s ist keine Datei", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s zu groß", name)
	}
	return b, nil
}

func (in Installer) install(root *os.Root) error {
	if !in.Key.Usable() {
		return update.ErrNoKey
	}
	// Widerrufe aus früheren Updates gelten weiter (Datei gehört root bzw. SYSTEM).
	if err := loadRevoked(in.Key, in.Exe); err != nil {
		return fmt.Errorf("Widerrufe lesen: %w", err)
	}
	raw, err := readRoot(root, updateSig, 4096)
	if err != nil {
		return err
	}
	s, err := update.ParseSigned(raw)
	if err != nil {
		return err
	}
	if err := in.Key.VerifySigned(s); err != nil {
		return err
	}
	if s.OS+"/"+s.Arch != Platform() {
		return fmt.Errorf("Update für %s/%s, dieser Rechner ist %s", s.OS, s.Arch, Platform())
	}
	if !update.Newer(s.Version, in.Current) {
		return fmt.Errorf("Version %s ist nicht neuer als %s (keine Rückstufung)", s.Version, in.Current)
	}
	bin, err := readRoot(root, updateBin, s.Size)
	if err != nil {
		return err
	}
	if err := in.Key.Verify(s, bin); err != nil {
		return err
	}
	// Widerrufe zuerst festhalten: Auch wenn das Ersetzen danach scheitert,
	// gelten die widerrufenen Schlüssel nicht mehr.
	if len(s.Revoked) > 0 {
		in.Key.Revoke(s.Revoked...)
		data := []byte(strings.Join(in.Key.Revoked(), "\n") + "\n")
		if err := writeFileAtomic(RevokedFile(in.Exe), data, 0o644); err != nil {
			return fmt.Errorf("Widerrufe speichern: %w", err)
		}
		slog.Info("Update-Schlüssel widerrufen", "kennungen", strings.Join(s.Revoked, ","))
	}
	if err := in.Replace(in.Exe, bin); err != nil {
		return fmt.Errorf("Binary ersetzen: %w", err)
	}
	slog.Info("Agent-Update installiert", "von", in.Current, "auf", s.Version)
	if in.Restart != nil {
		if err := in.Restart(); err != nil {
			return fmt.Errorf("installiert, aber Neustart fehlgeschlagen: %w", err)
		}
	}
	return nil
}

// replaceFile schreibt das neue Binary neben das alte und benennt es um.
func replaceFile(exe string, bin []byte) error {
	tmp := exe + ".neu"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := f.Write(bin); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return renameOver(tmp, exe)
}
