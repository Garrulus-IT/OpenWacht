// SPDX-License-Identifier: AGPL-3.0-only

package main

// openwacht-zentrale update-installieren (1.0.4): installiert ein Update der
// Zentrale, das in der Oberfläche hochgeladen wurde. Läuft als root im Dienst
// openwacht-zentrale-update.service, gestartet von
// openwacht-zentrale-update.path, sobald der Webdienst einen Auftrag ablegt.
//
// Der Ordner gehört dem Webdienst. Alles darin gilt deshalb als nicht
// vertrauenswürdig: Dateien werden ohne Symlinks und nur als reguläre Dateien
// gelesen, das Paket in einen eigenen Ordner von root kopiert und erst die
// Kopie geprüft (Prüfsumme, Signatur von SHA256SUMS mit den Schlüsseln dieses
// Programms, Plattform, nur neuer als die laufende Version). Erst dann ruft
// der Dienst apt auf. Das Ergebnis schreibt er ohne Symlinks zurück.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

const zentraleUpdateDir = "/var/lib/openwacht-update"

// Namen wie in internal/zentrale/zentraleupdate.go
const (
	zuAuftrag  = "auftrag"
	zuInArbeit = "in-arbeit"
	zuPaket    = "paket.deb"
	zuSummen   = "SHA256SUMS"
	zuSignatur = "SHA256SUMS.sig"
	zuErgebnis = "ergebnis.json"
)

// aptInstall: in Tests ersetzbar.
var aptInstall = func(ctx context.Context, deb string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "--no-install-recommends", deb)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd.CombinedOutput()
}

// zentraleUpdateAblage: Update aus der Oberfläche nur, wenn die Zentrale als
// Debian-Paket installiert ist (der Installationsdienst ruft apt) und systemd
// die Ablage angelegt hat.
func zentraleUpdateAblage() string {
	if _, err := os.Stat("/var/lib/dpkg/info/openwacht-zentrale.list"); err != nil {
		return ""
	}
	return zentraleUpdateDir
}

func cmdZentraleUpdate(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("update-installieren", flag.ContinueOnError)
	dir := fs.String("verzeichnis", zentraleUpdateDir, "Ablage des Webdienstes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("update-installieren braucht root (läuft als openwacht-zentrale-update.service)")
	}
	keys, err := update.Keys()
	if err != nil {
		return err
	}
	e := zentraleUpdateRun(ctx, *dir, keys, version.Version, runtime.GOARCH, "/run")
	fmt.Fprintln(stdout, e.Meldung)
	if !e.OK {
		return errors.New(e.Meldung)
	}
	return nil
}

// zentraleUpdateRun: ein Auftrag. Schreibt immer ein Ergebnis und räumt die
// Ablage auf, auch wenn etwas scheitert.
func zentraleUpdateRun(ctx context.Context, dir string, keys *update.Keyring, current, arch, tmpRoot string) zentrale.ZentraleErgebnis {
	e := zentrale.ZentraleErgebnis{Zeit: time.Now().UTC()}
	// Den Auftrag sofort umbenennen: Die Path-Unit startet sonst erneut, und
	// die Oberfläche zeigt „läuft“, bis das Ergebnis da ist.
	if err := os.Rename(filepath.Join(dir, zuAuftrag), filepath.Join(dir, zuInArbeit)); err != nil {
		e.Meldung = "Kein Auftrag."
		return e
	}
	defer func() {
		for _, n := range []string{zuInArbeit, zuPaket, zuSummen, zuSignatur} {
			os.Remove(filepath.Join(dir, n))
		}
		b, _ := json.Marshal(e)
		if err := writeNoFollow(dir, zuErgebnis, b); err != nil {
			fmt.Fprintln(os.Stderr, "Ergebnis nicht geschrieben:", err)
		}
	}()
	fail := func(format string, a ...any) zentrale.ZentraleErgebnis {
		e.Meldung = fmt.Sprintf(format, a...)
		return e
	}
	var auftrag zentrale.ZentraleAuftrag
	b, err := readRegular(filepath.Join(dir, zuInArbeit), 64<<10)
	if err != nil || json.Unmarshal(b, &auftrag) != nil {
		return fail("Auftrag nicht lesbar.")
	}
	e.Version = auftrag.Version
	sums, err := readRegular(filepath.Join(dir, zuSummen), update.MaxSums)
	if err != nil {
		return fail("SHA256SUMS nicht lesbar: %v", err)
	}
	sig, err := readRegular(filepath.Join(dir, zuSignatur), 4096)
	if err != nil {
		return fail("SHA256SUMS.sig nicht lesbar: %v", err)
	}
	if !update.ZentraleDatei.MatchString(auftrag.Datei) {
		return fail("Dateiname im Auftrag ungültig.")
	}
	// Eigener Ordner von root; geprüft und installiert wird nur die Kopie.
	priv, err := os.MkdirTemp(tmpRoot, "openwacht-update-")
	if err != nil {
		return fail("Arbeitsordner: %v", err)
	}
	defer os.RemoveAll(priv)
	deb := filepath.Join(priv, auftrag.Datei)
	sum, err := copyRegular(filepath.Join(dir, zuPaket), deb, update.MaxZentralePaket)
	if err != nil {
		return fail("Paket nicht lesbar: %v", err)
	}
	if sum != auftrag.SHA256 {
		return fail("Das Paket ist nicht das geprüfte (Prüfsumme weicht ab).")
	}
	p, err := keys.PruefeZentrale(sums, sig, auftrag.Datei, sum, current, arch)
	if err != nil {
		return fail("Abgelehnt: %v", err)
	}
	e.Version = p.Version
	cctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	out, err := aptInstall(cctx, deb)
	e.Ausgabe = tail(out, 8000)
	if err != nil {
		return fail("apt-get install ist gescheitert (%v). Die bisherige Version läuft weiter; Einzelheiten in der Ausgabe und mit journalctl -u openwacht-zentrale-update.", err)
	}
	e.OK = true
	e.Meldung = "Version " + p.Version + " installiert."
	return e
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

// openRegular öffnet eine Datei ohne Symlinks und ohne an einer FIFO zu
// hängen und prüft, dass sie eine reguläre Datei ist.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("keine reguläre Datei")
	}
	return f, nil
}

func readRegular(path string, max int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("zu groß")
	}
	return b, nil
}

// copyRegular kopiert src nach dst (neu, 0600) und liefert die Prüfsumme der Kopie.
func copyRegular(src, dst string, max int64) (string, error) {
	in, err := openRegular(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(out, io.LimitReader(in, max+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n == 0 || n > max {
		return "", errors.New("leer oder zu groß")
	}
	// Prüfsumme der Kopie, nicht der Quelle (die kann sich inzwischen ändern).
	f, err := os.Open(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeNoFollow schreibt name in dir über eine neue Datei und Umbenennen:
// Ein Symlink unter diesem Namen wird ersetzt, nie verfolgt.
func writeNoFollow(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}
