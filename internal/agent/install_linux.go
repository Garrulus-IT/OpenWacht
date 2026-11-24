// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// DefaultDir: Verzeichnis für Schlüssel, Zertifikat und Einstellungen.
var DefaultDir = "/var/lib/openwacht-agent"

// IsRoot: Die Einrichtung des Dienstes braucht Root.
func IsRoot() bool { return os.Geteuid() == 0 }

// CheckBinary stellt sicher, dass niemand außer Root das Agent-Binary oder
// eines seiner Verzeichnisse ändern kann. Sonst könnte jeder Benutzer dem
// Dienst eigenen Code unterschieben.
func CheckBinary(path string) error {
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for cur := p; ; cur = filepath.Dir(cur) {
		fi, err := os.Stat(cur)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("Dateirechte nicht prüfbar")
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s gehört nicht root; bitte das Binary nach /usr/local/bin kopieren (root, 0755)", cur)
		}
		// Gruppe/andere dürfen nicht schreiben (Sticky-Verzeichnisse wie /tmp sind auch ungeeignet).
		if fi.Mode().Perm()&0o022 != 0 || fi.Mode()&fs.ModeSticky != 0 {
			return fmt.Errorf("%s ist für andere beschreibbar; bitte das Binary nach /usr/local/bin kopieren", cur)
		}
		if cur == "/" {
			return nil
		}
	}
}

// EnsureUser legt den Systembenutzer an, falls es ihn noch nicht gibt.
func EnsureUser() (uid, gid int, err error) {
	u, err := user.Lookup(ServiceUser)
	if err != nil {
		cmd := exec.Command("useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
			"--comment", "OpenWacht-Agent", ServiceUser)
		if out, err := cmd.CombinedOutput(); err != nil {
			return 0, 0, fmt.Errorf("Systembenutzer anlegen: %v: %s", err, out)
		}
		if u, err = user.Lookup(ServiceUser); err != nil {
			return 0, 0, err
		}
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// HandOver übergibt das Verzeichnis samt Inhalt an den Dienstbenutzer.
//
// Läuft als root durch ein Verzeichnis, in das der Dienstbenutzer schreiben
// kann (Befund N4). Deshalb über os.Root: Kein Link führt hinaus, auch nicht
// ein Verzeichnis, das während des Laufs gegen einen Link getauscht wird.
// Dateien werden ohne Folgen von Links geöffnet und über das Handle
// übergeben (fchown); eine Datei mit mehreren harten Links (könnte auf eine
// Systemdatei zeigen) bricht ab, statt sie zu übergeben.
func HandOver(dir string, uid, gid int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// der Link selbst, nie sein Ziel
			return root.Lchown(p, uid, gid)
		}
		f, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && !fi.IsDir() && st.Nlink > 1 {
			return fmt.Errorf("%s hat mehrere harte Links; nicht übergeben (bitte prüfen und entfernen)", filepath.Join(dir, p))
		}
		return f.Chown(uid, gid)
	})
}

// Pfade für die Paket-Erkennung (in Tests ersetzbar).
var (
	etcUnitDir     = "/etc/systemd/system"
	pkgUnitDir     = PackagedUnitDir
	oldUnitsDir    = OldUnitsDir
	packagedBinary = PackagedBinary
)

// Packaged: Binary und Verzeichnis sind die des Pakets (.deb/.rpm), und die
// Units des Pakets liegen bereit. Dann schreibt „registrieren“ keine eigenen
// Units nach /etc, sonst verdeckten sie die des Pakets bei jedem Update.
func Packaged(binary, dir string) bool {
	if binary != packagedBinary || filepath.Clean(dir) != PackagedDir {
		return false
	}
	fi, err := os.Stat(filepath.Join(pkgUnitDir, "openwacht-agent.service"))
	return err == nil && fi.Mode().IsRegular()
}

// generatedMark: So beginnen Units, die „openwacht-agent“ selbst schreibt.
const generatedMark = "# Erzeugt von „openwacht-agent "

// RetireOldUnits verschiebt Units einer früheren Einrichtung ohne Paket aus
// /etc/systemd/system nach OldUnitsDir (nicht löschen). Fremde Units mit
// demselben Namen (vom Admin geschrieben) bleiben liegen; sie verdecken die
// Units des Pakets, deshalb kommt ihr Name in die Rückgabe als Warnung.
func RetireOldUnits() (moved, foreign []string, err error) {
	for _, n := range UnitNames {
		p := filepath.Join(etcUnitDir, n)
		fi, lerr := os.Lstat(p)
		if errors.Is(lerr, fs.ErrNotExist) {
			continue
		}
		if lerr != nil {
			return moved, foreign, lerr
		}
		b, rerr := os.ReadFile(p)
		if !fi.Mode().IsRegular() || rerr != nil || !bytes.HasPrefix(b, []byte(generatedMark)) {
			foreign = append(foreign, p)
			continue
		}
		if err := os.MkdirAll(oldUnitsDir, 0o755); err != nil {
			return moved, foreign, err
		}
		dst := filepath.Join(oldUnitsDir, n)
		if _, err := os.Lstat(dst); err == nil {
			dst += ".1"
		}
		if err := os.Rename(p, dst); err != nil {
			return moved, foreign, err
		}
		moved = append(moved, p)
	}
	return moved, foreign, nil
}

// InstallUnit schreibt die systemd-Unit und lädt systemd neu. Bei einer
// Installation aus dem Paket nutzt sie dessen Units.
func InstallUnit(binary, dir string) error {
	if Packaged(binary, dir) {
		if _, _, err := RetireOldUnits(); err != nil {
			return err
		}
		return enableUpdatePath()
	}
	unit, err := RenderUnit(binary, dir)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(UnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	return InstallUpdateUnits(binary, dir)
}

// InstallUpdateUnits schreibt den Installationsdienst für Updates, lädt
// systemd neu und aktiviert die Path-Unit.
func InstallUpdateUnits(binary, dir string) error {
	if Packaged(binary, dir) {
		return enableUpdatePath()
	}
	path, service, err := RenderUpdateUnits(binary, dir)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(UpdateServiceUnit, []byte(service), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(UpdatePathUnit, []byte(path), 0o644); err != nil {
		return err
	}
	return enableUpdatePath()
}

// enableUpdatePath lädt systemd neu und aktiviert den Installationsdienst.
func enableUpdatePath() error {
	if !SystemdRunning() {
		return nil
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
	}
	// reenable statt enable: entfernt auch Verknüpfungen auf Units, die
	// RetireOldUnits aus /etc verschoben hat (sonst blieben tote Links).
	if out, err := exec.Command("systemctl", "reenable", "openwacht-agent-update.path").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reenable openwacht-agent-update.path: %v: %s", err, out)
	}
	if out, err := exec.Command("systemctl", "start", "openwacht-agent-update.path").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl start openwacht-agent-update.path: %v: %s", err, out)
	}
	return nil
}

// SystemdRunning: Läuft das System unter systemd? (Übliche Prüfung, siehe sd_booted(3).)
func SystemdRunning() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

// ProcDropIn: Ergänzung der Unit für den Prozess-Sensor. ProtectProc=invisible
// verbirgt sonst die Prozesse anderer Benutzer. Geschrieben nur von
// „openwacht-agent sensoren -arten …,prozess“ (als root, auf dem Rechner).
var ProcDropIn = "/etc/systemd/system/openwacht-agent.service.d/sensoren-prozess.conf"

const procDropInText = `# Erzeugt von „openwacht-agent sensoren“: Der Prozess-Sensor zählt Prozesse
# anderer Benutzer nach Name (nur /proc/<pid>/comm, ohne Benutzer und
# Kommandozeile). Entfernt, sobald die Art prozess nicht mehr freigegeben ist.
[Service]
ProtectProc=default
`

// SetProcVisible schreibt oder entfernt die Ergänzung und lädt systemd neu.
// changed: Der Dienst muss neu starten, damit sie wirkt.
func SetProcVisible(on bool) (changed bool, err error) {
	cur, rerr := os.ReadFile(ProcDropIn)
	switch {
	case on && rerr == nil && string(cur) == procDropInText:
		return false, nil
	case on:
		if err := os.MkdirAll(filepath.Dir(ProcDropIn), 0o755); err != nil {
			return false, err
		}
		if err := writeFileAtomic(ProcDropIn, []byte(procDropInText), 0o644); err != nil {
			return false, err
		}
	case errors.Is(rerr, os.ErrNotExist):
		return false, nil
	default:
		if err := os.Remove(ProcDropIn); err != nil {
			return false, err
		}
	}
	if SystemdRunning() {
		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return true, fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
	}
	return true, nil
}
