// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"path/filepath"
)

// Installation aus einem Paket (Etappe 34): .deb und .rpm unter Linux, MSI
// unter Windows. Das Paket liefert Binary und Units; Registrierung und
// Dienst richtet „openwacht-agent paket-einrichten“ ein, das der
// Paketmanager nach dem Auspacken aufruft.

// Pfade der Linux-Pakete. Das Binary gehört root (CheckBinary), die Units
// liegen dort, wo Pakete sie ablegen; /etc/systemd/system bleibt frei für
// Änderungen des Admins.
const (
	PackagedBinary  = "/usr/bin/openwacht-agent"
	PackagedUnitDir = "/usr/lib/systemd/system"
	// PackagedDir: Verzeichnis der Registrierung bei Paketen (wie ohne Paket).
	PackagedDir = "/var/lib/openwacht-agent"
	// OldUnitsDir: Hier landen Units einer früheren Einrichtung von Hand,
	// die sonst die Units des Pakets verdecken würden (nie gelöscht).
	OldUnitsDir = "/etc/openwacht-agent/units-vor-paket"
)

// UnitNames: Units des Agents in fester Reihenfolge.
var UnitNames = []string{"openwacht-agent-update.path", "openwacht-agent-update.service", "openwacht-agent.service"}

// PackageUnits liefert die Units, die im Linux-Paket liegen (Name → Inhalt).
// Sie sind dieselben, die „registrieren“ ohne Paket schreibt, nur mit festen
// Pfaden.
func PackageUnits() (map[string]string, error) {
	unit, err := RenderUnit(PackagedBinary, PackagedDir)
	if err != nil {
		return nil, err
	}
	path, service, err := RenderUpdateUnits(PackagedBinary, PackagedDir)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"openwacht-agent.service":        unit,
		"openwacht-agent-update.path":    path,
		"openwacht-agent-update.service": service,
	}, nil
}

// Registered: Liegt im Verzeichnis eine Registrierung?
func Registered(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, fileConfig))
	return err == nil && fi.Mode().IsRegular()
}
