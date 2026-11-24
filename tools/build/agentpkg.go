// SPDX-License-Identifier: AGPL-3.0-only

package main

// Pakete für den Agent (Etappe 34): .deb (Debian, Ubuntu) und .rpm (RHEL,
// Rocky, Alma, SUSE). Inhalt in beiden gleich: Binary nach /usr/bin, Units
// nach /usr/lib/systemd/system (aus internal/agent, also dieselben wie bei
// „registrieren“ ohne Paket). Nach dem Auspacken ruft der Paketmanager
// „openwacht-agent paket-einrichten -aus-umgebung“ auf: Systembenutzer, alte
// Units einer Einrichtung von Hand beiseitelegen, mit OPENWACHT_ZENTRALE und
// OPENWACHT_TOKEN registrieren, Dienst (neu) starten.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/garrulus-it/openwacht/internal/agent"
)

const agentSummary = "OpenWacht-Agent (sendet Messwerte an die Zentrale)"

const agentDescription = `Agent von OpenWacht: sammelt Messwerte (CPU, Speicher, Platten, freigegebene
Sensoren) und sendet sie an die Zentrale. Er nimmt keine Befehle an und öffnet
keinen Port. Registrieren beim Installieren mit OPENWACHT_ZENTRALE und
OPENWACHT_TOKEN in der Umgebung oder danach mit „openwacht-agent registrieren“.`

// Skripte des .deb. Registrierung nur bei configure; bei einem Update
// startet paket-einrichten den Dienst mit der neuen Version neu.
const agentDebPostinst = `#!/bin/sh
# OpenWacht-Agent: Dienst einrichten, mit OPENWACHT_ZENTRALE/OPENWACHT_TOKEN
# auch registrieren. Mehrfach ausführbar.
set -e
case "$1" in
    configure)
        /usr/bin/openwacht-agent paket-einrichten -aus-umgebung
        ;;
esac
exit 0
`

const agentDebPrerm = `#!/bin/sh
# OpenWacht-Agent: Beim Entfernen Dienste anhalten (bei einem Update nicht).
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now openwacht-agent.service openwacht-agent-update.path >/dev/null 2>&1 || true
fi
exit 0
`

const agentDebPostrm = `#!/bin/sh
# OpenWacht-Agent: Die Registrierung in /var/lib/openwacht-agent bleibt
# auch bei purge (ohne Dienst sendet niemand mehr; in der Oberfläche sperren).
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = purge ]; then
    echo "OpenWacht-Agent: /var/lib/openwacht-agent bleibt erhalten; den Agent in der Oberfläche sperren oder löschen."
fi
exit 0
`

// Skripte des .rpm ($1: Anzahl der Installationen nach dem Schritt).
const agentRPMPost = `/usr/bin/openwacht-agent paket-einrichten -aus-umgebung
`

const agentRPMPreun = `if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now openwacht-agent.service openwacht-agent-update.path >/dev/null 2>&1 || true
fi
`

const agentRPMPostun = `if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
`

// agentPackageFiles: Inhalt beider Pakete.
func agentPackageFiles(bin []byte) ([]debFile, error) {
	units, err := agent.PackageUnits()
	if err != nil {
		return nil, err
	}
	files := []debFile{
		{agent.PackagedBinary[1:], bin, 0o755},
		{"usr/share/doc/openwacht-agent/copyright", copyrightFile("openwacht-agent"), 0o644},
	}
	names := make([]string, 0, len(units))
	for n := range units {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, debFile{agent.PackagedUnitDir[1:] + "/" + n, []byte(units[n]), 0o644})
	}
	return files, nil
}

// buildAgentPackages baut .deb und .rpm für ein Linux-Ziel. Rückgabe: Dateinamen.
func buildAgentPackages(out, binName, goarch, ver string, mtime time.Time) ([]string, error) {
	bin, err := os.ReadFile(filepath.Join(out, binName))
	if err != nil {
		return nil, err
	}
	files, err := agentPackageFiles(bin)
	if err != nil {
		return nil, err
	}
	spec := pkgSpec{
		name: "openwacht-agent", version: ver, summary: agentSummary, description: agentDescription,
		depends: []string{"passwd"}, files: files,
		postinst: agentDebPostinst, prerm: agentDebPrerm, postrm: agentDebPostrm,
	}
	deb, err := writeDeb(out, goarch, mtime, spec)
	if err != nil {
		return nil, fmt.Errorf("Debian-Paket: %w", err)
	}
	rpm, err := writeRPM(out, goarch, mtime, spec, rpmScripts{post: agentRPMPost, preun: agentRPMPreun, postun: agentRPMPostun})
	if err != nil {
		return nil, fmt.Errorf("RPM-Paket: %w", err)
	}
	return []string{deb, rpm}, nil
}
