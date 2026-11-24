// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"fmt"
	"regexp"
	"text/template"
)

// Nur unkritische Zeichen in Pfaden der Unit (Zulassungsliste statt Sperrliste).
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// Systembenutzer und Unit unter Linux.
const (
	ServiceUser = "openwacht-agent"
	UnitPath    = "/etc/systemd/system/openwacht-agent.service"
	// Installationsdienst für signierte Updates (Etappe 23)
	UpdatePathUnit    = "/etc/systemd/system/openwacht-agent-update.path"
	UpdateServiceUnit = "/etc/systemd/system/openwacht-agent-update.service"
)

// Der Installationsdienst läuft als root, aber nur, wenn der Agent eine
// geprüfte Version mit der Marke „bereit“ abgelegt hat. Er prüft selbst noch
// einmal mit dem Schlüssel aus dem installierten Binary.
var updatePathTemplate = template.Must(template.New("path").Parse(`# Erzeugt von „openwacht-agent registrieren“ bzw. „updates-einrichten“.
[Unit]
Description=OpenWacht-Agent: bereitgelegtes Update erkennen

[Path]
PathExists={{.Dir}}/update/bereit
Unit=openwacht-agent-update.service

[Install]
WantedBy=multi-user.target
`))

var updateServiceTemplate = template.Must(template.New("upd").Parse(`# Erzeugt von „openwacht-agent registrieren“ bzw. „updates-einrichten“.
[Unit]
Description=OpenWacht-Agent: signiertes Update installieren

[Service]
Type=oneshot
ExecStart={{.Binary}} update-installieren -verzeichnis {{.Dir}}
TimeoutStartSec=300
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0022
`))

// RenderUpdateUnits erzeugt Path- und Service-Unit des Installationsdienstes.
func RenderUpdateUnits(binary, dir string) (path, service string, err error) {
	for _, s := range []string{binary, dir} {
		if !safePath.MatchString(s) {
			return "", "", fmt.Errorf("Pfad %q ist für die Unit ungeeignet (absolut, ohne Leer- und Sonderzeichen)", s)
		}
	}
	var a, b bytes.Buffer
	data := struct{ Binary, Dir string }{binary, dir}
	if err := updatePathTemplate.Execute(&a, data); err != nil {
		return "", "", err
	}
	if err := updateServiceTemplate.Execute(&b, data); err != nil {
		return "", "", err
	}
	return a.String(), b.String(), nil
}

// Der Dienst läuft ohne Root und ohne Capabilities. Lesen darf er fast
// alles (für statfs und /proc), schreiben nur in sein Verzeichnis.
// ProtectHome=read-only statt yes: sonst sähe statfs für /home ein leeres
// tmpfs statt der echten Platte.
var unitTemplate = template.Must(template.New("unit").Parse(`# Erzeugt von „openwacht-agent registrieren“. Änderungen werden beim nächsten Registrieren überschrieben.
[Unit]
Description=OpenWacht-Agent (sendet Messwerte an die Zentrale)
Documentation=https://github.com/garrulus-it/openwacht
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.User}}
ExecStart={{.Binary}} starten -verzeichnis {{.Dir}}
Restart=always
RestartSec=10

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths={{.Dir}}
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
ProtectProc=invisible
RemoveIPC=yes
PrivateUsers=yes
UMask=0077

[Install]
WantedBy=multi-user.target
`))

// RenderUnit erzeugt die systemd-Unit.
func RenderUnit(binary, dir string) (string, error) {
	for _, s := range []string{binary, dir} {
		if !safePath.MatchString(s) {
			return "", fmt.Errorf("Pfad %q ist für die Unit ungeeignet (absolut, ohne Leer- und Sonderzeichen)", s)
		}
	}
	var b bytes.Buffer
	err := unitTemplate.Execute(&b, struct{ User, Binary, Dir string }{ServiceUser, binary, dir})
	return b.String(), err
}
