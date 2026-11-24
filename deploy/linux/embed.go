// SPDX-License-Identifier: AGPL-3.0-only

// Package deploylinux bettet die systemd-Units der Zentrale ein. Sie landen im
// Debian-Paket (tools/build) und, ohne Paket, über `openwacht-zentrale
// installieren` in /etc/systemd/system.
package deploylinux

import "embed"

//go:embed *.service *.socket *.timer
var units embed.FS

// UnitNames: alle Units in fester Reihenfolge.
var UnitNames = []string{
	"openwacht-migrieren.service",
	"openwacht-sicherung.service",
	"openwacht-sicherung.timer",
	"openwacht-traps.service",
	"openwacht-traps.socket",
	"openwacht-zentrale.service",
	"openwacht-zentrale.socket",
}

// Unit liefert den Inhalt einer Unit.
func Unit(name string) ([]byte, error) { return units.ReadFile(name) }
