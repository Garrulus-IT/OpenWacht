// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Gegenstände eines Proxmox-Hosts (zusätzlich zu stumm, neustart, platte:).
const (
	guestPrefix   = "gast:"
	backupPrefix  = "backup:"
	metaPrefix    = "meta:"
	storagePrefix = "pvespeicher:"
)

// Feste Schwellen (Entscheidung, 20.11.2026; einstellbar erst später).
const (
	BackupWarnAge = 26 * time.Hour
	BackupCritAge = 50 * time.Hour
	MetaWarnPct   = 80.0
	MetaCritPct   = 90.0
)

// esxiStatus: Verbindungs- bzw. Energiezustand eines ESXi-Hosts aus vCenter.
func esxiStatus(st string) string {
	switch st {
	case "not_responding":
		return "antwortet dem vCenter nicht"
	case "disconnected":
		return "vom vCenter getrennt"
	case "standby":
		return "im Standby"
	case "powered_off":
		return "ausgeschaltet"
	}
	return "nicht verbunden oder aus (" + st + ")"
}

func guestLabel(g snmp.Guest) string {
	// vCenter (Etappe 26): Hosts und VMs mit Namen statt Zahl
	switch g.Type {
	case "esxi":
		return "ESXi-Host " + g.Name
	case "vm":
		return "VM " + g.Name
	}
	kind := "VM"
	if g.Type == "lxc" {
		kind = "CT"
	}
	s := kind + " " + strconv.Itoa(g.VMID)
	if g.Name != "" {
		s += " (" + g.Name + ")"
	}
	return s
}

// age: „11 Std.“, „3 Tage“.
func age(d time.Duration) string {
	h := int(d / time.Hour)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d Min.", max(int(d/time.Minute), 1))
	case h < 72:
		return fmt.Sprintf("%d Std.", h)
	}
	return fmt.Sprintf("%d Tagen", h/24)
}

// evaluateProxmox: Gäste, Backups, Speicher und Thin-Pools. addNamed nimmt
// den Anzeigenamen mit, damit Alarme den Gastnamen zeigen.
func evaluateProxmox(host string, px *snmp.Proxmox, now time.Time, prev map[string]string,
	addNamed func(sub, name, status, msg string)) {
	for _, g := range px.Guests {
		label := host + " · " + guestLabel(g)
		id := strconv.Itoa(g.VMID)
		if !g.Template && g.OnBoot != nil && *g.OnBoot {
			switch g.Status {
			case "running":
				addNamed(guestPrefix+id, label, OK, "läuft")
			case "paused", "suspended":
				addNamed(guestPrefix+id, label, Warn, "angehalten ("+g.Status+")")
			default:
				if g.Type == "esxi" {
					addNamed(guestPrefix+id, label, Crit, esxiStatus(g.Status))
					continue
				}
				st := g.Status
				if st == "" {
					st = "unbekannt"
				}
				addNamed(guestPrefix+id, label, Crit, "läuft nicht ("+st+"), obwohl „beim Booten starten“ an ist")
			}
		}
		watch := g.InJob != nil && *g.InJob || g.InJob == nil && g.BackupOK != nil
		if !watch {
			continue
		}
		name := host + " · Backup " + guestLabel(g)
		failed := g.BackupError != "" && g.BackupTry != nil && (g.BackupOK == nil || g.BackupTry.After(*g.BackupOK))
		if g.BackupOK == nil {
			msg := "kein erfolgreiches Backup in den letzten 8 Tagen gefunden"
			if failed {
				msg += "; letzter Versuch: " + g.BackupError
			}
			addNamed(backupPrefix+id, name, Crit, msg)
			continue
		}
		a := now.Sub(*g.BackupOK)
		st := OK
		switch {
		case a >= BackupCritAge:
			st = Crit
		case a >= BackupWarnAge:
			st = Warn
		}
		msg := "letztes Backup vor " + age(max(a, 0))
		switch st {
		case Crit:
			msg += fmt.Sprintf(" (kritisch ab %d Std.)", int(BackupCritAge.Hours()))
		case Warn:
			msg += fmt.Sprintf(" (Warnung ab %d Std.)", int(BackupWarnAge.Hours()))
		}
		if failed {
			msg += "; letzter Versuch fehlgeschlagen: " + g.BackupError
		}
		addNamed(backupPrefix+id, name, st, msg)
	}
	for _, s := range px.Storages {
		if !s.Enabled {
			continue
		}
		name := host + " · Speicher " + s.Name
		if s.Active {
			// Verfügbar ist der Normalfall; die Belegung steht schon unter
			// „Speicher <name>“. Nur nach einer Störung entwarnen.
			if prev[storagePrefix+s.Name] != "" {
				addNamed(storagePrefix+s.Name, name, OK, "wieder verfügbar")
			}
		} else {
			addNamed(storagePrefix+s.Name, name, Crit, "nicht verfügbar (eingehängt, erreichbar?)")
		}
	}
	for _, t := range px.ThinPools {
		pct, ok := t.MetaPercent()
		if !ok {
			continue
		}
		sub := metaPrefix + t.Name
		st := Level(pct, MetaWarnPct, MetaCritPct, prev[sub])
		addNamed(sub, host+" · Thin-Pool "+t.Name+" Metadaten", st, usage(pct, "der Metadaten belegt", st, MetaWarnPct, MetaCritPct))
	}
}

// proxmoxSubjectName: Name für Gegenstände, die nicht mehr gemeldet werden.
func proxmoxSubjectName(host, sub string) (string, bool) {
	switch {
	case strings.HasPrefix(sub, guestPrefix):
		return host + " · Gast " + strings.TrimPrefix(sub, guestPrefix), true
	case strings.HasPrefix(sub, backupPrefix):
		return host + " · Backup " + strings.TrimPrefix(sub, backupPrefix), true
	case strings.HasPrefix(sub, metaPrefix):
		return host + " · Thin-Pool " + strings.TrimPrefix(sub, metaPrefix) + " Metadaten", true
	case strings.HasPrefix(sub, storagePrefix):
		return host + " · Speicher " + strings.TrimPrefix(sub, storagePrefix), true
	}
	return "", false
}
