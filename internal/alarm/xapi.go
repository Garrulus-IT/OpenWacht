// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"strings"

	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/xapi"
)

// Gegenstände eines XenServer-Pools (0.42.0), zusätzlich zu stumm, neustart,
// cpu und speicher (ganzer Pool) und platte: (Belegung der
// Storage-Repositories mit Prognose).
const (
	SubjectXenHA      = "xenha"
	SubjectXenUpdates = "xenupdates"
	xenHostPrefix     = "xenhost:"
	xenCPUPrefix      = "xencpu:"
	xenRAMPrefix      = "xenram:"
	xenVMPrefix       = "xenvm:"
	xenSRPrefix       = "xensr:"
)

// xenHostState: erreichbar, aktiviert, Wartungsmodus.
func xenHostState(h snmp.XAPIHost) (string, string) {
	role := ""
	if h.Master {
		role = " (Pool-Master)"
	}
	switch {
	case !h.Live:
		return Crit, "nicht erreichbar" + role
	case h.Maintenance:
		return Warn, "im Wartungsmodus" + role
	case !h.Enabled:
		return Warn, "deaktiviert, nimmt keine neuen VMs an" + role
	}
	msg := "läuft" + role
	if h.UptimeS > 0 {
		msg += ", seit " + age(secondsDur(int64(h.UptimeS)))
	}
	if h.MetricsError != "" {
		msg += "; Messwerte nicht abrufbar: " + h.MetricsError
	}
	return OK, msg
}

func xenVMLabel(v snmp.XAPIVM) string {
	if v.Host != "" {
		return "VM " + v.Name + " auf " + v.Host
	}
	return "VM " + v.Name
}

// xenVMState: nur für VMs, die laufen sollen (HA-Neustart oder automatisch starten).
func xenVMState(v snmp.XAPIVM) (string, string) {
	switch v.State {
	case "running":
		return OK, "läuft"
	case "paused":
		return Warn, "angehalten (paused)"
	case "suspended":
		return Warn, "ausgesetzt (suspended)"
	case "halted":
		return Crit, "ausgeschaltet, soll aber laufen (HA-Neustart oder „automatisch starten“)"
	}
	return Crit, "Zustand unbekannt"
}

func xenHAState(ha snmp.XAPIHA) (string, string) {
	if !ha.Enabled {
		return OK, "HA ausgeschaltet"
	}
	if ha.Overcommitted {
		return Crit, fmt.Sprintf("HA überbucht: Der Plan reicht nur für %d von %d tolerierten Host-Ausfällen", ha.Plan, ha.Tolerate)
	}
	if ha.Plan < ha.Tolerate {
		return Warn, fmt.Sprintf("HA-Plan reicht nur für %d von %d tolerierten Host-Ausfällen", ha.Plan, ha.Tolerate)
	}
	return OK, fmt.Sprintf("HA an, %d Host-Ausfall/Ausfälle abgedeckt", ha.Plan)
}

func xenUpdatesState(hosts []snmp.XAPIHost) (string, string, bool) {
	known := false
	var pending, steps []string
	for _, h := range hosts {
		if h.Updates != "" || len(h.Pending) > 0 {
			known = true
		}
		if h.Updates == "ausstehend" {
			pending = append(pending, h.Name)
		}
		for _, g := range h.Pending {
			steps = append(steps, h.Name+": "+guidanceText(g))
		}
	}
	if !known {
		return "", "", false
	}
	switch {
	case len(pending) > 0 && len(steps) > 0:
		return Warn, "Updates ausstehend auf " + listShort(pending) + "; außerdem " + listShort(steps), true
	case len(pending) > 0:
		return Warn, "Updates ausstehend auf " + listShort(pending), true
	case len(steps) > 0:
		return Warn, "Nach Updates noch zu tun: " + listShort(steps), true
	}
	return OK, "alle Hosts auf dem neuesten Stand", true
}

func guidanceText(g string) string { return xapi.GuidanceText(g) }

func listShort(names []string) string {
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" und %d weitere", len(names)-5)
	}
	return strings.Join(names, ", ")
}

// evaluateXAPI bewertet Hosts, VMs, Storage-Repositories, HA und Updates.
// Teile, deren Abfrage diesmal scheiterte, behalten ihren bisherigen Zustand.
func evaluateXAPI(host string, x *snmp.XAPI, partial []string, prev map[string]string, lim HostLimits,
	addNamed func(sub, name, status, msg string)) {
	keep := func(parts []string, prefixes ...string) bool {
		hit := false
		for _, p := range parts {
			hit = hit || contains(partial, p)
		}
		if !hit {
			return false
		}
		for _, sub := range sortedKeys(prev) {
			for _, p := range prefixes {
				if sub == p || strings.HasPrefix(sub, p) && p[len(p)-1] == ':' {
					addNamed(sub, xapiSubjectNameOr(host, sub), prev[sub], "zurzeit nicht abfragbar, letzter Zustand bleibt")
				}
			}
		}
		return true
	}
	if !keep([]string{"Hosts"}, xenHostPrefix) {
		for _, h := range x.Hosts {
			st, msg := xenHostState(h)
			addNamed(xenHostPrefix+h.Name, host+" · Host "+h.Name, st, msg)
		}
	}
	// CPU und RAM je Host erst ab zwei Hosts (sonst wie „CPU“ und „Speicher“ des Pools).
	if len(x.Hosts) > 1 {
		for _, h := range x.Hosts {
			if !h.Live {
				continue
			}
			if h.CPUPct != nil {
				sub := xenCPUPrefix + h.Name
				st := Level(*h.CPUPct, lim.CPUWarn, lim.CPUCrit, prev[sub])
				addNamed(sub, host+" · Host "+h.Name+" CPU", st, usage(*h.CPUPct, "CPU-Last (Mittel 10 Min.)", st, lim.CPUWarn, lim.CPUCrit))
			}
			if h.MemTotal > 0 && h.MemFree <= h.MemTotal {
				p := float64(h.MemTotal-h.MemFree) / float64(h.MemTotal) * 100
				sub := xenRAMPrefix + h.Name
				st := Level(p, lim.MemWarn, lim.MemCrit, prev[sub])
				addNamed(sub, host+" · Host "+h.Name+" RAM", st, usage(p, "RAM belegt", st, lim.MemWarn, lim.MemCrit))
			}
		}
	}
	if !keep([]string{"VMs"}, xenVMPrefix) {
		for _, v := range x.VMs {
			if !v.AutoStart {
				continue
			}
			st, msg := xenVMState(v)
			addNamed(xenVMPrefix+v.UUID, host+" · "+xenVMLabel(v), st, msg)
		}
	}
	if !keep([]string{"Speicher", "Anbindung"}, xenSRPrefix) {
		for _, s := range x.SRs {
			sub := xenSRPrefix + s.Name
			name := host + " · SR " + s.Name + " Anbindung"
			if len(s.Detached) > 0 {
				addNamed(sub, name, Crit, "nicht angebunden auf "+listShort(s.Detached))
			} else if prev[sub] != "" {
				addNamed(sub, name, OK, "wieder angebunden")
			}
		}
	}
	st, msg := xenHAState(x.HA)
	if st != OK || prev[SubjectXenHA] != "" || x.HA.Enabled {
		addNamed(SubjectXenHA, host+" · HA", st, msg)
	}
	if st, msg, ok := xenUpdatesState(x.Hosts); ok {
		addNamed(SubjectXenUpdates, host+" · Updates", st, msg)
	}
}

func xapiSubjectNameOr(host, sub string) string {
	if n, ok := xapiSubjectName(host, sub); ok {
		return n
	}
	return snmpSubjectName(host, sub)
}

// xapiSubjectName: Name für Gegenstände, die nicht mehr gemeldet werden.
func xapiSubjectName(host, sub string) (string, bool) {
	for _, x := range []struct{ prefix, label, suffix string }{
		{xenHostPrefix, "Host ", ""}, {xenCPUPrefix, "Host ", " CPU"}, {xenRAMPrefix, "Host ", " RAM"},
		{xenVMPrefix, "VM ", ""}, {xenSRPrefix, "SR ", " Anbindung"},
	} {
		if rest, ok := strings.CutPrefix(sub, x.prefix); ok {
			return host + " · " + x.label + rest + x.suffix, true
		}
	}
	switch sub {
	case SubjectXenHA:
		return host + " · HA", true
	case SubjectXenUpdates:
		return host + " · Updates", true
	}
	return "", false
}
