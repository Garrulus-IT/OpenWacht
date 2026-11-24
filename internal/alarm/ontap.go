// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Gegenstände eines NetApp-Clusters (0.41.0), zusätzlich zu stumm, neustart
// und platte: (Belegung der Aggregate und Volumes mit Prognose).
const (
	SubjectDisks     = "platten" // alle Platten zusammen
	nodePrefix       = "knoten:"
	aggrPrefix       = "aggregat:"
	volumePrefix     = "volume:"
	shelfPrefix      = "shelf:"
	mirrorPrefix     = "snapmirror:"
	emsPrefix        = "ems:"
	MaxEventSubjects = 20
)

// Verzögerung von SnapMirror wie das Alter von Backups (Proxmox).
var (
	MirrorWarnAge = BackupWarnAge
	MirrorCritAge = BackupCritAge
)

func secondsDur(s int64) time.Duration { return time.Duration(s) * time.Second }

func worst(a, b string) string {
	rank := map[string]int{OK: 0, Warn: 1, Crit: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// nodeState: Zustand eines Knotens mit HA und Hardware.
func nodeState(n snmp.ONTAPNode) (string, string) {
	st := OK
	var bad []string
	add := func(s, msg string) { st = worst(st, s); bad = append(bad, msg) }
	switch n.State {
	case "up":
	case "booting":
		add(Warn, "startet")
	case "taken_over", "waiting_for_giveback":
		add(Crit, "vom HA-Partner übernommen ("+n.State+")")
	case "down":
		add(Crit, "ausgefallen")
	case "degraded":
		add(Crit, "eingeschränkt (kritische Dienste offline)")
	default:
		add(Crit, "Zustand unbekannt (weder Knoten noch Partner erreichbar)")
	}
	switch n.Takeover {
	case "in_takeover":
		add(Crit, "hat den Partner "+n.Partner+" übernommen")
	case "in_progress":
		add(Warn, "Übernahme läuft")
	case "failed":
		add(Crit, "Übernahme fehlgeschlagen")
	case "not_possible":
		if n.Partner != "" {
			add(Warn, "Übernahme des Partners nicht möglich")
		}
	}
	if n.Giveback == "failed" {
		add(Warn, "Rückgabe fehlgeschlagen")
	}
	if n.Partner != "" && !n.HA {
		add(Warn, "Speicher-Failover ausgeschaltet")
	}
	if n.OverTemp {
		add(Crit, "Übertemperatur")
	}
	if n.FailedFans > 0 {
		add(Crit, fmt.Sprintf("%d Lüfter ausgefallen", n.FailedFans))
	}
	if n.FailedPSUs > 0 {
		add(Crit, fmt.Sprintf("%d Netzteil(e) ausgefallen", n.FailedPSUs))
	}
	if st != OK {
		return st, strings.Join(bad, ", ")
	}
	if n.Partner != "" {
		return OK, "läuft, HA mit " + n.Partner + " bereit"
	}
	return OK, "läuft"
}

func disksState(d snmp.ONTAPDisks) (string, string) {
	var broken, other []string
	for _, x := range d.Bad {
		if x.State == "broken" || x.Container == "broken" {
			broken = append(broken, x.Name)
		} else {
			other = append(other, x.Name+" "+diskText(x))
		}
	}
	list := func(names []string) string {
		if len(names) > 5 {
			return strings.Join(names[:5], ", ") + fmt.Sprintf(" und %d weitere", len(names)-5)
		}
		return strings.Join(names, ", ")
	}
	spares := fmt.Sprintf("%d Ersatzplatte(n)", d.Spares)
	switch {
	case len(broken) > 0:
		msg := fmt.Sprintf("%d Platte(n) ausgefallen: %s; %s", len(broken), list(broken), spares)
		if len(other) > 0 {
			msg += "; außerdem " + list(other)
		}
		return Crit, msg
	case len(other) > 0:
		return Warn, list(other) + "; " + spares
	}
	return OK, fmt.Sprintf("%d Platten in Ordnung, %s", d.Total, spares)
}

func diskText(d snmp.ONTAPDisk) string {
	switch d.State {
	case "copy":
		return "wird ersetzt (fällt voraussichtlich aus)"
	case "reconstructing":
		return "wird neu aufgebaut"
	case "removed":
		return "entfernt"
	case "unfail":
		return "wird wieder in Betrieb genommen"
	}
	return "auffällig (" + d.State + ")"
}

func partName(p snmp.ONTAPPart) string {
	switch p.Kind {
	case "psu":
		return "Netzteil " + p.ID
	case "module":
		return "Modul " + p.ID
	}
	return "Lüfter " + p.ID
}

func shelfState(s snmp.ONTAPShelf, prev string) (string, string) {
	st := OK
	var bad []string
	add := func(x, msg string) { st = worst(st, x); bad = append(bad, msg) }
	for _, p := range s.Parts {
		if p.State == "error" {
			add(Crit, partName(p)+" gestört")
		}
	}
	hottest := -1000
	for _, t := range s.Temps {
		if t.Celsius != nil && *t.Celsius > hottest {
			hottest = *t.Celsius
		}
		switch {
		case t.State == "error" && t.Celsius != nil:
			add(Crit, fmt.Sprintf("Temperaturfühler %s meldet Fehler (%d °C)", t.ID, *t.Celsius))
		case t.State == "error":
			add(Crit, "Temperaturfühler "+t.ID+" meldet Fehler")
		case t.Celsius == nil:
		case t.Crit != nil && *t.Celsius >= *t.Crit:
			add(Crit, fmt.Sprintf("%d °C an Fühler %s (kritisch ab %d °C)", *t.Celsius, t.ID, *t.Crit))
		case t.Warn != nil && (*t.Celsius >= *t.Warn || prev != OK && prev != "" && float64(*t.Celsius) >= float64(*t.Warn)-Hysteresis):
			add(Warn, fmt.Sprintf("%d °C an Fühler %s (Warnung ab %d °C)", *t.Celsius, t.ID, *t.Warn))
		}
	}
	if s.State == "error" && len(bad) == 0 {
		add(Crit, "meldet einen Fehler")
	}
	if s.State == "unknown" && len(bad) == 0 {
		add(Warn, "Zustand unbekannt")
	}
	if st != OK {
		return st, strings.Join(bad, ", ")
	}
	msg := "Netzteile, Module und Lüfter normal"
	if hottest > -1000 {
		msg += fmt.Sprintf(", bis %d °C", hottest)
	}
	return OK, msg
}

func mirrorState(m snmp.ONTAPMirror) (string, string) {
	from := ""
	if m.Source != "" {
		from = " von " + m.Source
	}
	if !m.Healthy {
		msg := "nicht gesund"
		if m.Reason != "" {
			msg += ": " + m.Reason
		}
		return Crit, msg + from
	}
	if m.State == "broken_off" {
		return Warn, "Beziehung getrennt (broken_off)" + from
	}
	if m.State == "uninitialized" {
		return Warn, "noch nicht initialisiert" + from
	}
	if m.LagS == nil {
		return OK, "gesund" + from
	}
	lag := secondsDur(*m.LagS)
	st := OK
	switch {
	case lag >= MirrorCritAge:
		st = Crit
	case lag >= MirrorWarnAge:
		st = Warn
	}
	msg := "Verzögerung " + age(lag)
	switch st {
	case Crit:
		msg += fmt.Sprintf(" (kritisch ab %d Std.)", int(MirrorCritAge.Hours()))
	case Warn:
		msg += fmt.Sprintf(" (Warnung ab %d Std.)", int(MirrorWarnAge.Hours()))
	}
	return st, msg + from
}

func aggrState(state string) (string, string) {
	switch state {
	case "online":
		return OK, "online"
	case "onlining", "relocating":
		return Warn, "wird umgeschaltet (" + state + ")"
	}
	return Crit, "nicht verfügbar (" + state + ")"
}

func volumeState(state string) (string, string) {
	switch state {
	case "online":
		return OK, "online"
	case "offline", "restricted", "mixed":
		return Warn, "nicht online (" + state + ")"
	}
	return Crit, "gestört (" + state + ")"
}

// evaluateONTAP bewertet Knoten, Aggregate, Volumes, Platten, Shelves,
// SnapMirror und EMS. Teile, deren Abfrage diesmal scheiterte, behalten ihren
// bisherigen Zustand (keine Entwarnung, weil eine Antwort fehlt).
func evaluateONTAP(host string, o *snmp.ONTAP, partial []string, prev map[string]string, addNamed func(sub, name, status, msg string)) {
	keep := func(part string, prefixes ...string) bool {
		if !contains(partial, part) {
			return false
		}
		for _, sub := range sortedKeys(prev) {
			for _, p := range prefixes {
				if sub == p || strings.HasPrefix(sub, p) && p[len(p)-1] == ':' {
					addNamed(sub, ontapSubjectNameOr(host, sub), prev[sub], "zurzeit nicht abfragbar, letzter Zustand bleibt")
				}
			}
		}
		return true
	}
	for _, n := range o.Nodes {
		st, msg := nodeState(n)
		addNamed(nodePrefix+n.Name, host+" · Knoten "+n.Name, st, msg)
	}
	for _, a := range o.Aggregates {
		st, msg := aggrState(a.State)
		// Online ist der Normalfall; die Belegung steht unter „Aggregat …“. Nur nach einer Störung entwarnen.
		if st != OK || prev[aggrPrefix+a.Name] != "" {
			addNamed(aggrPrefix+a.Name, host+" · Aggregat "+a.Name+" Zustand", st, msg)
		}
	}
	if !keep("Volumes", volumePrefix) {
		for _, v := range o.Volumes {
			st, msg := volumeState(v.State)
			if st != OK || prev[volumePrefix+v.Name] != "" {
				addNamed(volumePrefix+v.Name, host+" · Volume "+v.Name+" Zustand", st, msg)
			}
		}
	}
	if !keep("Platten", SubjectDisks) {
		st, msg := disksState(o.Disks)
		addNamed(SubjectDisks, host+" · Platten", st, msg)
	}
	if !keep("Shelves", shelfPrefix) {
		for _, s := range o.Shelves {
			st, msg := shelfState(s, prev[shelfPrefix+s.ID])
			addNamed(shelfPrefix+s.ID, host+" · Shelf "+s.ID, st, msg)
		}
	}
	if !keep("SnapMirror", mirrorPrefix) {
		for _, m := range o.Mirrors {
			st, msg := mirrorState(m)
			addNamed(mirrorPrefix+m.Destination, host+" · SnapMirror "+m.Destination, st, msg)
		}
	}
	if !keep("EMS", emsPrefix) {
		// je Meldung das jüngste Ereignis; höchstens MaxEventSubjects Meldungen
		latest := map[string]snmp.ONTAPEvent{}
		for _, e := range o.Events {
			if x, ok := latest[e.Name]; !ok || e.Time > x.Time {
				latest[e.Name] = e
			}
		}
		names := make([]string, 0, len(latest))
		for n := range latest {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool { return latest[names[i]].Time > latest[names[j]].Time })
		if len(names) > MaxEventSubjects {
			names = names[:MaxEventSubjects]
		}
		for _, n := range names {
			e := latest[n]
			msg := e.Message
			if e.Node != "" {
				msg = e.Node + ": " + msg
			}
			addNamed(emsPrefix+n, host+" · EMS "+n, Crit, msg+" ("+e.Severity+", "+e.Time+")")
		}
		for _, sub := range sortedKeys(prev) {
			if strings.HasPrefix(sub, emsPrefix) && latest[strings.TrimPrefix(sub, emsPrefix)].Name == "" {
				addNamed(sub, ontapSubjectNameOr(host, sub), OK, "keine neue Meldung in der letzten Stunde")
			}
		}
	}
}

func ontapSubjectNameOr(host, sub string) string {
	if n, ok := ontapSubjectName(host, sub); ok {
		return n
	}
	return snmpSubjectName(host, sub)
}

// ontapSubjectName: Name für Gegenstände, die nicht mehr gemeldet werden.
func ontapSubjectName(host, sub string) (string, bool) {
	for _, x := range []struct{ prefix, label, suffix string }{
		{nodePrefix, "Knoten ", ""}, {aggrPrefix, "Aggregat ", " Zustand"}, {volumePrefix, "Volume ", " Zustand"},
		{shelfPrefix, "Shelf ", ""}, {mirrorPrefix, "SnapMirror ", ""}, {emsPrefix, "EMS ", ""},
	} {
		if rest, ok := strings.CutPrefix(sub, x.prefix); ok {
			return host + " · " + x.label + rest + x.suffix, true
		}
	}
	if sub == SubjectDisks {
		return host + " · Platten", true
	}
	return "", false
}
