// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Hysteresis: So viele Prozentpunkte muss ein Messwert unter die Schwelle
// fallen, bevor ein gemeldetes Problem als behoben gilt. Verhindert, dass
// eine Platte bei 90 % im Minutentakt Alarm und Entwarnung schickt.
const Hysteresis = 2.0

// Gegenstände eines Host-Alarms (subject in alert_state_agents).
const (
	SubjectSilent = "stumm"
	SubjectMemory = "speicher"
	SubjectCPU    = "cpu"
	diskPrefix    = "platte:"
	// SubjectCollector: der Agent als Sammler (Etappe 15)
	SubjectCollector = "sammler"
)

// HostLimits sind die Schwellen der Zentrale. Eine Schwelle <= 0 ist aus.
type HostLimits struct {
	SilentAfter        time.Duration
	DiskWarn, DiskCrit float64
	MemWarn, MemCrit   float64
	CPUWarn, CPUCrit   float64 // Mittel über 15 Minuten
	// DiskDays: Warnung, wenn eine Platte laut Prognose in weniger Tagen voll
	// ist (Etappe 20b); 0 = aus.
	DiskDays float64
}

// Level ordnet einen Prozentwert mit Hysterese ein. prev ist der zuletzt
// gemeldete Zustand ("" = keiner).
func Level(pct, warn, crit float64, prev string) string {
	if crit > 0 && (pct >= crit || prev == Crit && pct >= crit-Hysteresis) {
		return Crit
	}
	if warn > 0 && (pct >= warn || (prev == Warn || prev == Crit) && pct >= warn-Hysteresis) {
		return Warn
	}
	return OK
}

// FullSoon: Ist eine Platte laut Prognose bald voll? Warnung unter limit
// Tagen (0 = aus); eine gemeldete Warnung endet erst bei limit plus einem
// Fünftel (mindestens 2 Tage), damit sie nicht flattert.
func FullSoon(days int, limit float64, prev string) bool {
	if limit <= 0 || days < 0 {
		return false
	}
	d := float64(days)
	if d < limit {
		return true
	}
	return (prev == Warn || prev == Crit) && d < limit+math.Max(2, math.Ceil(limit/5))
}

// FullText: „voll in etwa 9 Tagen“.
func FullText(days int) string {
	switch days {
	case 0:
		return "voll innerhalb eines Tages"
	case 1:
		return "voll in etwa einem Tag"
	}
	return fmt.Sprintf("voll in etwa %d Tagen", days)
}

// HostMetrics: der Teil des Snapshots, den die Alarme brauchen (JSON wie
// agentproto.Snapshot).
type HostMetrics struct {
	Memory struct {
		Total     uint64 `json:"gesamt"`
		Available uint64 `json:"verfuegbar"`
	} `json:"speicher"`
	Disks []struct {
		Mount  string `json:"einhaengepunkt"`
		FSType string `json:"dateisystem"`
		Total  uint64 `json:"gesamt"`
		Free   uint64 `json:"frei"`
	} `json:"platten"`
	// FullDays: Tage bis voll laut Prognose, nur für steigende Platten
	// (Einhängepunkt → Tage); nicht Teil des Snapshots.
	FullDays map[string]int `json:"-"`
	// CPU15: mittlere CPU-Auslastung der letzten 15 Minuten in Prozent; nil,
	// solange die Werte nicht weit genug zurückreichen.
	CPU15 *float64 `json:"cpu15"`
	// Collector: nur wenn dem Agent als Sammler Geräte zugewiesen sind
	// (agent_alarm_metrics, Migration 0018).
	Collector *CollectorMetrics `json:"sammler"`
}

// CollectorMetrics: Zustand eines Agents als Sammler.
type CollectorMetrics struct {
	Devices int  `json:"geraete"` // zugewiesene, eingeschaltete SNMP-Quellen
	On      bool `json:"aktiv"`   // lokal freigegeben (sammler -netze)
	// FetchedAgoS: seit dem letzten Abruf der Geräteliste; nil = nie
	FetchedAgoS *float64 `json:"abgeholt_vor_s"`
}

// Down: Grund, warum der Sammler gerade nicht abfragt; "" = er fragt ab.
func (c *CollectorMetrics) Down(silentAfter time.Duration) string {
	switch {
	case c == nil || c.Devices == 0:
		return ""
	case !c.On:
		return "lokal ausgeschaltet"
	case c.FetchedAgoS == nil:
		return "hat die Geräteliste noch nie abgeholt"
	case time.Duration(*c.FetchedAgoS*float64(time.Second)) >= silentAfter:
		return "holt seit " + since(time.Duration(*c.FetchedAgoS*float64(time.Second))) + " keine Geräteliste ab"
	}
	return ""
}

func devicesText(n int) string {
	if n == 1 {
		return "1 Gerät"
	}
	return fmt.Sprintf("%d Geräte", n)
}

// Netzwerkfreigaben alarmieren nicht: Sie gehören dem Server, der sie
// bereitstellt, und würden sonst von jedem Host gemeldet, der sie eingehängt hat.
var networkFS = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "ceph": true, "glusterfs": true}

// NetworkFS meldet, ob ein Dateisystem eine Netzwerkfreigabe ist. Der Verlauf
// lässt sie aus demselben Grund weg.
func NetworkFS(fsType string) bool { return networkFS[strings.ToLower(fsType)] }

// HostInput beschreibt einen Agent für einen Durchlauf.
type HostInput struct {
	Hostname string
	Revoked  bool
	Silent   time.Duration // seit der letzten Meldung
	// Warming: Die Zentrale läuft noch keine SilentAfter lang. Ein Agent,
	// der länger schweigt, wird dann nicht bewertet: Er hatte womöglich nur
	// keine Zentrale, bei der er sich melden konnte.
	Warming bool
	Metrics *HostMetrics // nil = keine Messwerte
}

// Finding ist ein bewerteter Gegenstand.
type Finding struct {
	Subject, Name, Status, Message string
}

// EvaluateHost bewertet einen Agent für einen Kanal. prev enthält die an
// diesen Kanal gemeldeten Probleme (Gegenstand → Zustand). Geliefert werden
// alle bewerteten Gegenstände, auch die mit OK; was gemeldet wird, entscheidet
// danach Decide. Gegenstände, die nicht mehr vorkommen (z. B. ausgehängte
// Platte), kommen als OK zurück, damit das Problem entwarnt wird.
func EvaluateHost(in HostInput, prev map[string]string, lim HostLimits) []Finding {
	var out []Finding
	if in.Revoked {
		for _, sub := range sortedKeys(prev) {
			out = append(out, Finding{sub, subjectName(in.Hostname, sub), OK, "Agent gesperrt, wird nicht mehr überwacht"})
		}
		return out
	}
	if in.Silent >= lim.SilentAfter {
		if in.Warming {
			return nil
		}
		// Die Messwerte sind veraltet: weder melden noch entwarnen.
		msg := "meldet sich nicht, " + since(in.Silent)
		if m := in.Metrics; m != nil && m.Collector != nil && m.Collector.Devices > 0 {
			msg += "; als Sammler fallen " + devicesText(m.Collector.Devices) + " aus"
		}
		return []Finding{{SubjectSilent, in.Hostname, Crit, msg}}
	}
	out = append(out, Finding{SubjectSilent, in.Hostname, OK, "meldet sich wieder"})
	if in.Metrics == nil {
		return out
	}
	seen := map[string]bool{SubjectSilent: true}
	m := in.Metrics
	if c := m.Collector; c != nil && c.Devices > 0 {
		// Ein Alarm für alle Geräte des Sammlers (Entscheidung, 20.11.2026); die
		// Geräte selbst werden grau und alarmieren nicht.
		seen[SubjectCollector] = true
		if why := c.Down(lim.SilentAfter); why != "" {
			out = append(out, Finding{SubjectCollector, subjectName(in.Hostname, SubjectCollector), Crit,
				"Sammler " + why + ", " + devicesText(c.Devices) + " ohne Abfrage"})
		} else {
			out = append(out, Finding{SubjectCollector, subjectName(in.Hostname, SubjectCollector), OK,
				"sammelt für " + devicesText(c.Devices)})
		}
	}
	if m.Memory.Total > 0 && m.Memory.Available <= m.Memory.Total && (lim.MemWarn > 0 || lim.MemCrit > 0) {
		pct := percentUsed(m.Memory.Total, m.Memory.Available)
		st := Level(pct, lim.MemWarn, lim.MemCrit, prev[SubjectMemory])
		out = append(out, Finding{SubjectMemory, subjectName(in.Hostname, SubjectMemory), st,
			usage(pct, "belegt", st, lim.MemWarn, lim.MemCrit)})
		seen[SubjectMemory] = true
	}
	if c := m.CPU15; c != nil && *c >= 0 && *c <= 100 && (lim.CPUWarn > 0 || lim.CPUCrit > 0) {
		st := Level(*c, lim.CPUWarn, lim.CPUCrit, prev[SubjectCPU])
		out = append(out, Finding{SubjectCPU, subjectName(in.Hostname, SubjectCPU), st,
			usage(*c, "ausgelastet, Mittel 15 Min.", st, lim.CPUWarn, lim.CPUCrit)})
		seen[SubjectCPU] = true
	}
	if lim.DiskWarn > 0 || lim.DiskCrit > 0 || lim.DiskDays > 0 {
		for _, d := range m.Disks {
			sub := diskPrefix + d.Mount
			if d.Mount == "" || d.Total == 0 || d.Free > d.Total || networkFS[strings.ToLower(d.FSType)] || seen[sub] {
				continue
			}
			pct := percentUsed(d.Total, d.Free)
			st := Level(pct, lim.DiskWarn, lim.DiskCrit, prev[sub])
			msg := usage(pct, "belegt", st, lim.DiskWarn, lim.DiskCrit)
			if days, ok := m.FullDays[d.Mount]; ok && FullSoon(days, lim.DiskDays, prev[sub]) {
				if st == OK {
					st = Warn
				}
				msg += ", " + FullText(days) + fmt.Sprintf(" (Warnung unter %.0f Tagen)", lim.DiskDays)
			}
			out = append(out, Finding{sub, subjectName(in.Hostname, sub), st, msg})
			seen[sub] = true
		}
	}
	for _, sub := range sortedKeys(prev) {
		if !seen[sub] {
			out = append(out, Finding{sub, subjectName(in.Hostname, sub), OK, "wird nicht mehr gemeldet oder überwacht"})
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func subjectName(host, sub string) string {
	switch {
	case sub == SubjectSilent:
		return host
	case sub == SubjectMemory:
		return host + " · Arbeitsspeicher"
	case sub == SubjectCPU:
		return host + " · CPU"
	case sub == SubjectCollector:
		return host + " · Sammler"
	case strings.HasPrefix(sub, diskPrefix):
		return host + " · Platte " + strings.TrimPrefix(sub, diskPrefix)
	}
	return host + " · " + sub
}

func percentUsed(total, free uint64) float64 {
	return float64(total-free) / float64(total) * 100
}

// usage: „92 % belegt (Warnschwelle 90 %)“. Abgerundet, damit eine Entwarnung
// nie die Schwelle selbst anzeigt.
func usage(pct float64, what, status string, warn, crit float64) string {
	s := fmt.Sprintf("%.0f %% %s", math.Floor(pct), what)
	switch status {
	case Crit:
		s += fmt.Sprintf(" (kritisch ab %.0f %%)", crit)
	case Warn:
		s += fmt.Sprintf(" (Warnung ab %.0f %%)", warn)
	}
	return s
}

// since: „seit 4 Min.“, „seit 3 Std. 10 Min.“, „seit 2 Tagen“.
func since(d time.Duration) string {
	m := int(d / time.Minute)
	switch {
	case m < 60:
		return fmt.Sprintf("seit %d Min.", max(m, 1))
	case m < 48*60:
		if m%60 == 0 {
			return fmt.Sprintf("seit %d Std.", m/60)
		}
		return fmt.Sprintf("seit %d Std. %d Min.", m/60, m%60)
	}
	return fmt.Sprintf("seit %d Tagen", m/(24*60))
}
