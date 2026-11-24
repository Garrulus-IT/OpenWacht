// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Gegenstände eines SNMP-Geräts zusätzlich zu stumm, speicher, cpu, platte:.
const (
	SubjectReboot      = "neustart"
	SubjectSystem      = "system"     // Synology: System, Netzteil, Lüfter
	SubjectTemperature = "temperatur" // Synology: Systemtemperatur
	SubjectUPS         = "usv"
	SubjectWAN         = "wan" // FRITZ!Box: Internetverbindung
	ifPrefix           = "if:"
	drivePrefix        = "laufwerk:"
	raidPrefix         = "raid:"
	supplyPrefix       = "toner:"
	// TrapPrefix: Zustand einer Trap-Regel, "trap:<Regel>" oder "trap:<Regel>:<Instanz>"
	TrapPrefix = "trap:"
)

// TrapState ist ein aktueller Zustand aus einer Trap-Regel (Migration 0017,
// snmp_trap_states_json).
type TrapState struct {
	Rule      string     `json:"regel"`
	Name      string     `json:"name"`
	Instance  string     `json:"instanz"`
	Status    string     `json:"status"` // warn, crit
	Message   string     `json:"meldung"`
	Authentic bool       `json:"bestaetigt"`
	Since     time.Time  `json:"seit"`
	Last      time.Time  `json:"zuletzt"`
	Hits      int        `json:"anzahl"`
	Until     *time.Time `json:"bis"`
}

// Subject: Gegenstand des Zustands.
func (t TrapState) Subject() string {
	if t.Instance == "" {
		return TrapPrefix + t.Rule
	}
	return TrapPrefix + t.Rule + ":" + t.Instance
}

// Label: Anzeigename ohne Gerät („Port getrennt (5)“).
func (t TrapState) Label() string {
	if t.Instance == "" {
		return t.Name
	}
	return t.Name + " (" + t.Instance + ")"
}

// Feste Schwellen für SNMP-Werte (einstellbar erst später, wie die übrigen).
const (
	// RebootWindow: So lange nach einem erkannten Neustart steht eine Warnung.
	RebootWindow     = 15 * time.Minute
	SystemTempWarn   = 65.0
	SystemTempCrit   = 75.0
	DriveTempWarn    = 55.0
	DriveTempCrit    = 60.0
	SupplyWarnBelow  = 10.0 // Prozent Restmenge
	SupplyCritBelow  = 2.0
	UPSChargeWarnPct = 50.0 // nur im Batteriebetrieb
)

// SNMPInput beschreibt ein SNMP-Gerät für einen Durchlauf.
type SNMPInput struct {
	Name     string // Gerätename
	Disabled bool   // Abfrage ausgeschaltet oder entfernt: alles entwarnen
	// Silent: seit der letzten erfolgreichen Abfrage; SilentAfter wie beim
	// Agent, aber mindestens drei Abfrageintervalle.
	Silent    time.Duration
	Interval  time.Duration
	Warming   bool
	LastError string
	Snapshot  *snmp.Snapshot
	CPU15     *float64
	// RebootedAgo: seit dem zuletzt erkannten Neustart; nil = keiner bekannt
	RebootedAgo *time.Duration
	// Watched: überwachte Schnittstellen (Namen)
	Watched []string
	// Excluded: ausgenommene Gegenstände (0.99.2) → Begründung (darf leer
	// sein). Sie gelten als OK, damit ein offener Alarm endet; „stumm“ lässt
	// sich nicht ausnehmen.
	Excluded map[string]string
	// Proxmox: Quelle ist ein Proxmox-Host (Texte „Proxmox-API“ statt SNMP)
	Proxmox bool
	// FritzBox: Quelle ist eine FRITZ!Box (Texte „TR-064“ statt SNMP)
	FritzBox bool
	// ONTAP: Quelle ist ein NetApp-Cluster (Texte „ONTAP-API“ statt SNMP)
	ONTAP bool
	// XAPI: Quelle ist ein XenServer-Pool (Texte „XAPI“ statt SNMP)
	XAPI bool
	// Now: Zeitpunkt der Bewertung (Alter der Backups); Null = jetzt
	Now time.Time
	// FullDays: Tage bis voll laut Prognose je Platte (nur steigende)
	FullDays map[string]int
	// Traps: aktuelle Zustände aus Trap-Regeln (abgelaufene sind schon weg)
	Traps []TrapState
	// CollectorDown: Die Quelle fragt ein Sammler ab, der gerade ausfällt
	// (Grund, z. B. „pve-1: meldet sich nicht“). Dann wird nichts bewertet:
	// Den Ausfall meldet ein einziger Alarm am Sammler (Etappe 15).
	CollectorDown string
}

// SilentLimit: ab wann ein SNMP-Gerät als stumm gilt.
func SilentLimit(lim HostLimits, interval time.Duration) time.Duration {
	return max(lim.SilentAfter, 3*interval)
}

// ExcludedMessage: Meldung eines ausgenommenen Gegenstands.
func ExcludedMessage(reason string) string {
	if reason == "" {
		return "ausgenommen"
	}
	return Clean("ausgenommen: "+reason, 300)
}

// EvaluateSNMP bewertet ein SNMP-Gerät für einen Empfänger, wie EvaluateHost.
// Ausgenommene Gegenstände (in.Excluded) kommen als OK zurück.
func EvaluateSNMP(in SNMPInput, prev map[string]string, lim HostLimits) []Finding {
	out := evaluateSNMP(in, prev, lim)
	if len(in.Excluded) == 0 {
		return out
	}
	for i := range out {
		if reason, ok := in.Excluded[out[i].Subject]; ok && out[i].Subject != SubjectSilent {
			out[i].Status, out[i].Message = OK, ExcludedMessage(reason)
		}
	}
	return out
}

func evaluateSNMP(in SNMPInput, prev map[string]string, lim HostLimits) []Finding {
	var out []Finding
	if in.Disabled {
		off := "SNMP-Abfrage ausgeschaltet"
		if in.Proxmox {
			off = "Proxmox-Abfrage ausgeschaltet"
		}
		if in.FritzBox {
			off = "FRITZ!Box-Abfrage ausgeschaltet"
		}
		if in.ONTAP {
			off = "NetApp-Abfrage ausgeschaltet"
		}
		if in.XAPI {
			off = "XenServer-Abfrage ausgeschaltet"
		}
		for _, sub := range sortedKeys(prev) {
			out = append(out, Finding{sub, snmpSubjectName(in.Name, sub), OK, off})
		}
		return out
	}
	if in.CollectorDown != "" {
		// weder melden noch entwarnen, wie bei einem stummen Agent
		return nil
	}
	silentAfter := SilentLimit(lim, in.Interval)
	if in.Silent >= silentAfter {
		if in.Warming {
			return nil
		}
		msg := "antwortet nicht auf SNMP, " + since(in.Silent)
		if in.Proxmox {
			msg = "antwortet nicht (Proxmox-API), " + since(in.Silent)
		}
		if in.FritzBox {
			msg = "antwortet nicht (TR-064), " + since(in.Silent)
		}
		if in.ONTAP {
			msg = "antwortet nicht (ONTAP-API), " + since(in.Silent)
		}
		if in.XAPI {
			msg = "antwortet nicht (XAPI), " + since(in.Silent)
		}
		if in.LastError != "" {
			msg += ": " + in.LastError
		}
		return []Finding{{SubjectSilent, in.Name, Crit, Clean(msg, 300)}}
	}
	out = append(out, Finding{SubjectSilent, in.Name, OK, "antwortet wieder"})
	seen := map[string]bool{SubjectSilent: true}
	// Trap-Zustände: unabhängig von der Abfrage; was fehlt, ist beendet
	// (Entwarnung, abgelaufen oder von Hand zurückgesetzt) und wird unten
	// als „nicht mehr gemeldet“ entwarnt.
	for _, t := range in.Traps {
		sub := t.Subject()
		if seen[sub] || (t.Status != Warn && t.Status != Crit) || !SNMPSubject(sub) {
			continue
		}
		seen[sub] = true
		out = append(out, Finding{sub, in.Name + " · " + Clean(t.Label(), 120), t.Status, Clean(t.Message, 300)})
	}
	s := in.Snapshot
	if s == nil {
		return appendGone(out, in.Name, prev, seen)
	}

	// Speicher, CPU und Platten wie beim Agent.
	hm := &HostMetrics{CPU15: in.CPU15, FullDays: in.FullDays}
	if s.Memory != nil {
		hm.Memory.Total, hm.Memory.Available = s.Memory.TotalBytes, s.Memory.AvailableBytes
	}
	for _, d := range s.Disks {
		hm.Disks = append(hm.Disks, struct {
			Mount  string `json:"einhaengepunkt"`
			FSType string `json:"dateisystem"`
			Total  uint64 `json:"gesamt"`
			Free   uint64 `json:"frei"`
		}{d.Mount, d.FSType, d.TotalBytes, d.FreeBytes})
	}
	hostPrev := map[string]string{}
	for k, v := range prev {
		if k == SubjectMemory || k == SubjectCPU || strings.HasPrefix(k, diskPrefix) {
			hostPrev[k] = v
		}
	}
	for _, f := range EvaluateHost(HostInput{Hostname: in.Name, Metrics: hm}, hostPrev, lim) {
		if f.Subject == SubjectSilent {
			continue
		}
		seen[f.Subject] = true
		if in.Proxmox && strings.HasPrefix(f.Subject, diskPrefix) {
			f.Name = in.Name + " · Speicher " + strings.TrimPrefix(f.Subject, diskPrefix)
		}
		if (in.ONTAP || in.XAPI) && strings.HasPrefix(f.Subject, diskPrefix) {
			// „Aggregat aggr1“, „Volume svm1/daten“, „SR NFS VM-Speicher“
			f.Name = in.Name + " · " + strings.TrimPrefix(f.Subject, diskPrefix)
		}
		out = append(out, f)
	}

	add := func(sub, status, msg string) {
		if seen[sub] {
			return
		}
		seen[sub] = true
		out = append(out, Finding{sub, snmpSubjectName(in.Name, sub), status, Clean(msg, 300)})
	}

	if in.RebootedAgo != nil && *in.RebootedAgo >= 0 && *in.RebootedAgo < RebootWindow {
		add(SubjectReboot, Warn, "neu gestartet, "+since(*in.RebootedAgo))
	} else if prev[SubjectReboot] != "" {
		add(SubjectReboot, OK, "läuft wieder normal")
	}

	ifs := map[string]snmp.Interface{}
	for _, it := range s.Interfaces {
		if _, dup := ifs[it.Name]; !dup {
			ifs[it.Name] = it
		}
	}
	for _, name := range in.Watched {
		it, ok := ifs[name]
		switch {
		case !ok:
			if len(s.Interfaces) > 0 && !contains(s.Truncated, "Schnittstellen") && !contains(s.Partial, "Schnittstellen") {
				add(ifPrefix+name, Crit, "Schnittstelle fehlt")
			}
		case !it.AdminUp:
			add(ifPrefix+name, Warn, "administrativ abgeschaltet")
		case it.Oper == "up":
			add(ifPrefix+name, OK, "verbunden"+speedText(it.SpeedBps))
		case it.Oper == "dormant":
			add(ifPrefix+name, OK, "bereit (dormant)")
		default:
			add(ifPrefix+name, Crit, "nicht verbunden ("+it.Oper+")")
		}
	}

	if syn := s.Synology; syn != nil {
		var bad []string
		if syn.SystemStatus == 2 {
			bad = append(bad, "System ausgefallen")
		}
		if syn.PowerStatus == 2 {
			bad = append(bad, "Netzteil ausgefallen")
		}
		if syn.SystemFan == 2 {
			bad = append(bad, "Systemlüfter ausgefallen")
		}
		if syn.CPUFan == 2 {
			bad = append(bad, "CPU-Lüfter ausgefallen")
		}
		if len(bad) > 0 {
			add(SubjectSystem, Crit, strings.Join(bad, ", "))
		} else {
			add(SubjectSystem, OK, "System, Netzteil und Lüfter normal")
		}
		if t := syn.Temperature; t != nil {
			st := Level(float64(*t), SystemTempWarn, SystemTempCrit, prev[SubjectTemperature])
			add(SubjectTemperature, st, tempText(*t, st, SystemTempWarn, SystemTempCrit))
		}
		for _, d := range syn.Disks {
			st, msg := driveState(d, prev[drivePrefix+d.Name])
			add(drivePrefix+d.Name, st, msg)
		}
		for _, r := range syn.Raids {
			st, msg := raidState(r.Status)
			add(raidPrefix+r.Name, st, msg)
		}
	}

	if u := s.UPS; u != nil {
		st, msg := upsState(u)
		add(SubjectUPS, st, msg)
	}

	for _, sp := range s.Supplies {
		if sp.Percent == nil {
			continue
		}
		p := *sp.Percent
		sub := supplyPrefix + sp.Name
		st := OK
		switch prevSt := prev[sub]; {
		case p <= SupplyCritBelow || prevSt == Crit && p <= SupplyCritBelow+Hysteresis:
			st = Crit
		case p <= SupplyWarnBelow || (prevSt == Warn || prevSt == Crit) && p <= SupplyWarnBelow+Hysteresis:
			st = Warn
		}
		msg := fmt.Sprintf("%.0f %% übrig", math.Floor(p))
		if st == Warn {
			msg += fmt.Sprintf(" (Warnung ab %.0f %%)", SupplyWarnBelow)
		} else if st == Crit {
			msg += fmt.Sprintf(" (kritisch ab %.0f %%)", SupplyCritBelow)
		}
		add(sub, st, msg)
	}

	if fb := s.FritzBox; fb != nil && fb.Connection != "" {
		st, msg := wanState(fb)
		add(SubjectWAN, st, msg)
	}

	if o := s.ONTAP; o != nil {
		evaluateONTAP(in.Name, o, s.Partial, prev, func(sub, name, status, msg string) {
			if seen[sub] {
				return
			}
			seen[sub] = true
			out = append(out, Finding{sub, name, status, Clean(msg, 300)})
		})
	}

	if x := s.XAPI; x != nil {
		evaluateXAPI(in.Name, x, s.Partial, prev, lim, func(sub, name, status, msg string) {
			if seen[sub] {
				return
			}
			seen[sub] = true
			out = append(out, Finding{sub, name, status, Clean(msg, 300)})
		})
	}

	if px := s.Proxmox; px != nil {
		now := in.Now
		if now.IsZero() {
			now = time.Now()
		}
		evaluateProxmox(in.Name, px, now, prev, func(sub, name, status, msg string) {
			if seen[sub] {
				return
			}
			seen[sub] = true
			out = append(out, Finding{sub, name, status, Clean(msg, 300)})
		})
	}
	return appendGone(out, in.Name, prev, seen)
}

// wanState: Internetverbindung einer FRITZ!Box. Getrennt ist ein Fehler; wird
// sie gerade (neu) aufgebaut, etwa bei der nächtlichen Zwangstrennung, nur
// eine Warnung.
func wanState(fb *snmp.FritzBox) (string, string) {
	if fb.Connected {
		return OK, "Internet verbunden"
	}
	why := ""
	if e := fb.LastError; e != "" && e != "ERROR_NONE" {
		why = ", letzter Fehler " + e
	}
	switch fb.Connection {
	case "Connecting", "Authenticating", "PendingDisconnect", "Disconnecting":
		return Warn, "Internetverbindung wird auf- oder abgebaut (" + fb.Connection + ")" + why
	}
	return Crit, "Internet getrennt (" + fb.Connection + ")" + why
}

func appendGone(out []Finding, name string, prev map[string]string, seen map[string]bool) []Finding {
	for _, sub := range sortedKeys(prev) {
		if !seen[sub] {
			out = append(out, Finding{sub, snmpSubjectName(name, sub), OK, "wird nicht mehr gemeldet oder überwacht"})
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func speedText(bps uint64) string {
	switch {
	case bps == 0:
		return ""
	case bps >= 1_000_000_000 && bps%1_000_000_000 == 0:
		return fmt.Sprintf(", %d Gbit/s", bps/1_000_000_000)
	case bps >= 1_000_000:
		return fmt.Sprintf(", %d Mbit/s", bps/1_000_000)
	}
	return fmt.Sprintf(", %d bit/s", bps)
}

func tempText(t int, st string, warn, crit float64) string {
	s := fmt.Sprintf("%d °C", t)
	switch st {
	case Crit:
		s += fmt.Sprintf(" (kritisch ab %.0f °C)", crit)
	case Warn:
		s += fmt.Sprintf(" (Warnung ab %.0f °C)", warn)
	}
	return s
}

// driveState: Status, Gesundheit und Temperatur eines Laufwerks, das
// Schlimmste zählt.
func driveState(d snmp.SynoDisk, prev string) (string, string) {
	st, msgs := OK, []string{}
	worse := func(s, m string) {
		if rank[s] > rank[st] {
			st = s
		}
		msgs = append(msgs, m)
	}
	switch d.Status {
	case 1, 2:
		// normal bzw. initialisiert (Systempartition vorhanden)
	case 3:
		worse(Warn, "nicht initialisiert")
	case 4:
		worse(Crit, "Systempartition fehlerhaft")
	case 5:
		worse(Crit, "Laufwerk defekt")
	case 6:
		worse(Crit, "getrennt")
	default:
		worse(Unknown, fmt.Sprintf("Status %d unbekannt", d.Status))
	}
	switch d.Health {
	case 2:
		worse(Warn, "Gesundheit: Warnung")
	case 3:
		worse(Crit, "Gesundheit: kritisch")
	case 4:
		worse(Crit, "Gesundheit: fällt aus")
	}
	if t := d.Temperature; t != nil {
		// Hysterese nur aus dem Temperaturteil ableiten, wenn der Rest OK ist.
		p := prev
		if st != OK {
			p = ""
		}
		ts := Level(float64(*t), DriveTempWarn, DriveTempCrit, p)
		if ts != OK {
			worse(ts, tempText(*t, ts, DriveTempWarn, DriveTempCrit))
		} else if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("normal, %d °C", *t))
		}
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "normal")
	}
	return st, strings.Join(msgs, ", ")
}

// raidState nach SYNOLOGY-RAID-MIB. Regelmäßige Arbeiten (Synchronisieren,
// Paritätsprüfung, Datenbereinigung) sind kein Problem: Die
// Datenbereinigung läuft z. B. monatlich und würde sonst jedes Mal melden.
func raidState(n int) (string, string) {
	switch n {
	case 1:
		return OK, "normal"
	case 7:
		return OK, "wird synchronisiert"
	case 8:
		return OK, "Paritätsprüfung läuft"
	case 13:
		return OK, "Datenbereinigung läuft"
	case 2:
		return Warn, "wird repariert"
	case 3, 20:
		return Warn, "wird migriert"
	case 4, 18:
		return Warn, "wird erweitert"
	case 5:
		return Warn, "wird gelöscht"
	case 6:
		return Warn, "wird erstellt"
	case 9:
		return Warn, "wird zusammengesetzt"
	case 10:
		return Warn, "Vorgang wird abgebrochen"
	case 14, 15, 16, 17, 19:
		return Warn, fmt.Sprintf("Umbau läuft (Status %d)", n)
	case 11:
		return Crit, "beeinträchtigt (degraded)"
	case 12:
		return Crit, "abgestürzt (crashed)"
	}
	return Unknown, fmt.Sprintf("Status %d unbekannt", n)
}

func upsState(u *snmp.UPS) (string, string) {
	var parts []string
	st := OK
	switch {
	case u.LowBattery:
		st = Crit
		parts = append(parts, "Batterie schwach")
	case u.OnBattery:
		st = Warn
		parts = append(parts, "Batteriebetrieb")
	}
	if u.Replace {
		if st == OK {
			st = Warn
		}
		parts = append(parts, "Batterie tauschen")
	}
	if u.OnBattery && u.ChargePct != nil && *u.ChargePct < UPSChargeWarnPct && st == Warn {
		st = Crit
	}
	if len(parts) == 0 {
		parts = append(parts, "Netzbetrieb")
	}
	if u.ChargePct != nil {
		parts = append(parts, fmt.Sprintf("Ladung %.0f %%", math.Floor(*u.ChargePct)))
	}
	if u.RuntimeS != nil && u.OnBattery {
		parts = append(parts, fmt.Sprintf("Restlaufzeit %.0f Min.", *u.RuntimeS/60))
	}
	return st, strings.Join(parts, ", ")
}

func snmpSubjectName(host, sub string) string {
	if n, ok := proxmoxSubjectName(host, sub); ok {
		return n
	}
	if n, ok := ontapSubjectName(host, sub); ok {
		return n
	}
	if n, ok := xapiSubjectName(host, sub); ok {
		return n
	}
	switch {
	case sub == SubjectReboot:
		return host + " · Neustart"
	case sub == SubjectSystem:
		return host + " · System"
	case sub == SubjectTemperature:
		return host + " · Temperatur"
	case sub == SubjectUPS:
		return host + " · USV"
	case sub == SubjectWAN:
		return host + " · Internet"
	case strings.HasPrefix(sub, ifPrefix):
		return host + " · Schnittstelle " + strings.TrimPrefix(sub, ifPrefix)
	case strings.HasPrefix(sub, drivePrefix):
		return host + " · Laufwerk " + strings.TrimPrefix(sub, drivePrefix)
	case strings.HasPrefix(sub, raidPrefix):
		return host + " · " + strings.TrimPrefix(sub, raidPrefix)
	case strings.HasPrefix(sub, supplyPrefix):
		return host + " · " + strings.TrimPrefix(sub, supplyPrefix)
	case strings.HasPrefix(sub, TrapPrefix):
		return host + " · Trap"
	}
	return subjectName(host, sub)
}

// SensorName: Anzeigename eines Gegenstands ohne Gerätenamen (Übersicht).
func SensorName(sub string) string {
	switch {
	case sub == SubjectSilent:
		return "Erreichbarkeit"
	case sub == SubjectMemory:
		return "Arbeitsspeicher"
	case sub == SubjectCPU:
		return "CPU"
	case strings.HasPrefix(sub, diskPrefix):
		return "Platte " + strings.TrimPrefix(sub, diskPrefix)
	}
	n := snmpSubjectName("", sub)
	return strings.TrimPrefix(n, " · ")
}

// SNMPSubject: gültiger Gegenstand eines SNMP-Geräts (wie der CHECK in der
// Datenbank).
func SNMPSubject(sub string) bool {
	switch sub {
	case SubjectSilent, SubjectMemory, SubjectCPU, SubjectReboot, SubjectSystem, SubjectTemperature, SubjectUPS, SubjectWAN, SubjectDisks,
		SubjectXenHA, SubjectXenUpdates:
		return true
	}
	for _, p := range []string{diskPrefix, ifPrefix, drivePrefix, raidPrefix, supplyPrefix, metaPrefix, storagePrefix,
		nodePrefix, aggrPrefix, volumePrefix, shelfPrefix, mirrorPrefix, emsPrefix,
		xenHostPrefix, xenCPUPrefix, xenRAMPrefix, xenVMPrefix, xenSRPrefix} {
		if strings.HasPrefix(sub, p) && len(sub) > len(p) {
			return true
		}
	}
	if rest, ok := strings.CutPrefix(sub, TrapPrefix); ok {
		id, inst, hasInst := strings.Cut(rest, ":")
		return len(sub) <= 300 && uuidLike(id) && (!hasInst || inst != "") && !strings.ContainsFunc(sub, unicodeControl)
	}
	for _, p := range []string{guestPrefix, backupPrefix} {
		if id, ok := strings.CutPrefix(sub, p); ok && len(id) >= 3 && len(id) <= 9 && id[0] != '0' &&
			strings.Trim(id, "0123456789") == "" {
			return true
		}
	}
	return false
}

// uuidLike: 8-4-4-4-12 Hexziffern in Kleinbuchstaben (wie die Datenbank).
func uuidLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

func unicodeControl(r rune) bool { return r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 }
