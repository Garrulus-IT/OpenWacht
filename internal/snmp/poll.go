// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/safe"
)

// Snapshot ist das Ergebnis einer Abfrage, gespeichert als JSON. Feldnamen
// wie beim Agent, damit Alarme und Oberfläche Speicher und Platten gleich
// behandeln. Datensparsam: sysContact (oft Name und Mail einer Person) wird
// nicht gelesen.
type Snapshot struct {
	CollectedAt time.Time    `json:"erfasst"`
	System      System       `json:"system"`
	CPU         *CPU         `json:"cpu,omitempty"`
	Memory      *Memory      `json:"speicher,omitempty"`
	Disks       []Disk       `json:"platten"`
	Interfaces  []Interface  `json:"schnittstellen"`
	Synology    *Synology    `json:"synology,omitempty"`
	UPS         *UPS         `json:"usv,omitempty"`
	Supplies    []Supply     `json:"verbrauchsmaterial"`
	Truncated   []string     `json:"gekuerzt,omitempty"`  // Tabellen, die über der Grenze lagen
	Partial     []string     `json:"teilweise,omitempty"` // Teile, deren Abfrage scheiterte
	Counters    *CounterInfo `json:"zaehler,omitempty"`
	Proxmox     *Proxmox     `json:"proxmox,omitempty"`
	FritzBox    *FritzBox    `json:"fritzbox,omitempty"`
	ONTAP       *ONTAP       `json:"ontap,omitempty"`
	XAPI        *XAPI        `json:"xapi,omitempty"`
	Citrix      *Citrix      `json:"citrix,omitempty"`
	// Eigene OIDs (Etappe 18b), Texte nur als Hash
	Extra []ExtraValue `json:"eigene,omitempty"`
	// Eigene Spalten (0.47.0), nur Kennzahlen ohne Indizes
	Columns []ColumnValue `json:"spalten,omitempty"`
}

type System struct {
	Descr    string `json:"beschreibung"`
	Name     string `json:"name"`
	Location string `json:"standort"`
	ObjectID string `json:"objekt_id"`
	// Laufzeit des SNMP-Agents in Hundertstelsekunden (32 Bit, läuft nach
	// 497 Tagen über) und in Sekunden
	UptimeTicks uint32 `json:"laufzeit_ticks"`
	UptimeS     uint64 `json:"laufzeit_s"`
	// HostUptimeTicks: Laufzeit des Rechners (hrSystemUptime, 1.0.6) in
	// Hundertstelsekunden; 0 = nicht geliefert. sysUpTime zählt nur den
	// SNMP-Dienst und springt auch zurück, wenn nur er neu startet.
	HostUptimeTicks uint32 `json:"rechner_laufzeit_ticks,omitempty"`
}

type CPU struct {
	Cores   int     `json:"kerne"`
	Percent float64 `json:"auslastung_prozent"`
}

type Memory struct {
	TotalBytes     uint64 `json:"gesamt"`
	AvailableBytes uint64 `json:"verfuegbar"`
}

type Disk struct {
	Mount      string `json:"einhaengepunkt"`
	FSType     string `json:"dateisystem"`
	TotalBytes uint64 `json:"gesamt"`
	FreeBytes  uint64 `json:"frei"`
}

// Interface: eine Schnittstelle aus IF-MIB. Raten in Bit/s seit der letzten
// Abfrage; nil, wenn sich keine Rate bilden ließ (erste Abfrage, Neustart,
// Zähler zurückgesetzt, unplausibel).
type Interface struct {
	Index     int      `json:"index"`
	Name      string   `json:"name"`
	Alias     string   `json:"alias,omitempty"`
	Type      int      `json:"typ"`
	SpeedBps  uint64   `json:"geschwindigkeit_bps"`
	AdminUp   bool     `json:"admin_an"`
	Oper      string   `json:"status"` // up | down | testing | unknown | dormant | notPresent | lowerLayerDown
	InOctets  uint64   `json:"ein_oktette"`
	OutOctets uint64   `json:"aus_oktette"`
	HC        bool     `json:"hc"` // 64-Bit-Zähler
	InErrors  uint64   `json:"ein_fehler"`
	OutErrors uint64   `json:"aus_fehler"`
	InBps     *float64 `json:"ein_bps"`
	OutBps    *float64 `json:"aus_bps"`
	// neue Fehler seit der letzten Abfrage
	NewErrors *uint64 `json:"fehler_neu"`
}

type Synology struct {
	Model        string     `json:"modell"`
	Version      string     `json:"version"`
	SystemStatus int        `json:"system"`   // 1 normal, 2 ausgefallen
	PowerStatus  int        `json:"netzteil"` // 1 normal, 2 ausgefallen
	SystemFan    int        `json:"luefter_system"`
	CPUFan       int        `json:"luefter_cpu"`
	Temperature  *int       `json:"temperatur"`
	Disks        []SynoDisk `json:"laufwerke"`
	Raids        []SynoRaid `json:"raids"`
	Upgrade      int        `json:"update"` // 1 verfügbar, 2 nicht verfügbar, …
}

type SynoDisk struct {
	Name        string `json:"name"`
	Model       string `json:"modell"`
	Status      int    `json:"status"`
	Health      int    `json:"gesundheit"` // 0 = nicht gemeldet
	Temperature *int   `json:"temperatur"`
	Role        string `json:"rolle,omitempty"`
}

type SynoRaid struct {
	Name       string `json:"name"`
	Status     int    `json:"status"`
	FreeBytes  uint64 `json:"frei"`
	TotalBytes uint64 `json:"gesamt"`
}

// UPS: aus der UPS-MIB (RFC 1628, USV mit Netzwerkkarte) oder aus der
// Synology-UPS-MIB (USV per USB am NAS).
type UPS struct {
	Source     string   `json:"quelle"` // rfc1628 | synology
	Model      string   `json:"modell,omitempty"`
	Status     string   `json:"status"` // Text der USV, z. B. „OL“, „OB LB“
	OnBattery  bool     `json:"batteriebetrieb"`
	LowBattery bool     `json:"batterie_schwach"`
	Replace    bool     `json:"batterie_tauschen"`
	ChargePct  *float64 `json:"ladung_prozent"`
	RuntimeS   *float64 `json:"restlaufzeit_s"`
	LoadPct    *float64 `json:"last_prozent"`
}

// Supply: Verbrauchsmaterial eines Druckers (Printer-MIB, RFC 3805).
type Supply struct {
	Name    string   `json:"name"`
	Level   int      `json:"stand"`   // -1 sonstiges, -2 unbekannt, -3 etwas vorhanden
	Max     int      `json:"maximum"` // -1, -2 wie oben
	Percent *float64 `json:"prozent"`
}

// CounterInfo: wann die Zähler gelesen wurden (für die Raten der nächsten
// Abfrage).
type CounterInfo struct {
	At          time.Time `json:"zeit"`
	UptimeTicks uint32    `json:"laufzeit_ticks"`
}

// OIDs (ohne führenden Punkt).
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
	oidHrSysUptime = "1.3.6.1.2.1.25.1.1.0"

	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfType        = "1.3.6.1.2.1.2.2.1.3"
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	oidIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfInOctets    = "1.3.6.1.2.1.2.2.1.10"
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias       = "1.3.6.1.2.1.31.1.1.1.18"

	oidHrStorageType  = "1.3.6.1.2.1.25.2.3.1.2"
	oidHrStorageDescr = "1.3.6.1.2.1.25.2.3.1.3"
	oidHrStorageUnits = "1.3.6.1.2.1.25.2.3.1.4"
	oidHrStorageSize  = "1.3.6.1.2.1.25.2.3.1.5"
	oidHrStorageUsed  = "1.3.6.1.2.1.25.2.3.1.6"
	oidHrProcLoad     = "1.3.6.1.2.1.25.3.3.1.2"

	hrStorageRAM       = "1.3.6.1.2.1.25.2.1.2"
	hrStorageFixedDisk = "1.3.6.1.2.1.25.2.1.4"

	// UCD-SNMP-MIB (Net-SNMP, auch Synology): Speicher in kB
	oidMemTotalReal = "1.3.6.1.4.1.2021.4.5.0"
	oidMemAvailReal = "1.3.6.1.4.1.2021.4.6.0"
	oidMemBuffer    = "1.3.6.1.4.1.2021.4.14.0"
	oidMemCached    = "1.3.6.1.4.1.2021.4.15.0"
	oidSsCPUIdle    = "1.3.6.1.4.1.2021.11.11.0"

	// SYNOLOGY-SYSTEM-MIB, -DISK-MIB, -RAID-MIB, -UPS-MIB (MIB Guide, Stand 2025)
	oidSynoSystemStatus = "1.3.6.1.4.1.6574.1.1.0"
	oidSynoTemperature  = "1.3.6.1.4.1.6574.1.2.0"
	oidSynoPowerStatus  = "1.3.6.1.4.1.6574.1.3.0"
	oidSynoSystemFan    = "1.3.6.1.4.1.6574.1.4.1.0"
	oidSynoCPUFan       = "1.3.6.1.4.1.6574.1.4.2.0"
	oidSynoModel        = "1.3.6.1.4.1.6574.1.5.1.0"
	oidSynoVersion      = "1.3.6.1.4.1.6574.1.5.3.0"
	oidSynoUpgrade      = "1.3.6.1.4.1.6574.1.5.4.0"
	oidSynoDiskID       = "1.3.6.1.4.1.6574.2.1.1.2"
	oidSynoDiskModel    = "1.3.6.1.4.1.6574.2.1.1.3"
	oidSynoDiskStatus   = "1.3.6.1.4.1.6574.2.1.1.5"
	oidSynoDiskTemp     = "1.3.6.1.4.1.6574.2.1.1.6"
	oidSynoDiskRole     = "1.3.6.1.4.1.6574.2.1.1.7"
	oidSynoDiskName     = "1.3.6.1.4.1.6574.2.1.1.12"
	oidSynoDiskHealth   = "1.3.6.1.4.1.6574.2.1.1.13"
	oidSynoRaidName     = "1.3.6.1.4.1.6574.3.1.1.2"
	oidSynoRaidStatus   = "1.3.6.1.4.1.6574.3.1.1.3"
	oidSynoRaidFree     = "1.3.6.1.4.1.6574.3.1.1.4"
	oidSynoRaidTotal    = "1.3.6.1.4.1.6574.3.1.1.5"
	oidSynoUPSModel     = "1.3.6.1.4.1.6574.4.1.1.0"
	oidSynoUPSStatus    = "1.3.6.1.4.1.6574.4.2.1.0"
	oidSynoUPSLoad      = "1.3.6.1.4.1.6574.4.2.12.1.0"
	oidSynoUPSCharge    = "1.3.6.1.4.1.6574.4.3.1.1.0"
	// upsBatteryRuntimeValue: nicht im MIB Guide, aus SYNOLOGY-UPS-MIB (PRÜFEN am Gerät)
	oidSynoUPSRuntime = "1.3.6.1.4.1.6574.4.3.6.1.0"

	// UPS-MIB (RFC 1628)
	oidUpsIdentModel        = "1.3.6.1.2.1.33.1.1.2.0"
	oidUpsBatteryStatus     = "1.3.6.1.2.1.33.1.2.1.0"
	oidUpsMinutesRemaining  = "1.3.6.1.2.1.33.1.2.3.0"
	oidUpsChargeRemaining   = "1.3.6.1.2.1.33.1.2.4.0"
	oidUpsOutputSource      = "1.3.6.1.2.1.33.1.4.1.0"
	oidUpsOutputPercentLoad = "1.3.6.1.2.1.33.1.4.4.1.5.1"

	// Printer-MIB (RFC 3805)
	oidPrtSupplyDescr = "1.3.6.1.2.1.43.11.1.1.6"
	oidPrtSupplyMax   = "1.3.6.1.2.1.43.11.1.1.8"
	oidPrtSupplyLevel = "1.3.6.1.2.1.43.11.1.1.9"
)

// Probe liest nur die Systemdaten (Knopf „Verbindung prüfen“).
func (c *Client) Probe(ctx context.Context, cfg Config) (_ System, err error) {
	defer safe.Recover("snmp", &err)
	ctx, cancel := context.WithTimeout(ctx, c.budget(10*time.Second))
	defer cancel()
	s, err := c.open(ctx, cfg)
	if err != nil {
		return System{}, err
	}
	defer s.close()
	return s.system()
}

func (c *Client) budget(def time.Duration) time.Duration {
	if c.Budget > 0 {
		return c.Budget
	}
	return def
}

func (s *session) system() (System, error) {
	v, err := s.get(oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidSysLocation, oidHrSysUptime)
	if err != nil {
		return System{}, err
	}
	var sys System
	sys.Descr, _ = v[oidSysDescr].text()
	sys.Name, _ = v[oidSysName].text()
	sys.Location, _ = v[oidSysLocation].text()
	sys.ObjectID, _ = v[oidSysObjectID].oid()
	up, _ := v[oidSysUpTime].uint()
	// dieselbe Regel wie ValidateCollected (Sammler): ohne Beschreibung und Namen kein Gerät
	if sys.Descr == "" && sys.Name == "" {
		return System{}, errors.New("das Gerät liefert keine Systemdaten (SNMPv2-MIB)")
	}
	// sysUpTime ist TimeTicks (32 Bit); größere Werte (falscher Typ) gelten als unbekannt
	if up > math.MaxUint32 {
		up = 0
	}
	sys.UptimeTicks = uint32(up)
	sys.UptimeS = up / 100
	if hr, ok := v[oidHrSysUptime].uint(); ok && hr <= math.MaxUint32 {
		sys.HostUptimeTicks = uint32(hr)
	}
	return sys, nil
}

// testPollHook: nur in Tests gesetzt, um eine Panik in der Abfrage auszulösen.
var testPollHook func()

// Poll fragt ein Gerät vollständig ab. prev ist die vorige Abfrage (für die
// Raten der Schnittstellen), darf nil sein. Scheitert nur ein Teil (z. B. eine
// Tabelle läuft in die Zeitgrenze), liefert Poll trotzdem, was da ist, und
// nennt den Teil in Partial. Antwortet das Gerät gar nicht, gibt es einen Fehler.
func (c *Client) Poll(ctx context.Context, cfg Config, prev *Snapshot) (_ *Snapshot, err error) {
	defer safe.Recover("snmp", &err)
	if testPollHook != nil {
		testPollHook()
	}
	ctx, cancel := context.WithTimeout(ctx, c.budget(30*time.Second))
	defer cancel()
	s, err := c.open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer s.close()
	snap := &Snapshot{Disks: []Disk{}, Interfaces: []Interface{}, Supplies: []Supply{}}
	if snap.System, err = s.system(); err != nil {
		return nil, err
	}
	snap.CollectedAt = c.now().UTC()
	snap.Counters = &CounterInfo{At: snap.CollectedAt, UptimeTicks: snap.System.UptimeTicks}

	part := func(name string, err error) {
		if err == nil {
			return
		}
		if errors.Is(err, ErrTooMuch) {
			snap.Truncated = append(snap.Truncated, name)
			return
		}
		snap.Partial = append(snap.Partial, name)
	}
	part("Schnittstellen", s.interfaces(snap))
	part("Speicher", s.storage(snap))
	part("CPU", s.cpu(snap))
	part("Synology", s.synology(snap))
	part("USV", s.ups(snap))
	part("Drucker", s.supplies(snap))
	if err := CheckExtraText(cfg.ExtraText, cfg.Extra); err != nil {
		return nil, err
	}
	if err := CheckExtraOIDs(cfg.Extra); err != nil {
		part("Eigene OIDs", err)
	} else {
		part("Eigene OIDs", s.extra(snap, cfg.Extra, cfg.ExtraText))
	}
	if err := CheckColumns(cfg.Columns); err != nil {
		part("Eigene Spalten", err)
	} else {
		part("Eigene Spalten", s.columns(snap, cfg.Columns))
	}
	if ctx.Err() != nil {
		snap.Partial = append(snap.Partial, "Zeitgrenze")
	}
	rates(snap, prev)
	return snap, nil
}

func ifStatus(n int64) string {
	switch n {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	}
	return "unknown"
}

func (s *session) interfaces(snap *Snapshot) error {
	descr, order, err := s.column(oidIfDescr, MaxInterfaces)
	if err != nil {
		return err
	}
	if len(order) == 0 {
		return nil
	}
	var truncated error
	if len(order) >= MaxInterfaces {
		truncated = ErrTooMuch
	}
	cols := map[string]map[string]value{}
	for _, o := range []string{oidIfType, oidIfSpeed, oidIfAdminStatus, oidIfOperStatus, oidIfInOctets, oidIfInErrors,
		oidIfOutOctets, oidIfOutErrors, oidIfName, oidIfHighSpeed, oidIfAlias, oidIfHCInOctets, oidIfHCOutOctets} {
		if o == oidIfHCInOctets || o == oidIfHCOutOctets {
			if s.version == V1 { // v1 kennt keine 64-Bit-Zähler
				continue
			}
		}
		m, _, err := s.column(o, MaxInterfaces)
		if err != nil {
			return err
		}
		cols[o] = m
	}
	for _, idx := range order {
		n, err := strconv.Atoi(idx)
		if err != nil || n < 0 {
			continue
		}
		var it Interface
		it.Index = n
		it.Name, _ = cols[oidIfName][idx].text()
		if it.Name == "" {
			it.Name, _ = descr[idx].text()
		}
		if it.Name == "" {
			it.Name = "if" + idx
		}
		it.Alias, _ = cols[oidIfAlias][idx].text()
		if t, ok := cols[oidIfType][idx].int(); ok && t > 0 && t < 1000 {
			it.Type = int(t)
		}
		if hs, ok := cols[oidIfHighSpeed][idx].uint(); ok && hs > 0 && hs <= 10_000_000 {
			it.SpeedBps = hs * 1_000_000
		} else if sp, ok := cols[oidIfSpeed][idx].uint(); ok {
			it.SpeedBps = sp
		}
		a, _ := cols[oidIfAdminStatus][idx].int()
		it.AdminUp = a == 1
		o, _ := cols[oidIfOperStatus][idx].int()
		it.Oper = ifStatus(o)
		hin, ok1 := cols[oidIfHCInOctets][idx].uint()
		hout, ok2 := cols[oidIfHCOutOctets][idx].uint()
		if ok1 && ok2 {
			it.InOctets, it.OutOctets, it.HC = hin, hout, true
		} else {
			it.InOctets = counter32(cols[oidIfInOctets][idx])
			it.OutOctets = counter32(cols[oidIfOutOctets][idx])
		}
		it.InErrors, _ = cols[oidIfInErrors][idx].uint()
		it.OutErrors, _ = cols[oidIfOutErrors][idx].uint()
		snap.Interfaces = append(snap.Interfaces, it)
	}
	sort.Slice(snap.Interfaces, func(i, j int) bool { return snap.Interfaces[i].Index < snap.Interfaces[j].Index })
	return truncated
}

// rates bildet Raten aus den Zählern der vorigen Abfrage. Keine Rate, wenn
// das Gerät neu gestartet ist (Laufzeit kleiner), die Zähler zurückgesetzt
// wurden oder die Rate über der Schnittstellengeschwindigkeit läge.
func rates(snap, prev *Snapshot) {
	if prev == nil || prev.Counters == nil || snap.Counters == nil {
		return
	}
	dt := snap.Counters.At.Sub(prev.Counters.At).Seconds()
	if dt < 1 || dt > 3600 {
		return
	}
	if Rebooted(prev.Counters.UptimeTicks, snap.Counters.UptimeTicks, dt) {
		return
	}
	old := map[int]Interface{}
	for _, it := range prev.Interfaces {
		old[it.Index] = it
	}
	for i := range snap.Interfaces {
		it := &snap.Interfaces[i]
		p, ok := old[it.Index]
		if !ok || p.HC != it.HC || p.Name != it.Name {
			continue
		}
		bits := 32
		if it.HC {
			bits = 64
		}
		limit := math.Inf(1)
		if it.SpeedBps > 0 {
			limit = float64(it.SpeedBps) * 1.1
		}
		if d, ok := delta(p.InOctets, it.InOctets, bits); ok {
			if r := float64(d) * 8 / dt; r <= limit {
				it.InBps = &r
			}
		}
		if d, ok := delta(p.OutOctets, it.OutOctets, bits); ok {
			if r := float64(d) * 8 / dt; r <= limit {
				it.OutBps = &r
			}
		}
		e1, ok1 := delta(p.InErrors, it.InErrors, 32)
		e2, ok2 := delta(p.OutErrors, it.OutErrors, 32)
		if ok1 && ok2 {
			n := e1 + e2
			it.NewErrors = &n
		}
	}
}

// delta: Zuwachs eines Zählers. Ein 32-Bit-Zähler darf einmal übergelaufen
// sein; bei 64 Bit ist ein kleinerer Wert ein Zurücksetzen.
func delta(old, cur uint64, bits int) (uint64, bool) {
	if cur >= old {
		return cur - old, true
	}
	if bits == 32 && old <= math.MaxUint32 && cur <= math.MaxUint32 {
		return cur + (1 << 32) - old, true
	}
	return 0, false
}

// MinUptimeForReboot: Ein Neustart wird nur gemeldet, wenn das Gerät davor
// mindestens so lange lief (1.0.6). Geplante nächtliche Neustarts (Laufzeit um
// 24 Stunden) bleiben so still. Gilt für alle Quellen (SNMP, Proxmox,
// FRITZ!Box, NetApp, XenServer).
const MinUptimeForReboot = 27 * time.Hour

// RebootCounts: Lief das Gerät vor dem Neustart lange genug, dass er gemeldet
// wird?
func RebootCounts(prevUptimeS uint64) bool {
	return prevUptimeS >= uint64(MinUptimeForReboot/time.Second)
}

// HostRebooted: zu meldender Neustart zwischen zwei Abfragen. Bevorzugt die
// Laufzeit des Rechners (hrSystemUptime), sonst sysUpTime, und nur, wenn
// das Gerät vorher mindestens MinUptimeForReboot lief.
func HostRebooted(prev, cur *Snapshot) bool {
	if prev == nil || cur == nil || prev.Counters == nil || cur.Counters == nil {
		return false
	}
	dt := cur.Counters.At.Sub(prev.Counters.At).Seconds()
	old, now := prev.System.UptimeTicks, cur.System.UptimeTicks
	if prev.System.HostUptimeTicks > 0 && cur.System.HostUptimeTicks > 0 {
		old, now = prev.System.HostUptimeTicks, cur.System.HostUptimeTicks
	}
	return RebootCounts(uint64(old)/100) && Rebooted(old, now, dt)
}

// Rebooted erkennt einen Neustart an der Laufzeit (sysUpTime in
// Hundertstelsekunden). Ein Überlauf des 32-Bit-Werts (nach 497 Tagen) ist
// kein Neustart: Dann lag der alte Wert kurz vor 2^32, und der neue passt zur
// vergangenen Zeit.
func Rebooted(oldTicks, newTicks uint32, dtSeconds float64) bool {
	if newTicks >= oldTicks {
		return false
	}
	// Toleranz für Abfragedauer und Uhren: großzügig 10 Minuten
	const tolerance = 60000
	wrapped := int64(oldTicks) + int64(dtSeconds*100) - 1<<32
	if wrapped > -tolerance && int64(newTicks) <= max(wrapped, 0)+tolerance {
		return false
	}
	return true
}

func (s *session) storage(snap *Snapshot) error {
	types, order, err := s.column(oidHrStorageType, MaxStorage)
	if err != nil {
		return err
	}
	var truncated error
	if len(order) >= MaxStorage {
		truncated = ErrTooMuch
	}
	var descr, units, size, used map[string]value
	if len(order) > 0 {
		if descr, _, err = s.column(oidHrStorageDescr, MaxStorage); err != nil {
			return err
		}
		if units, _, err = s.column(oidHrStorageUnits, MaxStorage); err != nil {
			return err
		}
		if size, _, err = s.column(oidHrStorageSize, MaxStorage); err != nil {
			return err
		}
		if used, _, err = s.column(oidHrStorageUsed, MaxStorage); err != nil {
			return err
		}
	}
	var ram *Memory
	seen := map[string]bool{}
	for _, idx := range order {
		t, _ := types[idx].oid()
		u, ok1 := units[idx].uint()
		sz, ok2 := size[idx].uint()
		us, ok3 := used[idx].uint()
		if !ok1 || !ok2 || !ok3 || u == 0 || u > 1<<20 || sz == 0 || us > sz {
			continue
		}
		total, inUse := sz*u, us*u
		if total/u != sz { // Überlauf
			continue
		}
		d, _ := descr[idx].text()
		switch t {
		case hrStorageRAM:
			if ram == nil {
				ram = &Memory{TotalBytes: total, AvailableBytes: total - inUse}
			}
		case hrStorageFixedDisk:
			if d == "" || seen[d] || len(snap.Disks) >= MaxDisks || pseudoMount(d) {
				continue
			}
			seen[d] = true
			snap.Disks = append(snap.Disks, Disk{Mount: d, TotalBytes: total, FreeBytes: total - inUse})
		}
	}
	// Net-SNMP zählt Puffer und Cache als belegt; UCD-SNMP-MIB liefert, was
	// wirklich verfügbar ist (wie MemAvailable beim Agent, ungefähr).
	v, err := s.get(oidMemTotalReal, oidMemAvailReal, oidMemBuffer, oidMemCached)
	if err == nil {
		tot, ok1 := v[oidMemTotalReal].uint()
		avail, ok2 := v[oidMemAvailReal].uint()
		buf, _ := v[oidMemBuffer].uint()
		cache, _ := v[oidMemCached].uint()
		if ok1 && ok2 && tot > 0 && tot < 1<<40 {
			a := avail + buf + cache
			if a > tot {
				a = tot
			}
			ram = &Memory{TotalBytes: tot * 1024, AvailableBytes: a * 1024}
		}
	}
	snap.Memory = ram
	return truncated
}

// pseudoMount: Dateisysteme im Arbeitsspeicher (tmpfs unter /run, /dev,
// /sys, /proc). Net-SNMP meldet sie als feste Platte; systemd-Credentials
// sind z. B. immer voll und würden sonst dauerhaft alarmieren.
func pseudoMount(m string) bool {
	for _, p := range []string{"/run", "/dev", "/sys", "/proc"} {
		if m == p || strings.HasPrefix(m, p+"/") {
			return true
		}
	}
	return false
}

func (s *session) cpu(snap *Snapshot) error {
	loads, order, err := s.column(oidHrProcLoad, MaxCPUs)
	if err != nil {
		return err
	}
	var sum float64
	n := 0
	for _, idx := range order {
		if l, ok := loads[idx].int(); ok && l >= 0 && l <= 100 {
			sum += float64(l)
			n++
		}
	}
	if n > 0 {
		snap.CPU = &CPU{Cores: n, Percent: sum / float64(n)}
		return nil
	}
	// Net-SNMP füllt hrProcessorLoad erst nach einer Minute; UCD-SNMP-MIB
	// kennt den Leerlaufanteil (ssCpuIdle) schon vorher.
	v, err := s.get(oidSsCPUIdle)
	if err != nil {
		return err
	}
	if idle, ok := v[oidSsCPUIdle].int(); ok && idle >= 0 && idle <= 100 {
		snap.CPU = &CPU{Percent: float64(100 - idle)}
	}
	return nil
}

func intPtr(v value, lo, hi int64) *int {
	if n, ok := v.int(); ok && n >= lo && n <= hi {
		x := int(n)
		return &x
	}
	return nil
}

func (s *session) synology(snap *Snapshot) error {
	// Erst eine OID: Geräte ohne Synology-MIB kosten so nur eine Anfrage.
	first, err := s.get(oidSynoSystemStatus)
	if err != nil {
		return err
	}
	st, ok := first[oidSynoSystemStatus].status()
	if !ok {
		return nil // kein Synology
	}
	v, err := s.get(oidSynoTemperature, oidSynoPowerStatus, oidSynoSystemFan, oidSynoCPUFan,
		oidSynoModel, oidSynoVersion, oidSynoUpgrade)
	if err != nil {
		return err
	}
	syn := &Synology{SystemStatus: int(st), Disks: []SynoDisk{}, Raids: []SynoRaid{}}
	syn.Model, _ = v[oidSynoModel].text()
	syn.Version, _ = v[oidSynoVersion].text()
	if n, ok := v[oidSynoPowerStatus].status(); ok {
		syn.PowerStatus = int(n)
	}
	if n, ok := v[oidSynoSystemFan].status(); ok {
		syn.SystemFan = int(n)
	}
	if n, ok := v[oidSynoCPUFan].status(); ok {
		syn.CPUFan = int(n)
	}
	if n, ok := v[oidSynoUpgrade].status(); ok {
		syn.Upgrade = int(n)
	}
	syn.Temperature = intPtr(v[oidSynoTemperature], -40, 150)
	snap.Synology = syn

	status, order, err := s.column(oidSynoDiskStatus, MaxDisks)
	if err != nil {
		return err
	}
	if len(order) > 0 {
		cols := map[string]map[string]value{}
		for _, o := range []string{oidSynoDiskID, oidSynoDiskModel, oidSynoDiskTemp, oidSynoDiskRole, oidSynoDiskName, oidSynoDiskHealth} {
			if cols[o], _, err = s.column(o, MaxDisks); err != nil {
				return err
			}
		}
		for _, idx := range order {
			var d SynoDisk
			n, _ := status[idx].status()
			d.Status = int(n)
			d.Name, _ = cols[oidSynoDiskName][idx].text()
			if d.Name == "" {
				d.Name, _ = cols[oidSynoDiskID][idx].text()
			}
			if d.Name == "" {
				d.Name = "Laufwerk " + idx
			}
			d.Model, _ = cols[oidSynoDiskModel][idx].text()
			d.Role, _ = cols[oidSynoDiskRole][idx].text()
			if h, ok := cols[oidSynoDiskHealth][idx].int(); ok && h >= 1 && h <= 4 {
				d.Health = int(h)
			}
			d.Temperature = intPtr(cols[oidSynoDiskTemp][idx], -40, 150)
			syn.Disks = append(syn.Disks, d)
		}
	}

	rstatus, order, err := s.column(oidSynoRaidStatus, MaxRaids)
	if err != nil {
		return err
	}
	if len(order) > 0 {
		names, _, err := s.column(oidSynoRaidName, MaxRaids)
		if err != nil {
			return err
		}
		free, _, err := s.column(oidSynoRaidFree, MaxRaids)
		if err != nil {
			return err
		}
		total, _, err := s.column(oidSynoRaidTotal, MaxRaids)
		if err != nil {
			return err
		}
		for _, idx := range order {
			var r SynoRaid
			n, _ := rstatus[idx].status()
			r.Status = int(n)
			r.Name, _ = names[idx].text()
			if r.Name == "" {
				r.Name = "RAID " + idx
			}
			f, ok1 := free[idx].uint()
			t, ok2 := total[idx].uint()
			if ok1 && ok2 && f <= t {
				r.FreeBytes, r.TotalBytes = f, t
			}
			syn.Raids = append(syn.Raids, r)
		}
	}

	// USV per USB am NAS
	u, err := s.get(oidSynoUPSModel, oidSynoUPSStatus, oidSynoUPSLoad, oidSynoUPSCharge, oidSynoUPSRuntime)
	if err != nil {
		return err
	}
	if text, ok := u[oidSynoUPSStatus].text(); ok && text != "" {
		ups := &UPS{Source: "synology", Status: text}
		ups.Model, _ = u[oidSynoUPSModel].text()
		nutFlags(ups, text)
		ups.ChargePct = pct(u[oidSynoUPSCharge])
		ups.LoadPct = pct(u[oidSynoUPSLoad])
		if r, ok := u[oidSynoUPSRuntime].float(); ok && r >= 0 && r < 1e7 {
			ups.RuntimeS = &r
		}
		snap.UPS = ups
	}
	return nil
}

// nutFlags liest den Status im Format von NUT („OL“, „OB LB“, „OL CHRG RB“).
func nutFlags(u *UPS, status string) {
	for _, f := range strings.Fields(strings.ToUpper(status)) {
		switch f {
		case "OB":
			u.OnBattery = true
		case "LB":
			u.LowBattery = true
		case "RB":
			u.Replace = true
		}
	}
}

func pct(v value) *float64 {
	if f, ok := v.float(); ok && f >= 0 && f <= 100 {
		return &f
	}
	return nil
}

func (s *session) ups(snap *Snapshot) error {
	if snap.UPS != nil {
		return nil // schon aus der Synology-MIB
	}
	first, err := s.get(oidUpsBatteryStatus)
	if err != nil {
		return err
	}
	bs, ok := first[oidUpsBatteryStatus].int()
	if !ok {
		return nil
	}
	v, err := s.get(oidUpsIdentModel, oidUpsMinutesRemaining, oidUpsChargeRemaining,
		oidUpsOutputSource, oidUpsOutputPercentLoad)
	if err != nil {
		return err
	}
	ups := &UPS{Source: "rfc1628"}
	ups.Model, _ = v[oidUpsIdentModel].text()
	src, _ := v[oidUpsOutputSource].int()
	var parts []string
	switch src {
	case 3:
		parts = append(parts, "Netzbetrieb")
	case 4:
		parts = append(parts, "Bypass")
	case 5:
		parts = append(parts, "Batteriebetrieb")
		ups.OnBattery = true
	case 2:
		parts = append(parts, "kein Ausgang")
	}
	switch bs {
	case 3:
		parts = append(parts, "Batterie schwach")
		ups.LowBattery = true
	case 4:
		parts = append(parts, "Batterie leer")
		ups.LowBattery = true
	}
	ups.Status = strings.Join(parts, ", ")
	if ups.Status == "" {
		ups.Status = "unbekannt"
	}
	ups.ChargePct = pct(v[oidUpsChargeRemaining])
	ups.LoadPct = pct(v[oidUpsOutputPercentLoad])
	if m, ok := v[oidUpsMinutesRemaining].float(); ok && m >= 0 && m < 1e5 {
		r := m * 60
		ups.RuntimeS = &r
	}
	snap.UPS = ups
	return nil
}

func (s *session) supplies(snap *Snapshot) error {
	descr, order, err := s.column(oidPrtSupplyDescr, MaxSupplies)
	if err != nil {
		return err
	}
	if len(order) == 0 {
		return nil
	}
	maxs, _, err := s.column(oidPrtSupplyMax, MaxSupplies)
	if err != nil {
		return err
	}
	levels, _, err := s.column(oidPrtSupplyLevel, MaxSupplies)
	if err != nil {
		return err
	}
	for _, idx := range order {
		var sp Supply
		sp.Name, _ = descr[idx].text()
		if sp.Name == "" {
			sp.Name = "Material " + idx
		}
		l, ok1 := levels[idx].int()
		m, ok2 := maxs[idx].int()
		if !ok1 || !ok2 || l < -3 || m < -2 || l > 1<<30 || m > 1<<30 {
			continue
		}
		sp.Level, sp.Max = int(l), int(m)
		if m > 0 && l >= 0 && l <= m {
			p := float64(l) / float64(m) * 100
			sp.Percent = &p
		}
		snap.Supplies = append(snap.Supplies, sp)
	}
	return nil
}

// counter32 liest ifInOctets/ifOutOctets. Die Spalten sind Counter32; ein
// Gerät, das dort Counter64 oder eine größere Zahl meldet, ist fehlerhaft.
// Der Wert zählt dann als fehlend, sonst lehnt die Zentrale die ganze
// Abfrage ab („32-Bit-Zähler zu groß“, vom Fuzzer gefunden).
func counter32(v value) uint64 {
	n, ok := v.uint()
	if !ok || n > math.MaxUint32 {
		return 0
	}
	return n
}
