// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// Messwerte von einem Sammler (Etappe 15): Ein Agent fragt das Gerät ab und
// schickt den Snapshot. Er ist nicht vertrauenswürdig wie alle Agent-Daten.
// ValidateCollected prüft dieselben Grenzen, die Poll beim Lesen eines Geräts
// einhält; ein ehrlicher Sammler (derselbe Code) besteht immer. Raten und
// neue Fehler rechnet die Zentrale selbst (ApplyRates), was der Sammler dafür
// schickt, wird verworfen.

// ApplyRates bildet die Raten aus den Zählern der vorigen Abfrage (wie Poll).
// Vorhandene Raten werden vorher verworfen.
func ApplyRates(snap, prev *Snapshot) {
	for i := range snap.Interfaces {
		snap.Interfaces[i].InBps, snap.Interfaces[i].OutBps, snap.Interfaces[i].NewErrors = nil, nil, nil
	}
	rates(snap, prev)
}

var partNames = []string{"Schnittstellen", "Speicher", "CPU", "Synology", "USV", "Drucker", "Eigene OIDs", "Zeitgrenze"}

var operStates = []string{"up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"}

func checkClean(field, s string, allowEmpty bool) error {
	if clean(s, MaxText) != s {
		return fmt.Errorf("%s: kein bereinigter Text", field)
	}
	if !allowEmpty && s == "" {
		return fmt.Errorf("%s: leer", field)
	}
	return nil
}

func checkPct(field string, p *float64) error {
	if p != nil && (math.IsNaN(*p) || *p < 0 || *p > 100) {
		return fmt.Errorf("%s: außerhalb 0–100", field)
	}
	return nil
}

func checkTemp(field string, t *int) error {
	if t != nil && (*t < -40 || *t > 150) {
		return fmt.Errorf("%s: unplausibel", field)
	}
	return nil
}

// status: Aufzählungswerte aus Herstellerteilen, ungeprüft als Zahl
// übernommen (SNMP INTEGER, 32 Bit)
func checkStatus(field string, n int) error {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return fmt.Errorf("%s: unplausibel", field)
	}
	return nil
}

// ValidateCollected prüft einen Snapshot von einem Sammler. now dient der
// Plausibilität des Zeitstempels (Uhr des Sammlers).
func (s *Snapshot) ValidateCollected(now time.Time) error {
	if s.CollectedAt.IsZero() || s.CollectedAt.After(now.Add(2*time.Minute)) || s.CollectedAt.Before(now.Add(-10*time.Minute)) {
		return errors.New("erfasst: Zeitstempel unplausibel (Uhr des Sammlers prüfen)")
	}
	if s.Counters == nil || !s.Counters.At.Equal(s.CollectedAt) || s.Counters.UptimeTicks != s.System.UptimeTicks {
		return errors.New("zaehler: passen nicht zur Abfrage")
	}
	if s.Proxmox != nil {
		return errors.New("proxmox: kommt nicht vom Sammler")
	}
	if s.FritzBox != nil {
		return errors.New("fritzbox: kommt nicht vom Sammler")
	}
	if s.ONTAP != nil {
		return errors.New("ontap: kommt nicht vom Sammler")
	}
	if s.XAPI != nil {
		return errors.New("xapi: kommt nicht vom Sammler")
	}
	if err := validateExtra(s.Extra); err != nil {
		return err
	}
	if err := validateColumns(s.Columns); err != nil {
		return err
	}
	sys := s.System
	for name, v := range map[string]string{"system.beschreibung": sys.Descr, "system.name": sys.Name, "system.standort": sys.Location} {
		if err := checkClean(name, v, true); err != nil {
			return err
		}
	}
	if sys.Descr == "" && sys.Name == "" {
		return errors.New("system: ohne Beschreibung und Namen")
	}
	if len(sys.ObjectID) > 300 || !validOID(sys.ObjectID) {
		return errors.New("system.objekt_id: keine OID")
	}
	if sys.UptimeS != uint64(sys.UptimeTicks)/100 {
		return errors.New("system.laufzeit_s: passt nicht zu den Ticks")
	}
	if c := s.CPU; c != nil {
		if c.Cores < 0 || c.Cores > MaxCPUs || math.IsNaN(c.Percent) || c.Percent < 0 || c.Percent > 100 {
			return errors.New("cpu: unplausibel")
		}
	}
	if m := s.Memory; m != nil && m.AvailableBytes > m.TotalBytes {
		return errors.New("speicher: frei größer als gesamt")
	}
	if s.Disks == nil || s.Interfaces == nil || s.Supplies == nil {
		return errors.New("platten, schnittstellen, verbrauchsmaterial: fehlen")
	}
	if len(s.Disks) > MaxDisks {
		return fmt.Errorf("platten: höchstens %d", MaxDisks)
	}
	seen := map[string]bool{}
	for i, d := range s.Disks {
		if err := checkClean(fmt.Sprintf("platten[%d].einhaengepunkt", i), d.Mount, false); err != nil {
			return err
		}
		if seen[d.Mount] || d.FSType != "" || d.FreeBytes > d.TotalBytes {
			return fmt.Errorf("platten[%d]: unplausibel", i)
		}
		seen[d.Mount] = true
	}
	if len(s.Interfaces) > MaxInterfaces {
		return fmt.Errorf("schnittstellen: höchstens %d", MaxInterfaces)
	}
	for i, it := range s.Interfaces {
		f := fmt.Sprintf("schnittstellen[%d]", i)
		if it.Index < 0 || i > 0 && it.Index < s.Interfaces[i-1].Index {
			return errors.New(f + ".index: unplausibel")
		}
		if err := checkClean(f+".name", it.Name, false); err != nil {
			return err
		}
		if err := checkClean(f+".alias", it.Alias, true); err != nil {
			return err
		}
		if it.Type < 0 || it.Type >= 1000 || !slices.Contains(operStates, it.Oper) {
			return errors.New(f + ": unplausibel")
		}
		if !it.HC && (it.InOctets > math.MaxUint32 || it.OutOctets > math.MaxUint32) {
			return errors.New(f + ": 32-Bit-Zähler zu groß")
		}
	}
	if y := s.Synology; y != nil {
		if err := checkClean("synology.modell", y.Model, true); err != nil {
			return err
		}
		if err := checkClean("synology.version", y.Version, true); err != nil {
			return err
		}
		for name, v := range map[string]int{"synology.system": y.SystemStatus, "synology.netzteil": y.PowerStatus,
			"synology.luefter_system": y.SystemFan, "synology.luefter_cpu": y.CPUFan, "synology.update": y.Upgrade} {
			if err := checkStatus(name, v); err != nil {
				return err
			}
		}
		if err := checkTemp("synology.temperatur", y.Temperature); err != nil {
			return err
		}
		if len(y.Disks) > MaxDisks || len(y.Raids) > MaxRaids {
			return errors.New("synology: zu viele Laufwerke oder RAIDs")
		}
		for i, d := range y.Disks {
			f := fmt.Sprintf("synology.laufwerke[%d]", i)
			for name, v := range map[string]string{".name": d.Name, ".modell": d.Model, ".rolle": d.Role} {
				if err := checkClean(f+name, v, name != ".name"); err != nil {
					return err
				}
			}
			if err := checkStatus(f+".status", d.Status); err != nil {
				return err
			}
			if d.Health < 0 || d.Health > 4 {
				return errors.New(f + ".gesundheit: unplausibel")
			}
			if err := checkTemp(f+".temperatur", d.Temperature); err != nil {
				return err
			}
		}
		for i, r := range y.Raids {
			f := fmt.Sprintf("synology.raids[%d]", i)
			if err := checkClean(f+".name", r.Name, false); err != nil {
				return err
			}
			if err := checkStatus(f+".status", r.Status); err != nil {
				return err
			}
			if r.FreeBytes > r.TotalBytes {
				return errors.New(f + ": frei größer als gesamt")
			}
		}
	}
	if u := s.UPS; u != nil {
		if u.Source != "rfc1628" && u.Source != "synology" {
			return errors.New("usv.quelle: unbekannt")
		}
		if err := checkClean("usv.modell", u.Model, true); err != nil {
			return err
		}
		if err := checkClean("usv.status", u.Status, false); err != nil {
			return err
		}
		if err := checkPct("usv.ladung_prozent", u.ChargePct); err != nil {
			return err
		}
		if err := checkPct("usv.last_prozent", u.LoadPct); err != nil {
			return err
		}
		if r := u.RuntimeS; r != nil && (math.IsNaN(*r) || *r < 0 || *r > 1e7) {
			return errors.New("usv.restlaufzeit_s: unplausibel")
		}
	}
	if len(s.Supplies) > MaxSupplies {
		return fmt.Errorf("verbrauchsmaterial: höchstens %d", MaxSupplies)
	}
	for i, sp := range s.Supplies {
		f := fmt.Sprintf("verbrauchsmaterial[%d]", i)
		if err := checkClean(f+".name", sp.Name, false); err != nil {
			return err
		}
		if sp.Level < -3 || sp.Max < -2 || sp.Level > 1<<30 || sp.Max > 1<<30 {
			return errors.New(f + ": unplausibel")
		}
		want := sp.Max > 0 && sp.Level >= 0 && sp.Level <= sp.Max
		if (sp.Percent != nil) != want {
			return errors.New(f + ".prozent: passt nicht zum Stand")
		}
		if want && math.Abs(*sp.Percent-float64(sp.Level)/float64(sp.Max)*100) > 1e-6 {
			return errors.New(f + ".prozent: passt nicht zum Stand")
		}
	}
	for _, list := range [][]string{s.Truncated, s.Partial} {
		if len(list) > len(partNames) {
			return errors.New("gekuerzt/teilweise: zu viele Einträge")
		}
		for _, p := range list {
			if !slices.Contains(partNames, p) {
				return errors.New("gekuerzt/teilweise: unbekannter Teil")
			}
		}
	}
	return nil
}

// validOID: leer oder Ziffern mit Punkten (ohne führenden Punkt).
func validOID(s string) bool {
	if s == "" {
		return true
	}
	prevDot := true
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			prevDot = false
		case c == '.' && !prevDot:
			prevDot = true
		default:
			return false
		}
	}
	return !prevDot
}
