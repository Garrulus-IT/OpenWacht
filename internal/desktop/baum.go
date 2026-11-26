// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"sort"
	"strings"
)

// Baum des Hauptfensters: Mandant → Untermandanten, Gruppen
// (verschachtelt) → Geräte. Jeder Knoten zählt die Sensoren darunter.

// KnotenArt eines Eintrags im Baum.
type KnotenArt int

const (
	KnotenMandant KnotenArt = iota
	KnotenGruppe
	KnotenGeraet
)

// Knoten im Baum.
type Knoten struct {
	Art       KnotenArt
	ID        string
	Name      string
	MandantID string
	Rolle     string // des Mandanten, in dem der Knoten liegt
	Geraet    *Geraet
	Kinder    []*Knoten
	Zaehler   Zaehler
	Geraete   []string // IDs aller Geräte darunter (auch dieses)
}

// Zustand: der schlimmste Zustand der Sensoren darunter ("" = keine Sensoren).
func (k *Knoten) Zustand() string {
	z := k.Zaehler
	switch {
	case z.Kritisch > 0:
		return "crit"
	case z.Warnung > 0:
		return "warn"
	case z.Unbekannt > 0:
		return "unknown"
	case z.Bestaetigt > 0:
		return "bestaetigt"
	case z.OK > 0:
		return "ok"
	case z.Sonst > 0:
		return "pause"
	}
	return ""
}

// Beschriftung: Name für Baum und Kopf (die Zahlen zeichnet das Fenster daneben).
func (k *Knoten) Beschriftung() string { return Kuerzen(k.Name, 100) }

// DarfAendern: Operator oder Admin im Mandanten des Knotens.
func DarfAendern(rolle string) bool { return rolle == "operator" || rolle == "admin" }

// BaumBauen ordnet den Stand zum Baum. Reihenfolge je Ebene: Untermandanten,
// Gruppen (nach Position), Geräte ohne Gruppe (nach Name).
func BaumBauen(st Stand) []*Knoten {
	mandanten := map[string]*Knoten{}
	for _, m := range st.Mandanten {
		mandanten[m.ID] = &Knoten{Art: KnotenMandant, ID: m.ID, Name: m.Name, MandantID: m.ID, Rolle: m.Rolle}
	}
	gruppen := map[string]*Knoten{}
	gs := append([]Gruppe(nil), st.Gruppen...)
	sort.SliceStable(gs, func(i, j int) bool {
		if gs[i].Position != gs[j].Position {
			return gs[i].Position < gs[j].Position
		}
		return strings.ToLower(gs[i].Name) < strings.ToLower(gs[j].Name)
	})
	for _, g := range gs {
		gruppen[g.ID] = &Knoten{Art: KnotenGruppe, ID: g.ID, Name: g.Name, MandantID: g.MandantID}
	}
	sensorZahl := map[string][]Sensor{}
	for _, s := range st.Sensoren {
		sensorZahl[s.GeraetID] = append(sensorZahl[s.GeraetID], s)
	}
	geraete := append([]Geraet(nil), st.Geraete...)
	sort.SliceStable(geraete, func(i, j int) bool {
		return strings.ToLower(geraete[i].Name) < strings.ToLower(geraete[j].Name)
	})

	var wurzeln []*Knoten
	// Mandanten: Untermandanten zuerst, in Namensreihenfolge.
	ms := append([]Mandant(nil), st.Mandanten...)
	sort.SliceStable(ms, func(i, j int) bool { return strings.ToLower(ms[i].Name) < strings.ToLower(ms[j].Name) })
	for _, m := range ms {
		k := mandanten[m.ID]
		if m.Ueber != nil {
			if e, ok := mandanten[*m.Ueber]; ok {
				e.Kinder = append(e.Kinder, k)
				continue
			}
		}
		wurzeln = append(wurzeln, k)
	}
	for _, g := range gs {
		k := gruppen[g.ID]
		if g.ElternID != nil {
			if e, ok := gruppen[*g.ElternID]; ok {
				e.Kinder = append(e.Kinder, k)
				continue
			}
		}
		if m, ok := mandanten[g.MandantID]; ok {
			m.Kinder = append(m.Kinder, k)
		}
	}
	for i := range geraete {
		d := &geraete[i]
		k := &Knoten{Art: KnotenGeraet, ID: d.ID, Name: d.Name, MandantID: d.MandantID, Geraet: d}
		k.Zaehler = Zaehlen(sensorZahl[d.ID])
		if d.GruppeID != nil {
			if g, ok := gruppen[*d.GruppeID]; ok {
				g.Kinder = append(g.Kinder, k)
				continue
			}
		}
		if m, ok := mandanten[d.MandantID]; ok {
			m.Kinder = append(m.Kinder, k)
		}
	}
	rollen := map[string]string{}
	for _, m := range st.Mandanten {
		rollen[m.ID] = m.Rolle
	}
	var summe func(k *Knoten)
	summe = func(k *Knoten) {
		k.Rolle = rollen[k.MandantID]
		if k.Art == KnotenGeraet {
			k.Geraete = []string{k.ID}
			return
		}
		k.Zaehler = Zaehler{}
		k.Geraete = nil
		for _, c := range k.Kinder {
			summe(c)
			k.Zaehler.Kritisch += c.Zaehler.Kritisch
			k.Zaehler.Warnung += c.Zaehler.Warnung
			k.Zaehler.Unbekannt += c.Zaehler.Unbekannt
			k.Zaehler.OK += c.Zaehler.OK
			k.Zaehler.Sonst += c.Zaehler.Sonst
			k.Zaehler.Bestaetigt += c.Zaehler.Bestaetigt
			k.Zaehler.Pausiert += c.Zaehler.Pausiert
			k.Zaehler.Neu += c.Zaehler.Neu
			k.Geraete = append(k.Geraete, c.Geraete...)
		}
	}
	for _, w := range wurzeln {
		summe(w)
	}
	return wurzeln
}

// Finden sucht einen Knoten nach Art und ID.
func Finden(wurzeln []*Knoten, art KnotenArt, id string) *Knoten {
	for _, w := range wurzeln {
		if w.Art == art && w.ID == id {
			return w
		}
		if k := Finden(w.Kinder, art, id); k != nil {
			return k
		}
	}
	return nil
}

// SensorenUnter: die Sensoren der Geräte unter einem Knoten (nil = alle).
func SensorenUnter(k *Knoten, alle []Sensor) []Sensor {
	if k == nil {
		return alle
	}
	ids := map[string]bool{}
	for _, g := range k.Geraete {
		ids[g] = true
	}
	var out []Sensor
	for _, s := range alle {
		if ids[s.GeraetID] {
			out = append(out, s)
		}
	}
	return out
}
