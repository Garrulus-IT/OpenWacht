// SPDX-License-Identifier: AGPL-3.0-only

package desktop

// Seite Topologie wie web/src/Topologie.tsx: die Abhängigkeiten der Geräte
// („hängt ab von“) als Bäume je Mandant. Gezeigt werden nur Geräte, die von
// etwas abhängen oder von denen etwas abhängt.

import (
	"sort"
	"strings"
)

// TopoKnoten: ein Gerät im Baum.
type TopoKnoten struct {
	Geraet Geraet
	Stand  string // crit, warn, unknown, ok, neu, pause, wartung
	Kinder []*TopoKnoten
}

// Gestrichelt: Linie gestrichelt, wenn das Gerät ruht, unbekannt oder ungeprüft ist.
func (k *TopoKnoten) Gestrichelt() bool {
	return k.Geraet.NichtErreichbarWegen != nil || k.Stand == "unknown" || k.Stand == "neu" || k.Stand == "pause"
}

// TopoStand: schlimmster Zustand der Sensoren; Wartung, wenn das Gerät in Wartung ist.
func TopoStand(g Geraet, sensoren []Sensor) string {
	if g.Wartung != nil {
		return "wartung"
	}
	if len(sensoren) == 0 {
		return "neu"
	}
	best := ""
	for _, s := range sensoren {
		st := s.Status
		if _, ok := AnzeigeRang[st]; !ok {
			st = "neu"
		}
		if best == "" || AnzeigeRang[st] < AnzeigeRang[best] {
			best = st
		}
	}
	return best
}

// nameSchluessel: Sortierung ungefähr wie localeCompare(…, "de").
var umlaute = strings.NewReplacer("ä", "a", "ö", "o", "ü", "u", "ß", "ss")

func nameSchluessel(s string) string { return umlaute.Replace(strings.ToLower(s)) }

// TopoBaeume: Bäume der Geräte eines Mandanten und wie viele ohne Abhängigkeit bleiben.
func TopoBaeume(geraete []Geraet, sensoren []Sensor) (wurzeln []*TopoKnoten, ohne int) {
	jeGeraet := map[string][]Sensor{}
	for _, s := range sensoren {
		jeGeraet[s.GeraetID] = append(jeGeraet[s.GeraetID], s)
	}
	nachID := map[string]Geraet{}
	for _, g := range geraete {
		nachID[g.ID] = g
	}
	kinder := map[string][]Geraet{}
	for _, g := range geraete {
		if g.AbhaengigVon != nil {
			if _, ok := nachID[*g.AbhaengigVon]; ok {
				kinder[*g.AbhaengigVon] = append(kinder[*g.AbhaengigVon], g)
			}
		}
	}
	nachName := func(l []Geraet) {
		sort.SliceStable(l, func(i, j int) bool { return nameSchluessel(l[i].Name) < nameSchluessel(l[j].Name) })
	}
	besucht := map[string]bool{}
	var bauen func(g Geraet) *TopoKnoten
	bauen = func(g Geraet) *TopoKnoten {
		besucht[g.ID] = true
		k := &TopoKnoten{Geraet: g, Stand: TopoStand(g, jeGeraet[g.ID])}
		ks := append([]Geraet(nil), kinder[g.ID]...)
		nachName(ks)
		for _, c := range ks {
			if !besucht[c.ID] { // Kreise schließt die Datenbank aus; trotzdem sicher
				k.Kinder = append(k.Kinder, bauen(c))
			}
		}
		return k
	}
	var ws []Geraet
	for _, g := range geraete {
		_, elternDa := nachID[deref(g.AbhaengigVon)]
		if (g.AbhaengigVon == nil || !elternDa) && len(kinder[g.ID]) > 0 {
			ws = append(ws, g)
		}
	}
	nachName(ws)
	for _, g := range ws {
		wurzeln = append(wurzeln, bauen(g))
	}
	for _, g := range geraete {
		if !besucht[g.ID] {
			ohne++
		}
	}
	return wurzeln, ohne
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
