// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Topologie wie web/src/Topologie.tsx: Bäume aus „hängt ab von“ je
// Mandant. Jeder Knoten trägt Form und Farbe des Geräts; die Linie links an
// einem Kind trägt dessen Zustand, gestrichelt, wenn es ruht, unbekannt oder
// ungeprüft ist. Ein Klick öffnet das Gerät unter Hosts. Maße wie die
// Stile .topo-* im Web (Karte höchstens 22rem, Kinder im Raster ab 14rem).

import (
	"fmt"
	"sort"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

func init() {
	seiten[seiteTopologie] = &seitenDef{malen: topoMalen, klick: func(z ziel, _ any) {
		if z.art == "geraet" {
			a.hostOeffnen(z.wert)
		}
	}}
}

var topoText = map[string]string{"ok": "OK", "warn": "Warnung", "crit": "Kritisch", "unknown": "Unbekannt",
	"neu": "noch nicht geprüft", "pause": "Pausiert", "wartung": "Wartung"}

func topoLinie(stand string) desktop.RGB {
	switch stand {
	case "crit":
		return th.f.Krit
	case "warn":
		return th.f.Warn
	case "unknown":
		return th.f.Unbek
	case "ok":
		return th.f.OK
	case "wartung":
		return th.f.Wartung
	}
	return th.f.Leise
}

func topoMalen(m *maler, _ any) {
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	m.klein("Die Bäume zeigen, welches Gerät von welchem abhängt (am Gerät unter „Bearbeiten“ › „hängt ab von“, im " +
		"Browser). Fällt ein Gerät aus, ruhen die Alarme der Geräte darunter. Die Linie zu einem Gerät trägt dessen Zustand; " +
		"gestrichelt heißt: ruht, unbekannt oder noch nicht geprüft. Ein Klick öffnet das Gerät.")
	if st.Zeit.IsZero() {
		m.klein("Lädt …")
		return
	}
	ids, mehrere, _ := a.bereich()
	f := m.f
	type jeM struct {
		id, name string
		w        []*desktop.TopoKnoten
		ohne     int
	}
	var liste []jeM
	for _, mn := range st.Mandanten {
		if !ids[mn.ID] {
			continue
		}
		var gs []desktop.Geraet
		for _, g := range st.Geraete {
			if g.MandantID == mn.ID {
				gs = append(gs, g)
			}
		}
		w, ohne := desktop.TopoBaeume(gs, st.Sensoren)
		if len(w) > 0 {
			liste = append(liste, jeM{mn.ID, mn.Name, w, ohne})
		}
	}
	sort.SliceStable(liste, func(i, j int) bool {
		if liste[i].id == f.mandant || liste[j].id == f.mandant {
			return liste[i].id == f.mandant
		}
		return liste[i].name < liste[j].name
	})
	if len(liste) == 0 {
		m.leer("Noch keine Abhängigkeiten. Unter Hosts am Gerät „Bearbeiten“ › „hängt ab von“ ein Elterngerät wählen " +
			"(im Browser), z. B. den Switch, an dem ein Drucker hängt.")
		return
	}
	for i, x := range liste {
		if i > 0 {
			m.abstand(20)
		}
		if mehrere {
			m.abschnitt(x.name)
		}
		l, r := m.innen()
		m.y += m.s(12)
		for _, k := range x.w {
			m.y += topoZweig(m, k, l, m.y, r-l, false) + m.s(12)
		}
		if x.ohne > 0 {
			t := fmt.Sprintf("%d weitere Geräte hängen weder von einem anderen ab, noch hängt etwas von ihnen ab.", x.ohne)
			if x.ohne == 1 {
				t = "1 weiteres Gerät hängt weder von einem anderen ab, noch hängt etwas von ihm ab."
			}
			m.klein(t)
		}
	}
}

// topoZweig zeichnet Knoten und Kinder ab (x, y) in der Breite w; liefert die Höhe.
func topoZweig(m *maler, k *desktop.TopoKnoten, x, y, w int32, kind bool) int32 {
	kh := m.s(52)
	kw := w
	if !kind || len(k.Kinder) > 0 {
		kw = min(w, m.s(352)) // 22rem
	}
	topoKarte(m, k, rect{x, y, x + kw, y + kh}, kind)
	h := kh
	if len(k.Kinder) == 0 {
		return h
	}
	// Kinder: Linie links (2 px), Raster mit Spalten ab 14rem, Abstand 8
	lx := x + m.s(20)
	ix := lx + m.s(2) + m.s(12)
	iw := x + w - ix
	gap := m.s(8)
	spalten := max(1, (iw+gap)/(m.s(224)+gap))
	sw := (iw - gap*(spalten-1)) / spalten
	cy := y + kh + m.s(8)
	col := int32(0)
	zeileH := int32(0)
	umbruch := func() {
		if col > 0 {
			cy += zeileH + gap
			col, zeileH = 0, 0
		}
	}
	for _, c := range k.Kinder {
		if len(c.Kinder) > 0 {
			umbruch()
			cy += topoZweig(m, c, ix, cy, iw, true) + gap
			continue
		}
		ch := topoZweig(m, c, ix+col*(sw+gap), cy, sw, true)
		zeileH = max(zeileH, ch)
		col++
		if col == spalten {
			umbruch()
		}
	}
	if col > 0 {
		cy += zeileH
	} else {
		cy -= gap
	}
	if m.zeichnen {
		fuellen(m.hdc, rect{lx, y + kh, lx + m.s(2), cy}, th.f.Linie)
	}
	return cy - y
}

func topoKarte(m *maler, k *desktop.TopoKnoten, r rect, kind bool) {
	if !m.zeichnen {
		return
	}
	hdc := m.hdc
	hover := m.ziel(r, "geraet", k.Geraet.ID)
	rand := th.f.Linie
	if hover {
		rand = th.f.Marke
	}
	rund(hdc, r, m.s(3), th.f.Flaeche, rand, true, true, false)
	x := r.Left + m.s(12)
	if kind {
		// Linie zum Gerät: 4 px in seinem Zustand, gestrichelt wenn es ruht
		c := topoLinie(k.Stand)
		if k.Gestrichelt() {
			for yy := r.Top + m.s(2); yy < r.Bottom-m.s(2); yy += m.s(8) {
				fuellen(hdc, rect{r.Left, yy, r.Left + m.s(4), min(yy+m.s(5), r.Bottom-m.s(2))}, c)
			}
		} else {
			fuellen(hdc, rect{r.Left, r.Top + 1, r.Left + m.s(4), r.Bottom - 1}, c)
		}
		x += m.s(4)
	}
	an := th.f.AnzeigeFuer(k.Stand)
	form(hdc, an.Form, an.Farbe, x, (r.Top+r.Bottom)/2-m.s(6), m.s(12))
	x += m.s(12) + m.s(8)
	unter := topoText[k.Stand]
	switch {
	case k.Geraet.NichtErreichbarWegen != nil:
		unter = "ruht, Elterngerät nicht erreichbar"
	case k.Geraet.Adresse != nil && *k.Geraet.Adresse != "":
		unter = *k.Geraet.Adresse
	}
	mitte := (r.Top + r.Bottom) / 2
	schreiben(hdc, k.Geraet.Name, rect{x, mitte - m.s(20), r.Right - m.s(8), mitte}, m.f.sch.t16b, th.f.Tinte, dtEndEllipsis)
	schreiben(hdc, unter, rect{x, mitte, r.Right - m.s(8), mitte + m.s(18)}, m.f.sch.t13, th.f.Leise, dtEndEllipsis)
}
