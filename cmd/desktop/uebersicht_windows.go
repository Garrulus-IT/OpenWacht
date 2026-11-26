// SPDX-License-Identifier: AGPL-3.0-only

package main

// Übersicht neben der Sonne im Dashboard, aufgebaut wie die Seite der
// Wandanzeige im Web (web/src/Wandanzeige.tsx): oben die Geräte je Zustand
// als Kacheln, darunter „Aktuell“ mit den Geräten, die ein Problem haben.
// Ein Klick auf ein Gerät öffnet seine Sensoren neben der Sonne.

import (
	"sort"
	"strconv"
	"strings"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

// kachelStatus: Reihenfolge der Kacheln wie in der Wandanzeige.
var kachelStatus = []struct{ sonne, anzeige, wort string }{
	{"crit", "crit", "Kritisch"}, {"quittiert", "bestaetigt", "Bestätigt"}, {"warn", "warn", "Warnung"},
	{"unknown", "unknown", "Unbekannt"}, {"wartung", "wartung", "Wartung"}, {"ok", "ok", "OK"},
}

var sonnenRang = map[string]int{"crit": 0, "quittiert": 1, "warn": 2, "unknown": 3, "wartung": 4, "ok": 5}

// pfadVon: Gruppen über einem Gerät, ohne den Mandanten an der Wurzel.
func (f *fenster) pfadVon(key string) string {
	var teile []string
	e := f.eintrag(key)
	for n := 0; e != nil && e.eltern != "" && n < 50; n++ {
		e = f.eintrag(e.eltern)
		if e != nil && e.eltern != "" {
			teile = append([]string{e.knoten.Name}, teile...)
		}
	}
	return strings.Join(teile, " › ")
}

func (f *fenster) abschnittTitel(hdc uintptr, t string, x, y, r int32) {
	pSetTextCharacterExtra.Call(hdc, uintptr(f.s(1)))
	schreiben(hdc, strings.ToUpper(t), rect{x, y, r, y + f.s(18)}, f.sch.t13b, th.f.Leise, 0)
	pSetTextCharacterExtra.Call(hdc, 0)
}

func (a *app) uebersichtMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	f.uebZiele = f.uebZiele[:0]
	p := f.s(16)
	y := p
	zahl := map[string]int{}
	type geraet struct {
		key, name, status string
	}
	var probleme []geraet
	for _, e := range f.eintraege {
		if e.knoten.Art != desktop.KnotenGeraet {
			continue
		}
		st := desktop.SonnenStatus(e.knoten)
		zahl[st]++
		if st != "ok" && st != "wartung" {
			probleme = append(probleme, geraet{e.key, e.knoten.Name, st})
		}
	}
	sort.SliceStable(probleme, func(i, j int) bool {
		if sonnenRang[probleme[i].status] != sonnenRang[probleme[j].status] {
			return sonnenRang[probleme[i].status] < sonnenRang[probleme[j].status]
		}
		return strings.ToLower(probleme[i].name) < strings.ToLower(probleme[j].name)
	})

	f.abschnittTitel(hdc, "Geräte", p, y, r.Right-p)
	y += f.s(18) + f.s(8)
	gap := f.s(8)
	kw := (r.Right - 2*p - 2*gap) / 3
	kh := f.s(72)
	for i, k := range kachelStatus {
		x := p + int32(i%3)*(kw+gap)
		ky := y + int32(i/3)*(kh+gap)
		kr := rect{x, ky, x + kw, ky + kh}
		an := th.f.AnzeigeFuer(k.anzeige)
		n := zahl[k.sonne]
		fg := th.f.Leise
		switch {
		case n > 0 && (k.sonne == "crit" || k.sonne == "warn"):
			rund(hdc, kr, f.s(6), an.Hauch, an.Farbe, true, true, false)
			fg = th.f.Tinte
		case n > 0:
			rund(hdc, kr, f.s(6), th.f.Flaeche, th.f.Linie, true, true, false)
			fg = th.f.Tinte
		default:
			rund(hdc, kr, f.s(6), th.f.Flaeche, th.f.LinieZart, true, true, false)
		}
		farbe := an.Farbe
		if n == 0 {
			farbe = mischen(an.Farbe, th.f.Flaeche, 45)
		}
		form(hdc, an.Form, farbe, x+f.s(12), ky+f.s(12)+(f.s(32)-f.s(16))/2, f.s(16))
		schreiben(hdc, strconv.Itoa(n), rect{x + f.s(12) + f.s(16) + f.s(8), ky + f.s(12), kr.Right - f.s(8), ky + f.s(12) + f.s(32)}, f.sch.t25b, fg, 0)
		schreiben(hdc, k.wort, rect{x + f.s(12), ky + f.s(12) + f.s(32), kr.Right - f.s(8), kr.Bottom - f.s(8)}, f.sch.t13, th.f.Leise, 0)
	}
	y += 2*kh + gap + f.s(24)

	f.abschnittTitel(hdc, "Aktuell", p, y, r.Right-p)
	y += f.s(18) + f.s(8)
	if len(probleme) == 0 {
		an := th.f.AnzeigeFuer("ok")
		form(hdc, an.Form, an.Farbe, p, y+(f.s(24)-f.s(12))/2, f.s(12))
		schreiben(hdc, "Alles in Ordnung: kein Gerät mit Problem.", rect{p + f.s(12) + f.s(8), y, r.Right - p, y + f.s(24)}, f.sch.t13, th.f.Leise, 0)
		return
	}
	zh := f.s(36)
	for i, g := range probleme {
		if y+zh > r.Bottom-p {
			rest := len(probleme) - i
			schreiben(hdc, "… und "+strconv.Itoa(rest)+" weitere", rect{p, y, r.Right - p, y + f.s(24)}, f.sch.t13, th.f.Leise, 0)
			break
		}
		zr := rect{p, y, r.Right - p, y + zh}
		f.uebZiele = append(f.uebZiele, ziel{zr, "geraet", g.key})
		hover := len(f.uebZiele)-1 == f.uebUeber
		anz := g.status
		if anz == "quittiert" {
			anz = "bestaetigt"
		}
		an := th.f.AnzeigeFuer(anz)
		bg := th.f.Zart
		if hover || g.key == f.dashHost {
			bg = th.f.MarkeHauch
		}
		fuellen(hdc, zr, bg)
		fuellen(hdc, rect{zr.Left, zr.Top, zr.Left + f.s(3), zr.Bottom}, an.Farbe)
		x := zr.Left + f.s(3) + f.s(12)
		form(hdc, an.Form, an.Farbe, x, y+(zh-f.s(12))/2, f.s(12))
		x += f.s(12) + f.s(12)
		w := min(breite(hdc, g.name, f.sch.t16b), zr.Right-x-f.s(8))
		schreiben(hdc, g.name, rect{x, y, x + w + 1, y + zh}, f.sch.t16b, th.f.Tinte, 0)
		x += w + f.s(12)
		if pf := f.pfadVon(g.key); pf != "" && x < zr.Right-f.s(40) {
			schreiben(hdc, pf, rect{x, y, zr.Right - f.s(8), y + zh}, f.sch.t13, th.f.Leise, 0)
		}
		y += zh + f.s(4)
	}
}
