// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite „Wartung“ wie web/src/WartungSeite.tsx: oben die laufenden
// Wartungen mit „Beenden“, darunter die Wartungsfenster mit Pausieren,
// Fortsetzen und Löschen. Anlegen und Bearbeiten (das Formular mit
// Wiederholung, Wochentagen und Zeitzone) bleiben im Browser.

import (
	"context"
	"strings"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

// wartungBereich: Daten der Seite im gewählten Bereich, nach der Suche gefiltert.
func (a *app) wartungBereich() (w desktop.Wartungen, geladen bool, fehler string, mehrere bool, rollen, namen map[string]string) {
	f := a.f
	a.mu.Lock()
	alle, geladen, fehler := a.wartungen, a.wartungGeladen, a.wartungFehler
	ms := a.stand.Mandanten
	a.mu.Unlock()
	ids := desktop.BereichIDs(ms, f.mandant, f.mitUnter)
	rollen, namen = map[string]string{}, map[string]string{}
	for _, m := range ms {
		rollen[m.ID], namen[m.ID] = m.Rolle, m.Name
	}
	w = alle.ImBereich(ids)
	if q := strings.ToLower(strings.TrimSpace(getText(f.suche))); q != "" {
		var r desktop.Wartungen
		for _, l := range w.Laufend {
			if strings.Contains(strings.ToLower(l.Ziel()+" "+l.Grund), q) {
				r.Laufend = append(r.Laufend, l)
			}
		}
		for _, x := range w.Fenster {
			if strings.Contains(strings.ToLower(x.Name+" "+x.Beschreibung()+" "+x.Grund), q) {
				r.Fenster = append(r.Fenster, x)
			}
		}
		w = r
	}
	return w, geladen, fehler, len(ids) > 1, rollen, namen
}

// kleinerKnopf: Knopf wie .knopf.knopf-klein (Höhe 30, 13 px); gefahr wie .knopf-gefahr.
func (f *fenster) kleinerKnopf(hdc uintptr, text string, x, y int32, hover, gefahr bool) rect {
	w := breite(hdc, text, f.sch.t13) + 2*f.s(8)
	r := rect{x, y, x + w, y + f.s(30)}
	fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
	switch {
	case gefahr && hover:
		fg, bg, rand = th.f.TextKrit, th.f.KritHauch, th.f.Krit
	case gefahr:
		fg, rand = th.f.TextKrit, mischen(th.f.Krit, th.f.Linie, 45)
	case hover:
		rand, bg = th.f.Leise, th.f.Zart
	}
	rund(hdc, r, f.s(3), bg, rand, true, true, false)
	schreiben(hdc, text, r, f.sch.t13, fg, dtCenter)
	return r
}

// marke: wie .marke bzw. .mandant-marke (13 px, Höhe 22).
func (f *fenster) marke(hdc uintptr, text string, x, y int32, fg, bg, rand desktop.RGB, fett bool) int32 {
	font := f.sch.t13
	if fett {
		font = f.sch.t13b
	}
	w := breite(hdc, text, font) + 2*f.s(8)
	r := rect{x, y, x + w, y + f.s(22)}
	rund(hdc, r, f.s(3), bg, rand, true, rand != bg, false)
	schreiben(hdc, text, r, font, fg, dtCenter)
	return w
}

// panelKopf: wie .panel-kopf (--zart, Titel 13 px fett mittig, Linie unten).
func (f *fenster) panelKopf(hdc uintptr, r rect, titel string) {
	fuellen(hdc, r, th.f.Zart)
	waagrecht(hdc, r.Left, r.Right, r.Bottom-1, th.f.LinieZart)
	schreiben(hdc, titel, r, f.sch.t13b, th.f.Tinte, dtCenter)
}

func (a *app) wartungMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Grund)
	f.wartZiele = f.wartZiele[:0]
	w, geladen, fehler, mehrere, rollen, namen := a.wartungBereich()
	darf := func(m string) bool { return desktop.DarfAendern(rollen[m]) }
	ziel := func(zr rect, art, wert string) bool {
		f.wartZiele = append(f.wartZiele, ziel{zr, art, wert})
		return len(f.wartZiele)-1 == f.wartUeber
	}
	// Breite wie .ansicht: Inhalt bis zum Rand, Panels mit Lücke 12
	x0, x1 := int32(0), r.Right
	y := -f.wartOff
	pad, kopfH := f.s(12), f.s(32)

	// Laufende Wartungen ------------------------------------------------------
	laufend := func(y0 int32) int32 {
		zeichnen := y0 > -1<<19
		y := y0 + f.s(8)
		text := func(t string, font uintptr, fg desktop.RGB) {
			h := hoeheText(hdc, t, font, x1-x0-2*pad)
			if zeichnen {
				schreiben(hdc, t, rect{x0 + pad, y, x1 - pad, y + h}, font, fg, dtWordBreak)
			}
			y += h
		}
		switch {
		case !geladen && fehler != "":
			text("Laden fehlgeschlagen: "+fehler, f.sch.t13, th.f.TextKrit)
		case !geladen:
			text("Lädt …", f.sch.t13, th.f.Leise)
		case len(w.Laufend) == 0:
			y += f.s(8)
			text("Gerade ist nichts in Wartung.", f.sch.t16, th.f.Leise)
			y += f.s(8)
		default:
			// Tabelle wie .tabelle: Kopf --zart, Zeilen mit --linie-zart
			tx0, tx1 := x0+pad, x1-pad
			breit := tx1 - tx0
			sp := []int32{tx0 + f.s(12), tx0 + breit*40/100, tx0 + breit*58/100, tx0 + breit*78/100}
			kh := f.s(34)
			if zeichnen {
				rund(hdc, rect{tx0, y, tx1, y + kh}, 0, th.f.Zart, th.f.Linie, true, false, false)
				for i, t := range []string{"Ziel", "Bis", "Grund", "Von"} {
					schreiben(hdc, t, rect{sp[i], y, tx1, y + kh}, f.sch.t13b, th.f.Leise, 0)
				}
				waagrecht(hdc, tx0, tx1, y+kh-1, th.f.Linie)
			}
			top := y
			y += kh
			zh := f.s(46)
			for i, l := range w.Laufend {
				if zeichnen {
					rechts := tx1
					if darf(l.MandantID) {
						bw := breite(hdc, "Beenden", f.sch.t13) + 2*f.s(8)
						bx := tx1 - f.s(12) - bw
						hover := ziel(rect{bx, y + (zh-f.s(30))/2, bx + bw, y + (zh-f.s(30))/2 + f.s(30)}, "beenden", l.ID)
						f.kleinerKnopf(hdc, "Beenden", bx, y+(zh-f.s(30))/2, hover, false)
						rechts = bx - f.s(8)
					}
					zx := sp[0]
					if mehrere {
						zx += f.marke(hdc, namen[l.MandantID], zx, y+(zh-f.s(22))/2, th.f.Leise, th.f.Flaeche, th.f.Linie, false) + f.s(8)
					}
					schreiben(hdc, l.Ziel(), rect{zx, y, sp[1] - f.s(12), y + zh}, f.sch.t13, th.f.Tinte, 0)
					schreiben(hdc, desktop.WartungZeit(l.Bis, ""), rect{sp[1], y, sp[2] - f.s(12), y + zh}, f.sch.t13, th.f.Tinte, 0)
					schreiben(hdc, strich(l.Grund), rect{sp[2], y, sp[3] - f.s(12), y + zh}, f.sch.t13, th.f.Tinte, 0)
					von := ""
					if l.Von != nil {
						von = *l.Von
					}
					schreiben(hdc, strich(von), rect{sp[3], y, rechts, y + zh}, f.sch.t13, th.f.Tinte, 0)
					if i < len(w.Laufend)-1 {
						waagrecht(hdc, tx0, tx1, y+zh-1, th.f.LinieZart)
					}
				}
				y += zh
			}
			if zeichnen {
				rund(hdc, rect{tx0, top, tx1, y}, 0, th.f.Flaeche, th.f.Linie, false, true, false)
			}
			y += f.s(8)
		}
		y += f.s(4)
		hw := min(x1-x0-2*pad, f.s(560)) // max-width 62ch
		h := hoeheText(hdc, wartungHinweis, f.sch.t13, hw)
		if zeichnen {
			schreiben(hdc, wartungHinweis, rect{x0 + pad, y, x0 + pad + hw, y + h}, f.sch.t13, th.f.Leise, dtWordBreak)
		}
		y += h + f.s(8)
		return y - y0
	}

	// Wartungsfenster ---------------------------------------------------------
	fenster := func(y0 int32) int32 {
		zeichnen := y0 > -1<<19
		y := y0 + f.s(8)
		tw := x1 - x0 - 2*pad
		zeile := func(t string, font uintptr, fg desktop.RGB) {
			h := hoeheText(hdc, t, font, tw)
			if zeichnen {
				schreiben(hdc, t, rect{x0 + pad, y, x1 - pad, y + h}, font, fg, dtWordBreak)
			}
			y += h
		}
		if !geladen {
			return y - y0 + f.s(8)
		}
		if len(w.Fenster) == 0 {
			y += f.s(8)
			zeile("Noch keine Wartungsfenster. Ein Fenster setzt Geräte, Sensoren oder ganze Gruppen zu festen Zeiten in Wartung, "+
				"z. B. jeden Monat nach dem Patchday.", f.sch.t16, th.f.Leise)
			return y - y0 + f.s(16)
		}
		for i, x := range w.Fenster {
			y += f.s(8)
			// Kopf: Name, Marke „läuft bis …“ bzw. „pausiert“, Mandant
			if zeichnen {
				nx := x0 + pad
				fg := th.f.Tinte
				if !x.Aktiv {
					fg = th.f.Leise
				}
				nw := min(breite(hdc, x.Name, f.sch.t16b), x1-pad-nx)
				schreiben(hdc, x.Name, rect{nx, y, nx + nw + 1, y + f.s(24)}, f.sch.t16b, fg, 0)
				nx += nw + f.s(8)
				my := y + f.s(1)
				switch {
				case x.LaeuftBis != nil:
					nx += f.marke(hdc, "läuft bis "+desktop.WartungZeit(*x.LaeuftBis, x.Zeitzone), nx, my, th.f.TextWartung, th.f.WartHauch, th.f.WartHauch, true) + f.s(8)
				case !x.Aktiv:
					nx += f.marke(hdc, "pausiert", nx, my, th.f.Tinte, th.f.Flaeche, th.f.Flaeche, true) + f.s(8)
				}
				if mehrere {
					f.marke(hdc, namen[x.MandantID], nx, my, th.f.Leise, th.f.Flaeche, th.f.Linie, false)
				}
			}
			y += f.s(24) + f.s(2)
			zeile(x.Beschreibung(), f.sch.t13, th.f.Leise)
			if x.Aktiv && len(x.Naechstes) > 0 && x.LaeuftBis == nil {
				zeile("nächstes Mal: "+desktop.WartungZeit(x.Naechstes[0], x.Zeitzone), f.sch.t13, th.f.Leise)
			}
			if x.Grund != "" {
				zeile("Grund: "+x.Grund, f.sch.t13, th.f.Leise)
			}
			if darf(x.MandantID) {
				y += f.s(8)
				if zeichnen {
					bx := x0 + pad
					for _, k := range []struct{ text, art string }{
						{"Bearbeiten", "bearbeiten"}, {map[bool]string{true: "Pausieren", false: "Fortsetzen"}[x.Aktiv], "pause"}, {"Löschen", "loeschen"},
					} {
						bw := breite(hdc, k.text, f.sch.t13) + 2*f.s(8)
						hover := ziel(rect{bx, y, bx + bw, y + f.s(30)}, k.art, x.ID)
						f.kleinerKnopf(hdc, k.text, bx, y, hover, k.art == "loeschen")
						bx += bw + f.s(8)
					}
				}
				y += f.s(30)
			}
			y += f.s(8)
			if zeichnen && i < len(w.Fenster)-1 {
				waagrecht(hdc, x0+pad, x1-pad, y, th.f.LinieZart)
			}
			y += 1
		}
		return y - y0 + f.s(4)
	}

	zeichne := func(titel string, inhalt func(int32) int32, knopf func(kr rect)) {
		oben := y
		kh := kopfH
		if knopf != nil {
			kh = f.s(40) // Platz für .knopf-klein mit Abstand wie im Web
		}
		h := inhalt(-1 << 20)
		unten := oben + kh + h
		rund(hdc, rect{x0, oben, x1, unten}, f.s(3), th.f.Flaeche, th.f.Linie, true, true, false)
		f.panelKopf(hdc, rect{x0 + 1, oben + 1, x1 - 1, oben + kh}, titel)
		if knopf != nil {
			knopf(rect{x0, oben, x1, oben + kh})
		}
		inhalt(oben + kh)
		y = unten + f.s(12)
	}
	zeichne("Laufende Wartungen", laufend, nil)
	var anlegen func(kr rect)
	if geladen && darf(f.mandant) {
		anlegen = func(kr rect) {
			bw := breite(hdc, "Fenster anlegen", f.sch.t13) + 2*f.s(8)
			bx := kr.Right - f.s(8) - bw
			by := kr.Top + (kr.Bottom-kr.Top-f.s(30))/2
			hover := ziel(rect{bx, by, bx + bw, by + f.s(30)}, "anlegen", "")
			f.kleinerKnopf(hdc, "Fenster anlegen", bx, by, hover, false)
		}
	}
	zeichne("Wartungsfenster", fenster, anlegen)
	f.wartHoehe = y + f.wartOff
}

const wartungHinweis = "In der Wartung laufen Messungen weiter; es gehen keine neuen Alarme und keine Erinnerungen hinaus, " +
	"Entwarnungen schon. Eine vorzeitig beendete Wartung aus einem Fenster beginnt erst beim nächsten Termin wieder."

func strich(s string) string {
	if strings.TrimSpace(s) == "" {
		return "–"
	}
	return s
}

func hoeheText(hdc uintptr, t string, font uintptr, w int32) int32 {
	if w <= 0 {
		return 0
	}
	return hoehe(hdc, t, font, w)
}

// wartungScrollen: Bildlauf der Seite (Mausrad).
func (f *fenster) wartungScrollen(d int32) {
	var r rect
	pGetClientRect.Call(uintptr(f.wartungF), uintptr(unsafe.Pointer(&r)))
	f.wartOff = max(0, min(f.wartOff+d, f.wartHoehe-r.Bottom))
	pInvalidateRect.Call(uintptr(f.wartungF), 0, 0)
}

// wartungLaden: Seite neu abfragen (beim Öffnen und nach jeder Änderung).
func (a *app) wartungLaden() {
	a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
		w, err := cl.WartungenHolen(ctx, "")
		a.mu.Lock()
		if err == nil {
			a.wartungen, a.wartungGeladen, a.wartungFehler = w, true, ""
		} else if !a.wartungGeladen {
			a.wartungFehler = fehlerText(err)
		}
		a.mu.Unlock()
		return nil
	}, func(error) {
		if a.f != nil {
			pInvalidateRect.Call(uintptr(a.f.wartungF), 0, 0)
		}
	})
}

func (a *app) wartungKlick(z ziel) {
	f := a.f
	a.mu.Lock()
	alle := a.wartungen
	a.mu.Unlock()
	fertig := func(was, gut string) func(error) {
		return func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Wartung", was+" fehlgeschlagen: "+fehlerText(err), true)
			} else {
				setStatusText(f, gut)
			}
			a.wartungLaden()
			a.jetztAbfragen()
		}
	}
	switch z.art {
	case "anlegen":
		a.oeffnen(desktop.WebPfad("/wartung", f.mandant, f.mitUnter))
		return
	case "bearbeiten":
		a.oeffnen(desktop.WebPfad("/wartung", f.mandant, f.mitUnter))
		return
	case "beenden":
		for _, l := range alle.Laufend {
			if l.ID == z.wert {
				if !bestaetigenFrage(f.hwnd, "Wartung beenden?", "„"+l.Ziel()+"“ ist in Wartung bis "+desktop.WartungZeit(l.Bis, "")+
					". Danach lösen Probleme wieder Alarme aus.", "Wartung beenden") {
					return
				}
				a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.LaufendBeenden(ctx, l) }, fertig("Beenden", "Wartung für „"+l.Ziel()+"“ beendet."))
			}
		}
	case "pause", "loeschen":
		for _, x := range alle.Fenster {
			if x.ID != z.wert {
				continue
			}
			if z.art == "loeschen" {
				if !bestaetigenDialog(f.hwnd, "Wartungsfenster löschen?", "Das Fenster „"+x.Name+
					"“ verschwindet. Eine laufende Wartung daraus endet sofort. Das lässt sich nicht rückgängig machen.", x.Name+" löschen") {
					return
				}
				a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.FensterLoeschen(ctx, x.ID) }, fertig("Löschen", "Wartungsfenster „"+x.Name+"“ gelöscht."))
				return
			}
			was, gut := "Pausieren", "Wartungsfenster „"+x.Name+"“ pausiert."
			if !x.Aktiv {
				was, gut = "Fortsetzen", "Wartungsfenster „"+x.Name+"“ läuft wieder nach Plan."
			}
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.FensterAktiv(ctx, x, !x.Aktiv) }, fertig(was, gut))
		}
	}
}
