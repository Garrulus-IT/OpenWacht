// SPDX-License-Identifier: AGPL-3.0-only

package main

// Modale Dialoge nach dem Corporate Design: Titel 20/700, Kontextzeile in
// --leise, Beschriftung über dem Feld, Felder 32 hoch mit Rand --linie und
// Radius 3 (Fokus 2 px --marke), Schwellen paarweise nebeneinander, Knöpfe
// unten rechts (Primär --marke, Gefahr --text-krit), Fehler als Streifen mit
// 4 px --krit. Gespeichert wird im Hintergrund; der Dialog bleibt offen, bis
// die Zentrale zugestimmt hat.

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

const (
	bsOwnerDraw       = 0x000B
	wmDrawItem        = 0x002B
	wmCtlColorListbox = 0x0134
	enSetFocus        = 0x0100
	enKillFocus       = 0x0200
	odsSelected       = 0x0001
	odsDisabled       = 0x0004
	odsFocus          = 0x0010
	odtButton         = 4
)

type drawItemStruct struct {
	CtlType, CtlID, ItemID, ItemAction, ItemState uint32
	HwndItem                                      uintptr
	Hdc                                           uintptr
	Rc                                            rect
	ItemData                                      uintptr
}

// dlgFeld: ein Feld im Dialog.
type dlgFeld struct {
	schluessel, beschriftung string
	art                      desktop.FeldArt
	texte, werte             []string // Auswahl: angezeigter Text und Wert
	hinweis                  string
	aus                      bool   // nicht änderbar
	geheim                   bool   // Eingabe verdeckt (Token)
	halb                     bool   // halbe Breite (paarweise nebeneinander)
	aenderung                func() // Auswahl geändert
	ctrl                     syscall.Handle
	label, rahmen            rect
	hintY                    int32
	an                       bool // Ja/Nein
	sel                      int  // Auswahl: gewählter Eintrag
}

type dialog struct {
	hwnd, owner      syscall.Handle
	titel            string
	einleitung       string
	dpi              int32
	sch              schriften
	felder           []*dlgFeld
	kinder           []syscall.Handle
	fehler           string
	fehlerFeld       string
	fehlerY, knopfY  int32
	ok, abbr         syscall.Handle
	okText           string
	gefahr           bool // Knopf löscht etwas
	nurOK            bool // nur ein Knopf (Meldung)
	werte            map[string]string
	aufbau           func(d *dialog)
	speichern        func(d *dialog, fertig func(error))
	fertig, ergebnis bool
	beschaeftigt     bool
	einleitungH      int32
	fehlerPraefix    string      // vor einer Meldung beim Speichern
	nachher          chan func() // Ergebnisse aus imHintergrund
	leeren           string      // dieses Feld beim nächsten Aufbau leeren (Passwort nach Fehler)
	fokus            string      // Feld, das beim Öffnen den Fokus bekommt
}

const wmDialogFertig = wmApp + 5

// imHintergrund: fn in einer eigenen Goroutine, fertig danach im Dialog
// (ohne die App, z. B. beim Anmelden vor dem Hauptfenster).
func (d *dialog) imHintergrund(fn func() error, fertig func(error)) {
	if d.nachher == nil {
		d.nachher = make(chan func(), 4)
	}
	go func() {
		err := fn()
		d.nachher <- func() { fertig(err) }
		pPostMessageW.Call(uintptr(d.hwnd), wmDialogFertig, 0, 0)
	}()
}

var (
	aktiverDialog *dialog
	dialogKlasse  bool
)

func (d *dialog) s(px int32) int32 { return px * d.dpi / 96 }

const (
	dlgBreite = 480
	dlgRand   = 24
)

func neuerDialog(owner syscall.Handle, titel string) *dialog {
	return &dialog{owner: owner, titel: titel, dpi: dpiVon(owner), werte: map[string]string{}, okText: "Speichern"}
}

// feld fügt ein Feld hinzu (nur in aufbau aufrufen).
func (d *dialog) feld(schluessel, beschriftung string, art desktop.FeldArt, hinweis string) *dlgFeld {
	f := &dlgFeld{schluessel: schluessel, beschriftung: beschriftung, art: art, hinweis: hinweis}
	d.felder = append(d.felder, f)
	return f
}

// auswahl: Feld mit festen Werten (texte werden angezeigt).
func (d *dialog) auswahl(schluessel, beschriftung string, texte, werte []string, hinweis string) *dlgFeld {
	f := d.feld(schluessel, beschriftung, desktop.FeldAuswahl, hinweis)
	f.texte, f.werte = texte, werte
	return f
}

// anlegen: Fenster und Steuerelemente nach aufbau, Größe passend, mittig.
func (d *dialog) anlegen() {
	inst, _, _ := pGetModuleHandleW.Call(0)
	if !dialogKlasse {
		cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{WndProc: syscall.NewCallback(dialogProc), Instance: syscall.Handle(inst), ClassName: utf16("OpenWachtDialog"),
			Cursor: syscall.Handle(cursor)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		dialogKlasse = true
	}
	d.sch.setzen(d.dpi)
	aktiverDialog = d
	h, _, _ := pCreateWindowExW.Call(wsExDlgModalFrame|wsExControlParent, uintptr(unsafe.Pointer(utf16("OpenWachtDialog"))),
		uintptr(unsafe.Pointer(utf16(d.titel))), wsPopup|wsCaption|wsSysMenu|wsClipChildren, 0, 0, uintptr(d.s(dlgBreite)), uintptr(d.s(300)),
		uintptr(d.owner), 0, inst, 0)
	d.hwnd = syscall.Handle(h)
	titelleiste(d.hwnd)
	d.aufbauen()
	var or, wr rect
	if d.owner != 0 {
		pGetWindowRect.Call(uintptr(d.owner), uintptr(unsafe.Pointer(&or)))
	} else {
		pSystemParametersInfoW.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&or)), 0)
	}
	pGetWindowRect.Call(uintptr(d.hwnd), uintptr(unsafe.Pointer(&wr)))
	w, hh := wr.Right-wr.Left, wr.Bottom-wr.Top
	x := or.Left + (or.Right-or.Left-w)/2
	y := or.Top + max((or.Bottom-or.Top-hh)/3, d.s(48)) // nie über der Markenleiste
	pSetWindowPos.Call(uintptr(d.hwnd), 0, uintptr(x), uintptr(max(y, 0)), 0, 0, swpNoSize|swpNoZOrder)
}

// lesen übernimmt die Eingaben in d.werte.
func (d *dialog) lesen() {
	for _, f := range d.felder {
		if f.ctrl == 0 {
			continue
		}
		switch f.art {
		case desktop.FeldAuswahl:
			if f.sel >= 0 && f.sel < len(f.werte) {
				d.werte[f.schluessel] = f.werte[f.sel]
			}
		case desktop.FeldJaNein:
			d.werte[f.schluessel] = map[bool]string{true: "ja", false: ""}[f.an]
		default:
			d.werte[f.schluessel] = getText(f.ctrl)
		}
	}
}

// aufbauen legt alle Steuerelemente neu an (auch nach Wechsel des Typs).
func (d *dialog) aufbauen() {
	if len(d.felder) > 0 {
		d.lesen()
	}
	if d.leeren != "" {
		d.werte[d.leeren], d.leeren = "", ""
	}
	for _, h := range d.kinder {
		pDestroyWindow.Call(uintptr(h))
	}
	d.kinder, d.felder = nil, nil
	d.aufbau(d)

	p := d.s(dlgRand)
	innen := d.s(dlgBreite) - 2*p
	neu := func(klasse, text string, style, ex uint32, id int) syscall.Handle {
		h := kind(d.hwnd, klasse, text, style, ex, id)
		send(h, wmSetFont, d.sch.t16, 1)
		d.kinder = append(d.kinder, h)
		return h
	}
	hdc, _, _ := pGetDC.Call(uintptr(d.hwnd))
	y := p + d.s(28) // Titel
	d.einleitungH = 0
	if d.einleitung != "" {
		y += d.s(4)
		d.einleitungH = hoehe(hdc, d.einleitung, d.sch.t13, innen)
		y += d.einleitungH
	}
	y += d.s(24)
	halbB := (innen - d.s(16)) / 2
	for i := 0; i < len(d.felder); i++ {
		zeile := []*dlgFeld{d.felder[i]}
		if d.felder[i].halb && i+1 < len(d.felder) && d.felder[i+1].halb {
			zeile = append(zeile, d.felder[i+1])
			i++
		}
		zeileH := int32(0)
		for j, g := range zeile {
			x, w := p, innen
			if len(zeile) == 2 {
				w = halbB
				x = p + int32(j)*(halbB+d.s(16))
			}
			g.label = rect{x, y, x + w, y + d.s(20)}
			fy := y + d.s(20) + d.s(4)
			fh := d.s(32)
			id := 1000 + indexVon(d.felder, g)
			wert := d.werte[g.schluessel]
			switch g.art {
			case desktop.FeldAuswahl:
				// selbst gezeichnet wie die Felder, Liste als schwebende Liste
				g.sel = 0
				for k := range g.texte {
					if g.werte[k] == wert {
						g.sel = k
					}
				}
				g.ctrl = neu("BUTTON", "", bsOwnerDraw|wsTabStop, 0, id)
				move(g.ctrl, x, fy, w, fh)
			case desktop.FeldJaNein:
				g.an = wert == "ja"
				g.ctrl = neu("BUTTON", g.beschriftung, bsOwnerDraw|wsTabStop, 0, id)
				move(g.ctrl, x, fy, w, fh)
				g.label = rect{} // Beschriftung steht neben dem Kästchen
			case desktop.FeldMehrzeilig:
				fh = d.s(80)
				g.ctrl = neu("EDIT", wert, wsTabStop|esMultiline|esAutoVScroll|esWantReturn|wsVScroll, 0, id)
				move(g.ctrl, x+d.s(8), fy+d.s(6), w-d.s(16), fh-d.s(12))
				send(g.ctrl, wmSetFont, d.sch.m13, 1)
			default:
				stil := uint32(wsTabStop | esAutoHScroll)
				if g.geheim {
					stil |= esPassword
				}
				g.ctrl = neu("EDIT", wert, stil, 0, id)
				eh := d.s(22)
				move(g.ctrl, x+d.s(8), fy+(fh-eh)/2, w-d.s(16), eh)
				if g.hinweis != "" {
					platzhalter(g.ctrl, g.hinweis, false)
				}
			}
			g.rahmen = rect{x, fy, x + w, fy + fh}
			if g.aus {
				enable(g.ctrl, false)
			}
			h := d.s(20) + d.s(4) + fh
			g.hintY = 0
			if g.hinweis != "" && (g.art == desktop.FeldAuswahl || g.art == desktop.FeldMehrzeilig) {
				g.hintY = fy + fh + d.s(4)
				h += d.s(4) + d.s(18)
			}
			zeileH = max(zeileH, h)
		}
		y += zeileH + d.s(16)
	}
	y += d.s(8)
	d.fehlerY = y
	if d.fehler != "" {
		y += hoehe(hdc, d.fehler, d.sch.t13, innen-d.s(4)-2*d.s(12)) + 2*d.s(8) + d.s(16)
	}
	pReleaseDC.Call(uintptr(d.hwnd), hdc)
	d.knopfY = y
	bh := d.s(32)
	d.ok = neu("BUTTON", d.okText, wsTabStop|bsOwnerDraw, 0, idOK)
	okB := knopfBreite(d, d.okText)
	right := p + innen
	if d.nurOK {
		d.abbr = 0
		move(d.ok, right-okB, y, okB, bh)
	} else {
		d.abbr = neu("BUTTON", "Abbrechen", wsTabStop|bsOwnerDraw, 0, idCancel)
		abB := knopfBreite(d, "Abbrechen")
		move(d.abbr, right-abB, y, abB, bh)
		move(d.ok, right-abB-d.s(8)-okB, y, okB, bh)
	}
	y += bh + p

	var wr, cr rect
	pGetWindowRect.Call(uintptr(d.hwnd), uintptr(unsafe.Pointer(&wr)))
	pGetClientRect.Call(uintptr(d.hwnd), uintptr(unsafe.Pointer(&cr)))
	rahmenH := (wr.Bottom - wr.Top) - cr.Bottom
	rahmenW := (wr.Right - wr.Left) - cr.Right
	pSetWindowPos.Call(uintptr(d.hwnd), 0, 0, 0, uintptr(d.s(dlgBreite)+rahmenW), uintptr(y+rahmenH), swpNoMove|swpNoZOrder)
	pInvalidateRect.Call(uintptr(d.hwnd), 0, 1)
	ziel := d.ok
	if d.gefahr && d.abbr != 0 {
		ziel = d.abbr // Enter löscht nie aus Versehen
	}
	for _, f := range d.felder {
		if f.ctrl != 0 && !f.aus {
			ziel = f.ctrl
			break
		}
	}
	if f := d.fehlerFeld; f != "" || d.fokus != "" {
		if f == "" {
			f, d.fokus = d.fokus, ""
		}
		for _, x := range d.felder {
			if x.schluessel == f {
				ziel = x.ctrl
			}
		}
	}
	pSetFocus.Call(uintptr(ziel))
}

func indexVon(l []*dlgFeld, f *dlgFeld) int {
	for i, x := range l {
		if x == f {
			return i
		}
	}
	return 0
}

func knopfBreite(d *dialog, t string) int32 {
	hdc, _, _ := pGetDC.Call(uintptr(d.hwnd))
	defer pReleaseDC.Call(uintptr(d.hwnd), hdc)
	return max(breite(hdc, t, d.sch.t13)+2*d.s(16), d.s(96))
}

// weiter: nächster Schritt im selben Fenster (z. B. Code nach dem Passwort):
// Felder neu, OK wieder frei, keine Meldung.
func (d *dialog) weiter() {
	d.beschaeftigt = false
	d.fehler, d.fehlerFeld = "", ""
	d.aufbauen()
	pInvalidateRect.Call(uintptr(d.ok), 0, 0)
}

func (d *dialog) fehlerZeigen(t string) {
	d.fehler = t
	d.aufbauen()
}

func (d *dialog) schliessen(ok bool) {
	d.ergebnis, d.fertig = ok, true
}

// zeigen: modal, bis gespeichert oder abgebrochen. true = gespeichert.
func (d *dialog) zeigen() bool {
	d.anlegen()
	if d.owner != 0 {
		enable(d.owner, false)
	}
	pShowWindow.Call(uintptr(d.hwnd), swShow)
	pSetForegroundWindow.Call(uintptr(d.hwnd))
	var m msg
	for !d.fertig {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			pPostQuitMessage.Call(0)
			break
		}
		// Esc bricht ab (IsDialogMessage tut das nur für echte Dialogklassen sicher)
		if m.Message == wmKeyDown && m.WParam == vkEscape {
			if r, _, _ := pGetAncestor.Call(uintptr(m.Hwnd), gaRoot); syscall.Handle(r) == d.hwnd && !d.beschaeftigt {
				d.schliessen(false)
				continue
			}
		}
		// ↑ ↓ in einem Auswahlfeld wechseln den Eintrag
		if m.Message == wmKeyDown && (m.WParam == vkUp || m.WParam == vkDown) {
			if f := d.feldVon(m.Hwnd); f != nil && f.art == desktop.FeldAuswahl && !f.aus {
				n := f.sel + map[bool]int{true: -1, false: 1}[m.WParam == vkUp]
				if n >= 0 && n < len(f.texte) {
					d.waehlen(f, n)
				}
				continue
			}
		}
		if dr, _, _ := pIsDialogMessageW.Call(uintptr(d.hwnd), uintptr(unsafe.Pointer(&m))); dr != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	if d.owner != 0 {
		enable(d.owner, true)
		pSetForegroundWindow.Call(uintptr(d.owner))
	}
	pDestroyWindow.Call(uintptr(d.hwnd))
	d.sch.frei()
	aktiverDialog = nil
	return d.ergebnis
}

func (d *dialog) feldVon(h syscall.Handle) *dlgFeld {
	for _, f := range d.felder {
		if f.ctrl == h {
			return f
		}
	}
	return nil
}

// waehlen setzt den Eintrag n eines Auswahlfelds (mit Folgen, z. B. Typwechsel).
func (d *dialog) waehlen(f *dlgFeld, n int) {
	if n == f.sel {
		return
	}
	d.lesen()
	f.sel = n
	d.werte[f.schluessel] = f.werte[n]
	pInvalidateRect.Call(uintptr(f.ctrl), 0, 0)
	if f.aenderung != nil {
		f.aenderung()
	}
}

// aufklappen: Liste eines Auswahlfelds unter dem Feld.
func (d *dialog) aufklappen(f *dlgFeld) {
	e := make([]listenEintrag, len(f.texte))
	for i, t := range f.texte {
		e[i] = listenEintrag{text: t, an: true, gewaehlt: i == f.sel}
	}
	p := point{f.rahmen.Left, f.rahmen.Bottom + d.s(4)}
	pClientToScreen.Call(uintptr(d.hwnd), uintptr(unsafe.Pointer(&p)))
	if i := schwebend(d.hwnd, e, p, f.rahmen.Right-f.rahmen.Left, false); i >= 0 {
		d.waehlen(f, i)
	}
	pSetFocus.Call(uintptr(f.ctrl))
}

func (d *dialog) okGedrueckt() {
	if d.beschaeftigt {
		return
	}
	d.lesen()
	if d.speichern == nil {
		d.schliessen(true)
		return
	}
	d.beschaeftigt = true
	pInvalidateRect.Call(uintptr(d.ok), 0, 0)
	d.fehlerFeld = ""
	d.speichern(d, func(err error) {
		d.beschaeftigt = false
		if d.fertig {
			return
		}
		pInvalidateRect.Call(uintptr(d.ok), 0, 0)
		if err != nil {
			p := d.fehlerPraefix
			if p == "" {
				p = "Speichern fehlgeschlagen: "
			}
			d.fehlerZeigen(p + fehlerText(err))
			return
		}
		d.schliessen(true)
	})
}

func (d *dialog) malen(hdc uintptr, r rect) {
	fuellen(hdc, r, th.f.Flaeche)
	p := d.s(dlgRand)
	innen := r.Right - 2*p
	schreiben(hdc, d.titel, rect{p, p, p + innen, p + d.s(28)}, d.sch.t20b, th.f.Tinte, 0)
	if d.einleitung != "" {
		y := p + d.s(28) + d.s(4)
		schreiben(hdc, d.einleitung, rect{p, y, p + innen, y + d.einleitungH}, d.sch.t13, th.f.Leise, dtWordBreak)
	}
	fokus, _, _ := pGetFocus.Call()
	for _, f := range d.felder {
		if f.label.Right > 0 {
			schreiben(hdc, f.beschriftung, f.label, d.sch.t13, th.f.Leise, 0)
		}
		if f.art != desktop.FeldAuswahl && f.art != desktop.FeldJaNein {
			bg := th.f.Flaeche
			if f.aus {
				bg = th.f.Zart
			}
			rand := th.f.Linie
			if f.schluessel == d.fehlerFeld {
				rand = th.f.Krit
			}
			rund(hdc, f.rahmen, d.s(3), bg, rand, true, true, false)
			if syscall.Handle(fokus) == f.ctrl {
				// Fokus: 2 px --marke
				rund(hdc, f.rahmen, d.s(3), 0, th.f.Marke, false, true, false)
				in := rect{f.rahmen.Left + 1, f.rahmen.Top + 1, f.rahmen.Right - 1, f.rahmen.Bottom - 1}
				rund(hdc, in, d.s(3), 0, th.f.Marke, false, true, false)
			}
		}
		if f.hintY > 0 {
			schreiben(hdc, f.hinweis, rect{f.rahmen.Left, f.hintY, f.rahmen.Right, f.hintY + d.s(18)}, d.sch.t13, th.f.Leise, 0)
		}
	}
	if d.fehler != "" {
		h := d.knopfY - d.s(16) - d.fehlerY
		fuellen(hdc, rect{p, d.fehlerY, p + innen, d.fehlerY + h}, th.f.KritHauch)
		fuellen(hdc, rect{p, d.fehlerY, p + d.s(4), d.fehlerY + h}, th.f.Krit)
		schreiben(hdc, d.fehler, rect{p + d.s(4) + d.s(12), d.fehlerY + d.s(8), p + innen - d.s(12), d.fehlerY + h}, d.sch.t13, th.f.Tinte, dtWordBreak)
	}
}

// knopfMalen: Knöpfe und Ja/Nein-Kästchen (Owner Draw).
func (d *dialog) knopfMalen(di *drawItemStruct) {
	hdc, r := di.Hdc, di.Rc
	fuellen(hdc, r, th.f.Flaeche)
	h := syscall.Handle(di.HwndItem)
	fokus := di.ItemState&odsFocus != 0
	aus := di.ItemState&odsDisabled != 0 || (h == d.ok && d.beschaeftigt)
	if h != d.ok && h != d.abbr {
		f := d.feldVon(h)
		if f == nil {
			return
		}
		if f.art == desktop.FeldAuswahl {
			// Auswahlfeld: wie ein Textfeld, Winkel rechts
			bg := th.f.Flaeche
			if f.aus {
				bg = th.f.Zart
			}
			rund(hdc, r, d.s(3), bg, th.f.Linie, true, true, false)
			if fokus {
				rund(hdc, r, d.s(3), 0, th.f.Marke, false, true, false)
				rund(hdc, rect{r.Left + 1, r.Top + 1, r.Right - 1, r.Bottom - 1}, d.s(3), 0, th.f.Marke, false, true, false)
			}
			t := ""
			if f.sel >= 0 && f.sel < len(f.texte) {
				t = f.texte[f.sel]
			}
			fg := th.f.Tinte
			if f.aus {
				fg = th.f.Leise
			}
			schreiben(hdc, t, rect{r.Left + d.s(8), r.Top, r.Right - d.s(32), r.Bottom}, d.sch.t16, fg, 0)
			chevron(hdc, r.Right-d.s(16), (r.Top+r.Bottom)/2, d.s(4), true, th.f.Leise)
			return
		}
		// Ja/Nein: Kästchen 16 mit Haken, Text daneben
		k := rect{r.Left, (r.Top + r.Bottom - d.s(16)) / 2, r.Left + d.s(16), (r.Top+r.Bottom-d.s(16))/2 + d.s(16)}
		if f.an {
			rund(hdc, k, d.s(3), th.f.Marke, th.f.Marke, true, true, false)
			haken(hdc, k, th.f.AufMarke, d.s(2))
		} else {
			rund(hdc, k, d.s(3), th.f.Flaeche, th.f.Leise, true, true, false)
		}
		if fokus {
			rund(hdc, rect{k.Left - 2, k.Top - 2, k.Right + 2, k.Bottom + 2}, d.s(3), 0, th.f.Marke, false, true, false)
		}
		schreiben(hdc, f.beschriftung, rect{k.Right + d.s(8), r.Top, r.Right, r.Bottom}, d.sch.t16, th.f.Tinte, 0)
		return
	}
	fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
	switch {
	case h == d.ok && d.gefahr:
		fg, rand = th.f.TextKrit, th.f.Krit
		if di.ItemState&odsSelected != 0 {
			bg = th.f.KritHauch
		}
	case h == d.ok:
		fg, bg, rand = th.f.AufMarke, th.f.Marke, th.f.Marke
		if di.ItemState&odsSelected != 0 {
			bg, rand = th.f.MarkeTief, th.f.MarkeTief
		}
	}
	if aus {
		fg, bg, rand = mischen(fg, th.f.Flaeche, 55), mischen(bg, th.f.Flaeche, 55), mischen(rand, th.f.Flaeche, 55)
	}
	rund(hdc, r, d.s(3), bg, rand, true, true, false)
	if fokus {
		in := rect{r.Left + 1, r.Top + 1, r.Right - 1, r.Bottom - 1}
		rund(hdc, in, d.s(3), 0, th.f.Marke, false, true, false)
	}
	t := getText(h)
	if d.beschaeftigt && h == d.ok {
		t = "Speichert …"
	}
	schreiben(hdc, t, r, d.sch.t13, fg, dtCenter)
}

// haken: Häkchen im Kästchen k.
func haken(hdc uintptr, k rect, c desktop.RGB, w int32) {
	stift, _, _ := pCreatePen.Call(psSolid, uintptr(w), cref(c))
	alt, _, _ := pSelectObject.Call(hdc, stift)
	b := k.Right - k.Left
	pMoveToEx.Call(hdc, uintptr(k.Left+b*3/14), uintptr(k.Top+b*8/14), 0)
	pLineTo.Call(hdc, uintptr(k.Left+b*6/14), uintptr(k.Top+b*11/14))
	pLineTo.Call(hdc, uintptr(k.Left+b*11/14), uintptr(k.Top+b*4/14))
	pSelectObject.Call(hdc, alt)
	pDeleteObject.Call(stift)
}

func dialogProc(hwnd, m, wp, lp uintptr) uintptr {
	d := aktiverDialog
	if d == nil || (d.hwnd != 0 && syscall.Handle(hwnd) != d.hwnd) {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	switch uint32(m) {
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		malen(hwnd, d.malen)
		return 0
	case wmDrawItem:
		di := zeigerAus[drawItemStruct](lp)
		if di.CtlType == odtButton {
			d.knopfMalen(di)
		}
		return 1
	case wmCommand:
		id, code := int(wp&0xffff), (wp>>16)&0xffff
		switch {
		case id == idOK && code == bnClicked:
			d.okGedrueckt()
		case id == idCancel:
			if !d.beschaeftigt {
				d.schliessen(false)
			}
		case id >= 1000 && id < 1000+len(d.felder):
			f := d.felder[id-1000]
			switch {
			case code == bnClicked && f.art == desktop.FeldAuswahl:
				d.aufklappen(f)
			case code == bnClicked && f.art == desktop.FeldJaNein:
				f.an = !f.an
				pInvalidateRect.Call(uintptr(f.ctrl), 0, 0)
			case code == enSetFocus || code == enKillFocus:
				pInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		return 0
	case wmClose:
		if !d.beschaeftigt {
			d.schliessen(false)
		}
		return 0
	case wmDialogFertig:
	leeren:
		for {
			select {
			case fn := <-d.nachher:
				fn()
			default:
				break leeren
			}
		}
		return 0
	case wmCtlColorEdit, wmCtlColorStatic, wmCtlColorListbox:
		pSetTextColor.Call(wp, cref(th.f.Tinte))
		pSetBkColor.Call(wp, cref(th.f.Flaeche))
		return pinsel(th.f.Flaeche)
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

// bestaetigenDialog: Rückfrage vor einer gefährlichen Aktion, z. B. Titel
// „Sensor löschen?“, Knopf „Ping löschen“ (docs/design/README.md §7).
func bestaetigenDialog(owner syscall.Handle, titel, text, knopf string) bool {
	d := neuerDialog(owner, titel)
	d.einleitung, d.okText, d.gefahr = text, knopf, true
	d.aufbau = func(*dialog) {}
	return d.zeigen()
}

// paarFelder: Felder, die nebeneinander stehen (jeweils Warnung | Kritisch).
var paarFelder = map[string]bool{
	"verlust_warnung": true, "verlust_kritisch": true, "antwort_warnung_ms": true, "antwort_kritisch_ms": true,
	"warnung_tage": true, "kritisch_tage": true, "warnung_ueber": true, "kritisch_ueber": true,
	"warnung_unter": true, "kritisch_unter": true, "abweichung_warnung_ms": true, "abweichung_kritisch_ms": true,
	"warnung_stunden": true, "kritisch_stunden": true, "mindestens": true, "hoechstens": true,
}

func paar(schluessel string) bool { return paarFelder[strings.TrimPrefix(schluessel, "z:")] }
