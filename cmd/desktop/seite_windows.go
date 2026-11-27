// SPDX-License-Identifier: AGPL-3.0-only

package main

// Gemeinsamer Rahmen für die Seiten, die die Weboberfläche nachbilden
// (Topologie, Zertifikate, Berichte, Sensor-Vorlagen, SNMP-Profile,
// Wandanzeigen, Benutzer und Mandanten): eine selbst gezeichnete, rollbare
// Fläche mit Panels wie .panel im Web, darin Absätze, Tabellen, Kennzahlen,
// Einträge und Knöpfe. Jede Seite beschreibt ihren Inhalt in einer Funktion
// malen(m); der Maler läuft zweimal (messen, dann zeichnen), damit die
// Panels ihre Höhe kennen, bevor ihr Rahmen gezeichnet wird. Daten lädt jede
// Seite selbst über laden(); die App ruft es beim Öffnen und alle 30 s.

import (
	"context"
	"strconv"
	"sync"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

// seitenDef: eine nachgebildete Seite.
type seitenDef struct {
	// laden holt die Daten (im Hintergrund); das Ergebnis bekommt malen.
	laden func(ctx context.Context, cl desktop.Client, f *fenster) (any, error)
	// malen beschreibt den Inhalt; daten ist nil, solange nichts geladen ist.
	malen func(m *maler, daten any)
	// klick: Klick auf ein Ziel (Knopf, Link, Umschalter) der Seite.
	klick func(z ziel, daten any)
}

var seiten = map[int]*seitenDef{}

// seitenStand: geladene Daten je Seite.
type seitenStand struct {
	mu      sync.Mutex
	daten   map[int]any
	fehler  map[int]string
	laedt   map[int]bool
	version int // steigt bei jedem Neuladen (z. B. Mandant gewechselt)
}

func (a *app) seiteDaten(s int) (any, string) {
	a.seitenSt.mu.Lock()
	defer a.seitenSt.mu.Unlock()
	return a.seitenSt.daten[s], a.seitenSt.fehler[s]
}

// seiteLaden: Daten der Seite neu holen, danach neu zeichnen.
func (a *app) seiteLaden(s int) {
	def := seiten[s]
	if def == nil || def.laden == nil || a.f == nil {
		return
	}
	f := a.f
	st := &a.seitenSt
	st.mu.Lock()
	if st.daten == nil {
		st.daten, st.fehler, st.laedt = map[int]any{}, map[int]string{}, map[int]bool{}
	}
	if st.laedt[s] {
		st.mu.Unlock()
		return
	}
	st.laedt[s] = true
	st.mu.Unlock()
	var d any
	a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
		var err error
		d, err = def.laden(ctx, cl, f)
		return err
	}, func(err error) {
		st.mu.Lock()
		st.laedt[s] = false
		if err != nil {
			st.fehler[s] = fehlerText(err)
		} else {
			st.daten[s], st.fehler[s] = d, ""
		}
		st.mu.Unlock()
		if f.seite == s {
			pInvalidateRect.Call(uintptr(f.seitenF), 0, 0)
		}
	})
}

// seiteVergessen: Daten verwerfen (z. B. nach Wechsel des Mandanten), dann laden.
func (a *app) seiteNeu(s int) {
	a.seitenSt.mu.Lock()
	if a.seitenSt.daten != nil {
		delete(a.seitenSt.daten, s)
		delete(a.seitenSt.fehler, s)
	}
	a.seitenSt.mu.Unlock()
	a.seiteLaden(s)
}

// --- Maler ---------------------------------------------------------------------

type knopfStil int

const (
	kNormal knopfStil = iota
	kHaupt
	kGefahr
)

// sKnopf: kleiner Knopf (.knopf-klein) mit Ziel.
type sKnopf struct {
	text, art, wert string
	stil            knopfStil
	aus             bool
}

// sZelle: Inhalt einer Tabellenzelle.
type sZelle struct {
	text      string
	klein     string      // zweite Zeile, leise
	farbe     desktop.RGB // 0 = Tinte
	fett      bool
	marke     string // Marke vor dem Text (z. B. Zustand)
	markeFg   desktop.RGB
	markeBg   desktop.RGB
	markeRand desktop.RGB
	form      string // Zustand als Form davor (crit, warn, …)
	mandant   string // Mandanten-Marke vor dem Text
	link      *ziel  // Text ist ein Link
	knoepfe   []sKnopf
}

type sSpalte struct {
	titel  string
	anteil int // Breite in Teilen
	rechts bool
}

type maler struct {
	f        *fenster
	hdc      uintptr
	zeichnen bool
	x0, x1   int32
	y        int32
	pad      int32
	// Panels: Höhe aus dem Messlauf
	panelNr  int
	hoehen   []int32
	panelTop int32
	inPanel  bool
	ziele    *[]ziel
	ueber    int
}

func (m *maler) s(px int32) int32 { return m.f.s(px) }

func (m *maler) ziel(r rect, art, wert string) bool {
	if !m.zeichnen {
		return false
	}
	*m.ziele = append(*m.ziele, ziel{r, art, wert})
	return len(*m.ziele)-1 == m.ueber
}

// innen: Textbereich (im Panel mit Rand).
func (m *maler) innen() (int32, int32) {
	if m.inPanel {
		return m.x0 + m.pad, m.x1 - m.pad
	}
	return m.x0, m.x1
}

// panel beginnt ein Panel wie .panel mit Kopf (.panel-kopf); knoepfe rechts im Kopf.
func (m *maler) panel(titel string, knoepfe ...sKnopf) {
	m.inPanel = true
	m.panelTop = m.y
	kh := m.s(32)
	if len(knoepfe) > 0 {
		kh = m.s(40)
	}
	if m.zeichnen {
		h := int32(0)
		if m.panelNr < len(m.hoehen) {
			h = m.hoehen[m.panelNr]
		}
		rund(m.hdc, rect{m.x0, m.y, m.x1, m.y + h}, m.s(3), th.f.Flaeche, th.f.Linie, true, true, false)
		if titel != "" {
			m.f.panelKopf(m.hdc, rect{m.x0 + 1, m.y + 1, m.x1 - 1, m.y + kh}, titel)
		}
		bx := m.x1 - m.s(8)
		for i := len(knoepfe) - 1; i >= 0; i-- {
			k := knoepfe[i]
			bw := breite(m.hdc, k.text, m.f.sch.t13) + 2*m.s(8)
			bx -= bw
			m.knopfMalen(k, bx, m.y+(kh-m.s(30))/2)
			bx -= m.s(8)
		}
	}
	if titel == "" {
		kh = 0
	}
	m.y += kh + m.s(8)
}

// ende schließt das Panel.
func (m *maler) ende() {
	m.y += m.s(8)
	if !m.zeichnen {
		m.hoehen = append(m.hoehen, m.y-m.panelTop)
	}
	m.panelNr++
	m.inPanel = false
	m.y += m.s(12)
}

func (m *maler) knopfMalen(k sKnopf, x, y int32) int32 {
	w := breite(m.hdc, k.text, m.f.sch.t13) + 2*m.s(8)
	if !m.zeichnen {
		return w
	}
	r := rect{x, y, x + w, y + m.s(30)}
	hover := false
	if !k.aus {
		hover = m.ziel(r, k.art, k.wert)
	}
	fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
	switch {
	case k.aus:
		fg = th.f.Leise
	case k.stil == kHaupt && hover:
		fg, bg, rand = th.f.AufMarke, th.f.MarkeTief, th.f.MarkeTief
	case k.stil == kHaupt:
		fg, bg, rand = th.f.AufMarke, th.f.Marke, th.f.Marke
	case k.stil == kGefahr && hover:
		fg, bg, rand = th.f.TextKrit, th.f.KritHauch, th.f.Krit
	case k.stil == kGefahr:
		fg, rand = th.f.TextKrit, mischen(th.f.Krit, th.f.Linie, 45)
	case hover:
		rand, bg = th.f.Leise, th.f.Zart
	}
	rund(m.hdc, r, m.s(3), bg, rand, true, true, false)
	schreiben(m.hdc, k.text, r, m.f.sch.t13, fg, dtCenter)
	return w
}

// knoepfe: Reihe kleiner Knöpfe.
func (m *maler) knoepfe(k ...sKnopf) {
	x, _ := m.innen()
	for _, kn := range k {
		x += m.knopfMalen(kn, x, m.y) + m.s(8)
	}
	m.y += m.s(30) + m.s(8)
}

// text: Absatz mit Umbruch.
func (m *maler) text(t string, font uintptr, fg desktop.RGB) {
	l, r := m.innen()
	h := hoeheText(m.hdc, t, font, r-l)
	if m.zeichnen {
		schreiben(m.hdc, t, rect{l, m.y, r, m.y + h}, font, fg, dtWordBreak)
	}
	m.y += h + m.s(6)
}

// klein: Hinweis wie .klein (13 px, leise, höchstens 62 Zeichen breit wie im Web nicht nötig).
func (m *maler) klein(t string) { m.text(t, m.f.sch.t13, th.f.Leise) }

// leer: wie .leer.
func (m *maler) leer(t string) {
	m.y += m.s(8)
	m.text(t, m.f.sch.t16, th.f.Leise)
	m.y += m.s(8)
}

// fehler: wie .meldung-fehler.
func (m *maler) fehler(t string) {
	l, r := m.innen()
	h := hoeheText(m.hdc, t, m.f.sch.t13, r-l-m.s(24)) + m.s(16)
	if m.zeichnen {
		fuellen(m.hdc, rect{l, m.y, r, m.y + h}, th.f.KritHauch)
		fuellen(m.hdc, rect{l, m.y, l + m.s(4), m.y + h}, th.f.Krit)
		schreiben(m.hdc, t, rect{l + m.s(16), m.y + m.s(8), r - m.s(8), m.y + h}, m.f.sch.t13, th.f.Tinte, dtWordBreak)
	}
	m.y += h + m.s(8)
}

// abschnitt: Zwischenüberschrift wie .abschnitt (20 px fett).
func (m *maler) abschnitt(t string) {
	l, r := m.innen()
	m.y += m.s(12)
	if m.zeichnen {
		schreiben(m.hdc, t, rect{l, m.y, r, m.y + m.s(26)}, m.f.sch.t20b, th.f.Tinte, 0)
	}
	m.y += m.s(26) + m.s(4)
}

// kleinTitel: wie .klein-titel (13 px fett, leise).
func (m *maler) kleinTitel(t string) {
	l, r := m.innen()
	m.y += m.s(4)
	if m.zeichnen {
		schreiben(m.hdc, t, rect{l, m.y, r, m.y + m.s(18)}, m.f.sch.t13b, th.f.Leise, 0)
	}
	m.y += m.s(18) + m.s(4)
}

// titelGross: wie .titel-gross.
func (m *maler) titelGross(t string) {
	l, r := m.innen()
	if m.zeichnen {
		schreiben(m.hdc, t, rect{l, m.y, r, m.y + m.s(32)}, m.f.sch.t25b, th.f.Tinte, 0)
	}
	m.y += m.s(32) + m.s(6)
}

// umschalter: Gruppe wie .umschalter; art bekommt den Index als Wert.
func (m *maler) umschalter(texte []string, aktiv int, art string) {
	x, _ := m.innen()
	h := m.s(30)
	for i, t := range texte {
		w := breite(m.hdc, t, m.f.sch.t13) + 2*m.s(12)
		if m.zeichnen {
			r := rect{x, m.y, x + w, m.y + h}
			hover := m.ziel(r, art, itoa(i))
			fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
			if i == aktiv {
				fg, bg = th.f.Flaeche, th.f.Tinte
			} else if hover {
				bg = th.f.Zart
			}
			rund(m.hdc, r, 0, bg, rand, true, true, false)
			schreiben(m.hdc, t, r, m.f.sch.t13, fg, dtCenter)
		}
		x += w - 1
	}
	m.y += h + m.s(8)
}

// auswahlFeld: Beschriftung und Feld mit Pfeil (klick öffnet eine Liste).
func (m *maler) auswahlFeld(beschriftung, wert, art string, breit int32) {
	l, _ := m.innen()
	if beschriftung != "" {
		if m.zeichnen {
			schreiben(m.hdc, beschriftung, rect{l, m.y, l + breit, m.y + m.s(18)}, m.f.sch.t13, th.f.Leise, 0)
		}
		m.y += m.s(20)
	}
	if m.zeichnen {
		r := rect{l, m.y, l + breit, m.y + m.s(32)}
		hover := m.ziel(r, art, "")
		rand := th.f.Linie
		if hover {
			rand = th.f.Leise
		}
		rund(m.hdc, r, m.s(3), th.f.Flaeche, rand, true, true, false)
		schreiben(m.hdc, wert, rect{r.Left + m.s(10), r.Top, r.Right - m.s(28), r.Bottom}, m.f.sch.t13, th.f.Tinte, 0)
		chevron(m.hdc, r.Right-m.s(16), (r.Top+r.Bottom)/2, m.s(4), true, th.f.Leise)
	}
	m.y += m.s(32) + m.s(8)
}

// kennzahlen: Kacheln wie .kennzahlen (.panel.kennzahl).
func (m *maler) kennzahlen(paare ...[2]string) {
	l, r := m.innen()
	n := int32(len(paare))
	if n == 0 {
		return
	}
	gap := m.s(12)
	w := (r - l - gap*(n-1)) / n
	h := m.s(64)
	if m.zeichnen {
		for i, p := range paare {
			x := l + int32(i)*(w+gap)
			kr := rect{x, m.y, x + w, m.y + h}
			rund(m.hdc, kr, m.s(3), th.f.Flaeche, th.f.Linie, true, true, false)
			schreiben(m.hdc, p[0], rect{x + m.s(12), m.y + m.s(8), kr.Right, m.y + m.s(26)}, m.f.sch.t13, th.f.Leise, 0)
			schreiben(m.hdc, p[1], rect{x + m.s(12), m.y + m.s(26), kr.Right, m.y + h - m.s(6)}, m.f.sch.t25b, th.f.Tinte, 0)
		}
	}
	m.y += h + m.s(12)
}

// tabelle wie .tabelle: Kopf --zart, Zeilen mit --linie-zart.
func (m *maler) tabelle(sp []sSpalte, zeilen [][]sZelle) {
	l, r := m.innen()
	summe := 0
	for _, s := range sp {
		summe += s.anteil
	}
	xs := make([]int32, len(sp)+1)
	xs[0] = l
	acc := 0
	for i, s := range sp {
		acc += s.anteil
		xs[i+1] = l + (r-l)*int32(acc)/int32(max(summe, 1))
	}
	kh := m.s(34)
	top := m.y
	if m.zeichnen {
		fuellen(m.hdc, rect{l, m.y, r, m.y + kh}, th.f.Zart)
		for i, s := range sp {
			fl := uintptr(0)
			if s.rechts {
				fl = dtRight
			}
			schreiben(m.hdc, s.titel, rect{xs[i] + m.s(12), m.y, xs[i+1] - m.s(12), m.y + kh}, m.f.sch.t13b, th.f.Leise, fl)
		}
		waagrecht(m.hdc, l, r, m.y+kh-1, th.f.Linie)
	}
	m.y += kh
	for zi, z := range zeilen {
		// Höhe: eine oder zwei Zeilen Text, Knöpfe 30
		zh := m.s(40)
		for _, c := range z {
			if c.klein != "" {
				zh = max(zh, m.s(52))
			}
		}
		if m.zeichnen {
			for i, c := range z {
				if i >= len(sp) {
					break
				}
				m.zelle(c, rect{xs[i] + m.s(12), m.y, xs[i+1] - m.s(12), m.y + zh}, sp[i].rechts)
			}
			if zi < len(zeilen)-1 {
				waagrecht(m.hdc, l, r, m.y+zh-1, th.f.LinieZart)
			}
		}
		m.y += zh
	}
	if m.zeichnen {
		rund(m.hdc, rect{l, top, r, m.y}, 0, th.f.Flaeche, th.f.Linie, false, true, false)
	}
	m.y += m.s(10)
}

func (m *maler) zelle(c sZelle, r rect, rechts bool) {
	hdc := m.hdc
	x := r.Left
	if len(c.knoepfe) > 0 {
		// Knöpfe rechtsbündig
		bx := r.Right
		for i := len(c.knoepfe) - 1; i >= 0; i-- {
			bx -= breite(hdc, c.knoepfe[i].text, m.f.sch.t13) + 2*m.s(8)
			m.knopfMalen(c.knoepfe[i], bx, r.Top+(r.Bottom-r.Top-m.s(30))/2)
			bx -= m.s(8)
		}
		r.Right = bx
	}
	mitte := (r.Top + r.Bottom) / 2
	if c.form != "" {
		an := th.f.AnzeigeFuer(c.form)
		form(hdc, an.Form, an.Farbe, x, mitte-m.s(6), m.s(12))
		x += m.s(12) + m.s(8)
	}
	if c.marke != "" {
		w := breite(hdc, c.marke, m.f.sch.t13b) + 2*m.s(8)
		mr := rect{x, mitte - m.s(11), x + w, mitte + m.s(11)}
		rand := c.markeRand
		if rand == 0 {
			rand = c.markeBg
		}
		rund(hdc, mr, m.s(3), c.markeBg, rand, true, true, false)
		schreiben(hdc, c.marke, mr, m.f.sch.t13b, c.markeFg, dtCenter)
		x += w + m.s(8)
	}
	oben, unten := rect{x, r.Top, r.Right, r.Bottom}, rect{}
	if c.klein != "" {
		oben = rect{x, mitte - m.s(20), r.Right, mitte}
		unten = rect{x, mitte, r.Right, mitte + m.s(20)}
	}
	if c.mandant != "" {
		mx := oben.Left
		if c.klein != "" {
			mx = unten.Left
		}
		my := mitte - m.s(11)
		if c.klein != "" {
			my = unten.Top + (m.s(20)-m.s(22))/2
		}
		mw := m.f.marke(hdc, c.mandant, mx, my, th.f.Leise, th.f.Flaeche, th.f.Linie, false)
		if c.klein != "" {
			unten.Left += mw + m.s(8)
		} else {
			oben.Left += mw + m.s(8)
		}
	}
	font := m.f.sch.t13
	if c.fett {
		font = m.f.sch.t13b
	}
	fg := c.farbe
	if fg == 0 {
		fg = th.f.Tinte
	}
	fl := uintptr(0)
	if rechts {
		fl = dtRight
	}
	if c.link != nil {
		w := min(breite(hdc, c.text, font), oben.Right-oben.Left)
		lr := rect{oben.Left, oben.Top + m.s(6), oben.Left + w, oben.Bottom - m.s(6)}
		hover := m.ziel(lr, c.link.art, c.link.wert)
		fg = th.f.Marke
		if hover {
			waagrecht(hdc, lr.Left, lr.Right, (oben.Top+oben.Bottom)/2+m.s(8), th.f.Marke)
		}
	}
	schreiben(hdc, c.text, oben, font, fg, fl)
	if c.klein != "" {
		schreiben(hdc, c.klein, unten, m.f.sch.t13, th.f.Leise, fl)
	}
}

// eintrag: Listeneintrag wie in .fenster-liste (Name fett, Marken, Zeilen, Knöpfe).
type sMarke struct {
	text         string
	fg, bg, rand desktop.RGB
	fett         bool
}

func (m *maler) eintrag(name string, leise bool, marken []sMarke, zeilen []string, knoepfe []sKnopf, letzter bool) {
	l, r := m.innen()
	if m.zeichnen {
		fg := th.f.Tinte
		if leise {
			fg = th.f.Leise
		}
		nw := min(breite(m.hdc, name, m.f.sch.t16b), r-l)
		schreiben(m.hdc, name, rect{l, m.y, l + nw + 1, m.y + m.s(24)}, m.f.sch.t16b, fg, 0)
		x := l + nw + m.s(8)
		for _, mk := range marken {
			x += m.f.marke(m.hdc, mk.text, x, m.y+m.s(1), mk.fg, mk.bg, mk.rand, mk.fett) + m.s(8)
		}
	}
	m.y += m.s(26)
	for _, z := range zeilen {
		if z != "" {
			m.text(z, m.f.sch.t13, th.f.Leise)
			m.y -= m.s(6)
		}
	}
	if len(knoepfe) > 0 {
		m.y += m.s(8)
		m.knoepfe(knoepfe...)
		m.y -= m.s(8)
	}
	m.y += m.s(8)
	if m.zeichnen && !letzter {
		waagrecht(m.hdc, l, r, m.y, th.f.LinieZart)
	}
	m.y += m.s(9)
}

// eigen: frei gezeichneter Bereich der Höhe h (z. B. Topologie).
func (m *maler) eigen(h int32, malen func(r rect)) {
	l, r := m.innen()
	if m.zeichnen {
		malen(rect{l, m.y, r, m.y + h})
	}
	m.y += h
}

// abstand: freier Raum.
func (m *maler) abstand(px int32) { m.y += m.s(px) }

// --- Fläche ----------------------------------------------------------------------

func (a *app) seiteMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Grund)
	def := seiten[f.seite]
	if def == nil {
		return
	}
	daten, fehler := a.seiteDaten(f.seite)
	lauf := func(m *maler) {
		if fehler != "" && daten == nil {
			m.fehler("Laden fehlgeschlagen: " + fehler)
			return
		}
		def.malen(m, daten)
	}
	// Messlauf
	mess := &maler{f: f, hdc: hdc, x0: 0, x1: r.Right, y: 0, pad: f.s(12), ziele: &f.seitenZiele, ueber: -1}
	lauf(mess)
	f.seitenHoehe = mess.y
	if f.seitenOff > max(0, f.seitenHoehe-r.Bottom) {
		f.seitenOff = max(0, f.seitenHoehe-r.Bottom)
	}
	f.seitenZiele = f.seitenZiele[:0]
	m := &maler{f: f, hdc: hdc, zeichnen: true, x0: 0, x1: r.Right, y: -f.seitenOff, pad: f.s(12), hoehen: mess.hoehen,
		ziele: &f.seitenZiele, ueber: f.seitenUeber}
	lauf(m)
}

func (f *fenster) seitenScrollen(d int32) {
	var r rect
	pGetClientRect.Call(uintptr(f.seitenF), uintptr(unsafe.Pointer(&r)))
	f.seitenOff = max(0, min(f.seitenOff+d, f.seitenHoehe-r.Bottom))
	pInvalidateRect.Call(uintptr(f.seitenF), 0, 0)
}

func (a *app) seiteKlick(z ziel) {
	f := a.f
	def := seiten[f.seite]
	if def == nil || def.klick == nil {
		return
	}
	daten, _ := a.seiteDaten(f.seite)
	def.klick(z, daten)
	pInvalidateRect.Call(uintptr(f.seitenF), 0, 0)
}

// listeWaehlen: Liste unter dem Ziel z (Auswahlfeld) öffnen; Ergebnis Index oder -1.
func (a *app) listeWaehlen(z ziel, texte []string, aktiv int) int {
	f := a.f
	e := make([]listenEintrag, len(texte))
	for i, t := range texte {
		e[i] = listenEintrag{text: t, an: true, gewaehlt: i == aktiv}
	}
	p := point{z.r.Left, z.r.Bottom + f.s(4)}
	pClientToScreen.Call(uintptr(f.seitenF), uintptr(unsafe.Pointer(&p)))
	return schwebend(f.hwnd, e, p, z.r.Right-z.r.Left, false)
}

// mandantText: Name eines Mandanten aus dem Stand.
func (a *app) mandantName(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.stand.Mandanten {
		if m.ID == id {
			return m.Name
		}
	}
	return ""
}

// bereich: Mandanten des gewählten Bereichs, ob mehrere, und Rolle je Mandant.
func (a *app) bereich() (ids map[string]bool, mehrere bool, rolle func(string) string) {
	f := a.f
	a.mu.Lock()
	ms := a.stand.Mandanten
	a.mu.Unlock()
	ids = desktop.BereichIDs(ms, f.mandant, f.mitUnter)
	rollen := map[string]string{}
	for _, m := range ms {
		rollen[m.ID] = m.Rolle
	}
	return ids, len(ids) > 1, func(id string) string { return rollen[id] }
}

func itoa(i int) string { return strconv.Itoa(i) }

// hostOeffnen: Gerät unter Hosts zeigen (wie onOeffnen im Web).
func (a *app) hostOeffnen(geraetID string) {
	f := a.f
	a.seiteWechseln(seiteHosts)
	key := "d:" + geraetID
	f.gewaehlt = key
	if h, ok := f.items[key]; ok {
		send(f.baum, tvmSelectItem, tvgnCaret, h)
	}
	a.auswahlZeigen(true)
}

// zustandsMarke: Marke wie .marke-<stand> (Kritisch gefüllt rot, Warnung gelb, OK gerahmt grün …).
func zustandsZelle(stand, text string) sZelle {
	c := sZelle{marke: text, markeFg: th.f.Tinte, markeBg: th.f.Flaeche, markeRand: th.f.Leise}
	switch stand {
	case "crit":
		c.markeFg, c.markeBg, c.markeRand = th.f.AufKrit, th.f.Krit, th.f.Krit
	case "warn":
		c.markeFg, c.markeBg, c.markeRand = th.f.AufWarn, th.f.Warn, th.f.Warn
	case "ok":
		c.markeFg, c.markeRand = th.f.TextOK, th.f.OK
	case "wartung":
		c.markeFg, c.markeBg, c.markeRand = th.f.TextWartung, th.f.WartHauch, th.f.WartHauch
	case "unknown":
	default:
		c.markeFg, c.markeRand = th.f.Leise, th.f.Linie
	}
	return c
}
