// SPDX-License-Identifier: AGPL-3.0-only

package main

// Sonnendiagramm im Dashboard wie das Widget „Sonnendiagramm“ der
// Weboberfläche (web/src/Sonne.tsx): Fugen und Mitte in der Farbe der
// Fläche, Namen fett, entlang des Bogens oder entlang des Strahls, in der
// Mitte der Name der Wurzel. internal/desktop/sonne.go rechnet und rastert
// die Flächen, hier kommen Schrift, Überfahren und Klick dazu. Ein Klick auf
// ein Gerät öffnet daneben seine Sensoren, ein Klick auf eine Gruppe zeigt
// sie als Sonne, ein Klick in die Mitte geht eine Ebene hinauf.

import (
	"math"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

var (
	pSetTextAlign = gdi32.NewProc("SetTextAlign")
	pTextOutW     = gdi32.NewProc("TextOutW")
)

const (
	taCenter   = 6
	taBaseline = 24
	taLeft     = 0
	taTop      = 0
)

// Kopf der Karte wie die Titelzeile eines Widgets.
const sonneKopfH = 40

// sonnenWurzel: Wurzel der Sonne (gewählte Gruppe, sonst der Bereich).
func (f *fenster) sonnenWurzel() *desktop.Knoten {
	if e := f.eintrag(f.sonnenKey); e != nil && e.knoten.Art != desktop.KnotenGeraet {
		return e.knoten
	}
	if len(f.eintraege) > 0 {
		return f.eintraege[0].knoten
	}
	return nil
}

func (f *fenster) elternVon(k *desktop.Knoten) string {
	for _, e := range f.eintraege {
		if e.knoten == k {
			return e.eltern
		}
	}
	return ""
}

// sonnenLage: Mitte und Durchmesser in Pixeln in der Karte.
func (f *fenster) sonnenLage(r rect) (cx, cy int32, n int32) {
	oben := f.s(sonneKopfH)
	unten := r.Bottom - f.s(32) // Zeile für den Hinweis
	n = min(r.Right-2*f.s(16), unten-oben-2*f.s(8))
	n = max(n, f.s(160))
	return r.Right / 2, oben + (unten-oben)/2, n
}

func (a *app) sonneMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	// Titelzeile wie ein Widget im Dashboard
	kopf := rect{0, 0, r.Right, f.s(sonneKopfH)}
	fuellen(hdc, kopf, th.f.Zart)
	waagrecht(hdc, 0, r.Right, kopf.Bottom-1, th.f.LinieZart)
	schreiben(hdc, "Sonnendiagramm", kopf, f.sch.t13b, th.f.Tinte, dtCenter)
	w := f.sonnenWurzel()
	if w == nil {
		schreiben(hdc, "Lädt …", rect{f.s(16), kopf.Bottom, r.Right, kopf.Bottom + f.s(40)}, f.sch.t13, th.f.Leise, 0)
		return
	}
	cx, cy, n := f.sonnenLage(r)
	a.mu.Lock()
	zeit := a.stand.Zeit
	a.mu.Unlock()
	sig := knotenKey(w) + "|" + zeit.String() + "|" + strconv.Itoa(int(n)) + "|" + map[bool]string{true: "d", false: "h"}[th.dunkel]
	if sig != f.sonnenSig || f.sonnenWurz != w || f.sonnenBild.h == 0 {
		f.sonnenSeg, f.sonnenRing = desktop.Sonne(w)
		if f.sonnenBild.h != 0 {
			pDeleteObject.Call(f.sonnenBild.h)
		}
		f.sonnenBild = f.sonneRendern(hdc, w, f.sonnenSeg, f.sonnenRing, n)
		f.sonnenSig, f.sonnenWurz = sig, w
	}
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	alt, _, _ := pSelectObject.Call(mem, f.sonnenBild.h)
	pBitBlt.Call(hdc, uintptr(cx-n/2), uintptr(cy-n/2), uintptr(n), uintptr(n), mem, 0, 0, srcCopy)
	pSelectObject.Call(mem, alt)
	pDeleteDC.Call(mem)

	// unten: was unter der Maus liegt, sonst eine Erklärung
	t := f.sonnenUeber
	if t == "" {
		t = "Klick auf ein Gerät zeigt seine Sensoren, auf eine Gruppe ihre Sonne, in die Mitte eine Ebene zurück."
		if f.sonnenKey == "" {
			t = "Klick auf ein Gerät zeigt seine Sensoren, auf eine Gruppe ihre Sonne."
		}
	}
	schreiben(hdc, t, rect{f.s(16), r.Bottom - f.s(32), r.Right - f.s(16), r.Bottom - f.s(8)}, f.sch.t13, th.f.Leise, dtCenter)
}

// sonneRendern: Flächen, Namen und Mitte einmal in ein Bild (n×n) zeichnen.
func (f *fenster) sonneRendern(hdc uintptr, w *desktop.Knoten, seg []desktop.Segment, ring []float64, n int32) bmp {
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	bm, _, _ := pCreateCompatibleBmp.Call(hdc, uintptr(n), uintptr(n))
	alt, _, _ := pSelectObject.Call(mem, bm)
	fuellen(mem, rect{0, 0, n, n}, th.f.Flaeche)
	flaechen := bitmapAus(desktop.SonnenBild(seg, ring, desktop.SonnenStatus(w), w.Kenn, int(n), th.f.Flaeche))
	alpha(mem, flaechen, 0, 0)
	pDeleteObject.Call(flaechen.h)
	k := float64(n) / 1000
	c := float64(n) / 2
	pSetBkMode.Call(mem, transparent)
	// Schrift wie im Web 6,5 bis 19 Einheiten, aber nie unter 8 px
	minS := math.Max(6.5, float64(f.s(8))/k)
	for _, s := range seg {
		b := desktop.SonnenBeschriftungIn(s.Knoten.Name, s.R0, s.R1, s.A0, s.A1, minS, 19)
		if b == nil {
			continue
		}
		_, tf := desktop.SegmentFarbe(s.Status, s.Kenn)
		if b.Radial {
			sonneRadial(mem, b, s, c, k, tf)
		} else {
			sonneBogen(mem, b, s, c, k, tf)
		}
	}
	// Mitte: Name der Wurzel, 26 Einheiten fett
	px := int32(26 * k)
	font := drehSchrift(px, 0)
	pSelectObject.Call(mem, font)
	name := w.Name
	loch := 0.27 * 492 * k * 1.8
	for len([]rune(name)) > 3 && float64(textBreite(mem, name)) > loch {
		r := []rune(strings.TrimSuffix(name, "…"))
		name = strings.TrimSpace(string(r[:len(r)-1])) + "…"
	}
	pSetTextColor.Call(mem, cref(th.f.Tinte))
	pSetTextAlign.Call(mem, taCenter|taBaseline)
	textAus(mem, int32(c), int32(c+0.35*float64(px)), name)
	pSetTextAlign.Call(mem, taLeft|taTop)
	pSelectObject.Call(mem, alt)
	pDeleteObject.Call(font)
	pDeleteDC.Call(mem)
	return bmp{bm, n, n}
}

// drehSchrift: D-DIN fett, um rot Grad im Uhrzeigersinn gedreht.
func drehSchrift(px int32, rot float64) uintptr {
	esc := int32(math.Mod(-rot*10+3600*4, 3600))
	h, _, _ := pCreateFontW.Call(uintptr(-px), 0, uintptr(esc), uintptr(esc), fwBold, 0, 0, 0, 1, 0, 0, 4, 0,
		uintptr(unsafe.Pointer(utf16("D-DIN"))))
	return h
}

func textAus(hdc uintptr, x, y int32, s string) {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > 1 {
		pTextOutW.Call(hdc, uintptr(x), uintptr(y), uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1))
	}
}

func textBreite(hdc uintptr, s string) int32 {
	u, _ := syscall.UTF16FromString(s)
	var sz struct{ CX, CY int32 }
	if len(u) > 1 {
		pGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&sz)))
	}
	return sz.CX
}

// sonneRadial: Name entlang des Strahls, Mitte des Segments, lesbar von links.
func sonneRadial(hdc uintptr, b *desktop.Beschriftung, s desktop.Segment, c, k float64, farbe desktop.RGB) {
	px := b.Schrift * k
	am := (s.A0 + s.A1) / 2
	mitte := (s.R0 + s.R1) / 2 * k
	rot := am*180/math.Pi - 90
	if am > math.Pi {
		rot += 180
	}
	rad := rot * math.Pi / 180
	x := c + mitte*math.Sin(am) - math.Sin(rad)*0.35*px
	y := c - mitte*math.Cos(am) + math.Cos(rad)*0.35*px
	font := drehSchrift(int32(math.Round(px)), rot)
	alt, _, _ := pSelectObject.Call(hdc, font)
	pSetTextColor.Call(hdc, cref(farbe))
	pSetTextAlign.Call(hdc, taCenter|taBaseline)
	textAus(hdc, int32(math.Round(x)), int32(math.Round(y)), b.Text)
	pSetTextAlign.Call(hdc, taLeft|taTop)
	pSelectObject.Call(hdc, alt)
	pDeleteObject.Call(font)
}

// sonneBogen: Name entlang des Bogens (textPath im Web), oben im
// Uhrzeigersinn, unten gegen ihn, damit er nie auf dem Kopf steht. Jedes
// Zeichen wird für sich gedreht gesetzt.
func sonneBogen(hdc uintptr, b *desktop.Beschriftung, s desktop.Segment, c, k float64, farbe desktop.RGB) {
	px := b.Schrift * k
	am := (s.A0 + s.A1) / 2
	unten := am > math.Pi/2 && am < 3*math.Pi/2
	radius := (s.R0 + s.R1) / 2 * k
	// Grundlinie 0,35 em unter dem Pfad (dy im Web): oben nach innen, unten nach außen
	grund := radius - 0.35*px
	if unten {
		grund = radius + 0.35*px
	}
	gerade := drehSchrift(int32(math.Round(px)), 0)
	alt, _, _ := pSelectObject.Call(hdc, gerade)
	zeichen := []rune(b.Text)
	breiten := make([]float64, len(zeichen))
	gesamt := 0.0
	for i, z := range zeichen {
		breiten[i] = float64(textBreite(hdc, string(z)))
		gesamt += breiten[i]
	}
	pSelectObject.Call(hdc, alt)
	pDeleteObject.Call(gerade)
	pSetTextColor.Call(hdc, cref(farbe))
	pSetTextAlign.Call(hdc, taCenter|taBaseline)
	lauf := -gesamt / 2
	for i, z := range zeichen {
		mitteZ := lauf + breiten[i]/2
		lauf += breiten[i]
		if z == ' ' {
			continue
		}
		wk := am + mitteZ/radius
		rot := wk * 180 / math.Pi
		if unten {
			wk = am - mitteZ/radius
			rot = wk*180/math.Pi + 180
		}
		x := c + grund*math.Sin(wk)
		y := c - grund*math.Cos(wk)
		font := drehSchrift(int32(math.Round(px)), rot)
		alt, _, _ := pSelectObject.Call(hdc, font)
		textAus(hdc, int32(math.Round(x)), int32(math.Round(y)), string(z))
		pSelectObject.Call(hdc, alt)
		pDeleteObject.Call(font)
	}
	pSetTextAlign.Call(hdc, taLeft|taTop)
}

// sonnenPunkt: Fensterpunkt in Sonnenkoordinaten.
func (f *fenster) sonnenPunkt(x, y int32) (float64, float64) {
	var r rect
	pGetClientRect.Call(uintptr(f.sonne), uintptr(unsafe.Pointer(&r)))
	cx, cy, n := f.sonnenLage(r)
	k := 1000 / float64(n)
	return float64(x-cx) * k, float64(y-cy) * k
}

func (a *app) sonneText(x, y int32) string {
	f := a.f
	if f.sonnenWurz == nil {
		return ""
	}
	sx, sy := f.sonnenPunkt(x, y)
	i := desktop.SonnenTreffer(f.sonnenSeg, f.sonnenRing, sx, sy)
	worte := map[string]string{"ok": "OK", "warn": "Warnung", "crit": "Kritisch", "quittiert": "Bestätigt",
		"unknown": "Unbekannt", "wartung": "Wartung oder pausiert"}
	switch {
	case i >= 0:
		s := f.sonnenSeg[i]
		return strings.Join(s.Pfad[1:], " › ") + ": " + worte[s.Status] + kennWort(s.Status, s.Kenn)
	case i == -1 || (math.Hypot(sx, sy) < 0.27*492 && f.sonnenKey != ""):
		st := desktop.SonnenStatus(f.sonnenWurz)
		return f.sonnenWurz.Name + ": " + worte[st] + kennWort(st, f.sonnenWurz.Kenn)
	}
	return ""
}

func (a *app) sonneKlick(x, y int32) {
	f := a.f
	if f.sonnenWurz == nil {
		return
	}
	sx, sy := f.sonnenPunkt(x, y)
	i := desktop.SonnenTreffer(f.sonnenSeg, f.sonnenRing, sx, sy)
	switch {
	case i >= 0 && f.sonnenSeg[i].Knoten.Art == desktop.KnotenGeraet:
		a.geraetOeffnen(knotenKey(f.sonnenSeg[i].Knoten))
	case i >= 0:
		f.sonnenKey = knotenKey(f.sonnenSeg[i].Knoten)
		pInvalidateRect.Call(uintptr(f.sonne), 0, 0)
	case math.Hypot(sx, sy) < 0.27*492+20 || i == -1:
		// eine Ebene hinauf
		if e := f.eintrag(f.sonnenKey); e != nil {
			f.sonnenKey = e.eltern
			if f.eintrag(f.sonnenKey) == nil || len(f.eintraege) > 0 && f.sonnenKey == f.eintraege[0].key {
				f.sonnenKey = ""
			}
			pInvalidateRect.Call(uintptr(f.sonne), 0, 0)
		}
	}
}

const tvmEnsureVisible = 0x1114

// kennWort: „ · Name der Kennfarbe“ wie im Tooltip der Web-Sonne.
func kennWort(status string, k *desktop.Kennfarbe) string {
	if _, ok := k.RGB(); ok && desktop.KennGilt(status) {
		return " · " + k.Name
	}
	return ""
}
