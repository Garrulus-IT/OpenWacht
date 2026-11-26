// SPDX-License-Identifier: AGPL-3.0-only

package main

// Ansicht „Sonne“: das Sonnendiagramm des gewählten Mandanten bzw. der
// gewählten Gruppe wie im Dashboard (internal/desktop/sonne.go rechnet und
// rastert, hier kommen Beschriftung, Überfahren und Klick dazu). Ein Klick
// auf ein Segment wählt es im Baum; ein Klick auf den inneren Ring geht eine
// Ebene hinauf.

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

// sonnenWurzel: gewählter Knoten, bei einem Gerät dessen Gruppe bzw. Mandant.
func (f *fenster) sonnenWurzel() *desktop.Knoten {
	key := f.gewaehlt
	for n := 0; n < 50; n++ {
		var e *baumEintrag
		for i := range f.eintraege {
			if f.eintraege[i].key == key {
				e = &f.eintraege[i]
			}
		}
		if e == nil {
			return nil
		}
		if e.knoten.Art != desktop.KnotenGeraet || e.eltern == "" {
			return e.knoten
		}
		key = e.eltern
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

// sonnenLage: Mitte und Maßstab (Pixel je Sonneneinheit) im Fenster.
func (f *fenster) sonnenLage(r rect) (cx, cy int32, n int32) {
	n = min(r.Right, r.Bottom-f.s(32)) - 2*f.s(16)
	n = max(n, f.s(160))
	return r.Right / 2, f.s(32) + (r.Bottom-f.s(32))/2, n
}

func (a *app) sonneMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	w := f.sonnenWurzel()
	if w == nil {
		return
	}
	cx, cy, n := f.sonnenLage(r)
	a.mu.Lock()
	zeit := a.stand.Zeit
	a.mu.Unlock()
	sig := knotenKey(w) + "|" + zeit.String() + "|" + strconv.Itoa(int(n)) + "|" + map[bool]string{true: "d", false: "h"}[th.dunkel]
	if sig != f.sonnenSig || f.sonnenWurz != w {
		f.sonnenSeg, f.sonnenRing = desktop.Sonne(w)
		if f.sonnenBild.h != 0 {
			pDeleteObject.Call(f.sonnenBild.h)
		}
		f.sonnenBild = bitmapAus(desktop.SonnenBild(f.sonnenSeg, f.sonnenRing, desktop.SonnenStatus(w), int(n), th.f.Flaeche))
		f.sonnenSig, f.sonnenWurz = sig, w
	}
	alpha(hdc, f.sonnenBild, cx-n/2, cy-n/2)
	k := float64(n) / 1000

	// Beschriftung: fett in 13 px (Skala), was nicht hineinpasst, entfällt
	pSetBkMode.Call(hdc, transparent)
	px13 := float64(f.s(13))
	pSetTextAlign.Call(hdc, taCenter|taBaseline)
	for _, s := range f.sonnenSeg {
		b := desktop.SonnenBeschriftungIn(s.Knoten.Name, s.R0, s.R1, s.A0, s.A1, px13/k, px13/k)
		if b == nil {
			continue
		}
		px := px13
		am := (s.A0 + s.A1) / 2
		mitte := (s.R0 + s.R1) / 2
		x := float64(cx) + mitte*math.Sin(am)*k
		y := float64(cy) - mitte*math.Cos(am)*k
		// Drehung im Uhrzeigersinn (Grad) wie im SVG
		var rot float64
		if b.Radial {
			rot = am*180/math.Pi - 90
			if am > math.Pi {
				rot += 180
			}
		} else {
			rot = am * 180 / math.Pi
			if am > math.Pi/2 && am < 3*math.Pi/2 {
				rot += 180
			}
		}
		rad := rot * math.Pi / 180
		// Grundlinie 0,35 em unter die Mitte
		x += -math.Sin(rad) * 0.35 * px
		y += math.Cos(rad) * 0.35 * px
		esc := int32(math.Mod(-rot*10+3600*2, 3600))
		font, _, _ := pCreateFontW.Call(uintptr(-int32(px)), 0, uintptr(esc), uintptr(esc), fwBold, 0, 0, 0, 1, 0, 0, 5, 0,
			uintptr(unsafe.Pointer(utf16("D-DIN"))))
		alt, _, _ := pSelectObject.Call(hdc, font)
		_, tf := desktop.SonnenFarbe(s.Status)
		pSetTextColor.Call(hdc, cref(tf))
		u, _ := syscall.UTF16FromString(b.Text)
		pTextOutW.Call(hdc, uintptr(int32(x)), uintptr(int32(y)), uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1))
		pSelectObject.Call(hdc, alt)
		pDeleteObject.Call(font)
	}
	pSetTextAlign.Call(hdc, taLeft|taTop)

	// Mitte: Name der Wurzel
	loch := int32(0.27 * 492 * k)
	schreiben(hdc, w.Name, rect{cx - loch, cy - f.s(14), cx + loch, cy + f.s(14)}, f.sch.t16b, th.f.Tinte, dtCenter)

	// oben links: was unter der Maus liegt, sonst eine Erklärung
	t := f.sonnenUeber
	if t == "" {
		t = "Jedes Gerät gleich breit, mit Problem tritt es hervor. Klick wählt, Klick in die Mitte geht eine Ebene hinauf."
	}
	schreiben(hdc, t, rect{f.s(16), 0, r.Right - f.s(16), f.s(32)}, f.sch.t13, th.f.Leise, 0)
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
		return strings.Join(s.Pfad[1:], " › ") + ": " + worte[s.Status]
	case i == -1:
		return f.sonnenWurz.Name + ": " + worte[desktop.SonnenStatus(f.sonnenWurz)]
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
	key := ""
	switch {
	case i >= 0:
		key = knotenKey(f.sonnenSeg[i].Knoten)
	case math.Hypot(sx, sy) < 0.27*492+20 || i == -1:
		key = f.elternVon(f.sonnenWurz) // eine Ebene hinauf
	}
	if h, ok := f.items[key]; ok && key != "" {
		send(f.baum, tvmEnsureVisible, 0, h)
		send(f.baum, tvmSelectItem, tvgnCaret, h)
	}
}

const tvmEnsureVisible = 0x1114
