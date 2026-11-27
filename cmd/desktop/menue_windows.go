// SPDX-License-Identifier: AGPL-3.0-only

package main

// Selbst gezeichnete schwebende Liste für Menüs und Auswahlfelder (statt
// TrackPopupMenu und COMBOBOX, die Systemschrift und Systemfarben zeigen):
// Fläche --flaeche, 1 px --linie, Radius 6, Schatten, Zeilen 32 in D-DIN 13,
// Überfahren --marke-hauch. Bedienbar mit Maus und Tasten (↑ ↓ Enter Esc).

import (
	"syscall"
	"unsafe"
)

var (
	pMonitorFromPoint = user32.NewProc("MonitorFromPoint")
	pGetMonitorInfoW  = user32.NewProc("GetMonitorInfoW")
)

const (
	csDropShadow   = 0x00020000
	wsExTopmost    = 0x00000008
	wsExToolWindow = 0x00000080
	wmRButtonUp    = 0x0205
	wmLButtonDownM = 0x0201
	wmRButtonDown  = 0x0204
	wmActivateApp  = 0x001C
	vkUp           = 0x26
	vkDown         = 0x28
	vkSpace        = 0x20
	monitorNearest = 2
)

type monitorInfo struct {
	Size          uint32
	Monitor, Work rect
	Flags         uint32
}

// listenEintrag: eine Zeile (text leer = Trennlinie).
type listenEintrag struct {
	text, kurz string // kurz: Taste rechts, z. B. „F2“
	an         bool
	gewaehlt   bool // Häkchen (Auswahlfeld)
}

type schwebeListe struct {
	hwnd     syscall.Handle
	e        []listenEintrag
	zeilen   []rect
	ueber    int
	ergebnis int
	fertig   bool
	dpi      int32
	sch      schriften
}

var (
	aktiveListe *schwebeListe
	listKlasse  bool
)

func (l *schwebeListe) s(px int32) int32 { return px * l.dpi / 96 }

// schwebend zeigt die Liste an p (Bildschirm), rechtsbündig bei rechts=true,
// mindestens breit min. Liefert den Index der Wahl oder -1.
func schwebend(owner syscall.Handle, e []listenEintrag, p point, minB int32, rechts bool) int {
	inst, _, _ := pGetModuleHandleW.Call(0)
	if !listKlasse {
		cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{Style: csDropShadow, WndProc: syscall.NewCallback(listeProc), Instance: syscall.Handle(inst),
			ClassName: utf16("OpenWachtListe"), Cursor: syscall.Handle(cursor)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		listKlasse = true
	}
	l := &schwebeListe{e: e, ueber: -1, ergebnis: -1, dpi: dpiVon(owner)}
	l.sch.setzen(l.dpi)
	defer l.sch.frei()
	for i, x := range e {
		if x.an && x.gewaehlt {
			l.ueber = i
		}
	}
	// Maße: Zeilen 32, Trennlinien 9, Innenabstand 4
	hdc, _, _ := pGetDC.Call(uintptr(owner))
	b := minB
	y := l.s(4)
	for _, x := range e {
		if x.text == "" {
			l.zeilen = append(l.zeilen, rect{0, y, 0, y + l.s(9)})
			y += l.s(9)
			continue
		}
		w := breite(hdc, x.text, l.sch.t13) + 2*l.s(16) + l.s(16)
		if x.kurz != "" {
			w += breite(hdc, x.kurz, l.sch.t13) + l.s(24)
		}
		b = max(b, w)
		l.zeilen = append(l.zeilen, rect{0, y, 0, y + l.s(32)})
		y += l.s(32)
	}
	pReleaseDC.Call(uintptr(owner), hdc)
	h := y + l.s(4)
	for i := range l.zeilen {
		l.zeilen[i].Left, l.zeilen[i].Right = l.s(4), b-l.s(4)
	}
	x0 := p.X
	if rechts {
		x0 -= b
	}
	// im Arbeitsbereich des Bildschirms halten
	mon, _, _ := pMonitorFromPoint.Call(uintptr(uint32(p.X))|uintptr(uint32(p.Y))<<32, monitorNearest)
	mi := monitorInfo{}
	mi.Size = uint32(unsafe.Sizeof(mi))
	if pGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); mi.Work.Right > 0 {
		x0 = max(min(x0, mi.Work.Right-b), mi.Work.Left)
		if p.Y+h > mi.Work.Bottom {
			p.Y = max(mi.Work.Bottom-h, mi.Work.Top)
		}
	}
	aktiveListe = l
	hw, _, _ := pCreateWindowExW.Call(wsExTopmost|wsExToolWindow|wsExNoActivate, uintptr(unsafe.Pointer(utf16("OpenWachtListe"))), 0,
		wsPopup, uintptr(x0), uintptr(p.Y), uintptr(b), uintptr(h), uintptr(owner), 0, inst, 0)
	l.hwnd = syscall.Handle(hw)
	pShowWindow.Call(hw, swShowNA)
	pSetCapture.Call(hw)
	var m msg
	for !l.fertig {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			pPostQuitMessage.Call(0)
			break
		}
		if m.Message == wmKeyDown {
			l.taste(m.WParam)
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		if r, _, _ := pIsWindow.Call(hw); r == 0 {
			break
		}
	}
	pReleaseCapture.Call()
	pDestroyWindow.Call(hw)
	aktiveListe = nil
	return l.ergebnis
}

func (l *schwebeListe) taste(vk uintptr) {
	schritt := func(d int) {
		i := l.ueber
		for n := 0; n < len(l.e); n++ {
			i = (i + d + len(l.e)) % len(l.e)
			if l.e[i].text != "" && l.e[i].an {
				l.ueber = i
				pInvalidateRect.Call(uintptr(l.hwnd), 0, 0)
				return
			}
		}
	}
	switch vk {
	case vkDown:
		schritt(1)
	case vkUp:
		schritt(-1)
	case vkReturn, vkSpace:
		if l.ueber >= 0 {
			l.ergebnis = l.ueber
		}
		l.fertig = true
	case vkEscape:
		l.fertig = true
	}
}

func (l *schwebeListe) bei(x, y int32) int {
	for i, r := range l.zeilen {
		if l.e[i].text != "" && x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom {
			return i
		}
	}
	return -1
}

func listeProc(hwnd, m, wp, lp uintptr) uintptr {
	l := aktiveListe
	if l == nil || (l.hwnd != 0 && syscall.Handle(hwnd) != l.hwnd) {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	x, y := int32(int16(lp&0xffff)), int32(int16((lp>>16)&0xffff))
	var cr rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	drin := x >= 0 && y >= 0 && x < cr.Right && y < cr.Bottom
	switch uint32(m) {
	case wmEraseBkgnd:
		return 1
	case wmMouseActivate:
		return maNoActivate // der erste Klick wählt schon aus
	case wmPaint:
		malen(hwnd, func(hdc uintptr, r rect) {
			fuellen(hdc, r, th.f.Linie)
			fuellen(hdc, rect{1, 1, r.Right - 1, r.Bottom - 1}, th.f.Flaeche)
			for i, e := range l.e {
				z := l.zeilen[i]
				if e.text == "" {
					waagrecht(hdc, z.Left+l.s(8), z.Right-l.s(8), (z.Top+z.Bottom)/2, th.f.LinieZart)
					continue
				}
				fg := th.f.Tinte
				if i == l.ueber && e.an {
					rund(hdc, z, l.s(3), th.f.MarkeHauch, th.f.MarkeHauch, true, false, false)
					fg = th.f.MarkeTief
				}
				if !e.an {
					fg = mischen(th.f.Tinte, th.f.Flaeche, 45)
				}
				if e.gewaehlt {
					k := rect{z.Left + l.s(8), (z.Top + z.Bottom - l.s(12)) / 2, z.Left + l.s(20), (z.Top+z.Bottom-l.s(12))/2 + l.s(12)}
					haken(hdc, k, th.f.Marke, l.s(2))
				}
				tr := rect{z.Left + l.s(24), z.Top, z.Right - l.s(12), z.Bottom}
				schreiben(hdc, e.text, tr, l.sch.t13, fg, 0)
				if e.kurz != "" {
					schreiben(hdc, e.kurz, tr, l.sch.t13, th.f.Leise, dtRight)
				}
			}
		})
		return 0
	case wmMouseMove:
		i := -1
		if drin {
			i = l.bei(x, y)
		}
		if i != l.ueber && (i < 0 || l.e[i].an) {
			l.ueber = i
			pInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case wmLButtonDownM, wmRButtonDown:
		if !drin {
			l.fertig = true // Klick daneben schließt
		}
		return 0
	case wmLButtonUp, wmRButtonUp:
		if drin {
			if i := l.bei(x, y); i >= 0 && l.e[i].an {
				l.ergebnis, l.fertig = i, true
			}
		}
		return 0
	case wmCaptureChanged, wmActivateApp:
		l.fertig = true
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

const (
	wmMouseActivate = 0x0021
	maNoActivate    = 3
	wsExNoActivate  = 0x08000000
	swShowNA        = 8
)
