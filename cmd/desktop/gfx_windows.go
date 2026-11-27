// SPDX-License-Identifier: AGPL-3.0-only

package main

// Zeichnen nach dem Corporate Design (docs/design/README.md): Farben aus den
// Tokens (desktop.Hell/Dunkel), Schriften D-DIN und JetBrains Mono aus der
// Programmdatei, Zustandsformen und Bildzeichen als Bitmaps mit Alphakanal.
// Alles mit GDI über syscall.

import (
	"bytes"
	"image"
	"image/draw"
	"image/png"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

var (
	msimg32 = windows.NewLazySystemDLL("msimg32.dll")
	dwmapi  = windows.NewLazySystemDLL("dwmapi.dll")

	pAddFontMemResourceEx   = gdi32.NewProc("AddFontMemResourceEx")
	pCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	pCreatePen              = gdi32.NewProc("CreatePen")
	pMoveToEx               = gdi32.NewProc("MoveToEx")
	pLineTo                 = gdi32.NewProc("LineTo")
	pSetTextCharacterExtra  = gdi32.NewProc("SetTextCharacterExtra")
	pSetTimer               = user32.NewProc("SetTimer")
	pSaveDC                 = gdi32.NewProc("SaveDC")
	pRestoreDC              = gdi32.NewProc("RestoreDC")
	pIntersectClipRect      = gdi32.NewProc("IntersectClipRect")
	pAlphaBlend             = msimg32.NewProc("AlphaBlend")
	pDwmSetWindowAttribute  = dwmapi.NewProc("DwmSetWindowAttribute")
	pTrackMouseEvent        = user32.NewProc("TrackMouseEvent")
	pGetProcAddress         = kernel32.NewProc("GetProcAddress")
	pLoadImageW             = user32.NewProc("LoadImageW")
	pRegQueryValueExWDword  = advapi32.NewProc("RegGetValueW")
	pGetSystemMetricsForDpi = user32.NewProc("GetSystemMetricsForDpi")
)

const (
	psSolid      = 0
	psDash       = 1
	acSrcAlpha   = 1
	biRGB        = 0
	dibRGBColors = 0
	imageIcon    = 1
	lrShared     = 0x8000
	rrfRtDword   = 0x00000010
	tmeLeave     = 0x00000002
	wmMouseLeave = 0x02A3
	dtCenter     = 0x0001
	dtRight      = 0x0002
	dtWordBreak  = 0x0010
	dtCalcRect   = 0x0400

	dwmwaDarkMode = 20 // DWMWA_USE_IMMERSIVE_DARK_MODE
)

// cref: Farbe als COLORREF (0x00BBGGRR).
func cref(c desktop.RGB) uintptr {
	return uintptr((c>>16)&0xff | (c & 0xff00) | (c&0xff)<<16)
}

// thema: aktuelle Farben (hell oder dunkel nach Windows-Einstellung).
type thema struct {
	f      desktop.Farben
	dunkel bool
	pinsel map[desktop.RGB]uintptr
}

var th = thema{f: desktop.Hell, pinsel: map[desktop.RGB]uintptr{}}

// themaLesen: „Apps im dunklen Modus“ aus HKCU\…\Themes\Personalize.
func themaLesen() bool {
	var v, n uint32 = 1, 4
	r, _, _ := pRegQueryValueExWDword.Call(hkeyCurrentUser,
		uintptr(unsafe.Pointer(utf16(`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`))),
		uintptr(unsafe.Pointer(utf16("AppsUseLightTheme"))), rrfRtDword, 0, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&n)))
	return r == 0 && v == 0
}

// themaSetzen wählt die Farben; die Pinsel der alten Farben werden frei.
func themaSetzen(dunkel bool) {
	for _, b := range th.pinsel {
		pDeleteObject.Call(b)
	}
	th.pinsel = map[desktop.RGB]uintptr{}
	th.dunkel = dunkel
	th.f = desktop.Hell
	if dunkel {
		th.f = desktop.Dunkel
	}
	dunkleMenues(dunkel)
}

func pinsel(c desktop.RGB) uintptr {
	if b, ok := th.pinsel[c]; ok {
		return b
	}
	b, _, _ := pCreateSolidBrush.Call(cref(c))
	th.pinsel[c] = b
	return b
}

// dunkleMenues: Kontextmenüs und Bildlaufleisten dunkel (uxtheme, Ordinal
// 135 SetPreferredAppMode und 136 FlushMenuThemes, seit Windows 10 1903).
// Ohne diese Funktionen bleiben sie hell.
func dunkleMenues(dunkel bool) {
	if uxtheme.Load() != nil {
		return
	}
	h := uxtheme.Handle()
	setze, _, _ := pGetProcAddress.Call(h, 135)
	flush, _, _ := pGetProcAddress.Call(h, 136)
	if setze == 0 || flush == 0 {
		return
	}
	modus := uintptr(3) // ForceLight
	if dunkel {
		modus = 2 // ForceDark
	}
	syscall.SyscallN(setze, modus)
	syscall.SyscallN(flush)
}

// titelleiste: dunkle Titelleiste im dunklen Modus (Windows 10 2004+).
func titelleiste(hwnd syscall.Handle) {
	if pDwmSetWindowAttribute.Find() != nil {
		return
	}
	v := uint32(0)
	if th.dunkel {
		v = 1
	}
	pDwmSetWindowAttribute.Call(uintptr(hwnd), dwmwaDarkMode, uintptr(unsafe.Pointer(&v)), 4)
}

// steuerThema: Bildlaufleisten und Auswahl der Steuerelemente passend.
func steuerThema(h syscall.Handle) {
	if pSetWindowTheme.Find() != nil {
		return
	}
	name := "Explorer"
	if th.dunkel {
		name = "DarkMode_Explorer"
	}
	pSetWindowTheme.Call(uintptr(h), uintptr(unsafe.Pointer(utf16(name))), 0)
}

// --- Schriften ---------------------------------------------------------------

var schriftDaten [][]byte // bleiben für die Laufzeit geladen

// schriftenLaden macht D-DIN und JetBrains Mono für diesen Prozess verfügbar.
func schriftenLaden() {
	for _, b := range desktop.Schriften() {
		var n uint32
		pAddFontMemResourceEx.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, uintptr(unsafe.Pointer(&n)))
		schriftDaten = append(schriftDaten, b)
	}
}

// schriften: alle Größen der Skala, die die App braucht (Pixel bei 96 dpi:
// 13, 16, 20, 25; nur 400 und 700).
type schriften struct {
	t13, t13b, t16, t16b, t20, t20b, t25b, m13 uintptr
	dpi                                        int32
}

func neueSchrift(dpi, px, gewicht int32, mono bool) uintptr {
	name := "D-DIN"
	if mono {
		name = "JetBrains Mono"
	}
	h, _, _ := pCreateFontW.Call(uintptr(-px*dpi/96), 0, 0, 0, uintptr(gewicht), 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16(name))))
	return h
}

func (s *schriften) setzen(dpi int32) {
	s.frei()
	s.dpi = dpi
	s.t13, s.t13b = neueSchrift(dpi, 13, fwNormal, false), neueSchrift(dpi, 13, fwBold, false)
	s.t16, s.t16b = neueSchrift(dpi, 16, fwNormal, false), neueSchrift(dpi, 16, fwBold, false)
	s.t20, s.t20b = neueSchrift(dpi, 20, fwNormal, false), neueSchrift(dpi, 20, fwBold, false)
	s.t25b = neueSchrift(dpi, 25, fwBold, false)
	s.m13 = neueSchrift(dpi, 13, fwNormal, true)
}

func (s *schriften) frei() {
	for _, h := range []uintptr{s.t13, s.t13b, s.t16, s.t16b, s.t20, s.t20b, s.t25b, s.m13} {
		if h != 0 {
			pDeleteObject.Call(h)
		}
	}
}

// --- Bitmaps mit Alphakanal --------------------------------------------------

type bitmapInfoHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPels, YPels           int32
	ClrUsed, ClrImportant  uint32
}

type bmp struct {
	h    uintptr
	w, y int32
}

// bitmapAus: 32-bit-DIB mit vormultipliziertem Alpha (für AlphaBlend).
func bitmapAus(img *image.NRGBA) bmp {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	bi := bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32, Compression: biRGB}
	var bits unsafe.Pointer
	hb, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), dibRGBColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hb == 0 || bits == nil {
		return bmp{}
	}
	px := unsafe.Slice((*byte)(bits), w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(img.Rect.Min.X+x, img.Rect.Min.Y+y)
			i := (y*w + x) * 4
			a := uint32(c.A)
			px[i+0] = byte(uint32(c.B) * a / 255)
			px[i+1] = byte(uint32(c.G) * a / 255)
			px[i+2] = byte(uint32(c.R) * a / 255)
			px[i+3] = c.A
		}
	}
	return bmp{hb, int32(w), int32(h)}
}

func bitmapAusPNG(b []byte) bmp {
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return bmp{}
	}
	n := image.NewNRGBA(img.Bounds())
	draw.Draw(n, n.Bounds(), img, img.Bounds().Min, draw.Src)
	return bitmapAus(n)
}

// alpha zeichnet b an (x, y) in Originalgröße.
func alpha(hdc uintptr, b bmp, x, y int32) {
	if b.h == 0 {
		return
	}
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	alt, _, _ := pSelectObject.Call(mem, b.h)
	blend := uintptr(255<<16 | acSrcAlpha<<24) // AC_SRC_OVER, Deckkraft 255, AC_SRC_ALPHA
	pAlphaBlend.Call(hdc, uintptr(x), uintptr(y), uintptr(b.w), uintptr(b.y), mem, 0, 0, uintptr(b.w), uintptr(b.y), blend)
	pSelectObject.Call(mem, alt)
	pDeleteDC.Call(mem)
}

type formSchluessel struct {
	form desktop.Form
	c    desktop.RGB
	n    int32
}

var formCache = map[formSchluessel]bmp{}

// form zeichnet eine Zustandsform n×n Pixel an (x, y).
func form(hdc uintptr, f desktop.Form, c desktop.RGB, x, y, n int32) {
	k := formSchluessel{f, c, n}
	b, ok := formCache[k]
	if !ok {
		b = bitmapAus(desktop.FormBild(f, c, int(n)))
		formCache[k] = b
	}
	alpha(hdc, b, x, y)
}

// formenLeeren: nach Wechsel von Thema oder Skalierung.
func formenLeeren() {
	for k, b := range formCache {
		pDeleteObject.Call(b.h)
		delete(formCache, k)
	}
}

// --- Flächen, Linien, Text ---------------------------------------------------

func fuellen(hdc uintptr, r rect, c desktop.RGB) {
	pFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), pinsel(c))
}

// rund: Rechteck mit Radius rad, gefüllt (fill) und/oder mit 1-px-Rand.
func rund(hdc uintptr, r rect, rad int32, fill, rand desktop.RGB, mitFuellung, mitRand bool, gestrichelt bool) {
	var stift uintptr
	if mitRand {
		stil := uintptr(psSolid)
		if gestrichelt {
			stil = psDash
		}
		stift, _, _ = pCreatePen.Call(stil, 1, cref(rand))
	} else {
		stift, _, _ = pGetStockObject.Call(nullPen)
	}
	altP, _, _ := pSelectObject.Call(hdc, stift)
	var b uintptr
	if mitFuellung {
		b = pinsel(fill)
	} else {
		b, _, _ = pGetStockObject.Call(nullBrush)
	}
	altB, _, _ := pSelectObject.Call(hdc, b)
	pRoundRect.Call(hdc, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom), uintptr(2*rad), uintptr(2*rad))
	pSelectObject.Call(hdc, altB)
	pSelectObject.Call(hdc, altP)
	if mitRand {
		pDeleteObject.Call(stift)
	}
}

func waagrecht(hdc uintptr, x1, x2, y int32, c desktop.RGB) {
	fuellen(hdc, rect{x1, y, x2, y + 1}, c)
}

func senkrecht(hdc uintptr, x, y1, y2 int32, c desktop.RGB) {
	fuellen(hdc, rect{x, y1, x + 1, y2}, c)
}

// schreiben: Text in r, einzeilig und senkrecht mittig, sonst flags.
func schreiben(hdc uintptr, s string, r rect, font uintptr, c desktop.RGB, flags uintptr) {
	if s == "" {
		return
	}
	pSelectObject.Call(hdc, font)
	pSetTextColor.Call(hdc, cref(c))
	pSetBkMode.Call(hdc, transparent)
	if flags&dtWordBreak == 0 {
		flags |= dtSingleLine | dtVCenter | dtEndEllipsis
	}
	pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(utf16(s))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags|dtNoPrefix)
}

// breite: Breite des Textes in Pixeln.
func breite(hdc uintptr, s string, font uintptr) int32 {
	pSelectObject.Call(hdc, font)
	u, _ := syscall.UTF16FromString(s)
	if len(u) <= 1 {
		return 0
	}
	var sz size
	pGetTextExtentPoint32W.Call(hdc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&sz)))
	return sz.Cx
}

// hoehe: Höhe eines umbrochenen Textes bei Breite w.
func hoehe(hdc uintptr, s string, font uintptr, w int32) int32 {
	pSelectObject.Call(hdc, font)
	r := rect{0, 0, w, 0}
	pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(utf16(s))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), dtWordBreak|dtCalcRect|dtNoPrefix)
	return r.Bottom
}

// malen: doppelt gepuffertes Zeichnen für WM_PAINT.
func malen(hwnd uintptr, fn func(hdc uintptr, r rect)) {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	var r rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	if r.Right <= 0 || r.Bottom <= 0 {
		return
	}
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	bm, _, _ := pCreateCompatibleBmp.Call(hdc, uintptr(r.Right), uintptr(r.Bottom))
	alt, _, _ := pSelectObject.Call(mem, bm)
	fn(mem, r)
	pBitBlt.Call(hdc, 0, 0, uintptr(r.Right), uintptr(r.Bottom), mem, 0, 0, srcCopy)
	pSelectObject.Call(mem, alt)
	pDeleteObject.Call(bm)
	pDeleteDC.Call(mem)
}

// mausVerlassen: WM_MOUSELEAVE anfordern (für Hervorhebung beim Überfahren).
func mausVerlassen(hwnd uintptr) {
	t := struct {
		Size, Flags uint32
		Hwnd        uintptr
		Hover       uint32
	}{Flags: tmeLeave, Hwnd: hwnd}
	t.Size = uint32(unsafe.Sizeof(t))
	pTrackMouseEvent.Call(uintptr(unsafe.Pointer(&t)))
}

// appIcon: Programmsymbol (Bildzeichen) aus der Ressource in Größe n.
func appIcon(n int32) uintptr {
	inst, _, _ := pGetModuleHandleW.Call(0)
	h, _, _ := pLoadImageW.Call(inst, 1, imageIcon, uintptr(n), uintptr(n), 0)
	return h
}

// --- Platzhalter in Eingabefeldern ---------------------------------------------

var (
	pSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	pCallWindowProcW   = user32.NewProc("CallWindowProcW")
	platzhalterProc    uintptr
	platzhalterFelder  = map[syscall.Handle]platzhalterInfo{}
)

type platzhalterInfo struct {
	alt   uintptr
	text  string
	nacht bool // auf der Markenleiste (--nacht-leise statt --leise)
}

const (
	gwlpWndProc = ^uintptr(3) // -4
	wmGetFont   = 0x0031
	wmKillFocus = 0x0008
	wmNcDestroy = 0x0082
)

// platzhalter zeigt text in --leise, solange das Feld leer ist und keinen
// Fokus hat (statt EM_SETCUEBANNER, das Systemgrau zeichnet).
func platzhalter(h syscall.Handle, text string, nacht bool) {
	if platzhalterProc == 0 {
		platzhalterProc = syscall.NewCallback(platzhalterWndProc)
	}
	alt, _, _ := pSetWindowLongPtrW.Call(uintptr(h), gwlpWndProc, platzhalterProc)
	platzhalterFelder[h] = platzhalterInfo{alt, text, nacht}
}

func platzhalterWndProc(hwnd, m, wp, lp uintptr) uintptr {
	info, ok := platzhalterFelder[syscall.Handle(hwnd)]
	if !ok {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	r, _, _ := pCallWindowProcW.Call(info.alt, hwnd, m, wp, lp)
	switch uint32(m) {
	case wmPaint:
		fokus, _, _ := pGetFocus.Call()
		n, _, _ := pGetWindowTextLengthW.Call(hwnd)
		if n == 0 && fokus != hwnd {
			hdc, _, _ := pGetDC.Call(hwnd)
			font, _, _ := pSendMessageW.Call(hwnd, wmGetFont, 0, 0)
			var cr rect
			pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
			c := th.f.Leise
			if info.nacht {
				c = th.f.NachtLeise
			}
			cr.Left += 2
			schreiben(hdc, info.text, cr, font, c, 0)
			pReleaseDC.Call(hwnd, hdc)
		}
	case wmSetFocus, wmKillFocus:
		pInvalidateRect.Call(hwnd, 0, 1)
	case wmNcDestroy:
		delete(platzhalterFelder, syscall.Handle(hwnd))
	}
	return r
}

// --- Piktogramme der Seitenleiste --------------------------------------------

type piktoSchluessel struct {
	name string
	c    desktop.RGB
	n    int32
}

var piktoCache = map[piktoSchluessel]bmp{}

// piktogramm zeichnet ein Piktogramm der Weboberfläche n×n bei (x, y).
func piktogramm(hdc uintptr, name string, c desktop.RGB, x, y, n int32) {
	k := piktoSchluessel{name, c, n}
	b, ok := piktoCache[k]
	if !ok {
		b = bitmapAus(desktop.PiktogrammBild(name, c, int(n)))
		piktoCache[k] = b
	}
	alpha(hdc, b, x, y)
}

func piktogrammeLeeren() {
	for k, b := range piktoCache {
		pDeleteObject.Call(b.h)
		delete(piktoCache, k)
	}
}
