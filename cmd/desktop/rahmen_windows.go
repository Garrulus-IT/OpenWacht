// SPDX-License-Identifier: AGPL-3.0-only

package main

// Rahmen des Hauptfensters wie web/src/Oberflaeche.tsx: Seitenleiste links
// (leiste_windows.go), Kopf mit Brotkrumen, Knöpfen der Seite und Suche oben,
// darunter der Inhalt der Seite auf --grund mit Karten auf --flaeche.

import (
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

// fenster: Zustand der Oberfläche (nur im Oberflächen-Thread benutzt).
type fenster struct {
	hwnd, leiste, kopfleiste, suche, hinweisF                    syscall.Handle
	befehle, baum, kopf, listKopf, liste, details, sonne, uebers syscall.Handle

	seite     int
	mandant   string // gewählter Mandant (Wurzel des Bereichs)
	mitUnter  bool
	dashHost  string // im Dashboard geöffnetes Gerät ("d:<id>"), "" = Übersicht
	sonnenKey string // Wurzel der Sonne (Klick auf Gruppe), "" = Bereich

	sonnenBild  bmp
	sonnenSig   string
	sonnenSeg   []desktop.Segment
	sonnenRing  []float64
	sonnenWurz  *desktop.Knoten
	sonnenUeber string

	sch       schriften
	dpi       int32
	logo      bmp
	zeilenBil uintptr // Bildliste nur für die Zeilenhöhe der Liste

	detailH int32
	ziehen  bool
	karten  []rect // Ränder der Karten im Inhalt
	detailR rect   // Karte mit Kopf, Liste und Einzelheiten

	eintraege []baumEintrag
	items     map[string]uintptr
	baumSig   string
	gewaehlt  string
	baue      bool

	zeilen  []listenZeile
	spalten []spalte
	breiten []int32
	sortSp  int // -1 = Zustand zuerst
	sortAb  bool

	knoepfe     []knopf // Befehle zum Gerät bzw. Sensor
	ueber       int     // Knopf unter der Maus, -1 = keiner
	kopfKnoepfe []knopf // Knöpfe der Seite im Kopf
	kopfUeber   int
	nurProbleme bool

	leisteOff   int32 // Bildlauf der Seitenleiste
	leisteHoehe int32
	leisteZiele []ziel
	leisteUeber int

	uebZiele []ziel
	uebUeber int

	wartungF  syscall.Handle // Seite Wartung
	wartZiele []ziel
	wartUeber int
	wartOff   int32
	wartHoehe int32

	meldung     string // kurze Rückmeldung oben im Inhalt
	meldungZeit time.Time
	sucheRahmen rect
}

// ziel: Klickfläche in einer selbst gezeichneten Fläche.
type ziel struct {
	r    rect
	art  string // nav, extern, mandant, unter, thema, abmelden, geraet
	wert string
}

func (z ziel) trifft(x, y int32) bool {
	return x >= z.r.Left && x < z.r.Right && y >= z.r.Top && y < z.r.Bottom
}

func (a *app) fensterAnlegen() (*fenster, error) {
	commonControls()
	schriftenLaden()
	themaSetzen(a.dunkel())
	inst, _, _ := pGetModuleHandleW.Call(0)
	cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
	f := &fenster{dpi: 96, sortSp: -1, items: map[string]uintptr{}, ueber: -1, kopfUeber: -1, leisteUeber: -1, uebUeber: -1, wartUeber: -1,
		mandant: a.cfg.Mandant, mitUnter: !a.cfg.OhneUnter}
	for _, k := range []struct {
		name string
		proc func(hwnd, m, wp, lp uintptr) uintptr
	}{{"OpenWachtFenster", fensterProc}, {"OpenWachtFlaeche", flaecheProc}} {
		wc := wndClassEx{WndProc: syscall.NewCallback(k.proc), Instance: syscall.Handle(inst), ClassName: utf16(k.name),
			Cursor: syscall.Handle(cursor)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			return nil, err
		}
	}
	a.f = f // fensterProc braucht es schon bei den ersten Nachrichten
	h, _, err := pCreateWindowExW.Call(wsExControlParent, uintptr(unsafe.Pointer(utf16("OpenWachtFenster"))),
		uintptr(unsafe.Pointer(utf16("OpenWacht"))), wsOverlappedWindow|wsClipChildren, cwUseDefault, cwUseDefault, 1360, 860, 0, 0, inst, 0)
	if h == 0 {
		a.f = nil
		return nil, err
	}
	f.hwnd = syscall.Handle(h)
	f.dpi = dpiVon(f.hwnd)
	f.detailH = f.s(200)

	flaeche := func(id int) syscall.Handle {
		return kind(f.hwnd, "OpenWachtFlaeche", "", wsClipChildren, 0, id)
	}
	f.leiste = flaeche(idLeiste)
	f.kopfleiste = flaeche(idKopfleiste)
	f.suche = kind(f.kopfleiste, "EDIT", "", wsTabStop|esAutoHScroll, 0, idSuche)
	platzhalter(f.suche, "Suchen", false)
	f.hinweisF = flaeche(idHinweis)
	f.sonne = flaeche(idSonne)
	f.uebers = flaeche(idUebersicht)
	f.wartungF = flaeche(idWartung)

	f.baum = kind(f.hwnd, "SysTreeView32", "", wsTabStop|tvsHasButtons|tvsLinesAtRoot|tvsShowSelAlways|tvsFullRowSelect|tvsTrackSelect, 0, idBaum)
	send(f.baum, tvmSetExtStyle, tvsExDoubleBuffer, tvsExDoubleBuffer)

	f.kopf = flaeche(idKopf)
	f.befehle = flaeche(idBefehle)
	f.listKopf = flaeche(idListKopf)
	f.liste = kind(f.hwnd, "SysListView32", "", wsTabStop|lvsReport|lvsSingleSel|lvsShowSelAlways|lvsNoColumnHeader, 0, idListe)
	send(f.liste, lvmSetExtendedStyle, lvsExFullRowSelect|lvsExDoubleBuffer, lvsExFullRowSelect|lvsExDoubleBuffer)
	c := lvColumn{Mask: lvcfWidth, Cx: 100}
	sendP(f.liste, lvmInsertColumnW, 0, unsafe.Pointer(&c))
	f.details = flaeche(idDetails)

	f.knoepfeAnlegen()
	f.dpiAnwenden()
	f.themaAnwenden()
	pSetWindowPos.Call(h, 0, 0, 0, uintptr(f.s(1360)), uintptr(f.s(860)), swpNoMove|swpNoZOrder|swpNoActivate)
	return f, nil
}

func (f *fenster) knoepfeAnlegen() {
	f.knoepfe = []knopf{
		{id: cmdNeuSensor, text: "+ Sensor", haupt: true},
		{id: 0}, // Lücke 24
		{id: cmdJetzt, text: "Jetzt abfragen"},
		{id: cmdBestaetigen, text: "Alarm bestätigen …"},
		{id: cmdWartung, text: "Wartung …"},
		{id: cmdPause, text: "Pausieren"},
		{id: cmdMehr, text: "Mehr", rechts: true, an: true},
		{id: cmdNurProbleme, text: "Nur Probleme", schalt: true, rechts: true, an: true},
	}
}

// kopfKnoepfeSetzen: Knöpfe der Seite im Kopf (wie kopf-rechts im Web).
func (f *fenster) kopfKnoepfeSetzen(schreiben bool) {
	var k []knopf
	if f.seite == seiteHosts {
		k = append(k, knopf{id: cmdNeuGeraet, text: "Host hinzufügen", an: schreiben})
	}
	k = append(k, knopf{id: cmdImBrowser, text: "Im Browser öffnen", an: true})
	gleich := len(k) == len(f.kopfKnoepfe)
	for i := range k {
		if gleich && (k[i].id != f.kopfKnoepfe[i].id || k[i].an != f.kopfKnoepfe[i].an) {
			gleich = false
		}
	}
	if !gleich {
		f.kopfKnoepfe = k
		f.kopfOrdnen()
		pInvalidateRect.Call(uintptr(f.kopfleiste), 0, 0)
	}
}

// dpiAnwenden: Schriften, Logo und Maße für die aktuelle Skalierung.
func (f *fenster) dpiAnwenden() {
	f.sch.setzen(f.dpi)
	formenLeeren()
	if f.logo.h != 0 {
		pDeleteObject.Call(f.logo.h)
	}
	f.logo = bitmapAusPNG(desktop.Zeichen(int(f.s(38))))
	send(f.suche, wmSetFont, f.sch.t13, 1)
	alt := f.zeilenBil
	f.zeilenBil, _, _ = pImageListCreate.Call(1, uintptr(f.s(zeileH)), ilcColor32, 1, 1)
	send(f.liste, lvmSetImageList, lvsilSmall, f.zeilenBil)
	if alt != 0 {
		pImageListDestroy.Call(alt)
	}
	send(f.baum, tvmSetItemHeight, uintptr(f.s(zeileH)), 0)
	send(f.baum, tvmSetIndent, uintptr(f.s(16)), 0)
	send(f.hwnd, wmSetIcon, 0, appIcon(f.s(16)))
	send(f.hwnd, wmSetIcon, 1, appIcon(f.s(32)))
	f.sonnenSig = ""
	f.anordnen()
}

// themaAnwenden: Farben der Steuerelemente nach hell/dunkel.
func (f *fenster) themaAnwenden() {
	formenLeeren()
	piktogrammeLeeren()
	f.sonnenSig = ""
	send(f.liste, lvmSetBkColor, 0, cref(th.f.Flaeche))
	send(f.baum, tvmSetBkColor, 0, cref(th.f.Flaeche))
	steuerThema(f.liste)
	steuerThema(f.baum)
	titelleiste(f.hwnd)
	pRedrawWindow.Call(uintptr(f.hwnd), 0, 0, rdwInvalidate|rdwErase|rdwAllChildren|rdwFrame)
}

func zeigen(h syscall.Handle, an bool) {
	pShowWindow.Call(uintptr(h), map[bool]uintptr{true: swShow, false: swHide}[an])
}

// hinweisText: was oben im Inhalt steht (Störung oder kurze Rückmeldung).
func (a *app) hinweisText() (string, bool) {
	a.mu.Lock()
	fehler, zentrale := a.standFehler, a.client.Zentrale
	a.mu.Unlock()
	if fehler != "" {
		return "Die Zentrale " + strings.TrimPrefix(zentrale, "https://") + " antwortet nicht: " + fehlerKurz(fehler) +
			". Die Anzeige versucht es alle 30 s erneut.", true
	}
	if f := a.f; f != nil && f.meldung != "" && time.Since(f.meldungZeit) < 15*time.Second {
		return f.meldung, false
	}
	return "", false
}

// anordnen: alle Teile nach Fenstergröße und Seite.
func (f *fenster) anordnen() {
	var r rect
	pGetClientRect.Call(uintptr(f.hwnd), uintptr(unsafe.Pointer(&r)))
	w, h := r.Right, r.Bottom
	if w <= 0 || h <= 0 {
		return
	}
	lb := f.s(leisteB)
	move(f.leiste, 0, 0, lb, h)
	x0 := lb + 1
	kh := f.s(kopfleiste)
	move(f.kopfleiste, x0, 0, w-x0, kh)
	f.kopfOrdnen()

	// Inhalt: Abstand oben 24, seitlich 32 (schmal 16), Lücke 16
	seitlich := f.s(32)
	if w-x0 < f.s(1000) {
		seitlich = f.s(16)
	}
	x := x0 + seitlich
	y := kh + 1 + f.s(24)
	cw := w - x - seitlich
	unten := h - f.s(24)
	if t, _ := a.hinweisText(); t != "" {
		move(f.hinweisF, x, y, cw, f.s(40))
		zeigen(f.hinweisF, true)
		y += f.s(40) + f.s(16)
	} else {
		zeigen(f.hinweisF, false)
	}
	ch := unten - y
	gap := f.s(16)
	f.karten = f.karten[:0]
	karte := func(hwnd syscall.Handle, kx, ky, kw, khh int32) {
		f.karten = append(f.karten, rect{kx, ky, kx + kw, ky + khh})
		if hwnd != 0 {
			move(hwnd, kx+1, ky+1, kw-2, khh-2)
		}
	}
	host := f.knoten()
	dash := f.seite == seiteDashboard
	hostOffen := dash && f.dashHost != "" && host != nil
	var detail rect
	switch {
	case dash && hostOffen:
		sw := max(min(cw*48/100, ch+f.s(32)), f.s(360))
		karte(f.sonne, x, y, sw, ch)
		detail = rect{x + sw + gap, y, x + cw, y + ch}
	case dash:
		ub := min(f.s(uebB), cw/3)
		karte(f.sonne, x, y, cw-ub-gap, ch)
		karte(f.uebers, x+cw-ub, y, ub, ch)
	case f.seite == seiteHosts:
		bb := min(f.s(baumB), cw/3)
		karte(f.baum, x, y, bb, ch)
		detail = rect{x + bb + gap, y, x + cw, y + ch}
	case f.seite == seiteWartung:
		move(f.wartungF, x, y, cw, ch)
	default:
		detail = rect{x, y, x + cw, y + ch}
	}
	zeigen(f.wartungF, f.seite == seiteWartung)
	zeigen(f.sonne, dash)
	zeigen(f.uebers, dash && !hostOffen)
	zeigen(f.baum, f.seite == seiteHosts)
	mitDetail := detail.Right > detail.Left
	for _, d := range []syscall.Handle{f.kopf, f.befehle, f.listKopf, f.liste, f.details} {
		zeigen(d, mitDetail)
	}
	f.detailR = detail
	if mitDetail {
		dx, dy, dw := detail.Left+1, detail.Top+1, detail.Right-detail.Left-2
		dh := detail.Bottom - detail.Top - 2
		f.karten = append(f.karten, detail)
		move(f.kopf, dx, dy, dw, f.s(kopfH))
		yy := dy + f.s(kopfH)
		move(f.befehle, dx, yy, dw, f.s(befehlH))
		f.knoepfeOrdnen(dw)
		yy += f.s(befehlH)
		move(f.listKopf, dx, yy, dw, f.s(zeileH))
		yy += f.s(zeileH)
		rest := dy + dh - yy
		f.detailH = min(max(f.detailH, f.s(detailMin)), max(rest-f.s(120)-f.s(luecke), f.s(detailMin)))
		move(f.liste, dx, yy, dw, rest-f.detailH-f.s(luecke))
		move(f.details, dx, dy+dh-f.detailH, dw, f.detailH)
		f.spaltenOrdnen(dw)
	}
	pRedrawWindow.Call(uintptr(f.hwnd), 0, 0, rdwInvalidate|rdwAllChildren)
}

// kopfOrdnen: Suche rechts, Knöpfe der Seite links davon.
func (f *fenster) kopfOrdnen() {
	var r rect
	pGetClientRect.Call(uintptr(f.kopfleiste), uintptr(unsafe.Pointer(&r)))
	w := r.Right
	if w <= 0 {
		return
	}
	seitlich := f.s(32)
	if w < f.s(1000) {
		seitlich = f.s(16)
	}
	sw := f.s(240)
	kh := f.s(kopfleiste)
	f.sucheRahmen = rect{w - seitlich - sw, (kh - f.s(32)) / 2, w - seitlich, (kh-f.s(32))/2 + f.s(32)}
	eh := f.s(20)
	move(f.suche, f.sucheRahmen.Left+f.s(8)+f.s(16)+f.s(8), f.sucheRahmen.Top+(f.s(32)-eh)/2, sw-f.s(40)-f.s(56), eh)
	hdc, _, _ := pGetDC.Call(uintptr(f.kopfleiste))
	defer pReleaseDC.Call(uintptr(f.kopfleiste), hdc)
	x := f.sucheRahmen.Left - f.s(12)
	for i := len(f.kopfKnoepfe) - 1; i >= 0; i-- {
		k := &f.kopfKnoepfe[i]
		bw := breite(hdc, k.text, f.sch.t13) + 2*f.s(16)
		k.r = rect{x - bw, f.sucheRahmen.Top, x, f.sucheRahmen.Bottom}
		x -= bw + f.s(8)
	}
}

// --- Daten anzeigen ----------------------------------------------------------

// aktualisieren zeigt den letzten Stand. immer=false: Liste nur bei Änderung
// neu aufbauen, damit Auswahl und Bildlauf bleiben.
func (a *app) aktualisieren(immer bool) {
	f := a.f
	if f == nil {
		return
	}
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	reihe := desktop.MandantenReihe(st.Mandanten)
	gibt := false
	for _, z := range reihe {
		if z.Mandant.ID == f.mandant {
			gibt = true
		}
	}
	if !gibt && len(reihe) > 0 {
		f.mandant = reihe[0].Mandant.ID
	}
	a.baum = desktop.BaumBauen(desktop.BereichStand(st, f.mandant, f.mitUnter))
	f.baumFuellen(a.baum)
	if f.dashHost != "" && f.eintrag(f.dashHost) == nil {
		f.dashHost = ""
	}
	if f.sonnenKey != "" && f.eintrag(f.sonnenKey) == nil {
		f.sonnenKey = ""
	}
	f.anordnen()
	a.auswahlZeigen(immer)
	pInvalidateRect.Call(uintptr(f.leiste), 0, 0)
	pInvalidateRect.Call(uintptr(f.uebers), 0, 0)
	pInvalidateRect.Call(uintptr(f.wartungF), 0, 0)
}

func (f *fenster) eintrag(key string) *baumEintrag {
	for i := range f.eintraege {
		if f.eintraege[i].key == key {
			return &f.eintraege[i]
		}
	}
	return nil
}

// knoten: der Knoten, dessen Sensoren Kopf und Liste zeigen (nil = keiner).
func (f *fenster) knoten() *desktop.Knoten {
	key := f.gewaehlt
	switch f.seite {
	case seiteDashboard:
		key = f.dashHost
	case seiteAlarme:
		if len(f.eintraege) > 0 {
			key = f.eintraege[0].key
		}
	case seiteWartung:
		return nil
	}
	if e := f.eintrag(key); e != nil {
		return e.knoten
	}
	return nil
}

// seiteWechseln: wie ein Klick in der Seitenleiste.
func (a *app) seiteWechseln(s int) {
	f := a.f
	if f.seite == s {
		if s == seiteDashboard && (f.dashHost != "" || f.sonnenKey != "") {
			f.dashHost, f.sonnenKey = "", ""
		} else {
			return
		}
	}
	f.seite = s
	a.wartungSicht.Store(s == seiteWartung)
	if s == seiteWartung {
		f.wartOff = 0
		a.wartungLaden()
	}
	f.anordnen()
	a.auswahlZeigen(true)
	pInvalidateRect.Call(uintptr(f.leiste), 0, 0)
}

// geraetOeffnen: Gerät aus Sonne oder Übersicht neben der Sonne öffnen.
func (a *app) geraetOeffnen(key string) {
	f := a.f
	if f.dashHost == key {
		f.dashHost = ""
	} else {
		f.dashHost = key
	}
	f.anordnen()
	a.auswahlZeigen(true)
	pInvalidateRect.Call(uintptr(f.sonne), 0, 0)
}

// krume: Zusatz in den Brotkrumen (gewähltes Gerät).
func (f *fenster) krume() string {
	k := f.knoten()
	switch {
	case k == nil:
		return ""
	case f.seite == seiteDashboard:
		return k.Name
	case f.seite == seiteHosts && k.Art == desktop.KnotenGeraet:
		return k.Name
	}
	return ""
}

func (a *app) kopfleisteMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	waagrecht(hdc, 0, r.Right, r.Bottom-1, th.f.Linie)
	seitlich := f.s(32)
	if r.Right < f.s(1000) {
		seitlich = f.s(16)
	}
	x := seitlich
	titel := seitenTitel[f.seite]
	links := f.sucheRahmen.Left - f.s(12)
	if len(f.kopfKnoepfe) > 0 {
		links = f.kopfKnoepfe[0].r.Left - f.s(12)
	}
	if k := f.krume(); k != "" {
		w := breite(hdc, titel, f.sch.t16)
		schreiben(hdc, titel, rect{x, 0, x + w + 1, r.Bottom}, f.sch.t16, th.f.Leise, 0)
		x += w
		w = breite(hdc, " › ", f.sch.t16)
		schreiben(hdc, " › ", rect{x, 0, x + w + 1, r.Bottom}, f.sch.t16, th.f.Leise, 0)
		x += w
		schreiben(hdc, k, rect{x, 0, links, r.Bottom}, f.sch.t16b, th.f.Tinte, 0)
	} else {
		schreiben(hdc, titel, rect{x, 0, links, r.Bottom}, f.sch.t16b, th.f.Tinte, 0)
	}
	for i, k := range f.kopfKnoepfe {
		knopfMalen(f, hdc, k, i == f.kopfUeber, false)
	}
	// Suche wie .kopf-suche: Rand, Lupe, Text, Taste „Strg K“
	rand := th.f.Linie
	fokus, _, _ := pGetFocus.Call()
	if syscall.Handle(fokus) == f.suche {
		rand = th.f.Marke
	}
	rund(hdc, f.sucheRahmen, f.s(3), th.f.Flaeche, rand, true, true, false)
	n := f.s(16)
	piktogramm(hdc, "suche", th.f.Leise, f.sucheRahmen.Left+f.s(8), (f.sucheRahmen.Top+f.sucheRahmen.Bottom-n)/2, n)
	t := "Strg K"
	tw := breite(hdc, t, f.sch.m13) + 2*f.s(4)
	kr := rect{f.sucheRahmen.Right - f.s(8) - tw, f.sucheRahmen.Top + f.s(6), f.sucheRahmen.Right - f.s(8), f.sucheRahmen.Bottom - f.s(6)}
	rund(hdc, kr, f.s(3), th.f.Zart, th.f.Linie, true, true, false)
	schreiben(hdc, t, kr, f.sch.m13, th.f.Leise, dtCenter)
}

// knopfMalen: Knopf wie .knopf im Web (Primär --marke, sonst Rand --linie).
func knopfMalen(f *fenster, hdc uintptr, k knopf, hover, schalter bool) {
	fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
	switch {
	case k.haupt:
		fg, bg, rand = th.f.AufMarke, th.f.Marke, th.f.Marke
		if hover {
			bg, rand = th.f.MarkeTief, th.f.MarkeTief
		}
	case schalter:
		fg, bg, rand = th.f.MarkeTief, th.f.MarkeHauch, th.f.Marke
	case hover:
		rand, bg = th.f.Leise, th.f.Zart
	}
	if !k.an {
		// wie im Web: 55 % Deckkraft
		fg, bg, rand = mischen(fg, th.f.Flaeche, 55), mischen(bg, th.f.Flaeche, 55), mischen(rand, th.f.Flaeche, 55)
	}
	rund(hdc, k.r, f.s(3), bg, rand, true, true, false)
	tr := k.r
	if k.id == cmdMehr {
		tr.Right -= f.s(16)
		chevron(hdc, tr.Right+f.s(4), (k.r.Top+k.r.Bottom)/2, f.s(4), true, fg)
		schreiben(hdc, k.text, rect{tr.Left + f.s(12), tr.Top, tr.Right, tr.Bottom}, f.sch.t13, fg, 0)
		return
	}
	schreiben(hdc, k.text, tr, f.sch.t13, fg, dtCenter)
}

func (a *app) hinweisMalen(hdc uintptr, r rect) {
	f := a.f
	t, fehler := a.hinweisText()
	fuellen(hdc, r, th.f.Grund)
	farbe, hauch := th.f.Marke, th.f.MarkeHauch
	if fehler {
		farbe, hauch = th.f.Krit, th.f.KritHauch
	}
	rund(hdc, r, f.s(3), hauch, hauch, true, false, false)
	fuellen(hdc, rect{0, 0, f.s(4), r.Bottom}, farbe)
	schreiben(hdc, t, rect{f.s(16), 0, r.Right - f.s(12), r.Bottom}, f.sch.t13, th.f.Tinte, 0)
}

// --- Nachrichten ------------------------------------------------------------

func punktAus(lp uintptr) (int32, int32) {
	return int32(int16(lp & 0xffff)), int32(int16((lp >> 16) & 0xffff))
}

func flaecheProc(hwnd, m, wp, lp uintptr) uintptr {
	if a == nil || a.f == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	f := a.f
	h := syscall.Handle(hwnd)
	switch uint32(m) {
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		malen(hwnd, func(hdc uintptr, r rect) {
			switch h {
			case f.leiste:
				a.leisteMalen(hdc, r)
			case f.kopfleiste:
				a.kopfleisteMalen(hdc, r)
			case f.hinweisF:
				a.hinweisMalen(hdc, r)
			case f.befehle:
				f.befehleMalen(hdc, r)
			case f.kopf:
				a.kopfMalen(hdc, r)
			case f.listKopf:
				f.listKopfMalen(hdc, r)
			case f.details:
				a.detailsMalen(hdc, r)
			case f.sonne:
				a.sonneMalen(hdc, r)
			case f.uebers:
				a.uebersichtMalen(hdc, r)
			case f.wartungF:
				a.wartungMalen(hdc, r)
			default:
				fuellen(hdc, r, th.f.Grund)
			}
		})
		return 0
	case wmCommand:
		// Suchfeld im Kopf: an das Hauptfenster weiterreichen
		pSendMessageW.Call(uintptr(f.hwnd), m, wp, lp)
		return 0
	case wmCtlColorEdit, wmCtlColorStatic:
		pSetTextColor.Call(wp, cref(th.f.Tinte))
		pSetBkColor.Call(wp, cref(th.f.Flaeche))
		return pinsel(th.f.Flaeche)
	case wmMouseWheel:
		if h == f.leiste {
			d := int32(int16(wp >> 16))
			f.leisteScrollen(-d * f.s(48) / 120)
			return 0
		}
		if h == f.wartungF {
			d := int32(int16(wp >> 16))
			f.wartungScrollen(-d * f.s(48) / 120)
			return 0
		}
	case wmSetCursor:
		var p point
		pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
		pScreenToClient.Call(hwnd, uintptr(unsafe.Pointer(&p)))
		if f.klickbar(h, p.X, p.Y) {
			c, _, _ := pLoadCursorW.Call(0, idcHand)
			pSetCursor.Call(c)
			return 1
		}
	case wmMouseMove:
		x, y := punktAus(lp)
		neuUeber := func(alt *int, neu int) {
			if neu != *alt {
				*alt = neu
				mausVerlassen(hwnd)
				pInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		switch h {
		case f.sonne:
			if t := a.sonneText(x, y); t != f.sonnenUeber {
				f.sonnenUeber = t
				mausVerlassen(hwnd)
				pInvalidateRect.Call(hwnd, 0, 0)
			}
		case f.befehle:
			neuUeber(&f.ueber, knopfBei(f.knoepfe, x, y))
		case f.kopfleiste:
			neuUeber(&f.kopfUeber, knopfBei(f.kopfKnoepfe, x, y))
		case f.leiste:
			neuUeber(&f.leisteUeber, zielBei(f.leisteZiele, x, y))
		case f.uebers:
			neuUeber(&f.uebUeber, zielBei(f.uebZiele, x, y))
		case f.wartungF:
			neuUeber(&f.wartUeber, zielBei(f.wartZiele, x, y))
		}
		return 0
	case wmMouseLeave:
		switch h {
		case f.sonne:
			f.sonnenUeber = ""
		case f.befehle:
			f.ueber = -1
		case f.kopfleiste:
			f.kopfUeber = -1
		case f.leiste:
			f.leisteUeber = -1
		case f.uebers:
			f.uebUeber = -1
		case f.wartungF:
			f.wartUeber = -1
		}
		pInvalidateRect.Call(hwnd, 0, 0)
		return 0
	case wmLButtonUp:
		x, y := punktAus(lp)
		switch h {
		case f.befehle:
			if i := knopfBei(f.knoepfe, x, y); i >= 0 && f.knoepfe[i].an {
				a.befehlFenster(f.knoepfe[i].id)
			}
		case f.kopfleiste:
			if i := knopfBei(f.kopfKnoepfe, x, y); i >= 0 && f.kopfKnoepfe[i].an {
				a.befehlFenster(f.kopfKnoepfe[i].id)
			} else if x >= f.sucheRahmen.Left && x < f.sucheRahmen.Right {
				pSetFocus.Call(uintptr(f.suche))
			}
		case f.listKopf:
			sx := int32(0)
			for i, sp := range f.spalten {
				if x >= sx && x < sx+f.breiten[i] {
					if f.sortSp == sp.id {
						f.sortAb = !f.sortAb
					} else {
						f.sortSp, f.sortAb = sp.id, false
					}
					a.auswahlZeigen(true)
					break
				}
				sx += f.breiten[i]
			}
		case f.kopf:
			if f.seite == seiteDashboard && f.dashHost != "" && x > f.kopfSchliessenX() {
				a.befehlFenster(cmdSchliessen)
			}
		case f.sonne:
			a.sonneKlick(x, y)
		case f.leiste:
			if i := zielBei(f.leisteZiele, x, y); i >= 0 {
				a.leisteKlick(f.leisteZiele[i])
			}
		case f.uebers:
			if i := zielBei(f.uebZiele, x, y); i >= 0 {
				a.geraetOeffnen(f.uebZiele[i].wert)
			}
		case f.wartungF:
			if i := zielBei(f.wartZiele, x, y); i >= 0 {
				a.wartungKlick(f.wartZiele[i])
			}
		}
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

// klickbar: Hand statt Pfeil über Zielen, die etwas tun.
func (f *fenster) klickbar(h syscall.Handle, x, y int32) bool {
	switch h {
	case f.leiste:
		return zielBei(f.leisteZiele, x, y) >= 0
	case f.uebers:
		return zielBei(f.uebZiele, x, y) >= 0
	case f.wartungF:
		return zielBei(f.wartZiele, x, y) >= 0
	case f.sonne:
		return f.sonnenUeber != ""
	case f.kopf:
		return f.seite == seiteDashboard && f.dashHost != "" && x > f.kopfSchliessenX()
	}
	return false
}

func knopfBei(l []knopf, x, y int32) int {
	for i, k := range l {
		if k.id != 0 && x >= k.r.Left && x < k.r.Right && y >= k.r.Top && y < k.r.Bottom {
			return i
		}
	}
	return -1
}

func zielBei(l []ziel, x, y int32) int {
	for i, z := range l {
		if z.trifft(x, y) {
			return i
		}
	}
	return -1
}

func fensterProc(hwnd, m, wp, lp uintptr) uintptr {
	if a == nil || a.f == nil || (a.f.hwnd != 0 && syscall.Handle(hwnd) != a.f.hwnd) {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	f := a.f
	if f.hwnd == 0 { // noch in CreateWindowEx
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	switch uint32(m) {
	case wmSize:
		f.anordnen()
		return 0
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		malen(hwnd, func(hdc uintptr, r rect) {
			fuellen(hdc, r, th.f.Grund)
			senkrecht(hdc, f.s(leisteB), 0, r.Bottom, th.f.Linie)
			for _, k := range f.karten {
				rund(hdc, k, f.s(6), th.f.Flaeche, th.f.Linie, true, true, false)
			}
		})
		return 0
	case wmGetMinMaxInfo:
		mi := zeigerAus[minMaxInfo](lp)
		mi.MinTrackSize = point{f.s(1040), f.s(640)}
		return 0
	case wmDpiChanged:
		f.dpi = int32(wp & 0xffff)
		r := zeigerAus[rect](lp)
		f.detailH = f.s(200)
		pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
		f.dpiAnwenden()
		return 0
	case wmSettingChange:
		if utf16Text(lp) == "ImmersiveColorSet" {
			if d := a.dunkel(); d != th.dunkel {
				themaSetzen(d)
				f.themaAnwenden()
			}
		}
		return 0
	case wmClose:
		// Nur ausblenden: Die App bleibt im Infobereich.
		pShowWindow.Call(hwnd, swHide)
		a.fensterOffen.Store(false)
		return 0
	case wmSetCursor:
		if syscall.Handle(wp) == f.hwnd {
			var p point
			pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
			pScreenToClient.Call(hwnd, uintptr(unsafe.Pointer(&p)))
			if f.amTrenner(p.X, p.Y) {
				c, _, _ := pLoadCursorW.Call(0, idcSizeNS)
				pSetCursor.Call(c)
				return 1
			}
		}
	case wmLButtonDown:
		x, y := punktAus(lp)
		if f.amTrenner(x, y) {
			f.ziehen = true
			pSetCapture.Call(hwnd)
		}
		return 0
	case wmMouseMove:
		if f.ziehen {
			_, y := punktAus(lp)
			f.detailH = f.detailR.Bottom - 1 - y - f.s(luecke)/2
			f.anordnen()
		}
		return 0
	case wmLButtonUp:
		if f.ziehen {
			f.ziehen = false
			pReleaseCapture.Call()
		}
		return 0
	case wmCaptureChanged:
		f.ziehen = false
		return 0
	case wmCommand:
		id, code := wp&0xffff, (wp>>16)&0xffff
		switch {
		case id == idSuche && code == enChange:
			a.auswahlZeigen(true)
			f.wartOff = 0
			pInvalidateRect.Call(uintptr(f.wartungF), 0, 0)
		case id == idSuche && (code == 0x0100 || code == 0x0200): // EN_SETFOCUS, EN_KILLFOCUS
			pInvalidateRect.Call(uintptr(f.kopfleiste), 0, 0)
		}
		return 0
	case wmNotify:
		hdr := zeigerAus[nmHdr](lp)
		switch hdr.IDFrom {
		case idBaum:
			switch hdr.Code {
			case tvnSelChangedW:
				if f.baue {
					return 0
				}
				nt := zeigerAus[nmTreeView](lp)
				if i := int(nt.ItemNew.LParam); i < len(f.eintraege) {
					f.gewaehlt = f.eintraege[i].key
				}
				a.auswahlZeigen(true)
				pInvalidateRect.Call(uintptr(f.kopfleiste), 0, 0)
				return 0
			case nmRClick:
				a.kontextBaum()
				return 1
			case nmCustomDraw:
				cd := zeigerAus[nmCustomDrawLV](lp)
				switch cd.DrawStage {
				case cddsPrepaint:
					return cdrfNotifyItem
				case cddsItemPrepaint:
					f.baumZeileMalen(cd.Hdc, cd)
					return cdrfSkipDefault
				}
				return cdrfDoDefault
			}
		case idListe:
			switch hdr.Code {
			case lvnItemChanged:
				nl := zeigerAus[nmListView](lp)
				if nl.Changed&lvifState != 0 && (nl.NewState^nl.OldState)&lvisSelected != 0 {
					a.detailsZeigen()
				}
				return 0
			case nmDblClk, nmReturn:
				if z := f.gewaehlteZeile(); z != nil {
					if z.check != nil {
						a.befehlFenster(cmdBearbeiten)
					} else {
						a.befehlFenster(cmdImBrowser)
					}
				}
				return 0
			case nmRClick:
				a.kontextListe()
				return 0
			case nmCustomDraw:
				cd := zeigerAus[nmCustomDrawLV](lp)
				switch cd.DrawStage {
				case cddsPrepaint:
					return cdrfNotifyItem | cdrfNotifyPostPaint
				case cddsItemPrepaint:
					f.zeileMalen(cd.Hdc, int(cd.ItemSpec))
					return cdrfSkipDefault
				case cddsPostpaint:
					if len(f.zeilen) == 0 {
						var r rect
						pGetClientRect.Call(uintptr(f.liste), uintptr(unsafe.Pointer(&r)))
						t := "Keine Sensoren hier."
						switch {
						case f.seite == seiteAlarme && getText(f.suche) == "":
							t = "Keine aktiven Alarme. Alles in Ordnung."
						case f.nurProbleme && getText(f.suche) == "":
							t = "Keine aktiven Alarme."
						case getText(f.suche) != "" || f.nurProbleme:
							t = "Keine Sensoren für diese Auswahl."
						}
						schreiben(cd.Hdc, t, rect{f.s(16), f.s(8), r.Right - f.s(16), f.s(8) + f.s(32)}, f.sch.t13, th.f.Leise, 0)
					}
				}
				return cdrfDoDefault
			}
		}
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

// amTrenner: liegt der Punkt in der Lücke zwischen Liste und Einzelheiten?
func (f *fenster) amTrenner(x, y int32) bool {
	d := f.detailR
	if d.Right <= d.Left {
		return false
	}
	unten := d.Bottom - 1 - f.detailH
	return x > d.Left && x < d.Right && y >= unten-f.s(luecke) && y < unten
}

// schalterAn: Zustand der Schalter in der Befehlsleiste.
func (f *fenster) schalterAn(id int) bool {
	return id == cmdNurProbleme && (f.nurProbleme || f.seite == seiteAlarme)
}

// setStatusText: kurze Rückmeldung oben im Inhalt („Gespeichert.“).
func setStatusText(f *fenster, t string) {
	if f == nil {
		return
	}
	f.meldung, f.meldungZeit = t, time.Now()
	f.anordnen()
	pInvalidateRect.Call(uintptr(f.hinweisF), 0, 0)
	time.AfterFunc(16*time.Second, func() {
		a.ergebnisse <- func() {
			if a.f != nil {
				a.f.anordnen()
			}
		}
		pPostMessageW.Call(uintptr(a.hwnd), wmAktion, 0, 0)
	})
}
