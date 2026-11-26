// SPDX-License-Identifier: AGPL-3.0-only

package main

// Hauptfenster der Desktop-App (1.0.6) nach dem Corporate Design
// (docs/design/README.md): oben die Markenleiste in Nachtblau mit Bildzeichen
// und Suche, darunter die Befehlsleiste, links der Baum Mandant → Gruppe →
// Gerät, rechts Kopf, Sensorliste und Einzelheiten, unten die Statusleiste.
// Alles ist selbst gezeichnet (Farben aus den Tokens, D-DIN und JetBrains
// Mono); Baum und Liste sind Steuerelemente von Windows, die die App über
// Custom Draw vollständig selbst malt. Hell oder dunkel folgt Windows.
//
// Was die App ändern darf, entscheidet die Zentrale nach der Rolle des
// API-Tokens; die Knöpfe richten sich nach der Rolle, die sie je Mandant meldet.

import (
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	utf16pkg "unicode/utf16"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

const (
	idMarke    = 201
	idSuche    = 202
	idBefehle  = 203
	idBaum     = 204
	idKopf     = 205
	idListKopf = 206
	idListe    = 207
	idDetails  = 208
	idStatus   = 209
	idSonne    = 210
)

// Befehle aus Befehlsleiste, Menü „Mehr“ und Kontextmenüs.
const (
	cmdAktualisieren = 301 + iota
	cmdNeuGeraet
	cmdNeuSensor
	cmdBearbeiten
	cmdJetzt
	cmdPause
	cmdWartung
	cmdBestaetigen
	cmdLoeschen
	cmdNurProbleme
	cmdImBrowser
	cmdGeraetBearbeiten
	cmdGeraetLoeschen
	cmdGeraetWartung
	cmdMehr
	cmdUeber
	cmdAnsichtListe
	cmdAnsichtSonne
)

// Maße in Pixeln bei 96 dpi (Abstände nur aus der Skala 4/8/12/16/24/32/48).
const (
	leisteH   = 48
	befehlH   = 48
	baumB     = 280
	kopfH     = 64
	zeileH    = 32
	statusH   = 32
	detailMin = 120
	luecke    = 8
)

// Spalten der Sensorliste.
const (
	spZustand = iota
	spSensor
	spGeraet
	spMeldung
	spWert
	spTyp
	spSeit
)

type spalte struct {
	id     int
	titel  string
	breite int32 // 0 = übriger Platz
	rechts bool
}

var alleSpalten = []spalte{
	{spZustand, "Zustand", 120, false},
	{spSensor, "Sensor", 180, false},
	{spGeraet, "Gerät", 130, false},
	{spMeldung, "Meldung", 0, false},
	{spWert, "Wert", 90, true},
	{spTyp, "Typ", 120, false},
	{spSeit, "seit", 110, false},
}

// listenZeile: eine Zeile der Sensorliste mit den Angaben aus dem Check.
type listenZeile struct {
	desktop.Zeile
	wert, typ string
	check     *desktop.Check
}

func (z listenZeile) text(sp int) string {
	switch sp {
	case spZustand:
		return z.Zustand
	case spSensor:
		return z.Sensor
	case spGeraet:
		return z.Geraet
	case spMeldung:
		return z.Meldung
	case spWert:
		return z.wert
	case spTyp:
		return z.typ
	case spSeit:
		return z.Seit
	}
	return ""
}

type baumEintrag struct {
	key    string
	knoten *desktop.Knoten
	eltern string
	tiefe  int32
}

// knopf der Befehlsleiste.
type knopf struct {
	id     int
	text   string
	haupt  bool // Primärknopf in --marke
	schalt bool // Schalter (an/aus)
	rechts bool
	an     bool
	r      rect
}

// fenster: Zustand der Oberfläche (nur im Oberflächen-Thread benutzt).
type fenster struct {
	hwnd, marke, suche, befehle, baum, kopf, listKopf, liste, details, status, sonne syscall.Handle

	ansicht     int // 0 = Liste, 1 = Sonne
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

	knoepfe     []knopf
	ueber       int // Knopf unter der Maus, -1 = keiner
	nurProbleme bool

	meldung     string // kurze Rückmeldung in der Statusleiste
	meldungZeit time.Time
	sucheRahmen rect
}

func (f *fenster) s(px int32) int32 { return px * f.dpi / 96 }

func knotenKey(k *desktop.Knoten) string {
	return [...]string{"m:", "g:", "d:"}[k.Art] + k.ID
}

// fensterZeigen legt das Fenster beim ersten Mal an und holt es nach vorn.
func (a *app) fensterZeigen() {
	if a.f == nil {
		f, err := a.fensterAnlegen()
		if err != nil {
			meldung("OpenWacht Desktop", "Fenster: "+err.Error(), true)
			return
		}
		a.f = f
	}
	if r, _, _ := pIsIconic.Call(uintptr(a.f.hwnd)); r != 0 {
		pShowWindow.Call(uintptr(a.f.hwnd), swRestore)
	} else {
		pShowWindow.Call(uintptr(a.f.hwnd), swShow)
	}
	pSetForegroundWindow.Call(uintptr(a.f.hwnd))
	a.fensterOffen.Store(true)
	a.aktualisieren(true)
	a.jetztAbfragen()
}

func (a *app) jetztAbfragen() {
	select {
	case a.jetzt <- struct{}{}:
	default:
	}
}

func (a *app) fensterAnlegen() (*fenster, error) {
	commonControls()
	schriftenLaden()
	themaSetzen(themaLesen())
	inst, _, _ := pGetModuleHandleW.Call(0)
	cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
	f := &fenster{dpi: 96, sortSp: -1, items: map[string]uintptr{}, ueber: -1}
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
	titel := "OpenWacht"
	if z := a.zentrale(); z != "" {
		titel += " – " + strings.TrimPrefix(z, "https://")
	}
	a.f = f // fensterProc braucht es schon bei den ersten Nachrichten
	h, _, err := pCreateWindowExW.Call(wsExControlParent, uintptr(unsafe.Pointer(utf16("OpenWachtFenster"))),
		uintptr(unsafe.Pointer(utf16(titel))), wsOverlappedWindow|wsClipChildren, cwUseDefault, cwUseDefault, 1280, 800, 0, 0, inst, 0)
	if h == 0 {
		a.f = nil
		return nil, err
	}
	f.hwnd = syscall.Handle(h)
	f.dpi = dpiVon(f.hwnd)
	f.detailH = f.s(232)

	flaeche := func(id int) syscall.Handle {
		return kind(f.hwnd, "OpenWachtFlaeche", "", wsClipChildren, 0, id)
	}
	f.marke = flaeche(idMarke)
	f.suche = kind(f.marke, "EDIT", "", wsTabStop|esAutoHScroll, 0, idSuche)
	platzhalter(f.suche, "Suchen (Strg+F)", true)
	f.befehle = flaeche(idBefehle)

	f.baum = kind(f.hwnd, "SysTreeView32", "", wsTabStop|tvsHasButtons|tvsLinesAtRoot|tvsShowSelAlways|tvsFullRowSelect|tvsTrackSelect, 0, idBaum)
	send(f.baum, tvmSetExtStyle, tvsExDoubleBuffer, tvsExDoubleBuffer)

	f.kopf = flaeche(idKopf)
	f.listKopf = flaeche(idListKopf)
	f.liste = kind(f.hwnd, "SysListView32", "", wsTabStop|lvsReport|lvsSingleSel|lvsShowSelAlways|lvsNoColumnHeader, 0, idListe)
	send(f.liste, lvmSetExtendedStyle, lvsExFullRowSelect|lvsExDoubleBuffer, lvsExFullRowSelect|lvsExDoubleBuffer)
	c := lvColumn{Mask: lvcfWidth, Cx: 100}
	sendP(f.liste, lvmInsertColumnW, 0, unsafe.Pointer(&c))
	f.details = flaeche(idDetails)
	f.status = flaeche(idStatus)
	f.sonne = flaeche(idSonne)
	pShowWindow.Call(uintptr(f.sonne), swHide)

	f.knoepfeAnlegen()
	f.dpiAnwenden()
	f.themaAnwenden()
	pSetWindowPos.Call(h, 0, 0, 0, uintptr(f.s(1280)), uintptr(f.s(800)), swpNoMove|swpNoZOrder|swpNoActivate)
	return f, nil
}

func (f *fenster) knoepfeAnlegen() {
	f.knoepfe = []knopf{
		{id: cmdNeuSensor, text: "Sensor hinzufügen", haupt: true},
		{id: cmdNeuGeraet, text: "Gerät hinzufügen"},
		{id: 0}, // Lücke 24
		{id: cmdJetzt, text: "Jetzt abfragen"},
		{id: cmdBestaetigen, text: "Alarm bestätigen …"},
		{id: cmdWartung, text: "Wartung setzen …"},
		{id: cmdPause, text: "Sensor pausieren"},
		{id: cmdMehr, text: "Mehr", rechts: true, an: true},
		{id: cmdNurProbleme, text: "Nur Probleme", schalt: true, rechts: true, an: true},
		{id: cmdAnsichtSonne, text: "Sonne", schalt: true, rechts: true, an: true},
		{id: cmdAnsichtListe, text: "Liste", schalt: true, rechts: true, an: true},
	}
}

// dpiAnwenden: Schriften, Logo und Maße für die aktuelle Skalierung.
func (f *fenster) dpiAnwenden() {
	f.sch.setzen(f.dpi)
	formenLeeren()
	if f.logo.h != 0 {
		pDeleteObject.Call(f.logo.h)
	}
	f.logo = bitmapAusPNG(desktop.Zeichen(int(f.s(32))))
	if f.logo.w != f.s(32) {
		// nächstgrößeres Bild: mittig in 32 setzen (AlphaBlend skaliert nicht schön)
		f.logo = bitmapAusPNG(desktop.Zeichen(int(f.s(32))))
	}
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
	f.anordnen()
}

// themaAnwenden: Farben der Steuerelemente nach hell/dunkel.
func (f *fenster) themaAnwenden() {
	formenLeeren()
	send(f.liste, lvmSetBkColor, 0, cref(th.f.Flaeche))
	send(f.baum, tvmSetBkColor, 0, cref(th.f.Flaeche))
	steuerThema(f.liste)
	steuerThema(f.baum)
	titelleiste(f.hwnd)
	pRedrawWindow.Call(uintptr(f.hwnd), 0, 0, rdwInvalidate|rdwErase|rdwAllChildren|rdwFrame)
}

// anordnen: alle Teile nach der Fenstergröße.
func (f *fenster) anordnen() {
	var r rect
	pGetClientRect.Call(uintptr(f.hwnd), uintptr(unsafe.Pointer(&r)))
	w, h := r.Right, r.Bottom
	if w <= 0 || h <= 0 {
		return
	}
	lh, bh, sh := f.s(leisteH), f.s(befehlH), f.s(statusH)
	move(f.marke, 0, 0, w, lh)
	sw := min(f.s(280), w/3)
	f.sucheRahmen = rect{w - f.s(16) - sw, (lh - f.s(32)) / 2, w - f.s(16), (lh-f.s(32))/2 + f.s(32)}
	eh := f.s(20)
	move(f.suche, f.sucheRahmen.Left+f.s(12), f.sucheRahmen.Top+(f.s(32)-eh)/2, sw-f.s(24), eh)
	move(f.befehle, 0, lh, w, bh)
	f.knoepfeOrdnen(w)

	oben := lh + bh
	unten := h - sh
	bb := f.s(baumB)
	move(f.baum, 0, oben, bb, unten-oben)
	rx := bb + 1 // 1 px Linie
	rw := w - rx
	move(f.kopf, rx, oben, rw, f.s(kopfH))
	f.detailH = min(max(f.detailH, f.s(detailMin)), unten-oben-f.s(kopfH)-f.s(160))
	ly := oben + f.s(kopfH)
	move(f.listKopf, rx, ly, rw, f.s(zeileH))
	ly += f.s(zeileH)
	lhoehe := unten - ly - f.s(luecke) - f.detailH
	move(f.liste, rx, ly, rw, lhoehe)
	// Sonne: ganze rechte Fläche unter dem Kopf (Einzelheiten beim Überfahren)
	move(f.sonne, rx, ly-f.s(zeileH), rw, unten-(ly-f.s(zeileH)))
	zeig := func(h syscall.Handle, an bool) {
		pShowWindow.Call(uintptr(h), map[bool]uintptr{true: swShow, false: swHide}[an])
	}
	zeig(f.listKopf, f.ansicht == 0)
	zeig(f.liste, f.ansicht == 0)
	zeig(f.sonne, f.ansicht == 1)
	zeig(f.details, f.ansicht == 0)
	move(f.details, rx, unten-f.detailH, rw, f.detailH)
	move(f.status, 0, unten, w, sh)
	f.spaltenOrdnen(rw)
	pInvalidateRect.Call(uintptr(f.hwnd), 0, 1)
}

// spaltenOrdnen: sichtbare Spalten und Breiten (Meldung nimmt den Rest).
func (f *fenster) spaltenOrdnen(rw int32) {
	k := f.knoten()
	f.spalten = f.spalten[:0]
	for _, sp := range alleSpalten {
		if sp.id == spGeraet && k != nil && k.Art == desktop.KnotenGeraet {
			continue // bei einem Gerät steht es im Kopf
		}
		f.spalten = append(f.spalten, sp)
	}
	sb, _, _ := pGetSystemMetricsForDpi.Call(2, uintptr(f.dpi)) // SM_CXVSCROLL
	if sb == 0 {
		sb = uintptr(f.s(17))
	}
	rest := rw - int32(sb) - 1 // senkrechte Bildlaufleiste, nie waagrecht
	for _, sp := range f.spalten {
		rest -= f.s(sp.breite)
	}
	f.breiten = make([]int32, len(f.spalten))
	for i, sp := range f.spalten {
		f.breiten[i] = f.s(sp.breite)
		if sp.breite == 0 {
			f.breiten[i] = max(rest, f.s(120))
		}
	}
	sum := int32(0)
	for _, b := range f.breiten {
		sum += b
	}
	send(f.liste, lvmSetColumnWidth, 0, uintptr(sum))
	pInvalidateRect.Call(uintptr(f.listKopf), 0, 0)
	pInvalidateRect.Call(uintptr(f.liste), 0, 0)
}

// knoepfeOrdnen: Lage der Knöpfe (links ab 16, rechts bis 16 vor dem Rand).
func (f *fenster) knoepfeOrdnen(w int32) {
	hdc, _, _ := pGetDC.Call(uintptr(f.befehle))
	defer pReleaseDC.Call(uintptr(f.befehle), hdc)
	y := (f.s(befehlH) - f.s(32)) / 2
	x := f.s(16)
	for i := range f.knoepfe {
		k := &f.knoepfe[i]
		if k.rechts {
			continue
		}
		if k.id == 0 {
			x += f.s(24) - f.s(8)
			continue
		}
		bw := breite(hdc, k.text, f.sch.t13) + 2*f.s(12)
		k.r = rect{x, y, x + bw, y + f.s(32)}
		x += bw + f.s(8)
	}
	x = w - f.s(16)
	for i := range f.knoepfe {
		k := &f.knoepfe[i]
		if !k.rechts {
			continue
		}
		bw := breite(hdc, k.text, f.sch.t13) + 2*f.s(12)
		if k.id == cmdMehr {
			bw += f.s(16)
		}
		k.r = rect{x - bw, y, x, y + f.s(32)}
		x -= bw + f.s(8)
	}
}

func (f *fenster) knopf(id int) *knopf {
	for i := range f.knoepfe {
		if f.knoepfe[i].id == id {
			return &f.knoepfe[i]
		}
	}
	return nil
}

func (f *fenster) knopfAn(id int, an bool) {
	if k := f.knopf(id); k != nil && k.an != an {
		k.an = an
		pInvalidateRect.Call(uintptr(f.befehle), 0, 0)
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
	a.baum = desktop.BaumBauen(st)
	f.baumFuellen(a.baum)
	a.auswahlZeigen(immer)
	pInvalidateRect.Call(uintptr(f.status), 0, 0)
}

func (f *fenster) baumFuellen(wurzeln []*desktop.Knoten) {
	var eintraege []baumEintrag
	var sig strings.Builder
	var lauf func(ks []*desktop.Knoten, eltern string, tiefe int32)
	lauf = func(ks []*desktop.Knoten, eltern string, tiefe int32) {
		for _, k := range ks {
			key := knotenKey(k)
			eintraege = append(eintraege, baumEintrag{key, k, eltern, tiefe})
			sig.WriteString(eltern + ">" + key + ";")
			lauf(k.Kinder, key, tiefe+1)
		}
	}
	lauf(wurzeln, "", 0)
	if s := sig.String(); s == f.baumSig && len(f.items) == len(eintraege) {
		f.eintraege = eintraege // gleicher Aufbau: nur neu zeichnen
		pInvalidateRect.Call(uintptr(f.baum), 0, 0)
		return
	}
	offen := map[string]bool{}
	erstesMal := len(f.items) == 0
	for key, h := range f.items {
		if send(f.baum, tvmGetItemState, h, tvisExpanded)&tvisExpanded != 0 {
			offen[key] = true
		}
	}
	f.baue = true
	send(f.baum, wmSetRedraw, 0, 0)
	send(f.baum, tvmDeleteItem, 0, tviRoot)
	f.items = map[string]uintptr{}
	f.eintraege = eintraege
	for i, e := range eintraege {
		parent := tviRoot
		if e.eltern != "" {
			parent = f.items[e.eltern]
		}
		is := tvInsertStruct{Parent: parent, InsertAfter: tviLast, Item: tvItem{
			Mask: tvifText | tvifParam, Text: utf16(e.knoten.Name), LParam: uintptr(i)}}
		f.items[e.key] = sendP(f.baum, tvmInsertItemW, 0, unsafe.Pointer(&is))
	}
	for _, e := range eintraege {
		// Ab Werk: Mandanten und oberste Gruppen offen
		if offen[e.key] || (erstesMal && (e.knoten.Art == desktop.KnotenMandant || strings.HasPrefix(e.eltern, "m:"))) {
			if len(e.knoten.Kinder) > 0 {
				send(f.baum, tvmExpand, tveExpand, f.items[e.key])
			}
		}
	}
	f.baumSig = sig.String()
	if h, ok := f.items[f.gewaehlt]; ok {
		send(f.baum, tvmSelectItem, tvgnCaret, h)
	} else if len(eintraege) > 0 {
		f.gewaehlt = eintraege[0].key
		send(f.baum, tvmSelectItem, tvgnCaret, f.items[f.gewaehlt])
	}
	send(f.baum, wmSetRedraw, 1, 0)
	f.baue = false
}

// knoten: der im Baum gewählte Knoten (nil = keiner).
func (f *fenster) knoten() *desktop.Knoten {
	for _, e := range f.eintraege {
		if e.key == f.gewaehlt {
			return e.knoten
		}
	}
	return nil
}

// auswahlZeigen: Kopf, Liste und Einzelheiten zum gewählten Knoten.
func (a *app) auswahlZeigen(immer bool) {
	f := a.f
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	k := f.knoten()
	sensoren := desktop.SensorenUnter(k, st.Sensoren)
	zeilen := desktop.Zeilen(sensoren, !f.nurProbleme, getText(f.suche), time.Now())
	checks := map[string]*desktop.Check{}
	for i := range st.Checks {
		checks[st.Checks[i].ID] = &st.Checks[i]
	}
	lz := make([]listenZeile, len(zeilen))
	for i, z := range zeilen {
		l := listenZeile{Zeile: z}
		switch z.Art {
		case "check":
			if c := checks[z.QuelleID]; c != nil {
				l.check = c
				l.typ = desktop.TypName(c.Typ)
				if c.Messwert != nil {
					l.wert = desktop.Kuerzen(*c.Messwert, 60)
				}
				if c.Wartung != nil && z.Anzeige == "ok" {
					l.Anzeige, l.Zustand = "wartung", "Wartung"
				}
			}
		case "host":
			l.typ = "Wert des Agents"
		case "snmp":
			l.typ = "SNMP-Abfrage"
		}
		lz[i] = l
	}
	f.sortieren(lz)
	var r rect
	pGetClientRect.Call(uintptr(f.listKopf), uintptr(unsafe.Pointer(&r)))
	f.spaltenOrdnen(r.Right)
	pInvalidateRect.Call(uintptr(f.kopf), 0, 0)
	pInvalidateRect.Call(uintptr(f.sonne), 0, 0)
	f.listeFuellen(lz, immer)
	a.detailsZeigen()
}

func (f *fenster) sortieren(lz []listenZeile) {
	if f.sortSp < 0 {
		return
	}
	sp := f.sortSp
	rang := map[string]int{"crit": 0, "warn": 1, "unknown": 2, "bestaetigt": 3, "neu": 4, "wartung": 5, "pause": 6, "ok": 7}
	sort.SliceStable(lz, func(i, j int) bool {
		var less, gleich bool
		if sp == spZustand {
			a, b := rang[lz[i].Anzeige], rang[lz[j].Anzeige]
			less, gleich = a < b, a == b
		} else {
			a, b := strings.ToLower(lz[i].text(sp)), strings.ToLower(lz[j].text(sp))
			less, gleich = a < b, a == b
		}
		if gleich {
			return false
		}
		return less != f.sortAb
	})
}

func gleicheListe(a, b []listenZeile) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Zeile != b[i].Zeile || a[i].wert != b[i].wert || a[i].typ != b[i].typ {
			return false
		}
	}
	return true
}

func (f *fenster) gewaehlteZeile() *listenZeile {
	i := int(int32(send(f.liste, lvmGetNextItem, ^uintptr(0), lvniSelected)))
	if i < 0 || i >= len(f.zeilen) {
		return nil
	}
	return &f.zeilen[i]
}

func (f *fenster) listeFuellen(zeilen []listenZeile, immer bool) {
	if !immer && gleicheListe(f.zeilen, zeilen) {
		for i := range zeilen {
			f.zeilen[i].check = zeilen[i].check
		}
		pInvalidateRect.Call(uintptr(f.liste), 0, 0)
		return
	}
	gewaehlt := ""
	if z := f.gewaehlteZeile(); z != nil {
		gewaehlt = z.Schluessel
	}
	oben := int(send(f.liste, lvmGetTopIndex, 0, 0))
	send(f.liste, wmSetRedraw, 0, 0)
	send(f.liste, lvmDeleteAllItems, 0, 0)
	neu := -1
	f.zeilen = zeilen
	for i, z := range zeilen {
		it := lvItem{Mask: lvifText, Item: int32(i), Text: utf16(z.Sensor)}
		sendP(f.liste, lvmInsertItemW, 0, unsafe.Pointer(&it))
		if gewaehlt != "" && z.Schluessel == gewaehlt {
			neu = i
		}
	}
	if len(zeilen) > 0 && !immer {
		n := int(send(f.liste, lvmGetCountPerPage, 0, 0))
		send(f.liste, lvmEnsureVisible, uintptr(min(len(zeilen)-1, oben+max(n-1, 0))), 0)
		send(f.liste, lvmEnsureVisible, uintptr(min(len(zeilen)-1, oben)), 0)
	}
	if neu >= 0 {
		st := lvItem{StateMask: lvisSelected | lvisFocused, State: lvisSelected | lvisFocused}
		sendP(f.liste, lvmSetItemState, uintptr(neu), unsafe.Pointer(&st))
	}
	send(f.liste, wmSetRedraw, 1, 0)
	pInvalidateRect.Call(uintptr(f.liste), 0, 0)
}

// detailsZeigen: Knöpfe passend zur Auswahl, Einzelheiten neu zeichnen.
func (a *app) detailsZeigen() {
	f := a.f
	k := f.knoten()
	z := f.gewaehlteZeile()
	schreiben := k != nil && desktop.DarfAendern(k.Rolle)
	istCheck := z != nil && z.check != nil
	istGeraet := k != nil && k.Art == desktop.KnotenGeraet
	f.knopfAn(cmdNeuGeraet, k != nil && schreiben)
	f.knopfAn(cmdNeuSensor, schreiben && (istGeraet || z != nil))
	f.knopfAn(cmdJetzt, schreiben && istCheck)
	f.knopfAn(cmdPause, schreiben && istCheck)
	f.knopfAn(cmdWartung, schreiben && (istCheck || (z == nil && istGeraet)))
	f.knopfAn(cmdBestaetigen, schreiben && z != nil && z.AlarmNeu)
	p := "Sensor pausieren"
	if istCheck && !z.check.Aktiv {
		p = "Sensor fortsetzen"
	}
	if kn := f.knopf(cmdPause); kn != nil && kn.text != p {
		kn.text = p
		var r rect
		pGetClientRect.Call(uintptr(f.befehle), uintptr(unsafe.Pointer(&r)))
		f.knoepfeOrdnen(r.Right)
		pInvalidateRect.Call(uintptr(f.befehle), 0, 0)
	}
	pInvalidateRect.Call(uintptr(f.details), 0, 0)
}

// symbolFuerFenster: Das Fenster trägt das Bildzeichen, der Zustand steht
// nur im Infobereich (docs/design/README.md §8).
func (a *app) symbolFuerFenster() {}

// setStatusText: kurze Rückmeldung in der Statusleiste („Gespeichert.“).
func setStatusText(f *fenster, t string) {
	if f == nil {
		return
	}
	f.meldung, f.meldungZeit = t, time.Now()
	pInvalidateRect.Call(uintptr(f.status), 0, 0)
}

// --- Zeichnen ---------------------------------------------------------------

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
			case f.marke:
				a.markeMalen(hdc, r)
			case f.befehle:
				f.befehleMalen(hdc, r)
			case f.kopf:
				a.kopfMalen(hdc, r)
			case f.listKopf:
				f.listKopfMalen(hdc, r)
			case f.details:
				a.detailsMalen(hdc, r)
			case f.status:
				a.statusMalen(hdc, r)
			case f.sonne:
				a.sonneMalen(hdc, r)
			default:
				fuellen(hdc, r, th.f.Grund)
			}
		})
		return 0
	case wmCommand:
		// Suchfeld in der Markenleiste: an das Hauptfenster weiterreichen
		pSendMessageW.Call(uintptr(f.hwnd), m, wp, lp)
		return 0
	case wmCtlColorEdit, wmCtlColorStatic:
		// Suchfeld in der Markenleiste
		pSetTextColor.Call(wp, cref(th.f.NachtTinte))
		pSetBkColor.Call(wp, cref(th.f.Nacht))
		return pinsel(th.f.Nacht)
	case wmMouseMove:
		if h == f.sonne {
			x, y := int32(int16(lp&0xffff)), int32(int16((lp>>16)&0xffff))
			if t := a.sonneText(x, y); t != f.sonnenUeber {
				f.sonnenUeber = t
				mausVerlassen(hwnd)
				pInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		if h == f.befehle {
			x, y := int32(int16(lp&0xffff)), int32(int16((lp>>16)&0xffff))
			neu := -1
			for i, k := range f.knoepfe {
				if k.id != 0 && x >= k.r.Left && x < k.r.Right && y >= k.r.Top && y < k.r.Bottom {
					neu = i
				}
			}
			if neu != f.ueber {
				f.ueber = neu
				mausVerlassen(hwnd)
				pInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		return 0
	case wmMouseLeave:
		if h == f.sonne && f.sonnenUeber != "" {
			f.sonnenUeber = ""
			pInvalidateRect.Call(hwnd, 0, 0)
		}
		if h == f.befehle && f.ueber != -1 {
			f.ueber = -1
			pInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case wmLButtonUp:
		x, y := int32(int16(lp&0xffff)), int32(int16((lp>>16)&0xffff))
		switch h {
		case f.befehle:
			for _, k := range f.knoepfe {
				if k.id != 0 && k.an && x >= k.r.Left && x < k.r.Right && y >= k.r.Top && y < k.r.Bottom {
					a.befehlFenster(k.id)
					return 0
				}
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
		case f.marke:
			if x >= f.sucheRahmen.Left && x < f.sucheRahmen.Right {
				pSetFocus.Call(uintptr(f.suche))
			}
		case f.sonne:
			a.sonneKlick(x, y)
		}
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

func (a *app) markeMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Nacht)
	n := f.s(32)
	alpha(hdc, f.logo, f.s(16)+(n-f.logo.w)/2, (r.Bottom-f.logo.y)/2)
	// Wortmarke: „Open“ fett, „Wacht“ normal, ohne Leerzeichen, Abstand ¼ der Zeichenhöhe
	x := f.s(16) + n + n/4
	w := breite(hdc, "Open", f.sch.t20b)
	schreiben(hdc, "Open", rect{x, 0, x + w + 2, r.Bottom}, f.sch.t20b, th.f.NachtTinte, 0)
	x += w
	schreiben(hdc, "Wacht", rect{x, 0, x + f.s(120), r.Bottom}, f.sch.t20, th.f.NachtTinte, 0)
	// Suchfeld auf Nachtblau: Rand --nacht-leise, mit Fokus --marke der dunklen Spalte
	rand := th.f.NachtLeise
	if fokus, _, _ := pGetFocus.Call(); syscall.Handle(fokus) == f.suche {
		rand = desktop.Dunkel.Marke
	}
	rund(hdc, f.sucheRahmen, f.s(3), th.f.Nacht, rand, true, true, false)
}

func (f *fenster) befehleMalen(hdc uintptr, r rect) {
	fuellen(hdc, r, th.f.Flaeche)
	waagrecht(hdc, 0, r.Right, r.Bottom-1, th.f.Linie)
	for i, k := range f.knoepfe {
		if k.id == 0 {
			continue
		}
		hover := i == f.ueber && k.an
		fg, bg, rand := th.f.Tinte, th.f.Flaeche, th.f.Linie
		switch {
		case k.haupt:
			fg, bg, rand = th.f.AufMarke, th.f.Marke, th.f.Marke
			if hover {
				bg, rand = th.f.MarkeTief, th.f.MarkeTief
			}
		case k.schalt && f.schalterAn(k.id):
			fg, bg, rand = th.f.MarkeTief, th.f.MarkeHauch, th.f.Marke
		case hover:
			rand = th.f.Leise
		}
		if !k.an {
			// wie im Web: 55 % Deckkraft
			fg, bg, rand = mischen(fg, th.f.Flaeche, 55), mischen(bg, th.f.Flaeche, 55), mischen(rand, th.f.Flaeche, 55)
		}
		rund(hdc, k.r, f.s(3), bg, rand, true, true, false)
		tr := k.r
		tr.Left += f.s(12)
		tr.Right -= f.s(12)
		if k.id == cmdMehr {
			tr.Right -= f.s(16)
			chevron(hdc, tr.Right+f.s(10), (k.r.Top+k.r.Bottom)/2, f.s(4), true, fg)
		}
		schreiben(hdc, k.text, tr, f.sch.t13, fg, 0)
	}
}

// mischen: Farbe a zu p Prozent über b.
func mischen(a, b desktop.RGB, p int) desktop.RGB {
	m := func(sh uint) desktop.RGB {
		x := int(a>>sh&0xff)*p/100 + int(b>>sh&0xff)*(100-p)/100
		return desktop.RGB(x) << sh
	}
	return m(16) | m(8) | m(0)
}

// chevron: kleiner Winkel nach unten (unten=true) bzw. nach rechts.
func chevron(hdc uintptr, cx, cy, g int32, unten bool, c desktop.RGB) {
	stift, _, _ := pCreatePen.Call(psSolid, uintptr(max(g/2, 1)), cref(c))
	alt, _, _ := pSelectObject.Call(hdc, stift)
	if unten {
		pMoveToEx.Call(hdc, uintptr(cx-g), uintptr(cy-g/2), 0)
		pLineTo.Call(hdc, uintptr(cx), uintptr(cy+g/2))
		pLineTo.Call(hdc, uintptr(cx+g+1), uintptr(cy-g/2-1))
	} else {
		pMoveToEx.Call(hdc, uintptr(cx-g/2), uintptr(cy-g), 0)
		pLineTo.Call(hdc, uintptr(cx+g/2), uintptr(cy))
		pLineTo.Call(hdc, uintptr(cx-g/2-1), uintptr(cy+g+1))
	}
	pSelectObject.Call(hdc, alt)
	pDeleteObject.Call(stift)
}

// chevronOben: Winkel nach oben (Sortierung aufsteigend).
func chevronOben(hdc uintptr, cx, cy, g int32, c desktop.RGB) {
	stift, _, _ := pCreatePen.Call(psSolid, uintptr(max(g/2, 1)), cref(c))
	alt, _, _ := pSelectObject.Call(hdc, stift)
	pMoveToEx.Call(hdc, uintptr(cx-g), uintptr(cy+g/2), 0)
	pLineTo.Call(hdc, uintptr(cx), uintptr(cy-g/2))
	pLineTo.Call(hdc, uintptr(cx+g+1), uintptr(cy+g/2+1))
	pSelectObject.Call(hdc, alt)
	pDeleteObject.Call(stift)
}

// zustandsMarke: Marke wie .marke im Web (24 hoch, Radius 3, 13/700,
// Versalien, Form davor). Liefert die Breite; zeichnen=false misst nur.
func (f *fenster) zustandsMarke(hdc uintptr, status, text string, x, y int32, zeichnen bool) int32 {
	an := th.f.AnzeigeFuer(status)
	t := strings.ToUpper(text)
	pSetTextCharacterExtra.Call(hdc, 1)
	defer pSetTextCharacterExtra.Call(hdc, 0)
	w := breite(hdc, t, f.sch.t13b) + f.s(8)*2 + f.s(12) + f.s(4)
	if !zeichnen {
		return w
	}
	r := rect{x, y, x + w, y + f.s(24)}
	fg, formFarbe := an.Text, an.Farbe
	switch {
	case an.Gefuellt:
		rund(hdc, r, f.s(3), an.Farbe, an.Farbe, true, false, false)
		fg, formFarbe = an.AufFarbe, an.AufFarbe
	case status == "ok":
		rund(hdc, r, f.s(3), 0, an.Farbe, false, true, false)
	case status == "unknown":
		rund(hdc, r, f.s(3), 0, th.f.Leise, false, true, true)
	case status == "neu" || status == "":
		rund(hdc, r, f.s(3), 0, th.f.Linie, false, true, false)
	default:
		rund(hdc, r, f.s(3), an.Hauch, an.Hauch, true, false, false)
	}
	form(hdc, an.Form, formFarbe, x+f.s(8), y+(f.s(24)-f.s(12))/2, f.s(12))
	schreiben(hdc, t, rect{x + f.s(8) + f.s(12) + f.s(4), y, x + w, y + f.s(24)}, f.sch.t13b, fg, 0)
	return w
}

func (a *app) kopfMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	waagrecht(hdc, 0, r.Right, r.Bottom-1, th.f.Linie)
	k := f.knoten()
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	if k == nil {
		t := "Lädt …"
		if !st.Zeit.IsZero() {
			t = "Dieses API-Token sieht keine Mandanten."
		}
		schreiben(hdc, t, rect{f.s(24), 0, r.Right, r.Bottom}, f.sch.t16, th.f.Leise, 0)
		return
	}
	an := th.f.AnzeigeFuer(k.Zustand())
	form(hdc, an.Form, an.Farbe, f.s(24), (r.Bottom-f.s(24))/2, f.s(24))
	x := f.s(24) + f.s(24) + f.s(16)

	// Zustandsmarken rechts, nur mit Zahl > 0
	z := k.Zaehler
	marken := []struct {
		status string
		n      int
		wort   string
	}{{"crit", z.Kritisch, "Kritisch"}, {"warn", z.Warnung, "Warnung"}, {"unknown", z.Unbekannt, "Unbekannt"},
		{"bestaetigt", z.Bestaetigt, "Bestätigt"}, {"pause", z.Pausiert, "Pausiert"}, {"neu", z.Neu, "Neu"}, {"ok", z.OK, "OK"}}
	mx := r.Right - f.s(24)
	my := (r.Bottom - f.s(24)) / 2
	for i := len(marken) - 1; i >= 0; i-- {
		m := marken[i]
		if m.n == 0 {
			continue
		}
		t := strconv.Itoa(m.n) + " " + m.wort
		w := f.zustandsMarke(hdc, m.status, t, 0, 0, false)
		mx -= w
		f.zustandsMarke(hdc, m.status, t, mx, my, true)
		mx -= f.s(8)
	}

	var unter []string
	switch k.Art {
	case desktop.KnotenGeraet:
		d := k.Geraet
		if d.GruppeID != nil {
			for _, g := range st.Gruppen {
				if g.ID == *d.GruppeID {
					unter = append(unter, "Gruppe "+g.Name)
				}
			}
		}
		if d.AgentID != nil {
			unter = append(unter, "mit Agent")
		}
		if d.SNMPID != nil {
			unter = append(unter, "mit SNMP-Abfrage")
		}
		if d.Wartung != nil {
			w := "In Wartung bis " + d.Wartung.Bis.Local().Format("15:04")
			if d.Wartung.Grund != "" {
				w += " · " + d.Wartung.Grund
			}
			unter = append(unter, w)
		}
	case desktop.KnotenGruppe:
		unter = append(unter, "Gruppe", geraeteText(len(k.Geraete)))
	case desktop.KnotenMandant:
		unter = append(unter, "Mandant", geraeteText(len(k.Geraete)))
	}
	if k.Rolle != "" && !desktop.DarfAendern(k.Rolle) {
		unter = append(unter, "nur ansehen (Rolle Leser)")
	}
	schreiben(hdc, k.Name, rect{x, f.s(8), mx - f.s(16), f.s(8) + f.s(28)}, f.sch.t20b, th.f.Tinte, 0)
	uy := f.s(36)
	ux := x
	text := strings.Join(unter, "  ·  ")
	if k.Art == desktop.KnotenGeraet && k.Geraet.Adresse != nil && *k.Geraet.Adresse != "" {
		ad := *k.Geraet.Adresse
		w := breite(hdc, ad, f.sch.m13)
		schreiben(hdc, ad, rect{ux, uy, ux + w + 1, uy + f.s(20)}, f.sch.m13, th.f.Leise, 0)
		ux += w
		if text != "" {
			text = "  ·  " + text
		}
	}
	schreiben(hdc, text, rect{ux, uy, mx - f.s(16), uy + f.s(20)}, f.sch.t13, th.f.Leise, 0)
}

func geraeteText(n int) string {
	if n == 1 {
		return "1 Gerät"
	}
	return strconv.Itoa(n) + " Geräte"
}

func (f *fenster) listKopfMalen(hdc uintptr, r rect) {
	fuellen(hdc, r, th.f.Zart)
	waagrecht(hdc, 0, r.Right, r.Bottom-1, th.f.Linie)
	x := int32(0)
	for i, sp := range f.spalten {
		w := f.breiten[i]
		tr := rect{x + f.s(12), 0, x + w - f.s(12), r.Bottom}
		fl := uintptr(dtLeft)
		if sp.rechts {
			fl = dtRight
		}
		t := strings.ToUpper(sp.titel)
		pSetTextCharacterExtra.Call(hdc, 1)
		tw := breite(hdc, t, f.sch.t13b)
		schreiben(hdc, t, tr, f.sch.t13b, th.f.Leise, fl)
		pSetTextCharacterExtra.Call(hdc, 0)
		if f.sortSp == sp.id {
			cx := tr.Left + tw + f.s(12)
			if sp.rechts {
				cx = tr.Right - tw - f.s(12)
			}
			if f.sortAb {
				chevron(hdc, cx, r.Bottom/2, f.s(3), true, th.f.Leise)
			} else {
				chevronOben(hdc, cx, r.Bottom/2, f.s(3), th.f.Leise)
			}
		}
		x += w
	}
}

// zeileMalen: eine Zeile der Sensorliste (Custom Draw, vollständig selbst).
func (f *fenster) zeileMalen(hdc uintptr, i int) {
	if i < 0 || i >= len(f.zeilen) {
		return
	}
	z := f.zeilen[i]
	var r rect // Left = LVIR_BOUNDS
	sendP(f.liste, lvmGetItemRect, uintptr(i), unsafe.Pointer(&r))
	gewaehlt := send(f.liste, lvmGetItemState, uintptr(i), lvisSelected)&lvisSelected != 0
	bg := th.f.Flaeche
	if gewaehlt {
		bg = th.f.MarkeHauch
	}
	fuellen(hdc, r, bg)
	waagrecht(hdc, r.Left, r.Right, r.Bottom-1, th.f.LinieZart)
	if gewaehlt {
		fuellen(hdc, rect{r.Left, r.Top, r.Left + f.s(3), r.Bottom}, th.f.Marke)
	}
	an := th.f.AnzeigeFuer(z.Anzeige)
	x := r.Left
	for j, sp := range f.spalten {
		w := f.breiten[j]
		tr := rect{x + f.s(12), r.Top, x + w - f.s(12), r.Bottom - 1}
		font, farbe := f.sch.t13, th.f.Tinte
		fl := uintptr(dtLeft)
		switch sp.id {
		case spZustand:
			form(hdc, an.Form, an.Farbe, tr.Left, r.Top+(r.Bottom-r.Top-f.s(16))/2, f.s(16))
			tr.Left += f.s(16) + f.s(8)
			farbe = an.Text
		case spSensor:
			if gewaehlt {
				font, farbe = f.sch.t13b, th.f.MarkeTief
			}
		case spWert:
			font, fl = f.sch.m13, dtRight
		case spTyp:
			farbe = th.f.Leise
		case spSeit:
			farbe = th.f.Leise
		}
		schreiben(hdc, z.text(sp.id), tr, font, farbe, fl)
		x += w
	}
}

// baumZeileMalen: ein Eintrag im Baum (Custom Draw, vollständig selbst).
func (f *fenster) baumZeileMalen(hdc uintptr, cd *nmCustomDrawLV) {
	i := int(cd.ItemLParam)
	if i < 0 || i >= len(f.eintraege) {
		return
	}
	e := f.eintraege[i]
	k := e.knoten
	r := cd.Rc
	var cr rect
	pGetClientRect.Call(uintptr(f.baum), uintptr(unsafe.Pointer(&cr)))
	r.Left, r.Right = 0, cr.Right
	gewaehlt := cd.ItemState&cdisSelected != 0
	ueber := cd.ItemState&cdisHot != 0
	bg := th.f.Flaeche
	switch {
	case gewaehlt:
		bg = th.f.MarkeHauch
	case ueber:
		bg = th.f.Zart
	}
	fuellen(hdc, r, bg)
	if gewaehlt {
		fuellen(hdc, rect{0, r.Top, f.s(3), r.Bottom}, th.f.Marke)
	}
	ein := f.s(16)
	cy := (r.Top + r.Bottom) / 2
	x := e.tiefe * ein
	if len(k.Kinder) > 0 {
		offen := send(f.baum, tvmGetItemState, cd.ItemSpec, tvisExpanded)&tvisExpanded != 0
		chevron(hdc, x+ein/2, cy, f.s(4), offen, th.f.Leise)
	}
	x += ein
	an := th.f.AnzeigeFuer(k.Zustand())
	form(hdc, an.Form, an.Farbe, x, cy-f.s(8), f.s(16))
	x += f.s(16) + f.s(8)

	// Probleme rechts: Form 12 und Zahl in Mono
	rx := r.Right - f.s(12)
	z := k.Zaehler
	for _, p := range []struct {
		status string
		n      int
	}{{"unknown", z.Unbekannt}, {"warn", z.Warnung}, {"crit", z.Kritisch}} {
		if p.n == 0 {
			continue
		}
		pa := th.f.AnzeigeFuer(p.status)
		t := strconv.Itoa(p.n)
		w := breite(hdc, t, f.sch.m13)
		schreiben(hdc, t, rect{rx - w, r.Top, rx, r.Bottom}, f.sch.m13, pa.Text, dtRight)
		rx -= w + f.s(4) + f.s(12)
		form(hdc, pa.Form, pa.Farbe, rx, cy-f.s(6), f.s(12))
		rx -= f.s(8)
	}
	font, farbe := f.sch.t13, th.f.Tinte
	if k.Art == desktop.KnotenMandant {
		font = f.sch.t13b
	}
	if gewaehlt {
		font, farbe = f.sch.t13b, th.f.MarkeTief
	}
	schreiben(hdc, k.Name, rect{x, r.Top, rx - f.s(4), r.Bottom}, font, farbe, 0)
}

type detailZeile struct {
	k, v string
	mono bool
}

func (a *app) detailsMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	fuellen(hdc, rect{0, 0, r.Right, f.s(3)}, th.f.Marke) // Panel-Oberkante
	k := f.knoten()
	z := f.gewaehlteZeile()
	p := f.s(16)
	y := f.s(3) + p
	var zeilen []detailZeile
	add := func(k, v string, mono bool) {
		if strings.TrimSpace(v) != "" {
			zeilen = append(zeilen, detailZeile{k, v, mono})
		}
	}
	zeit := func(t *time.Time) string {
		if t == nil || t.IsZero() {
			return ""
		}
		return desktop.ZeitText(*t)
	}
	var titel, status, meldungText string
	switch {
	case z != nil:
		titel, status, meldungText = z.Sensor, z.Anzeige, z.Meldung
		add("Gerät", z.Geraet, false)
		if c := z.check; c != nil {
			wo := "misst die Zentrale"
			if c.AmAgent {
				wo = "misst der Agent"
			}
			add("Typ", desktop.TypName(c.Typ)+" ("+wo+")", false)
			if t, ok := desktop.TypNach(c.Typ); ok {
				w := desktop.WerteAusZiel(t, c.Ziel)
				for _, fe := range t.Felder {
					v := w[fe.Schluessel]
					switch {
					case v == "" || fe.Art == desktop.FeldMehrzeilig:
						continue
					case fe.Art == desktop.FeldJaNein:
						v = "ja"
					}
					add(fe.Beschriftung, v, fe.Art == desktop.FeldGanzzahl || fe.Art == desktop.FeldZahl || fe.Schluessel == "host" || fe.Schluessel == "url")
				}
			}
			add("Intervall", desktop.IntervallText(c.Intervall), false)
			if c.Messwert != nil {
				add("Wert", *c.Messwert, true)
			}
			if c.Seit != nil {
				add("Zustand seit", desktop.ZeitText(*c.Seit)+" ("+z.Seit+")", true)
			}
			add("Zuletzt abgefragt", zeit(c.Zuletzt), true)
			if c.Aktiv {
				add("Nächste Abfrage", zeit(&c.Naechste), true)
			} else {
				add("Aktiv", "nein, pausiert", false)
			}
			if c.Wartung != nil {
				w := "In Wartung bis " + desktop.ZeitText(c.Wartung.Bis)
				if c.Wartung.Grund != "" {
					w += " · " + c.Wartung.Grund
				}
				if c.Wartung.UeberGeraet {
					w += " (über das Gerät)"
				}
				add("Wartung", w, false)
			}
			if c.Herkunft != nil {
				add("Aus Vorlage", *c.Herkunft, false)
			}
		} else {
			add("Typ", z.typ+" – Grenzen stellst du in OpenWacht im Browser ein", false)
			add("seit", z.Seit, false)
		}
		if z.AlarmID != "" {
			if z.AlarmNeu {
				add("Alarm", "offen, nicht bestätigt", false)
			} else {
				add("Alarm", "offen, bestätigt", false)
			}
		}
	case k != nil:
		titel, status = k.Name, k.Zustand()
		switch k.Art {
		case desktop.KnotenGeraet:
			d := k.Geraet
			if d.Adresse != nil {
				add("Adresse", *d.Adresse, true)
			}
			add("Agent", map[bool]string{true: "ja", false: "nein"}[d.AgentID != nil], false)
			add("SNMP-Abfrage", map[bool]string{true: "ja", false: "nein"}[d.SNMPID != nil], false)
			add("Eigene Sensoren", strconv.Itoa(d.Checks), true)
			if d.Wartung != nil {
				add("Wartung", "In Wartung bis "+desktop.ZeitText(d.Wartung.Bis)+" · "+d.Wartung.Grund, false)
			}
		default:
			add("Geräte", strconv.Itoa(len(k.Geraete)), true)
		}
		if k.Rolle != "" {
			rolle := map[string]string{"leser": "Leser", "operator": "Operator", "admin": "Admin"}[k.Rolle]
			if !desktop.DarfAendern(k.Rolle) {
				rolle += " – nur ansehen. Zum Ändern brauchst du ein API-Token mit der Rolle Operator."
			}
			add("Rolle des Tokens", rolle, false)
		}
	default:
		return
	}
	// Titelzeile: Form, Name, Zustandsmarke
	an := th.f.AnzeigeFuer(status)
	form(hdc, an.Form, an.Farbe, p, y+(f.s(24)-f.s(16))/2, f.s(16))
	tx := p + f.s(16) + f.s(8)
	mw := int32(0)
	if an.Wort != "" {
		mw = f.zustandsMarke(hdc, status, an.Wort, 0, 0, false)
	}
	tw := min(breite(hdc, titel, f.sch.t16b), r.Right-tx-mw-2*p)
	schreiben(hdc, titel, rect{tx, y, tx + tw + 1, y + f.s(24)}, f.sch.t16b, th.f.Tinte, 0)
	if an.Wort != "" {
		f.zustandsMarke(hdc, status, an.Wort, tx+tw+f.s(12), y, true)
	}
	y += f.s(24) + f.s(12)
	// Meldung als Streifen: links 4 px in der Zustandsfarbe auf dem Hauch
	if meldungText != "" {
		mh := hoehe(hdc, meldungText, f.sch.t13, r.Right-2*p-f.s(4)-2*f.s(12)) + 2*f.s(8)
		fuellen(hdc, rect{p, y, r.Right - p, y + mh}, an.Hauch)
		fuellen(hdc, rect{p, y, p + f.s(4), y + mh}, an.Farbe)
		schreiben(hdc, meldungText, rect{p + f.s(4) + f.s(12), y + f.s(8), r.Right - p - f.s(12), y + mh}, f.sch.t13, th.f.Tinte, dtWordBreak)
		y += mh + f.s(12)
	}
	// Schlüssel-Wert-Raster, bei genug Breite in zwei Spalten, Zeilen 24
	kw := f.s(160)
	spalteB := (r.Right - 2*p) / 2
	proSpalte := (len(zeilen) + 1) / 2
	if spalteB < kw+f.s(200) {
		spalteB, proSpalte = r.Right-2*p, len(zeilen)
	}
	for i, zl := range zeilen {
		sx := p
		zy := y + int32(i)*f.s(24)
		if i >= proSpalte {
			sx += spalteB
			zy = y + int32(i-proSpalte)*f.s(24)
		}
		if zy+f.s(24) > r.Bottom {
			continue
		}
		schreiben(hdc, zl.k, rect{sx, zy, sx + kw - f.s(8), zy + f.s(24)}, f.sch.t13, th.f.Leise, 0)
		font := f.sch.t13
		if zl.mono {
			font = f.sch.m13
		}
		schreiben(hdc, zl.v, rect{sx + kw, zy, sx + spalteB - f.s(16), zy + f.s(24)}, font, th.f.Tinte, 0)
	}
}

func (a *app) statusMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Zart)
	waagrecht(hdc, 0, r.Right, 0, th.f.Linie)
	a.mu.Lock()
	st, fehler, zentrale := a.stand, a.standFehler, a.client.Zentrale
	a.mu.Unlock()
	host := strings.TrimPrefix(zentrale, "https://")
	x := f.s(16)
	cy := r.Bottom / 2
	var links string
	var an desktop.Anzeige
	switch {
	case fehler != "":
		an = th.f.AnzeigeFuer("crit")
		links = "Die Zentrale " + host + " antwortet nicht: " + fehlerKurz(fehler) + ". Die Anzeige versucht es alle 30 s erneut."
	case st.Zeit.IsZero():
		an = th.f.AnzeigeFuer("")
		links = "Verbinde mit " + host + " …"
	default:
		an = th.f.AnzeigeFuer("ok")
		links = "Verbunden mit " + host
	}
	form(hdc, an.Form, an.Farbe, x, cy-f.s(6), f.s(12))
	x += f.s(12) + f.s(8)
	rechts := ""
	if !st.Zeit.IsZero() {
		rechts = "Stand " + st.Zeit.Local().Format("15:04") + " · alle 30 s"
	}
	if f.meldung != "" && time.Since(f.meldungZeit) < 15*time.Second {
		rechts = f.meldung + "     " + rechts
	}
	rw := breite(hdc, rechts, f.sch.t13)
	schreiben(hdc, rechts, rect{r.Right - f.s(16) - rw, 0, r.Right - f.s(16), r.Bottom}, f.sch.t13, th.f.Leise, dtRight)
	schreiben(hdc, links, rect{x, 0, r.Right - f.s(16) - rw - f.s(24), r.Bottom}, f.sch.t13, th.f.Leise, 0)
}

// --- Nachrichten ------------------------------------------------------------

func (a *app) kontextBaum() {
	f := a.f
	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	ht := tvHitTestInfo{Pt: p}
	pScreenToClient.Call(uintptr(f.baum), uintptr(unsafe.Pointer(&ht.Pt)))
	if h := sendP(f.baum, tvmHitTest, 0, unsafe.Pointer(&ht)); h != 0 {
		send(f.baum, tvmSelectItem, tvgnCaret, h)
	}
	k := f.knoten()
	if k == nil {
		return
	}
	schreiben := desktop.DarfAendern(k.Rolle)
	var eintraege []menuEintrag
	if k.Art == desktop.KnotenGeraet {
		eintraege = append(eintraege, menuEintrag{cmdNeuSensor, "Sensor hinzufügen …\tStrg+N", schreiben},
			menuEintrag{cmdGeraetBearbeiten, "Gerät bearbeiten …", schreiben},
			menuEintrag{cmdGeraetWartung, wartungText(k.Geraet.Wartung != nil), schreiben},
			menuEintrag{}, menuEintrag{cmdGeraetLoeschen, "Gerät löschen …\tEntf", schreiben}, menuEintrag{})
	}
	eintraege = append(eintraege, menuEintrag{cmdNeuGeraet, "Gerät hinzufügen …", schreiben},
		menuEintrag{cmdImBrowser, "Im Browser öffnen", true}, menuEintrag{cmdAktualisieren, "Ansicht aktualisieren\tF5", true})
	a.befehlFenster(a.kontextmenue(eintraege, p))
}

func wartungText(aktiv bool) string {
	if aktiv {
		return "Wartung beenden"
	}
	return "Wartung setzen …"
}

func (a *app) kontextListe() {
	f := a.f
	z := f.gewaehlteZeile()
	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	if z == nil {
		return
	}
	k := f.knoten()
	schreiben := k != nil && desktop.DarfAendern(k.Rolle)
	c := z.check
	var e []menuEintrag
	if c != nil {
		pause := "Sensor pausieren"
		if !c.Aktiv {
			pause = "Sensor fortsetzen"
		}
		e = append(e, menuEintrag{cmdBearbeiten, "Sensor bearbeiten …\tF2", schreiben}, menuEintrag{cmdJetzt, "Jetzt abfragen", schreiben},
			menuEintrag{cmdPause, pause, schreiben}, menuEintrag{cmdWartung, wartungText(c.Wartung != nil && !c.Wartung.UeberGeraet), schreiben})
	}
	if z.AlarmNeu {
		e = append(e, menuEintrag{cmdBestaetigen, "Alarm bestätigen …", schreiben})
	}
	e = append(e, menuEintrag{cmdNeuSensor, "Sensor hinzufügen …\tStrg+N", schreiben}, menuEintrag{})
	if c != nil {
		e = append(e, menuEintrag{cmdLoeschen, "Sensor löschen …\tEntf", schreiben}, menuEintrag{})
	}
	e = append(e, menuEintrag{cmdImBrowser, "Gerät im Browser öffnen", true})
	a.befehlFenster(a.kontextmenue(e, p))
}

// mehrMenue: seltene Befehle unter „Mehr“.
func (a *app) mehrMenue() {
	f := a.f
	k := f.knopf(cmdMehr)
	p := point{k.r.Right, k.r.Bottom + f.s(4)} // Menü rechtsbündig unter dem Knopf
	pClientToScreen.Call(uintptr(f.befehle), uintptr(unsafe.Pointer(&p)))
	kn := f.knoten()
	z := f.gewaehlteZeile()
	schreiben := kn != nil && desktop.DarfAendern(kn.Rolle)
	bearbeitbar := schreiben && ((z != nil && z.check != nil) || (z == nil && kn != nil && kn.Art == desktop.KnotenGeraet))
	e := []menuEintrag{
		{cmdBearbeiten, "Bearbeiten …\tF2", bearbeitbar},
		{cmdLoeschen, "Löschen …\tEntf", bearbeitbar},
		{},
		{cmdImBrowser, "Im Browser öffnen", true},
		{cmdAktualisieren, "Ansicht aktualisieren\tF5", true},
		{},
		{cmdUeber, "Über OpenWacht Desktop", true},
	}
	a.befehlFenster(a.kontextmenueAus(e, p, tpmRightAlign))
}

type menuEintrag struct {
	id   int
	text string
	an   bool
}

func (a *app) kontextmenue(e []menuEintrag, p point) int { return a.kontextmenueAus(e, p, 0) }

const tpmRightAlign = 0x0008

func (a *app) kontextmenueAus(e []menuEintrag, p point, ausrichtung uintptr) int {
	l := make([]listenEintrag, len(e))
	for i, x := range e {
		t, kurz, _ := strings.Cut(x.text, "\t")
		l[i] = listenEintrag{text: t, kurz: kurz, an: x.an}
	}
	i := schwebend(a.f.hwnd, l, p, a.f.s(200), ausrichtung == tpmRightAlign)
	if i < 0 {
		return 0
	}
	return e[i].id
}

// taste: Kurzbefehle im Hauptfenster. true = erledigt.
func (a *app) taste(vk uintptr) bool {
	f := a.f
	fokus, _, _ := pGetFocus.Call()
	switch {
	case vk == vkF5:
		a.befehlFenster(cmdAktualisieren)
	case vk == 'F' && istStrg():
		pSetFocus.Call(uintptr(f.suche))
		send(f.suche, emSetSel, 0, ^uintptr(0))
	case vk == 'N' && istStrg():
		a.befehlFenster(cmdNeuSensor)
	case vk == vkF2:
		a.befehlFenster(cmdBearbeiten)
	case vk == vkDelete && syscall.Handle(fokus) == f.liste:
		a.befehlFenster(cmdLoeschen)
	case vk == vkDelete && syscall.Handle(fokus) == f.baum:
		a.befehlFenster(cmdGeraetLoeschen)
	case vk == vkEscape && syscall.Handle(fokus) == f.suche && getText(f.suche) != "":
		setText(f.suche, "")
	default:
		return false
	}
	return true
}

// utf16Text: nullterminierter UTF-16-Text (lParam von WM_SETTINGCHANGE).
func utf16Text(p uintptr) string {
	if p == 0 {
		return ""
	}
	z := unsafe.Pointer(zeigerAus[uint16](p))
	var u []uint16
	for i := 0; i < 256; i++ {
		c := *(*uint16)(unsafe.Add(z, 2*i))
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16pkg.Decode(u))
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
			senkrecht(hdc, f.s(baumB), 0, r.Bottom, th.f.Linie)
		})
		return 0
	case wmGetMinMaxInfo:
		mi := zeigerAus[minMaxInfo](lp)
		mi.MinTrackSize = point{f.s(960), f.s(600)}
		return 0
	case wmDpiChanged:
		f.dpi = int32(wp & 0xffff)
		r := zeigerAus[rect](lp)
		f.detailH = f.s(232)
		pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
		f.dpiAnwenden()
		return 0
	case wmSettingChange:
		if utf16Text(lp) == "ImmersiveColorSet" {
			if d := themaLesen(); d != th.dunkel {
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
		x, y := int32(int16(lp&0xffff)), int32(int16((lp>>16)&0xffff))
		if f.amTrenner(x, y) {
			f.ziehen = true
			pSetCapture.Call(hwnd)
		}
		return 0
	case wmMouseMove:
		if f.ziehen {
			y := int32(int16((lp >> 16) & 0xffff))
			var r rect
			pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
			f.detailH = r.Bottom - f.s(statusH) - y - f.s(luecke)/2
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
		case id == idSuche && (code == 0x0100 || code == 0x0200): // EN_SETFOCUS, EN_KILLFOCUS
			pInvalidateRect.Call(uintptr(f.marke), 0, 0)
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
	var r rect
	pGetClientRect.Call(uintptr(f.hwnd), uintptr(unsafe.Pointer(&r)))
	unten := r.Bottom - f.s(statusH) - f.detailH
	return f.ansicht == 0 && x > f.s(baumB) && y >= unten-f.s(luecke) && y < unten
}

// fehlerKurz: Ursache in einem Halbsatz statt der technischen Meldung.
func fehlerKurz(f string) string {
	l := strings.ToLower(f)
	switch {
	case strings.Contains(l, "x509") || strings.Contains(l, "certificate"):
		return "Windows vertraut dem Zertifikat der Zentrale nicht"
	case strings.Contains(l, "no such host"):
		return "Name nicht gefunden"
	case strings.Contains(l, "refused") || strings.Contains(l, "connectex") || strings.Contains(l, "unreachable"):
		return "keine Verbindung"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline"):
		return "keine Antwort in 25 s"
	}
	return desktop.Kuerzen(f, 100)
}

// schalterAn: Zustand der Schalter in der Befehlsleiste.
func (f *fenster) schalterAn(id int) bool {
	switch id {
	case cmdNurProbleme:
		return f.nurProbleme
	case cmdAnsichtListe:
		return f.ansicht == 0
	case cmdAnsichtSonne:
		return f.ansicht == 1
	}
	return false
}
