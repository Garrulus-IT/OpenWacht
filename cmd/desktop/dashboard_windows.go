// SPDX-License-Identifier: AGPL-3.0-only

package main

// Dashboard wie Startseite.tsx im Web (1.0.7): dasselbe Layout des Kontos im
// selben Raster, mit Seiten, „An Fenster anpassen“ und Bearbeiten. Modell,
// Packen und Daten stehen in internal/desktop/dashboard.go; hier wird
// gezeichnet und geklickt.
//
// Unterschiede zum Web, bewusst:
//   - Die Größe stellt man über „Ändern › Einstellungen“ ein, nicht durch
//     Ziehen an der Ecke.
//   - Listen in einem Widget rollen nicht; passt nicht alles hinein, steht
//     unten „… und n weitere“. Ein höheres Widget zeigt mehr.
//   - Mit einem API-Token gibt es kein Layout des Kontos: Die App zeigt dann
//     das Standard-Layout, Anpassen geht nur mit Konto-Anmeldung.
//
// Ein Klick auf ein Gerät öffnet es wie bisher neben der Sonne.

import (
	"context"
	"crypto/rand"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

// dash: Zustand des Dashboards in der App.
var dash struct {
	mu sync.Mutex
	// lokal: bearbeitetes Layout, solange angepasst wird oder ein Speichern
	// läuft; sonst kommt das Layout bei jedem Laden frisch von der Zentrale.
	lokal     *desktop.DashLayout
	speichert int
	letzte    *desktop.DashDaten

	bearb bool
	// Sonnen je Widget: Bild und Lage für Klicks
	sonnen map[string]*dashSonne
}

type dashSonne struct {
	sig       string
	bild      bmp
	seg       []desktop.Segment
	ring      []float64
	wurzel    *desktop.Knoten
	cx, cy, n int32
}

func init() {
	seiten[seiteDashboard] = &seitenDef{laden: dashLaden, malen: dashMalen, klick: dashKlick}
}

func dashLaden(ctx context.Context, cl desktop.Client, f *fenster) (any, error) {
	// Direkt nach dem Start fehlt der Stand noch: kurz warten, sonst hätten
	// die Widgets keine Gerätenamen und keinen Bereich.
	var st desktop.Stand
	for i := 0; i < 40; i++ {
		a.mu.Lock()
		st = a.stand
		a.mu.Unlock()
		if !st.Zeit.IsZero() || ctx.Err() != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	ids := desktop.BereichIDs(st.Mandanten, f.mandant, f.mitUnter)
	dash.mu.Lock()
	var layout *desktop.DashLayout
	if dash.lokal != nil {
		l := *dash.lokal
		layout = &l
	}
	alt := dash.letzte
	dash.mu.Unlock()
	d, err := cl.DashDatenHolen(ctx, layout, st, ids, alt)
	if err != nil {
		return nil, err
	}
	dash.mu.Lock()
	dash.letzte = &d
	// Während des Ladens weiter bearbeitet: Das neuere Layout gilt.
	if dash.lokal != nil {
		d.Layout = *dash.lokal
	}
	dash.mu.Unlock()
	return &d, nil
}

// dashVergessen: nach Ab- oder Anmeldung gehört das Layout einem anderen Konto.
func dashVergessen() {
	dash.mu.Lock()
	dash.lokal, dash.letzte, dash.bearb = nil, nil, false
	dash.mu.Unlock()
}

// dashAendern: Layout lokal setzen, zeichnen und im Hintergrund speichern.
func dashAendern(d *desktop.DashDaten, l desktop.DashLayout, meldung string) {
	l.Eigen = true
	d.Layout = l
	dash.mu.Lock()
	kopie := l
	dash.lokal = &kopie
	dash.speichert++
	dash.mu.Unlock()
	if meldung != "" {
		setStatusText(a.f, meldung)
	}
	a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
		return cl.DashSpeichern(ctx, l)
	}, func(err error) {
		dash.mu.Lock()
		dash.speichert--
		if dash.speichert == 0 && !dash.bearb {
			dash.lokal = nil
		}
		dash.mu.Unlock()
		if err != nil {
			hinweis(a.f.hwnd, "Dashboard", "Speichern fehlgeschlagen: "+fehlerText(err), true)
		}
		// Daten für neue Widgets holen
		a.seiteLaden(seiteDashboard)
	})
	pInvalidateRect.Call(uintptr(a.f.seitenF), 0, 0)
}

func dashSeite(l desktop.DashLayout) int {
	if a.cfg.DashSeite >= 0 && a.cfg.DashSeite < len(l.SeitenNamen()) {
		return a.cfg.DashSeite
	}
	return 0
}

// widgetBereich: fester Mandant (mit Untermandanten), sonst der Bereich der Seitenleiste.
func widgetBereich(w desktop.Widget, st desktop.Stand, ids map[string]bool) (map[string]bool, bool) {
	if w.MandantID != "" {
		if eigene := desktop.BereichIDs(st.Mandanten, w.MandantID, true); len(eigene) > 0 {
			return eigene, len(eigene) > 1
		}
	}
	return ids, len(ids) > 1
}

// --- Zeichnen --------------------------------------------------------------------

func dashMalen(m *maler, daten any) {
	f := m.f
	d, ok := daten.(*desktop.DashDaten)
	if !ok {
		m.klein("Lädt …")
		return
	}
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	ids, _, _ := a.bereich()
	l := d.Layout
	seite := dashSeite(l)
	namen := l.SeitenNamen()

	// Leiste: Seiten links, Knöpfe rechts
	y0 := m.y
	x := m.x0
	if len(namen) > 1 || dash.bearb {
		for i, n := range namen {
			w := breite(m.hdc, n, f.sch.t13b) + 2*m.s(12)
			r := rect{x, y0, x + w, y0 + m.s(32)}
			hover := m.ziel(r, "seite", itoa(i))
			if m.zeichnen {
				fg := th.f.Leise
				if i == seite || hover {
					fg = th.f.Tinte
				}
				schreiben(m.hdc, n, r, f.sch.t13b, fg, dtCenter)
				if i == seite {
					fuellen(m.hdc, rect{r.Left, r.Bottom - m.s(3), r.Right, r.Bottom}, th.f.Marke)
				}
			}
			x += w + m.s(4)
		}
	}
	var k []sKnopf
	switch {
	case l.NurLesen:
	case dash.bearb:
		if len(namen) < desktop.DashMaxSeiten {
			k = append(k, sKnopf{text: "+ Seite", art: "seite-neu"})
		}
		k = append(k, sKnopf{text: "Seite umbenennen", art: "seite-name"})
		if len(namen) > 1 {
			k = append(k, sKnopf{text: "Seite löschen", art: "seite-weg", stil: kGefahr})
		}
		k = append(k, sKnopf{text: "+ Widget", art: "neu", aus: len(l.Widgets) >= desktop.DashMaxWidgets},
			sKnopf{text: "Standard wiederherstellen", art: "standard"}, sKnopf{text: "Fertig", art: "fertig", stil: kHaupt})
	default:
		k = append(k, sKnopf{text: "Anpassen", art: "anpassen"})
	}
	fit := sKnopf{text: "An Fenster anpassen", art: "fenster"}
	if a.cfg.DashFenster {
		fit.text = "An Fenster angepasst"
	}
	if !dash.bearb {
		k = append([]sKnopf{fit}, k...)
	}
	bx := m.x1
	for i := len(k) - 1; i >= 0; i-- {
		bx -= breite(m.hdc, k[i].text, f.sch.t13) + 2*m.s(8)
		m.knopfMalen(k[i], bx, y0+m.s(1))
		bx -= m.s(8)
	}
	if m.zeichnen {
		waagrecht(m.hdc, m.x0, m.x1, y0+m.s(32), th.f.LinieZart)
		if l.NurLesen && x == m.x0 {
			schreiben(m.hdc, "Standard-Layout: Dein eigenes Dashboard gibt es mit der Anmeldung „Konto (wie im Browser)“.",
				rect{m.x0, y0, bx, y0 + m.s(32)}, f.sch.t13, th.f.Leise, 0)
		}
	}
	m.y += m.s(32) + m.s(12)

	idx := l.AufSeite(seite)
	if len(idx) == 0 {
		t := "Diese Seite ist leer. Über „Anpassen“ fügst du Widgets hinzu oder stellst den Standard wieder her."
		if dash.bearb {
			t = "Diese Seite ist leer: „+ Widget“ fügt eines hinzu."
		}
		m.leer(t)
		return
	}
	ws := make([]desktop.Widget, len(idx))
	for i, j := range idx {
		ws[i] = l.Widgets[j]
	}
	gap := m.s(8)
	breit := m.x1 - m.x0
	spalten := desktop.DashSpaltenFuer(int(breit * 96 / f.dpi))
	plaetze, reihen := desktop.DashPacken(ws, spalten)
	sb := (breit - int32(spalten-1)*gap) / int32(spalten)
	zh := m.s(216)
	if spalten == 1 {
		zh = m.s(260)
	} else if a.cfg.DashFenster && !dash.bearb {
		var cr rect
		pGetClientRect.Call(uintptr(f.seitenF), ptr(&cr))
		frei := cr.Bottom - (m.y + f.seitenOff) - m.s(4)
		zh = max(m.s(140), (frei-int32(reihen-1)*gap)/int32(reihen))
	}
	hoehe := int32(reihen)*zh + int32(reihen-1)*gap
	jetzt := time.Now()
	m.eigen(hoehe, func(r rect) {
		for i, w := range ws {
			p := plaetze[i]
			wr := rect{r.Left + int32(p.X)*(sb+gap), r.Top + int32(p.Y)*(zh+gap), 0, 0}
			wr.Right = wr.Left + int32(p.B)*sb + int32(p.B-1)*gap
			if p.X+p.B == spalten {
				wr.Right = r.Right
			}
			wr.Bottom = wr.Top + int32(p.H)*zh + int32(p.H-1)*gap
			widgetMalen(m, d, st, ids, w, wr, i, len(ws), jetzt)
		}
	})
}

type widgetCtx struct {
	m     *maler
	f     *fenster
	hdc   uintptr
	d     *desktop.DashDaten
	st    desktop.Stand
	ids   map[string]bool
	mehr  bool
	w     desktop.Widget
	r     rect // Inhalt
	jetzt time.Time
}

func widgetMalen(m *maler, d *desktop.DashDaten, st desktop.Stand, ids map[string]bool, w desktop.Widget, wr rect, pos, anzahl int, jetzt time.Time) {
	f := m.f
	hdc := m.hdc
	rand := th.f.Linie
	if dash.bearb {
		rand = th.f.Marke
	}
	rund(hdc, wr, m.s(3), th.f.Flaeche, rand, true, true, dash.bearb)
	kh := m.s(32)
	kopf := rect{wr.Left + 1, wr.Top + 1, wr.Right - 1, wr.Top + kh}
	titel := w.TitelVon(st.Geraete)
	fuellen(hdc, kopf, th.f.Zart)
	waagrecht(hdc, kopf.Left, kopf.Right, kopf.Bottom-1, th.f.LinieZart)
	tr := kopf
	if dash.bearb {
		bw := breite(hdc, "Ändern", f.sch.t13) + 2*m.s(8) + m.s(14)
		br := rect{kopf.Right - bw - m.s(4), kopf.Top + m.s(3), kopf.Right - m.s(4), kopf.Bottom - m.s(4)}
		hover := m.ziel(br, "aendern", w.ID)
		bg, rd := th.f.Flaeche, th.f.Linie
		if hover {
			bg, rd = th.f.MarkeHauch, th.f.Marke
		}
		rund(hdc, br, m.s(3), bg, rd, true, true, false)
		schreiben(hdc, "Ändern", rect{br.Left + m.s(8), br.Top, br.Right - m.s(14), br.Bottom}, f.sch.t13, th.f.Tinte, 0)
		chevron(hdc, br.Right-m.s(11), (br.Top+br.Bottom)/2, m.s(4), true, th.f.Leise)
		tr.Right = br.Left - m.s(4)
		tr.Left += m.s(8)
		schreiben(hdc, titel, tr, f.sch.t13b, th.f.Tinte, 0)
	} else {
		if w.MandantID != "" {
			titel += " · " + a.mandantName(w.MandantID)
		}
		schreiben(hdc, titel, rect{tr.Left + m.s(8), tr.Top, tr.Right - m.s(8), tr.Bottom}, f.sch.t13b, th.f.Tinte, dtCenter)
	}
	wids, mehr := widgetBereich(w, st, ids)
	c := &widgetCtx{m: m, f: f, hdc: hdc, d: d, st: st, ids: wids, mehr: mehr, w: w, jetzt: jetzt,
		r: rect{wr.Left + m.s(12), kopf.Bottom + m.s(8), wr.Right - m.s(12), wr.Bottom - m.s(8)}}
	pSaveDC.Call(hdc)
	pIntersectClipRect.Call(hdc, uintptr(wr.Left+1), uintptr(kopf.Bottom), uintptr(wr.Right-1), uintptr(wr.Bottom-1))
	if c.r.Bottom-c.r.Top > m.s(16) {
		c.inhalt()
	}
	pRestoreDC.Call(hdc, ^uintptr(0))
}

// --- Bausteine der Inhalte -------------------------------------------------------

func (c *widgetCtx) s(px int32) int32 { return c.f.s(px) }

func (c *widgetCtx) hinweis(t string) {
	schreiben(c.hdc, t, rect{c.r.Left, c.r.Top, c.r.Right, c.r.Bottom}, c.f.sch.t13, th.f.Leise, dtWordBreak)
}

// fehlerOder: Fehler der Art zeigen (true) oder „Lädt …“, wenn die Daten fehlen.
func (c *widgetCtx) fehlt(art string, da bool) bool {
	if e := c.d.Fehler[art]; e != "" {
		c.hinweis("Laden fehlgeschlagen: " + e)
		return true
	}
	if !da {
		c.hinweis("Lädt …")
		return true
	}
	return false
}

// ziel im Inhalt: nur, soweit es sichtbar ist.
func (c *widgetCtx) ziel(r rect, art, wert string) bool {
	if r.Top >= c.r.Bottom || r.Bottom <= c.r.Top {
		return false
	}
	r.Bottom = min(r.Bottom, c.r.Bottom)
	return c.m.ziel(r, art, wert)
}

// formPunkt: Zustand als Form (12 px), bei gültiger Kennfarbe in ihrer Farbe.
func (c *widgetCtx) formPunkt(status string, kenn *desktop.Kennfarbe, x, y, zh int32) {
	an := th.f.AnzeigeFuer(status)
	farbe := an.Farbe
	if k, ok := kenn.RGB(); ok && desktop.KennGilt(status) {
		farbe = k
	}
	form(c.hdc, an.Form, farbe, x, y+(zh-c.s(12))/2, c.s(12))
}

// zeilen: Liste mit fester Zeilenhöhe; malt, was passt, und nennt den Rest.
func (c *widgetCtx) zeilen(n int, zh int32, oben int32, zeile func(i int, r rect)) {
	y := oben
	for i := 0; i < n; i++ {
		rest := n - i
		if y+zh > c.r.Bottom && !(rest == 1 && y+zh <= c.r.Bottom+c.s(6)) {
			if y+c.s(18) > c.r.Bottom {
				if i < 2 {
					return // zu niedrig für Zeile und Hinweis: die eine Zeile bleibt
				}
				y -= zh // die letzte Zeile weicht dem Hinweis
				rest++
				fuellen(c.hdc, rect{c.r.Left, y, c.r.Right, c.r.Bottom + c.s(8)}, th.f.Flaeche)
			}
			schreiben(c.hdc, "… und "+itoa(rest)+" weitere", rect{c.r.Left, y, c.r.Right, y + c.s(18)}, c.f.sch.t13, th.f.Leise, 0)
			return
		}
		zeile(i, rect{c.r.Left, y, c.r.Right, y + zh})
		if i < n-1 {
			waagrecht(c.hdc, c.r.Left, c.r.Right, y+zh-1, th.f.LinieZart)
		}
		y += zh
	}
}

// link: Text als Link auf ein Gerät; liefert die Breite.
func (c *widgetCtx) link(text, geraet string, r rect, font uintptr) int32 {
	w := min(breite(c.hdc, text, font), r.Right-r.Left)
	lr := rect{r.Left, r.Top, r.Left + w, r.Bottom}
	hover := geraet != "" && c.ziel(lr, "geraet", geraet)
	fg := th.f.Tinte
	if hover {
		fg = th.f.Marke
	}
	schreiben(c.hdc, text, lr, font, fg, 0)
	if hover {
		waagrecht(c.hdc, lr.Left, lr.Right, (lr.Top+lr.Bottom)/2+c.s(9), th.f.Marke)
	}
	return w
}

func (c *widgetCtx) mandant(id string) string {
	if !c.mehr {
		return ""
	}
	return a.mandantName(id)
}

// pegel: Balken 0–100 % mit Zahl rechts.
func (c *widgetCtx) pegel(r rect, v float64) {
	zw := c.s(44)
	bar := rect{r.Left, (r.Top+r.Bottom)/2 - c.s(4), r.Right - zw - c.s(6), (r.Top+r.Bottom)/2 + c.s(4)}
	rund(c.hdc, bar, c.s(3), th.f.Zart, th.f.LinieZart, true, true, false)
	farbe := th.f.OK
	switch {
	case v >= 90:
		farbe = th.f.Krit
	case v >= 80:
		farbe = th.f.Warn
	}
	if w := int32(float64(bar.Right-bar.Left) * math.Min(100, math.Max(0, v)) / 100); w > 1 {
		rund(c.hdc, rect{bar.Left, bar.Top, bar.Left + w, bar.Bottom}, c.s(3), farbe, farbe, true, false, false)
	}
	schreiben(c.hdc, strconv.Itoa(int(v+0.5))+" %", rect{r.Right - zw, r.Top, r.Right, r.Bottom}, c.f.sch.m13, th.f.Tinte, dtRight)
}

func prozentText(v *float64) string {
	if v == nil {
		return "–"
	}
	return strings.Replace(strconv.FormatFloat(math.Round(*v*10)/10, 'f', -1, 64), ".", ",", 1) + " %"
}

// --- Inhalte ---------------------------------------------------------------------

func (c *widgetCtx) inhalt() {
	switch c.w.Typ {
	case "zustand":
		c.zustand()
	case "alarme":
		c.alarme()
	case "sensoren":
		c.sensoren()
	case "auslastung":
		c.auslastung()
	case "platten":
		c.platten()
	case "prognose":
		c.prognose()
	case "alarme_je_tag":
		c.alarmeJeTag()
	case "verfuegbarkeit":
		c.verfuegbarkeit()
	case "graph":
		c.graph()
	case "sonne":
		c.sonne()
	case "ereignisse":
		c.ereignisse()
	case "zertifikate":
		c.zertifikate()
	case "wartung":
		c.wartung()
	case "sensor":
		c.sensor()
	case "uhr":
		c.uhr()
	case "notiz":
		if c.w.Text == "" {
			c.hinweis("Leere Notiz: „Anpassen“ › „Ändern“ › Einstellungen.")
		} else {
			schreiben(c.hdc, c.w.Text, c.r, c.f.sch.t13, th.f.Tinte, dtWordBreak)
		}
	default:
		c.hinweis("Dieses Widget kennt diese Version der App noch nicht.")
	}
}

func (c *widgetCtx) imBereich() []desktop.Sensor {
	var out []desktop.Sensor
	for _, s := range c.st.Sensoren {
		if c.ids[s.MandantID] {
			out = append(out, s)
		}
	}
	return out
}

var zustandSpalten = []struct {
	gruppen []string
	titel   string
}{
	{[]string{"crit"}, "Kritisch"}, {[]string{"warn"}, "Warnung"}, {[]string{"unknown"}, "Unbekannt"}, {[]string{"ok"}, "OK"},
	{[]string{"wartung", "pause"}, "Wartung/Pause"},
}

func (c *widgetCtx) zustand() {
	geraete, sens := desktop.ZustandZahlen(c.st.Sensoren, c.ids)
	r := c.r
	erste := min(c.s(110), (r.Right-r.Left)/4)
	sw := (r.Right - r.Left - erste) / int32(len(zustandSpalten))
	schmal := sw < c.s(84)
	for i, sp := range zustandSpalten {
		t := sp.titel
		if schmal {
			t = map[string]string{"Kritisch": "Krit.", "Warnung": "Warn.", "Unbekannt": "Unbek.", "OK": "OK", "Wartung/Pause": "Wart."}[t]
		}
		schreiben(c.hdc, t, rect{r.Left + erste + int32(i)*sw, r.Top, r.Left + erste + int32(i+1)*sw - c.s(6), r.Top + c.s(18)}, c.f.sch.t13,
			th.f.Leise, dtRight)
	}
	farben := map[string]desktop.RGB{"crit": th.f.Krit, "warn": th.f.Warn, "unknown": th.f.Leise, "ok": th.f.OK, "wartung": th.f.Wartung,
		"pause": th.f.Linie}
	text := map[string]desktop.RGB{"crit": th.f.TextKrit, "warn": th.f.TextWarn}
	y := r.Top + c.s(22)
	for _, z := range []struct {
		name string
		zahl map[string]int
		art  string
	}{{"Geräte", geraete, "nav-hosts"}, {"Sensoren", sens, "nav-alarme"}} {
		if y+c.s(34) > r.Bottom {
			break
		}
		gesamt := 0
		for _, n := range z.zahl {
			gesamt += n
		}
		w := c.link(z.name, "", rect{r.Left, y, r.Left + erste - c.s(30), y + c.s(30)}, c.f.sch.t13b)
		if c.ziel(rect{r.Left, y, r.Left + w, y + c.s(30)}, z.art, "") {
			waagrecht(c.hdc, r.Left, r.Left+w, y+c.s(24), th.f.Marke)
		}
		schreiben(c.hdc, itoa(gesamt), rect{r.Left + w + c.s(6), y, r.Left + erste, y + c.s(30)}, c.f.sch.t13, th.f.Leise, 0)
		for i, sp := range zustandSpalten {
			n := 0
			for _, g := range sp.gruppen {
				n += z.zahl[g]
			}
			fg, font := th.f.Leise, c.f.sch.t20
			if n > 0 && i < 3 {
				font = c.f.sch.t25b
				fg = th.f.Tinte
				if t, ok := text[sp.gruppen[0]]; ok {
					fg = t
				}
			} else if n > 0 {
				fg = th.f.Tinte
			}
			schreiben(c.hdc, itoa(n), rect{r.Left + erste + int32(i)*sw, y, r.Left + erste + int32(i+1)*sw - c.s(6), y + c.s(30)}, font, fg, dtRight)
		}
		y += c.s(32)
		// Balken der Verteilung
		br := desktop.BalkenBreiten(z.zahl)
		x := float64(r.Left)
		ganz := float64(r.Right - r.Left)
		for _, g := range []string{"crit", "warn", "unknown", "ok", "wartung", "pause"} {
			if br[g] <= 0 {
				continue
			}
			x2 := x + ganz*br[g]/100
			fuellen(c.hdc, rect{int32(x), y, int32(x2) - 1, y + c.s(8)}, farben[g])
			x = x2
		}
		y += c.s(8) + c.s(12)
	}
}

func (c *widgetCtx) alarme() {
	var offen []desktop.Sensor
	for _, s := range c.imBereich() {
		if s.Alarm != nil && s.Alarm.Ende == nil {
			offen = append(offen, s)
		}
	}
	if len(offen) == 0 {
		c.hinweis("Keine aktiven Alarme.")
		return
	}
	rang := map[string]int{"crit": 0, "unknown": 1, "warn": 2, "ok": 3, "pause": 5}
	sort.SliceStable(offen, func(i, j int) bool {
		bi, bj := offen[i].Alarm.Bestaetigt != nil, offen[j].Alarm.Bestaetigt != nil
		if bi != bj {
			return !bi
		}
		return rang[desktop.SensorGruppe(offen[i])] < rang[desktop.SensorGruppe(offen[j])]
	})
	breit := c.r.Right-c.r.Left > c.s(520)
	mw := c.s(118)
	c.zeilen(len(offen), c.s(34), c.r.Top, func(i int, r rect) {
		s := offen[i]
		status, wort := s.Status, desktop.StatusText(s.Status)
		if s.Alarm.Bestaetigt != nil && status == "crit" {
			status, wort = "bestaetigt", "Bestätigt"
		}
		c.f.zustandsMarke(c.hdc, status, wort, r.Left, r.Top+(r.Bottom-r.Top-c.s(24))/2, true)
		x := r.Left + mw
		rest := r.Right - x
		hw := rest * 40 / 100
		if breit {
			hw = rest * 24 / 100
		}
		host := s.Host
		if host == "" {
			host = "–"
		}
		w := c.link(host, s.GeraetID, rect{x, r.Top, x + hw - c.s(8), r.Bottom}, c.f.sch.t13b)
		if mt := c.mandant(s.MandantID); mt != "" && w+c.s(8) < hw {
			schreiben(c.hdc, mt, rect{x + w + c.s(6), r.Top, x + hw - c.s(8), r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		}
		x += hw
		if breit {
			nw := rest * 26 / 100
			schreiben(c.hdc, s.Name, rect{x, r.Top, x + nw - c.s(8), r.Bottom}, c.f.sch.t13, th.f.Tinte, 0)
			schreiben(c.hdc, s.Meldung, rect{x + nw, r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		} else {
			schreiben(c.hdc, s.Name, rect{x, r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Tinte, 0)
		}
	})
}

func (c *widgetCtx) sensoren() {
	var liste []desktop.Sensor
	for _, s := range c.imBereich() {
		if g := desktop.SensorGruppe(s); g == "crit" || g == "warn" || g == "unknown" {
			liste = append(liste, s)
		}
	}
	if len(liste) == 0 {
		c.hinweis("Alle Sensoren sind OK.")
		return
	}
	rang := map[string]int{"crit": 0, "unknown": 1, "warn": 2}
	sort.SliceStable(liste, func(i, j int) bool {
		gi, gj := rang[desktop.SensorGruppe(liste[i])], rang[desktop.SensorGruppe(liste[j])]
		if gi != gj {
			return gi < gj
		}
		return strings.ToLower(liste[i].Host+" "+liste[i].Name) < strings.ToLower(liste[j].Host+" "+liste[j].Name)
	})
	c.zeilen(len(liste), c.s(26), c.r.Top, func(i int, r rect) {
		s := liste[i]
		c.formPunkt(desktop.SensorGruppe(s), s.Kennfarbe, r.Left, r.Top, r.Bottom-r.Top)
		x := r.Left + c.s(20)
		name, rest := s.Host, s.Name
		if name == "" {
			name, rest = s.Name, s.Meldung
		}
		w := c.link(name, s.GeraetID, rect{x, r.Top, x + (r.Right-x)*55/100, r.Bottom}, c.f.sch.t13b)
		schreiben(c.hdc, rest, rect{x + w + c.s(8), r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
	})
}

func (c *widgetCtx) auslastung() {
	if c.fehlt("auslastung", true) {
		return
	}
	cpu := desktop.AuslastungTop(c.d.Auslastung, c.ids, false, 8)
	ram := desktop.AuslastungTop(c.d.Auslastung, c.ids, true, 8)
	if len(cpu) == 0 && len(ram) == 0 {
		c.hinweis("Keine aktuellen Messwerte im Bereich.")
		return
	}
	teil := func(titel string, liste []desktop.Auslastung, ramWert bool, r rect) {
		schreiben(c.hdc, titel, rect{r.Left, r.Top, r.Right, r.Top + c.s(18)}, c.f.sch.t13b, th.f.Leise, 0)
		y := r.Top + c.s(22)
		for _, z := range liste {
			if y+c.s(22) > r.Bottom {
				break
			}
			nw := (r.Right - r.Left) * 45 / 100
			c.link(z.Name, z.GeraetID, rect{r.Left, y, r.Left + nw - c.s(8), y + c.s(22)}, c.f.sch.t13)
			v := z.CPU
			if ramWert {
				v = z.RAM
			}
			c.pegel(rect{r.Left + nw, y, r.Right, y + c.s(22)}, *v)
			y += c.s(22)
		}
	}
	r := c.r
	if r.Right-r.Left > c.s(520) {
		mitte := (r.Left + r.Right) / 2
		teil("CPU", cpu, false, rect{r.Left, r.Top, mitte - c.s(12), r.Bottom})
		teil("RAM", ram, true, rect{mitte + c.s(12), r.Top, r.Right, r.Bottom})
		return
	}
	mitte := (r.Top + r.Bottom) / 2
	teil("CPU", cpu, false, rect{r.Left, r.Top, r.Right, mitte - c.s(4)})
	teil("RAM", ram, true, rect{r.Left, mitte + c.s(4), r.Right, r.Bottom})
}

func (c *widgetCtx) plattenImBereich() []desktop.Platte {
	var out []desktop.Platte
	for _, p := range c.d.Platten {
		if c.ids[p.MandantID] {
			out = append(out, p)
		}
	}
	return out
}

func (c *widgetCtx) platten() {
	if c.fehlt("platten", c.d.Platten != nil) {
		return
	}
	liste := c.plattenImBereich()
	sort.SliceStable(liste, func(i, j int) bool { return liste[i].Belegt > liste[j].Belegt })
	if len(liste) > 5 {
		liste = liste[:5]
	}
	if len(liste) == 0 {
		c.hinweis("Keine Platten im Bereich.")
		return
	}
	breit := c.r.Right-c.r.Left > c.s(520)
	c.zeilen(len(liste), c.s(26), c.r.Top, func(i int, r rect) {
		p := liste[i]
		ganz := r.Right - r.Left
		nw := ganz * 55 / 100
		if breit {
			nw = ganz * 38 / 100
		}
		w := c.link(p.Geraet, p.GeraetID, rect{r.Left, r.Top, r.Left + nw*60/100, r.Bottom}, c.f.sch.t13b)
		schreiben(c.hdc, p.Platte, rect{r.Left + w + c.s(6), r.Top, r.Left + nw - c.s(8), r.Bottom}, c.f.sch.m13, th.f.Leise, 0)
		if breit {
			pw := ganz * 30 / 100
			c.pegel(rect{r.Left + nw, r.Top, r.Left + nw + pw, r.Bottom}, p.Belegt)
			schreiben(c.hdc, p.PrognoseText(), rect{r.Left + nw + pw + c.s(12), r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		} else {
			c.pegel(rect{r.Left + nw, r.Top, r.Right, r.Bottom}, p.Belegt)
		}
	})
}

func (c *widgetCtx) prognose() {
	if c.fehlt("prognose", c.d.Platten != nil) {
		return
	}
	var bald []desktop.Platte
	for _, p := range c.plattenImBereich() {
		if p.Stand == "steigt" && p.Tage != nil && *p.Tage <= 90 {
			bald = append(bald, p)
		}
	}
	if len(bald) == 0 {
		c.hinweis("Keine Platte läuft in den nächsten 90 Tagen voll.")
		return
	}
	sort.SliceStable(bald, func(i, j int) bool { return *bald[i].Tage < *bald[j].Tage })
	if len(bald) > 10 {
		bald = bald[:10]
	}
	c.zeilen(len(bald), c.s(26), c.r.Top, func(i int, r rect) {
		p := bald[i]
		st := "pause"
		if *p.Tage <= 14 {
			st = "warn"
		}
		c.formPunkt(st, nil, r.Left, r.Top, r.Bottom-r.Top)
		x := r.Left + c.s(20)
		tw := breite(c.hdc, p.PrognoseText(), c.f.sch.t13) + c.s(8)
		w := c.link(p.Geraet, p.GeraetID, rect{x, r.Top, r.Right - tw - c.s(40), r.Bottom}, c.f.sch.t13b)
		schreiben(c.hdc, p.Platte, rect{x + w + c.s(6), r.Top, r.Right - tw, r.Bottom}, c.f.sch.m13, th.f.Leise, 0)
		schreiben(c.hdc, p.PrognoseText(), rect{r.Right - tw, r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Tinte, dtRight)
	})
}

func (c *widgetCtx) alarmeJeTag() {
	if c.fehlt("alarme_je_tag", c.d.Kennzahlen != nil) {
		return
	}
	tage := c.d.Kennzahlen.AlarmeJeTag(c.jetzt)
	gesamt, maxN := 0, 1
	for _, t := range tage {
		n := t.Warn + t.Crit + t.Unknown
		gesamt += n
		maxN = max(maxN, n)
	}
	r := c.r
	schreiben(c.hdc, "Begonnene Alarme, letzte 30 Tage", rect{r.Left, r.Top, r.Right - c.s(90), r.Top + c.s(18)}, c.f.sch.t13, th.f.Leise, 0)
	schreiben(c.hdc, itoa(gesamt)+" insgesamt", rect{r.Right - c.s(120), r.Top, r.Right, r.Top + c.s(18)}, c.f.sch.t13b, th.f.Tinte, dtRight)
	// Obergrenze 1, 2, 5, 10 …
	p := math.Pow(10, math.Floor(math.Log10(float64(maxN))))
	yMax := 10 * p
	for _, f := range []float64{1, 2, 5} {
		if f*p >= float64(maxN) {
			yMax = f * p
			break
		}
	}
	l := r.Left + c.s(28)
	oben, unten := r.Top+c.s(26), r.Bottom-c.s(18)
	if unten-oben < c.s(20) {
		return
	}
	for _, f := range []float64{0, 1} {
		y := unten - int32(float64(unten-oben)*f)
		waagrecht(c.hdc, l, r.Right, y, th.f.LinieZart)
		schreiben(c.hdc, itoa(int(yMax*f)), rect{r.Left, y - c.s(9), l - c.s(6), y + c.s(9)}, c.f.sch.t13, th.f.Leise, dtRight)
	}
	bw := float64(r.Right-l) / float64(len(tage))
	for i, t := range tage {
		x := l + int32(float64(i)*bw) + 1
		w := max(int32(bw)-2, 1)
		y := unten
		for _, teil := range []struct {
			n     int
			farbe desktop.RGB
		}{{t.Crit, th.f.Krit}, {t.Warn, th.f.Warn}, {t.Unknown, th.f.Leise}} {
			if teil.n == 0 {
				continue
			}
			h := max(int32(float64(unten-oben)*float64(teil.n)/yMax), 2)
			fuellen(c.hdc, rect{x, y - h, x + w, y}, teil.farbe)
			y -= h
		}
	}
	datum := func(t time.Time) string { return t.Format("02.01.") }
	schreiben(c.hdc, datum(tage[0].Tag), rect{l, unten + c.s(2), l + c.s(60), r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
	schreiben(c.hdc, datum(tage[29].Tag), rect{r.Right - c.s(60), unten + c.s(2), r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, dtRight)
}

func (c *widgetCtx) verfuegbarkeit() {
	if c.fehlt("verfuegbarkeit", c.d.Kennzahlen != nil) {
		return
	}
	liste := c.d.Kennzahlen.Verfuegbarkeit(c.ids)
	if len(liste) == 0 {
		c.hinweis("Noch keine Werte.")
		return
	}
	r := c.r
	zw := c.s(64)
	schreiben(c.hdc, "schlechteste zuerst", rect{r.Left, r.Top, r.Right - 2*zw, r.Top + c.s(18)}, c.f.sch.t13, th.f.Leise, 0)
	schreiben(c.hdc, "7 Tage", rect{r.Right - 2*zw, r.Top, r.Right - zw, r.Top + c.s(18)}, c.f.sch.t13, th.f.Leise, dtRight)
	schreiben(c.hdc, "30 Tage", rect{r.Right - zw, r.Top, r.Right, r.Top + c.s(18)}, c.f.sch.t13, th.f.Leise, dtRight)
	farbe := func(v *float64) desktop.RGB {
		switch {
		case v != nil && *v < 95:
			return th.f.TextKrit
		case v != nil && *v < 99:
			return th.f.TextWarn
		}
		return th.f.Tinte
	}
	c.zeilen(len(liste), c.s(26), r.Top+c.s(22), func(i int, zr rect) {
		z := liste[i]
		nw := (zr.Right - zr.Left - 2*zw) * 50 / 100
		c.link(z.Geraet, z.GeraetID, rect{zr.Left, zr.Top, zr.Left + nw - c.s(8), zr.Bottom}, c.f.sch.t13b)
		schreiben(c.hdc, z.Was, rect{zr.Left + nw, zr.Top, zr.Right - 2*zw, zr.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		schreiben(c.hdc, prozentText(z.Tage7), rect{zr.Right - 2*zw, zr.Top, zr.Right - zw, zr.Bottom}, c.f.sch.m13, farbe(z.Tage7), dtRight)
		schreiben(c.hdc, prozentText(z.Tage30), rect{zr.Right - zw, zr.Top, zr.Right, zr.Bottom}, c.f.sch.m13, farbe(z.Tage30), dtRight)
	})
}

// Linienfarben der Graphen (Markenfarbe zuerst, dann die Kennfarben-Vorschläge)
func graphFarbe(i int) desktop.RGB {
	if i == 0 {
		return th.f.Marke
	}
	c, _ := (&desktop.Kennfarbe{Farbe: desktop.KennVorschlaege[(i-1)%len(desktop.KennVorschlaege)]}).RGB()
	return c
}

func (c *widgetCtx) graph() {
	g, ok := c.d.Graphen[c.w.ID]
	if !ok {
		c.hinweis("Lädt …")
		return
	}
	if g.Hinweis != "" {
		c.hinweis(g.Hinweis)
		return
	}
	var linien []desktop.GraphLinie
	for _, l := range g.Linien {
		if (c.w.GeraetID != "" || l.MandantID == "" || c.ids[l.MandantID]) && len(l.Punkte) > 0 {
			linien = append(linien, l)
		}
	}
	if len(linien) == 0 || g.Spanne <= 0 {
		c.hinweis("Keine Messwerte im Zeitraum.")
		return
	}
	r := c.r
	l := r.Left + c.s(34)
	legende := int32(0)
	if len(linien) > 1 {
		legende = c.s(20)
	}
	oben, unten := r.Top+c.s(6), r.Bottom-c.s(18)-legende
	if unten-oben < c.s(24) {
		return
	}
	for _, f := range []float64{0, 0.5, 1} {
		y := unten - int32(float64(unten-oben)*f)
		waagrecht(c.hdc, l, r.Right, y, th.f.LinieZart)
		schreiben(c.hdc, itoa(int(100*f))+" %", rect{r.Left, y - c.s(9), l - c.s(4), y + c.s(9)}, c.f.sch.t13, th.f.Leise, dtRight)
	}
	ende := float64(c.d.Zeit.Unix())
	for _, ln := range linien {
		ende = math.Max(ende, ln.Punkte[len(ln.Punkte)-1][0])
	}
	start := ende - float64(g.Spanne)
	xVon := func(t float64) int32 { return l + int32(float64(r.Right-l)*(t-start)/float64(g.Spanne)) }
	yVon := func(v float64) int32 { return unten - int32(float64(unten-oben)*math.Min(100, math.Max(0, v))/100) }
	for i, ln := range linien {
		stift, _, _ := pCreatePen.Call(psSolid, uintptr(c.s(2)), cref(graphFarbe(i)))
		alt, _, _ := pSelectObject.Call(c.hdc, stift)
		letzte := -1e18
		for _, p := range ln.Punkte {
			if p[0] < start {
				continue
			}
			x, y := xVon(p[0]), yVon(p[1])
			// Lücke (mehr als zwei Schritte ohne Wert): Linie reißt ab
			if p[0]-letzte > float64(2*max(g.Schritt, 1)) {
				pMoveToEx.Call(c.hdc, uintptr(x), uintptr(y), 0)
			} else {
				pLineTo.Call(c.hdc, uintptr(x), uintptr(y))
			}
			letzte = p[0]
		}
		pSelectObject.Call(c.hdc, alt)
		pDeleteObject.Call(stift)
	}
	zeit := func(t float64) string {
		z := time.Unix(int64(t), 0)
		if g.Spanne > 2*86400 {
			return z.Format("02.01.")
		}
		return z.Format("15:04")
	}
	schreiben(c.hdc, zeit(start), rect{l, unten + c.s(2), l + c.s(60), unten + c.s(18)}, c.f.sch.t13, th.f.Leise, 0)
	schreiben(c.hdc, zeit(ende), rect{r.Right - c.s(60), unten + c.s(2), r.Right, unten + c.s(18)}, c.f.sch.t13, th.f.Leise, dtRight)
	if legende > 0 {
		x := l
		for i, ln := range linien {
			w := breite(c.hdc, ln.Name, c.f.sch.t13)
			if x+c.s(14)+w > r.Right {
				break
			}
			fuellen(c.hdc, rect{x, r.Bottom - c.s(11), x + c.s(10), r.Bottom - c.s(8)}, graphFarbe(i))
			schreiben(c.hdc, ln.Name, rect{x + c.s(14), r.Bottom - legende, x + c.s(14) + w + 1, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
			x += c.s(14) + w + c.s(14)
		}
	}
}

func (c *widgetCtx) sonne() {
	// Baum des Widgets: fester Mandant mit Untermandanten, sonst der Bereich
	var wurzel *desktop.Knoten
	if c.w.MandantID != "" {
		if b := desktop.BaumBauen(desktop.BereichStand(c.st, c.w.MandantID, true)); len(b) > 0 {
			wurzel = b[0]
		}
	} else if len(a.baum) > 0 {
		wurzel = a.baum[0]
	}
	if wurzel == nil {
		c.hinweis("Lädt …")
		return
	}
	r := c.r
	n := min(r.Right-r.Left, r.Bottom-r.Top)
	if n < c.s(80) {
		return
	}
	if dash.sonnen == nil {
		dash.sonnen = map[string]*dashSonne{}
	}
	s := dash.sonnen[c.w.ID]
	if s == nil {
		s = &dashSonne{}
		dash.sonnen[c.w.ID] = s
	}
	sig := c.w.MandantID + "|" + c.f.mandant + "|" + strconv.FormatBool(c.f.mitUnter) + "|" + c.st.Zeit.String() + "|" + itoa(int(n)) + "|" +
		strconv.FormatBool(th.dunkel)
	if s.sig != sig || s.bild.h == 0 {
		if s.bild.h != 0 {
			pDeleteObject.Call(s.bild.h)
		}
		s.seg, s.ring = desktop.Sonne(wurzel)
		s.bild = c.f.sonneRendern(c.hdc, wurzel, s.seg, s.ring, n)
		s.sig, s.wurzel = sig, wurzel
	}
	s.cx, s.cy, s.n = (r.Left+r.Right)/2, (r.Top+r.Bottom)/2, n
	mem, _, _ := pCreateCompatibleDC.Call(c.hdc)
	alt, _, _ := pSelectObject.Call(mem, s.bild.h)
	pBitBlt.Call(c.hdc, uintptr(s.cx-n/2), uintptr(s.cy-n/2), uintptr(n), uintptr(n), mem, 0, 0, srcCopy)
	pSelectObject.Call(mem, alt)
	pDeleteDC.Call(mem)
	c.ziel(rect{s.cx - n/2, s.cy - n/2, s.cx + n/2, s.cy + n/2}, "sonne", c.w.ID)
}

func (c *widgetCtx) ereignisse() {
	if c.fehlt("ereignisse", c.d.Alarme != nil || c.d.Fehler["ereignisse"] == "") {
		return
	}
	liste := desktop.Ereignisse(c.d.Alarme, c.ids, c.jetzt)
	if len(liste) == 0 {
		c.hinweis("Keine Ereignisse in den letzten 4 Stunden.")
		return
	}
	zw := c.s(84)
	c.zeilen(len(liste), c.s(26), c.r.Top, func(i int, r rect) {
		e := liste[i]
		st := e.Status
		var kenn *desktop.Kennfarbe
		if st == "bestaetigt" {
			st = "pause"
		} else {
			kenn = e.Alarm.Kennfarbe
		}
		c.formPunkt(st, kenn, r.Left, r.Top, r.Bottom-r.Top)
		x := r.Left + c.s(20)
		schreiben(c.hdc, desktop.VorZeit(e.Zeit, c.jetzt), rect{x, r.Top, x + zw, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		x += zw
		w := min(breite(c.hdc, e.Alarm.Name, c.f.sch.t13), (r.Right-x)*70/100)
		schreiben(c.hdc, e.Alarm.Name, rect{x, r.Top, x + w + 1, r.Bottom}, c.f.sch.t13, th.f.Tinte, 0)
		schreiben(c.hdc, e.Text, rect{x + w + c.s(6), r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
	})
}

func (c *widgetCtx) zertifikate() {
	liste := desktop.Zertifikate(c.st.Checks, c.ids, c.jetzt)
	if len(liste) == 0 {
		c.hinweis("Keine Sensoren „TLS-Zertifikat“ im Bereich.")
		return
	}
	namen := map[string]string{}
	for _, g := range c.st.Geraete {
		namen[g.ID] = g.Name
	}
	c.zeilen(len(liste), c.s(26), c.r.Top, func(i int, r rect) {
		z := liste[i]
		c.formPunkt(z.Stand, nil, r.Left, r.Top, r.Bottom-r.Top)
		x := r.Left + c.s(20)
		rest := z.RestText()
		fg := th.f.Tinte
		switch {
		case z.Rest != nil && *z.Rest < 0:
			fg = th.f.TextKrit
		case z.Rest != nil && *z.Rest <= 14:
			fg = th.f.TextWarn
		}
		tw := breite(c.hdc, rest, c.f.sch.t13) + c.s(8)
		w := c.link(z.Check.Name, z.Check.GeraetID, rect{x, r.Top, r.Right - tw - c.s(8), r.Bottom}, c.f.sch.t13b)
		schreiben(c.hdc, namen[z.Check.GeraetID], rect{x + w + c.s(6), r.Top, r.Right - tw, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		schreiben(c.hdc, rest, rect{r.Right - tw, r.Top, r.Right, r.Bottom}, c.f.sch.t13, fg, dtRight)
	})
}

func (c *widgetCtx) wartung() {
	if c.fehlt("wartung", true) {
		return
	}
	w := c.d.Wartungen.ImBereich(c.ids)
	type zeile struct {
		laeuft     bool
		name, rest string
		bis        string
	}
	var liste []zeile
	for _, l := range w.Laufend {
		liste = append(liste, zeile{true, l.Ziel(), l.Grund, "bis " + l.Bis.Local().Format("02.01. 15:04")})
	}
	var kommend []desktop.WartungFenster
	for _, f := range w.Fenster {
		if f.Aktiv && len(f.Naechstes) == 2 {
			kommend = append(kommend, f)
		}
	}
	sort.SliceStable(kommend, func(i, j int) bool { return kommend[i].Naechstes[0].Before(kommend[j].Naechstes[0]) })
	for _, f := range kommend {
		liste = append(liste, zeile{false, f.Name, f.ZielName, "ab " + f.Naechstes[0].Local().Format("02.01. 15:04")})
	}
	if len(liste) == 0 {
		c.hinweis("Keine laufende und keine geplante Wartung.")
		return
	}
	c.zeilen(len(liste), c.s(26), c.r.Top, func(i int, r rect) {
		z := liste[i]
		st := "pause"
		if z.laeuft {
			st = "wartung"
		}
		c.formPunkt(st, nil, r.Left, r.Top, r.Bottom-r.Top)
		x := r.Left + c.s(20)
		tw := breite(c.hdc, z.bis, c.f.sch.t13) + c.s(8)
		w := min(breite(c.hdc, z.name, c.f.sch.t13b), r.Right-tw-x-c.s(8))
		schreiben(c.hdc, z.name, rect{x, r.Top, x + w + 1, r.Bottom}, c.f.sch.t13b, th.f.Tinte, 0)
		schreiben(c.hdc, z.rest, rect{x + w + c.s(6), r.Top, r.Right - tw, r.Bottom}, c.f.sch.t13, th.f.Leise, 0)
		schreiben(c.hdc, z.bis, rect{r.Right - tw, r.Top, r.Right, r.Bottom}, c.f.sch.t13, th.f.Leise, dtRight)
	})
}

func (c *widgetCtx) sensor() {
	if c.w.Sensor == "" {
		c.hinweis("Noch kein Sensor gewählt: „Anpassen“ › „Ändern“ › Einstellungen.")
		return
	}
	var s *desktop.Sensor
	for i := range c.st.Sensoren {
		if c.st.Sensoren[i].Schluessel == c.w.Sensor {
			s = &c.st.Sensoren[i]
		}
	}
	if s == nil {
		c.hinweis("Diesen Sensor gibt es nicht mehr, oder er ist für dich nicht sichtbar.")
		return
	}
	status, wort := s.Status, desktop.StatusText(s.Status)
	if s.Alarm != nil && s.Alarm.Bestaetigt != nil && status == "crit" {
		status, wort = "bestaetigt", "Bestätigt"
	}
	r := c.r
	teile := c.s(24) + c.s(8) + c.s(22) + c.s(20)
	if s.Seit != nil {
		teile += c.s(18)
	}
	y := max(r.Top, (r.Top+r.Bottom-teile)/2)
	mw := c.f.zustandsMarke(c.hdc, status, wort, 0, 0, false)
	c.f.zustandsMarke(c.hdc, status, wort, (r.Left+r.Right-mw)/2, y, true)
	y += c.s(24) + c.s(8)
	titel := s.Name
	if s.Host != "" {
		titel = s.Host + " · " + s.Name
	}
	tw := min(breite(c.hdc, titel, c.f.sch.t16b), r.Right-r.Left)
	tr := rect{(r.Left + r.Right - tw) / 2, y, (r.Left+r.Right-tw)/2 + tw + 1, y + c.s(22)}
	fg := th.f.Tinte
	if c.ziel(tr, "geraet", s.GeraetID) {
		fg = th.f.Marke
	}
	schreiben(c.hdc, titel, tr, c.f.sch.t16b, fg, 0)
	y += c.s(22)
	schreiben(c.hdc, s.Meldung, rect{r.Left, y, r.Right, y + c.s(20)}, c.f.sch.t13, th.f.Tinte, dtCenter)
	y += c.s(20)
	if s.Seit != nil {
		schreiben(c.hdc, "seit "+desktop.VorZeit(*s.Seit, c.jetzt), rect{r.Left, y, r.Right, y + c.s(18)}, c.f.sch.t13, th.f.Leise, dtCenter)
	}
}

var wochentage = []string{"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"}
var monate = []string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}

func (c *widgetCtx) uhr() {
	r := c.r
	t := c.jetzt
	zeit := t.Format("15:04")
	font := c.f.sch.t25b
	if r.Right-r.Left < breite(c.hdc, zeit, font) {
		font = c.f.sch.t16b
	}
	mitte := (r.Top + r.Bottom) / 2
	schreiben(c.hdc, zeit, rect{r.Left, mitte - c.s(30), r.Right, mitte + c.s(4)}, font, th.f.Tinte, dtCenter)
	datum := wochentage[t.Weekday()] + ", " + itoa(t.Day()) + ". " + monate[t.Month()-1] + " " + itoa(t.Year())
	if breite(c.hdc, datum, c.f.sch.t13) > r.Right-r.Left {
		datum = t.Format("02.01.2006")
	}
	schreiben(c.hdc, datum, rect{r.Left, mitte + c.s(6), r.Right, mitte + c.s(24)}, c.f.sch.t13, th.f.Leise, dtCenter)
}

// --- Klicks ----------------------------------------------------------------------

func dashKlick(z ziel, daten any) {
	f := a.f
	d, ok := daten.(*desktop.DashDaten)
	if !ok {
		return
	}
	l := d.Layout
	seite := dashSeite(l)
	namen := l.SeitenNamen()
	zuSeite := func(n int) {
		a.cfg.DashSeite = n
		a.cfgSpeichern()
		f.seitenOff = 0
	}
	switch z.art {
	case "geraet":
		if f.eintrag("d:"+z.wert) != nil {
			a.geraetOeffnen("d:" + z.wert)
		} else {
			a.hostOeffnen(z.wert)
		}
	case "nav-hosts":
		a.seiteWechseln(seiteHosts)
	case "nav-alarme":
		a.seiteWechseln(seiteAlarme)
	case "sonne":
		s := dash.sonnen[z.wert]
		if s == nil || s.n == 0 {
			return
		}
		k := 1000 / float64(s.n)
		if i := desktop.SonnenTreffer(s.seg, s.ring, float64(f.klickX-s.cx)*k, float64(f.klickY-s.cy)*k); i >= 0 {
			kn := s.seg[i].Knoten
			if kn.Art == desktop.KnotenGeraet {
				dashKlick(ziel{art: "geraet", wert: kn.ID}, daten)
			}
		}
	case "seite":
		n, _ := strconv.Atoi(z.wert)
		zuSeite(n)
	case "fenster":
		a.cfg.DashFenster = !a.cfg.DashFenster
		a.cfgSpeichern()
		f.seitenOff = 0
	case "anpassen":
		dash.mu.Lock()
		dash.bearb = true
		kopie := l
		dash.lokal = &kopie
		dash.mu.Unlock()
	case "fertig":
		dash.mu.Lock()
		dash.bearb = false
		if dash.speichert == 0 {
			dash.lokal = nil
		}
		dash.mu.Unlock()
	case "standard":
		if !bestaetigenDialog(f.hwnd, "Standard wiederherstellen?", "Alle Seiten und Widgets deines Dashboards gehen verloren.",
			"Standard wiederherstellen") {
			return
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.DashZuruecksetzen(ctx) }, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Dashboard", "Zurücksetzen fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			dash.mu.Lock()
			dash.lokal, dash.bearb = nil, false
			dash.mu.Unlock()
			zuSeite(0)
			setStatusText(f, "Standard wiederhergestellt.")
			a.seiteNeu(seiteDashboard)
		})
	case "seite-neu":
		name, ok := textDialog("Neue Seite", "Name der Seite", "Seite "+itoa(len(namen)+1), "Anlegen")
		if !ok {
			return
		}
		l.Seiten = append(append([]string{}, namen...), kuerzen(name, 40))
		zuSeite(len(l.Seiten) - 1)
		dashAendern(d, l, "Seite angelegt.")
	case "seite-name":
		name, ok := textDialog("Seite umbenennen", "Name der Seite", namen[seite], "Umbenennen")
		if !ok {
			return
		}
		l.Seiten = append([]string{}, namen...)
		l.Seiten[seite] = kuerzen(name, 40)
		dashAendern(d, l, "Seite umbenannt.")
	case "seite-weg":
		n := len(l.AufSeite(seite))
		text := "Die Seite ist leer."
		if n > 0 {
			text = "Ihre " + itoa(n) + " Widgets gehen verloren."
			if n == 1 {
				text = "Ihr Widget geht verloren."
			}
		}
		if !bestaetigenDialog(f.hwnd, "Seite „"+namen[seite]+"“ löschen?", text, "Seite löschen") {
			return
		}
		l.Widgets = desktop.SeiteLoeschen(l.Widgets, seite)
		l.Seiten = append(append([]string{}, namen[:seite]...), namen[seite+1:]...)
		if len(l.Seiten) == 1 && l.Seiten[0] == "Übersicht" {
			l.Seiten = nil
		}
		zuSeite(0)
		dashAendern(d, l, "Seite gelöscht.")
	case "neu":
		texte := make([]string, len(desktop.WidgetArten))
		for i, art := range desktop.WidgetArten {
			texte[i] = art.Titel + " – " + art.Text
		}
		i := a.listeWaehlen(z, texte, -1)
		if i < 0 {
			return
		}
		art := desktop.WidgetArten[i]
		w := desktop.Widget{ID: desktop.NeueWidgetID(l.Widgets, func(b []byte) { _, _ = rand.Read(b) }), Typ: art.Typ, Breite: art.Breite,
			Hoehe: art.Hoehe, Seite: seite}
		if art.Typ == "notiz" || art.Typ == "sensor" {
			neu, ok := widgetDialog(w, l, true)
			if !ok {
				return
			}
			w = neu
		}
		l.Widgets = append(append([]desktop.Widget{}, l.Widgets...), w)
		dashAendern(d, l, art.Titel+" hinzugefügt.")
	case "aendern":
		pos := -1
		for i, w := range l.Widgets {
			if w.ID == z.wert {
				pos = i
			}
		}
		if pos < 0 {
			return
		}
		w := l.Widgets[pos]
		auf := l.AufSeite(seite)
		vor, hinter := -1, -1
		for i, j := range auf {
			if j == pos {
				if i > 0 {
					vor = auf[i-1]
				}
				if i < len(auf)-1 {
					hinter = auf[i+1]
				}
			}
		}
		e := []listenEintrag{{text: "Einstellungen …", an: true}, {text: "Nach vorn", an: vor >= 0}, {text: "Nach hinten", an: hinter >= 0},
			{text: "Breiter", an: w.Breite < desktop.DashSpalten}, {text: "Schmaler", an: w.Breite > desktop.DashMinBreite},
			{text: "Höher", an: w.Hoehe < desktop.DashMaxHoehe}, {text: "Niedriger", an: w.Hoehe > 1},
			{text: "Verdoppeln", an: len(l.Widgets) < desktop.DashMaxWidgets}, {text: "Entfernen", an: true}}
		p := point{z.r.Left, z.r.Bottom + f.s(4)}
		pClientToScreen.Call(uintptr(f.seitenF), ptr(&p))
		ws := append([]desktop.Widget{}, l.Widgets...)
		titel := w.TitelVon(nil)
		switch schwebend(f.hwnd, e, p, f.s(180), false) {
		case 0:
			neu, ok := widgetDialog(w, l, false)
			if !ok {
				return
			}
			ws[pos] = neu
			l.Widgets = ws
			dashAendern(d, l, "Einstellungen übernommen.")
		case 1:
			l.Widgets = desktop.Verschieben(ws, pos, vor)
			dashAendern(d, l, titel+" nach vorn.")
		case 2:
			l.Widgets = desktop.Verschieben(ws, pos, hinter)
			dashAendern(d, l, titel+" nach hinten.")
		case 3:
			ws[pos].Breite++
			l.Widgets = ws
			dashAendern(d, l, titel+": "+itoa(ws[pos].Breite)+" Spalten.")
		case 4:
			ws[pos].Breite--
			l.Widgets = ws
			dashAendern(d, l, titel+": "+itoa(ws[pos].Breite)+" Spalten.")
		case 5:
			ws[pos].Hoehe++
			l.Widgets = ws
			dashAendern(d, l, titel+": "+itoa(ws[pos].Hoehe)+" Reihen.")
		case 6:
			ws[pos].Hoehe--
			l.Widgets = ws
			dashAendern(d, l, titel+": "+itoa(ws[pos].Hoehe)+" Reihen.")
		case 7:
			kopie := w
			kopie.ID = desktop.NeueWidgetID(ws, func(b []byte) { _, _ = rand.Read(b) })
			l.Widgets = append(ws[:pos+1], append([]desktop.Widget{kopie}, ws[pos+1:]...)...)
			dashAendern(d, l, titel+" verdoppelt.")
		case 8:
			l.Widgets = append(ws[:pos], ws[pos+1:]...)
			dashAendern(d, l, titel+" entfernt.")
		}
	}
}

func kuerzen(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// widgetDialog: Titel, Größe, Seite, Mandant und Inhalt eines Widgets.
func widgetDialog(w desktop.Widget, l desktop.DashLayout, neu bool) (desktop.Widget, bool) {
	f := a.f
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	art, _ := desktop.WidgetArtVon(w.Typ)
	d := neuerDialog(f.hwnd, "Einstellungen: "+art.Titel)
	d.okText = "Übernehmen"
	if neu {
		d.okText = "Hinzufügen"
	}
	d.werte["titel"], d.werte["breite"], d.werte["hoehe"], d.werte["seite"] = w.Titel, itoa(w.Breite), itoa(w.Hoehe), itoa(w.Seite)
	d.werte["mandant"], d.werte["geraet"], d.werte["text"], d.werte["sensor"] = w.MandantID, w.GeraetID, w.Text, w.Sensor
	d.werte["wert"], d.werte["zeitraum"] = "cpu", "24h"
	if w.Wert != "" {
		d.werte["wert"] = w.Wert
	}
	if w.Zeitraum != "" {
		d.werte["zeitraum"] = w.Zeitraum
	}
	ohneMandant := w.Typ == "uhr" || w.Typ == "notiz" || w.Typ == "sensor"
	d.aufbau = func(d *dialog) {
		d.feld("titel", "Titel (leer = „"+art.Titel+"“)", desktop.FeldText, "")
		var bt, bw, ht, hw []string
		for n := desktop.DashMinBreite; n <= desktop.DashSpalten; n++ {
			zusatz := map[int]string{12: " (ganze Breite)", 6: " (halbe Breite)", 4: " (ein Drittel)", 3: " (ein Viertel)"}[n]
			bt, bw = append(bt, itoa(n)+" Spalten"+zusatz), append(bw, itoa(n))
		}
		for n := 1; n <= desktop.DashMaxHoehe; n++ {
			ht, hw = append(ht, itoa(n)+map[bool]string{true: " Reihe", false: " Reihen"}[n == 1]), append(hw, itoa(n))
		}
		d.auswahl("breite", "Breite", bt, bw, "").halb = true
		d.auswahl("hoehe", "Höhe", ht, hw, "").halb = true
		if namen := l.SeitenNamen(); len(namen) > 1 {
			var sw []string
			for i := range namen {
				sw = append(sw, itoa(i))
			}
			d.auswahl("seite", "Seite", namen, sw, "")
		}
		switch w.Typ {
		case "notiz":
			d.feld("text", "Text (höchstens 500 Zeichen)", desktop.FeldMehrzeilig, "")
		case "sensor":
			type wahl struct{ text, wert string }
			var liste []wahl
			for _, s := range st.Sensoren {
				t := s.Name
				if s.Host != "" {
					t = s.Host + " · " + s.Name
				}
				liste = append(liste, wahl{t, s.Schluessel})
			}
			sort.SliceStable(liste, func(i, j int) bool { return strings.ToLower(liste[i].text) < strings.ToLower(liste[j].text) })
			var t, v []string
			for _, x := range liste {
				t, v = append(t, x.text), append(v, x.wert)
			}
			d.auswahl("sensor", "Sensor", t, v, "")
		case "graph":
			d.auswahl("wert", "Wert", []string{"CPU-Auslastung", "Arbeitsspeicher belegt"}, []string{"cpu", "speicher"}, "").halb = true
			d.auswahl("zeitraum", "Zeitraum", []string{"1 Std.", "24 Std.", "7 Tage", "30 Tage"}, []string{"1h", "24h", "7t", "30t"}, "").halb = true
			t, v := []string{"die höchsten im Bereich"}, []string{""}
			ger := append([]desktop.Geraet{}, st.Geraete...)
			sort.SliceStable(ger, func(i, j int) bool { return strings.ToLower(ger[i].Name) < strings.ToLower(ger[j].Name) })
			for _, g := range ger {
				if (g.AgentID != nil && *g.AgentID != "") || (g.SNMPID != nil && *g.SNMPID != "") {
					t, v = append(t, g.Name+" ("+a.mandantName(g.MandantID)+")"), append(v, g.ID)
				}
			}
			d.auswahl("geraet", "Gerät", t, v, "Mit Gerät zeigt der Graph immer dieses Gerät, egal welcher Mandant gewählt ist.")
		}
		if !ohneMandant {
			t, v := []string{"wie in der Seitenleiste"}, []string{""}
			for _, z := range desktop.MandantenReihe(st.Mandanten) {
				t, v = append(t, strings.Repeat("   ", z.Tiefe)+z.Mandant.Name), append(v, z.Mandant.ID)
			}
			d.auswahl("mandant", "Mandant", t, v, "Ein fester Mandant zeigt ihn mit allen Untermandanten.")
		}
	}
	out := w
	d.speichern = func(d *dialog, fertig func(error)) {
		out.Titel = kuerzen(d.werte["titel"], 60)
		out.Breite, _ = strconv.Atoi(d.werte["breite"])
		out.Hoehe, _ = strconv.Atoi(d.werte["hoehe"])
		out.Seite, _ = strconv.Atoi(d.werte["seite"])
		out.MandantID, out.GeraetID, out.Wert, out.Zeitraum = "", "", "", ""
		switch w.Typ {
		case "notiz":
			out.Text = strings.ReplaceAll(d.werte["text"], "\r\n", "\n")
			if len([]rune(out.Text)) > 500 {
				d.fehlerFeld = "text"
				fertig(errText("Höchstens 500 Zeichen."))
				return
			}
		case "sensor":
			out.Sensor = d.werte["sensor"]
			if out.Sensor == "" {
				d.fehlerFeld = "sensor"
				fertig(errText("Bitte einen Sensor wählen."))
				return
			}
		case "graph":
			out.Wert, out.Zeitraum, out.GeraetID = d.werte["wert"], d.werte["zeitraum"], d.werte["geraet"]
		}
		if !ohneMandant && out.GeraetID == "" {
			out.MandantID = d.werte["mandant"]
		}
		out = out.Normal(len(l.SeitenNamen()))
		fertig(nil)
	}
	return out, d.zeigen()
}
