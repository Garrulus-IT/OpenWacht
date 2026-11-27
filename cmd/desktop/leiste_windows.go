// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seitenleiste wie im Web (.leiste in web/src/styles.css): Wortmarke,
// Mandantenwahl mit „mit Untermandanten“, die Gruppen Überwachen, Einrichten
// und Verwaltung mit den Piktogrammen der Weboberfläche, unten Token,
// Verbindung, Darstellung und Abmelden. Punkte ohne eigene Seite in der App
// tragen einen Pfeil und öffnen die Seite im Browser.

import (
	"strings"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
	"github.com/garrulus-it/openwacht/internal/version"
)

type navPunkt struct {
	id, text string
	seite    int    // -1 = im Browser
	pfad     string // Pfad der Weboberfläche (web/src/navigation.ts)
}

// nativ: Seite der App (sonst öffnet der Punkt den Browser).
func (p navPunkt) nativ() bool {
	return p.seite >= 0 && (p.seite <= seiteWartung || seiten[p.seite] != nil)
}

var navGruppen = []struct {
	titel  string
	punkte []navPunkt
}{
	{"Überwachen", []navPunkt{
		{"dashboard", "Dashboard", seiteDashboard, "/"},
		{"hosts", "Hosts", seiteHosts, "/hosts"},
		{"topologie", "Topologie", seiteTopologie, "/topologie"},
		{"zertifikate", "Zertifikate", seiteZertifikate, "/zertifikate"},
		{"alarme", "Alarme", seiteAlarme, "/alarme"},
		{"berichte", "Berichte", seiteBerichte, "/berichte"},
	}},
	{"Einrichten", []navPunkt{
		{"vorlagen", "Sensor-Vorlagen", seiteVorlagen, "/sensor-vorlagen"},
		{"snmpprofile", "SNMP-Profile", seiteSNMP, "/snmp-profile"},
		{"anzeigen", "Wandanzeigen", seiteWandanzeigen, "/wandanzeigen"},
		{"wartung", "Wartung", seiteWartung, "/wartung"},
	}},
	{"Verwaltung", []navPunkt{
		{"verwaltung", "Benutzer und Mandanten", seiteVerwaltung, "/verwaltung"},
	}},
}

var darstellungen = []struct{ wert, text string }{{"", "wie System"}, {"hell", "Hell"}, {"dunkel", "Dunkel"}}

func darstellungText(w string) string {
	for _, d := range darstellungen {
		if d.wert == w {
			return d.text
		}
	}
	return "wie System"
}

// seitePfad: Pfad der aktuellen Seite im Web (für „Im Browser öffnen“).
func (f *fenster) seitePfad() string {
	for _, g := range navGruppen {
		for _, p := range g.punkte {
			if p.seite == f.seite {
				return p.pfad
			}
		}
	}
	return "/"
}

func (f *fenster) leisteScrollen(d int32) {
	var r rect
	pGetClientRect.Call(uintptr(f.leiste), uintptr(unsafe.Pointer(&r)))
	f.leisteOff = max(min(f.leisteOff+d, f.leisteHoehe-r.Bottom), 0)
	pInvalidateRect.Call(uintptr(f.leiste), 0, 0)
}

// auswahlFeld: Feld wie select im Web (Rand --linie, Grund --grund, Winkel rechts).
func (f *fenster) auswahlFeld(hdc uintptr, r rect, text string, hover bool) {
	rand := th.f.Linie
	if hover {
		rand = th.f.Leise
	}
	rund(hdc, r, f.s(3), th.f.Grund, rand, true, true, false)
	schreiben(hdc, text, rect{r.Left + f.s(8), r.Top, r.Right - f.s(28), r.Bottom}, f.sch.t13, th.f.Tinte, 0)
	chevron(hdc, r.Right-f.s(14), (r.Top+r.Bottom)/2, f.s(4), true, th.f.Leise)
}

func (a *app) leisteMalen(hdc uintptr, r rect) {
	f := a.f
	fuellen(hdc, r, th.f.Flaeche)
	a.mu.Lock()
	st, fehler, zentrale := a.stand, a.standFehler, a.client.Zentrale
	a.mu.Unlock()
	f.leisteZiele = f.leisteZiele[:0]
	ziel := func(rr rect, art, wert string) bool {
		f.leisteZiele = append(f.leisteZiele, ziel{rr, art, wert})
		return len(f.leisteZiele)-1 == f.leisteUeber
	}
	links, rechts := f.s(8), r.Right-f.s(8)
	y := f.s(12) - f.leisteOff

	// Marke: Bildzeichen und Wortmarke („Open“ fett, „Wacht“ normal)
	n := f.s(38)
	mh := f.s(40)
	alpha(hdc, f.logo, links+f.s(8), y+(mh-f.logo.y)/2)
	x := links + f.s(8) + n + f.s(8)
	w := breite(hdc, "Open", f.sch.t20b)
	schreiben(hdc, "Open", rect{x, y, x + w + 1, y + mh}, f.sch.t20b, th.f.Tinte, 0)
	schreiben(hdc, "Wacht", rect{x + w, y, rechts, y + mh}, f.sch.t20, th.f.Tinte, 0)
	y += mh + f.s(4) + f.s(8)

	// Mandant
	reihe := desktop.MandantenReihe(st.Mandanten)
	if len(reihe) > 0 {
		ix := links + f.s(8)
		schreiben(hdc, "Mandant", rect{ix, y, rechts, y + f.s(18)}, f.sch.t13, th.f.Leise, 0)
		y += f.s(18) + f.s(4)
		name := ""
		for _, z := range reihe {
			if z.Mandant.ID == f.mandant {
				name = z.Mandant.Name
			}
		}
		fr := rect{ix, y, rechts - f.s(8), y + f.s(36)}
		f.auswahlFeld(hdc, fr, name, ziel(fr, "mandant", ""))
		y += f.s(36) + f.s(8)
		if desktop.HatUntermandanten(st.Mandanten, f.mandant) {
			kr := rect{ix, y, rechts - f.s(8), y + f.s(24)}
			hover := ziel(kr, "unter", "")
			k := rect{ix, y + f.s(4), ix + f.s(16), y + f.s(20)}
			switch {
			case f.mitUnter:
				rund(hdc, k, f.s(3), th.f.Marke, th.f.Marke, true, true, false)
				haken(hdc, k, th.f.AufMarke, f.s(2))
			case hover:
				rund(hdc, k, f.s(3), th.f.Flaeche, th.f.Tinte, true, true, false)
			default:
				rund(hdc, k, f.s(3), th.f.Flaeche, th.f.Leise, true, true, false)
			}
			schreiben(hdc, "mit Untermandanten", rect{k.Right + f.s(8), y, kr.Right, kr.Bottom}, f.sch.t13, th.f.Leise, 0)
			y += f.s(24) + f.s(8)
		}
		waagrecht(hdc, links, rechts, y, th.f.LinieZart)
		y += f.s(4)
	}

	// Navigation
	for _, g := range navGruppen {
		y += f.s(12)
		t := strings.ToUpper(g.titel)
		pSetTextCharacterExtra.Call(hdc, uintptr(f.s(1)))
		schreiben(hdc, t, rect{links + f.s(12), y, rechts, y + f.s(18)}, f.sch.t13b, th.f.Leise, 0)
		pSetTextCharacterExtra.Call(hdc, 0)
		y += f.s(18) + f.s(4)
		for _, p := range g.punkte {
			pr := rect{links, y, rechts, y + f.s(36)}
			art := "nav"
			if !p.nativ() {
				art = "extern"
			}
			hover := ziel(pr, art, p.id)
			aktiv := p.nativ() && p.seite == f.seite
			fg, font := th.f.Tinte, f.sch.t16
			switch {
			case aktiv:
				rund(hdc, pr, f.s(6), th.f.MarkeHauch, th.f.MarkeHauch, true, false, false)
				fuellen(hdc, rect{pr.Left, pr.Top + f.s(2), pr.Left + f.s(3), pr.Bottom - f.s(2)}, th.f.Marke)
				fg, font = th.f.MarkeTief, f.sch.t16b
			case hover:
				rund(hdc, pr, f.s(6), th.f.Zart, th.f.Zart, true, false, false)
			}
			in := f.s(20)
			piktogramm(hdc, p.id, fg, pr.Left+f.s(8), (pr.Top+pr.Bottom-in)/2, in)
			tx := pr.Left + f.s(8) + in + f.s(8)
			tr := pr.Right - f.s(8)
			if !p.nativ() {
				e := f.s(14)
				farbe := th.f.Leise
				if hover {
					farbe = th.f.Tinte
				}
				piktogramm(hdc, "extern", farbe, tr-e, (pr.Top+pr.Bottom-e)/2, e)
				tr -= e + f.s(8)
			}
			schreiben(hdc, p.text, rect{tx, pr.Top, tr, pr.Bottom}, font, fg, 0)
			y += f.s(36) + f.s(2)
		}
	}

	// Fuß: unten angeschlagen, bei wenig Platz unter der Navigation
	fussH := f.s(8) + f.s(24) + f.s(4) + f.s(18) + f.s(8) + f.s(18) + f.s(12) + f.s(18) + f.s(4) + f.s(36) + f.s(12) +
		f.s(32) + f.s(8) + f.s(18) + f.s(12)
	fy := max(y+f.s(16), r.Bottom-fussH)
	f.leisteHoehe = fy + fussH + f.leisteOff
	y = fy
	waagrecht(hdc, links, rechts, y, th.f.LinieZart)
	y += f.s(8)
	ix := links + f.s(8)
	rolle := ""
	for _, m := range st.Mandanten {
		if m.ID == f.mandant {
			rolle = map[string]string{"leser": "Leser", "operator": "Operator", "admin": "Admin"}[m.Rolle]
		}
	}
	in := f.s(20)
	piktogramm(hdc, "person", th.f.Tinte, ix, y+(f.s(24)-in)/2, in)
	wer := "API-Token"
	if a.cfg.MitKonto() && a.cfg.Email != "" {
		wer = a.cfg.Email
	}
	if rolle != "" {
		wer += " · " + rolle
	}
	schreiben(hdc, wer, rect{ix + in + f.s(8), y, rechts, y + f.s(24)}, f.sch.t16, th.f.Tinte, 0)
	y += f.s(24) + f.s(4)
	schreiben(hdc, strings.TrimPrefix(zentrale, "https://"), rect{ix, y, rechts, y + f.s(18)}, f.sch.t13, th.f.Leise, 0)
	y += f.s(18) + f.s(8)
	var an desktop.Anzeige
	zeile := ""
	switch {
	case fehler != "":
		an, zeile = th.f.AnzeigeFuer("crit"), "Keine Verbindung"
	case st.Zeit.IsZero():
		an, zeile = th.f.AnzeigeFuer(""), "Verbinde …"
	default:
		an, zeile = th.f.AnzeigeFuer("ok"), "Verbunden · Stand "+st.Zeit.Local().Format("15:04")
	}
	form(hdc, an.Form, an.Farbe, ix, y+(f.s(18)-f.s(12))/2, f.s(12))
	schreiben(hdc, zeile, rect{ix + f.s(12) + f.s(8), y, rechts, y + f.s(18)}, f.sch.t13, th.f.Leise, 0)
	y += f.s(18) + f.s(12)
	schreiben(hdc, "Darstellung", rect{ix, y, rechts, y + f.s(18)}, f.sch.t13, th.f.Leise, 0)
	y += f.s(18) + f.s(4)
	dr := rect{ix, y, rechts - f.s(8), y + f.s(36)}
	f.auswahlFeld(hdc, dr, darstellungText(a.cfg.Darstellung), ziel(dr, "thema", ""))
	y += f.s(36) + f.s(12)
	bw := breite(hdc, "Abmelden", f.sch.t13) + 2*f.s(16)
	br := rect{ix, y, ix + bw, y + f.s(32)}
	knopfMalen(f, hdc, knopf{text: "Abmelden", an: true, r: br}, ziel(br, "abmelden", ""), false)
	y += f.s(32) + f.s(8)
	schreiben(hdc, "OpenWacht Desktop "+version.Version, rect{ix, y, rechts, y + f.s(18)}, f.sch.t13, th.f.Leise, 0)
}

func (a *app) leisteKlick(z ziel) {
	f := a.f
	switch z.art {
	case "nav":
		for _, g := range navGruppen {
			for _, p := range g.punkte {
				if p.id == z.wert {
					a.seiteWechseln(p.seite)
				}
			}
		}
	case "extern":
		for _, g := range navGruppen {
			for _, p := range g.punkte {
				if p.id == z.wert {
					a.oeffnen(desktop.WebPfad(p.pfad, f.mandant, f.mitUnter))
				}
			}
		}
	case "unter":
		f.mitUnter = !f.mitUnter
		a.cfg.OhneUnter = !f.mitUnter
		a.cfgSpeichern()
		f.dashHost, f.sonnenKey = "", ""
		a.aktualisieren(true)
	case "mandant":
		a.mu.Lock()
		reihe := desktop.MandantenReihe(a.stand.Mandanten)
		a.mu.Unlock()
		e := make([]listenEintrag, len(reihe))
		for i, m := range reihe {
			e[i] = listenEintrag{text: strings.Repeat("    ", m.Tiefe) + m.Mandant.Name, an: true, gewaehlt: m.Mandant.ID == f.mandant}
		}
		if i := schwebend(f.hwnd, e, a.leistePunkt(z.r), z.r.Right-z.r.Left, false); i >= 0 && reihe[i].Mandant.ID != f.mandant {
			f.mandant = reihe[i].Mandant.ID
			a.cfg.Mandant = f.mandant
			a.cfgSpeichern()
			f.dashHost, f.sonnenKey, f.gewaehlt = "", "", ""
			a.aktualisieren(true)
		}
	case "thema":
		e := make([]listenEintrag, len(darstellungen))
		for i, d := range darstellungen {
			e[i] = listenEintrag{text: d.text, an: true, gewaehlt: d.wert == a.cfg.Darstellung}
		}
		if i := schwebend(f.hwnd, e, a.leistePunkt(z.r), z.r.Right-z.r.Left, false); i >= 0 {
			a.cfg.Darstellung = darstellungen[i].wert
			a.cfgSpeichern()
			if d := a.dunkel(); d != th.dunkel {
				themaSetzen(d)
				f.themaAnwenden()
			} else {
				pInvalidateRect.Call(uintptr(f.leiste), 0, 0)
			}
		}
	case "abmelden":
		a.abmelden()
	}
}

// leistePunkt: Bildschirmpunkt unter einem Feld der Leiste (für die Liste).
func (a *app) leistePunkt(r rect) point {
	p := point{r.Left, r.Bottom + a.f.s(4)}
	pClientToScreen.Call(uintptr(a.f.leiste), uintptr(unsafe.Pointer(&p)))
	return p
}

// dunkel: Darstellung nach Einstellung, sonst wie Windows.
func (a *app) dunkel() bool { return dunkelNach(a.cfg.Darstellung) }

func (a *app) cfgSpeichern() {
	if p, err := desktop.ConfigPath(); err == nil {
		if err := desktop.SaveConfig(p, a.cfg); err != nil {
			setStatusText(a.f, "Einstellung nicht gespeichert: "+err.Error())
		}
	}
}
