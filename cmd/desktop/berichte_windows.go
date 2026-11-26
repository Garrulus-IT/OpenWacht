// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Berichte wie web/src/Berichte.tsx: Monat wählen, Verfügbarkeit je
// Mandant und Gerät, Alarme, Kapazität; „Als PDF“ legt den Bericht in den
// Ordner Downloads und öffnet ihn; Admins setzen das SLA-Ziel.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

var bericht = struct{ monat string }{}

type berichtDaten struct {
	abfrage string
	b       desktop.Bericht
}

func init() {
	seiten[seiteBerichte] = &seitenDef{laden: berichtLaden, malen: berichtMalen, klick: berichtKlick}
}

func berichtMonat() string {
	if bericht.monat == "" {
		bericht.monat = desktop.Monate(time.Now())[1] // wie im Web: der letzte volle Monat
	}
	return bericht.monat
}

func berichtAbfrage(f *fenster) string {
	return desktop.BerichtAbfrage(f.mandant, berichtMonat(), f.mitUnter)
}

func berichtLaden(ctx context.Context, cl desktop.Client, f *fenster) (any, error) {
	q := berichtAbfrage(f)
	b, err := cl.BerichtHolen(ctx, q)
	return berichtDaten{q, b}, err
}

func berichtMalen(m *maler, daten any) {
	f := m.f
	m.titelGross("Bericht " + desktop.MonatName(berichtMonat()))
	l, _ := m.innen()
	y := m.y
	m.auswahlFeld("Monat", desktop.MonatName(berichtMonat()), "monat", m.s(220))
	// „Als PDF“ neben dem Monat
	if m.zeichnen {
		m.knopfMalen(sKnopf{text: "Als PDF", art: "pdf", stil: kHaupt}, l+m.s(232), y+m.s(21))
	}
	m.klein("Verfügbarkeit: Anteil der Zeit ohne offenen kritischen Alarm zu Ping, Agent oder Abfragequelle; Wartungen " +
		"zählen nicht als Ausfall. Den Bericht per Mail am Monatsanfang stellst du am Mail-Kanal ein (Alarme › Kanäle › " +
		"Bereitschaft und Eskalation, im Browser).")
	_, _, rolle := a.bereich()
	if rolle(f.mandant) == "admin" {
		m.knoepfe(sKnopf{text: "SLA-Ziel für " + a.mandantName(f.mandant) + " …", art: "sla"})
	}
	d, ok := daten.(berichtDaten)
	if !ok || d.abfrage != berichtAbfrage(f) {
		m.klein("Lädt …")
		return
	}
	b := d.b
	m.kennzahlen([2]string{"Geräte", itoa(len(b.Geraete))}, [2]string{"Alarme", itoa(b.Alarme)},
		[2]string{"davon kritisch", itoa(b.Kritisch)}, [2]string{"Platten bald voll", itoa(len(b.Prognose))})

	m.panel("Verfügbarkeit je Mandant")
	var tm [][]sZelle
	for _, t := range b.Mandanten {
		farbe := th.f.TextKrit
		if t.Erfuellt {
			farbe = th.f.TextOK
		}
		tm = append(tm, []sZelle{{text: t.Name}, {text: itoa(t.Geraete)}, {text: desktop.Prozent(t.Verfuegbarkeit), farbe: farbe},
			{text: desktop.Prozent(t.Ziel) + " " + map[bool]string{true: "erreicht", false: "verfehlt"}[t.Erfuellt]}})
	}
	m.tabelle([]sSpalte{{"Mandant", 40, false}, {"Geräte", 15, false}, {"Verfügbar", 20, false}, {"Ziel", 25, false}}, tm)
	m.ende()

	m.panel("Verfügbarkeit je Gerät")
	if len(b.Geraete) == 0 {
		m.leer("Keine Geräte.")
	} else {
		var tg [][]sZelle
		for _, g := range b.Geraete {
			farbe := th.f.TextKrit
			if g.Erfuellt {
				farbe = th.f.TextOK
			}
			ausfall := "–"
			if g.AusfallMinuten > 0 {
				ausfall = fmt.Sprintf("%s (%d×)", desktop.Dauer(g.AusfallMinuten), g.Ausfaelle)
			}
			tg = append(tg, []sZelle{{text: g.Name, fett: true, klein: g.Mandant}, {text: desktop.Prozent(g.Verfuegbarkeit), farbe: farbe},
				{text: ausfall}, {text: map[bool]string{true: "erreicht", false: "verfehlt"}[g.Erfuellt]}})
		}
		m.tabelle([]sSpalte{{"Gerät", 40, false}, {"Verfügbar", 20, false}, {"Ausfall", 25, false}, {"Ziel", 15, false}}, tg)
	}
	m.ende()

	m.panel("Alarme")
	m.text(fmt.Sprintf("%d Alarme begonnen, davon %d kritisch und %d Warnungen; %d bestätigt.", b.Alarme, b.Kritisch, b.Warnungen, b.Bestaetigt),
		f.sch.t13, th.f.Tinte)
	if len(b.Laengste) > 0 {
		var ta [][]sZelle
		for _, x := range b.Laengste {
			form := "warn"
			if x.Schwere == "crit" {
				form = "crit"
			}
			dauer := desktop.Dauer(x.Minuten)
			if x.Offen {
				dauer += " (offen)"
			}
			ta = append(ta, []sZelle{{form: form, text: x.Name, klein: x.Mandant}, {text: x.Beginn.Local().Format("02.01.06, 15:04")}, {text: dauer}})
		}
		m.tabelle([]sSpalte{{"Längste Alarme", 55, false}, {"Beginn", 25, false}, {"Dauer", 20, false}}, ta)
	}
	m.ende()

	m.panel("Kapazität")
	if len(b.Prognose) == 0 {
		m.leer("Keine Platte läuft in den nächsten 90 Tagen voll.")
	} else {
		for _, p := range b.Prognose {
			m.text(fmt.Sprintf("• %s · %s: %s %% belegt, voll in %d Tagen", p.Geraet, p.Platte,
				strings.Replace(fmt.Sprintf("%g", p.Belegt), ".", ",", 1), p.Tage), f.sch.t13, th.f.Tinte)
		}
	}
	m.ende()
}

func berichtKlick(z ziel, _ any) {
	f := a.f
	switch z.art {
	case "monat":
		ms := desktop.Monate(time.Now())
		texte := make([]string, len(ms))
		aktiv := 0
		for i, x := range ms {
			texte[i] = desktop.MonatName(x)
			if x == berichtMonat() {
				aktiv = i
			}
		}
		if i := a.listeWaehlen(z, texte, aktiv); i >= 0 && ms[i] != bericht.monat {
			bericht.monat = ms[i]
			a.seiteNeu(seiteBerichte)
		}
	case "pdf":
		q := berichtAbfrage(f)
		name := "OpenWacht-Bericht-" + berichtMonat() + "-" + dateiName(a.mandantName(f.mandant)) + ".pdf"
		setStatusText(f, "PDF wird erstellt …")
		var pfad string
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			b, err := cl.BerichtPDF(ctx, q)
			if err != nil {
				return err
			}
			pfad, err = downloadsSchreiben(name, b)
			return err
		}, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Bericht als PDF", "PDF fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			setStatusText(f, "PDF gespeichert: "+pfad)
			pShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16("open"))), uintptr(unsafe.Pointer(utf16(pfad))), 0, 0, swShowNormal)
		})
	case "sla":
		mandant := f.mandant
		d := neuerDialog(f.hwnd, "SLA-Ziel für "+a.mandantName(mandant))
		d.einleitung = "Ziel für die Verfügbarkeit in Prozent, zwischen 50 und 100. Leer: erbt vom übergeordneten Mandanten bzw. 99,5 %."
		d.aufbau = func(d *dialog) { d.feld("ziel", "SLA-Ziel in %", desktop.FeldText, "z. B. 99,5; leer = erben") }
		d.speichern = func(d *dialog, fertig func(error)) {
			ziel, err := desktop.ZielLesen(d.werte["ziel"])
			if err != nil {
				d.fehlerFeld = "ziel"
				fertig(err)
				return
			}
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.SLAZiel(ctx, mandant, ziel) }, fertig)
		}
		if d.zeigen() {
			setStatusText(f, "SLA-Ziel gespeichert.")
			a.seiteNeu(seiteBerichte)
		}
	}
}

// downloadsSchreiben legt eine Datei in den Ordner Downloads des Benutzers
// (gibt es ihn nicht, in den Ordner für temporäre Dateien); vorhandene
// Dateien werden nicht überschrieben, sondern nummeriert.
func downloadsSchreiben(name string, b []byte) (string, error) {
	dir := ""
	if h, err := os.UserHomeDir(); err == nil {
		if st, err := os.Stat(filepath.Join(h, "Downloads")); err == nil && st.IsDir() {
			dir = filepath.Join(h, "Downloads")
		}
	}
	if dir == "" {
		dir = os.TempDir()
	}
	basis, endung := strings.TrimSuffix(name, filepath.Ext(name)), filepath.Ext(name)
	for i := 1; i < 100; i++ {
		p := filepath.Join(dir, name)
		if i > 1 {
			p = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", basis, i, endung))
		}
		fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := fh.Write(b); err != nil {
			fh.Close()
			return "", err
		}
		return p, fh.Close()
	}
	return "", fmt.Errorf("Datei %s gibt es schon zu oft", name)
}

// dateiName: nur Zeichen, die in Dateinamen sicher sind.
func dateiName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '.':
			b.WriteRune('-')
		case strings.ContainsRune("äöüÄÖÜß", r):
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "Mandant"
	}
	return b.String()
}
