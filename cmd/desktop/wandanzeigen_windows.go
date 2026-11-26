// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Wandanzeigen wie AnzeigenListe in web/src/Verwaltung.tsx: Anzeigen
// mit Mandant, Umfang, Netz und letztem Abruf; Admins legen an (der Link
// erscheint nur einmal), erzeugen einen neuen Link, stellen den Ton ein und
// löschen. Der Name öffnet die Vorschau im Browser.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

type wandAnzeige struct {
	ID        string     `json:"id"`
	MandantID string     `json:"mandant_id"`
	Name      string     `json:"name"`
	MitUnter  bool       `json:"mit_untermandanten"`
	Netz      *string    `json:"netz"`
	ZuletztDa *time.Time `json:"zuletzt_da"`
	Ton       *wandTon   `json:"ton"`
}

type wandTon struct {
	Ton         string `json:"ton"` // aus, krit, warn
	Klang       string `json:"klang"`
	Lautstaerke int    `json:"lautstaerke"`
	Entwarnung  bool   `json:"entwarnung"`
}

func init() {
	seiten[seiteWandanzeigen] = &seitenDef{
		laden: func(ctx context.Context, cl desktop.Client, _ *fenster) (any, error) {
			var out struct {
				Anzeigen []wandAnzeige `json:"anzeigen"`
			}
			err := cl.Anfrage(ctx, http.MethodGet, "/api/v1/anzeigen", nil, &out)
			return out.Anzeigen, err
		},
		malen: wandMalen,
		klick: wandKlick,
	}
}

func wandMalen(m *maler, daten any) {
	f := m.f
	ids, mehrere, rolle := a.bereich()
	admin := rolle(f.mandant) == "admin"
	var kopf []sKnopf
	if admin {
		kopf = append(kopf, sKnopf{text: "Wandanzeige anlegen", art: "neu"})
	}
	m.panel("Wandanzeigen", kopf...)
	m.klein("Eine Wandanzeige zeigt den Zustand eines Mandanten als Sonnendiagramm auf einem Bildschirm, ohne Benutzerkonto. " +
		"Sie sieht nur Namen und Farben und kann nichts ändern. Wer den Link hat, sieht die Anzeige; Löschen sperrt sie sofort. " +
		"Ein Klick auf den Namen öffnet eine Vorschau im Browser; „Neuer Link“ ersetzt den Link, der alte und alle damit " +
		"angemeldeten Bildschirme gelten sofort nicht mehr.")
	liste, ok := daten.([]wandAnzeige)
	if !ok {
		m.klein("Lädt …")
		m.ende()
		return
	}
	var tab [][]sZelle
	jetzt := time.Now()
	for _, x := range liste {
		if !ids[x.MandantID] {
			continue
		}
		zeigt := "nur diesen Mandanten"
		if x.MitUnter {
			zeigt = "mit Untermandanten"
		}
		netz := "überall"
		if x.Netz != nil && *x.Netz != "" {
			netz = *x.Netz
		}
		zuletzt := "noch nie"
		if x.ZuletztDa != nil {
			zuletzt = desktop.Vor(*x.ZuletztDa, jetzt)
		}
		name := sZelle{text: x.Name, link: &ziel{art: "vorschau", wert: x.ID}}
		if mehrere {
			name.klein = a.mandantName(x.MandantID)
		}
		var k []sKnopf
		if rolle(x.MandantID) == "admin" {
			k = []sKnopf{{text: "Ton", art: "ton", wert: x.ID}, {text: "Neuer Link", art: "link", wert: x.ID},
				{text: "Löschen", art: "loeschen", wert: x.ID, stil: kGefahr}}
		}
		tab = append(tab, []sZelle{name, {text: zeigt}, {text: netz}, {text: zuletzt}, {knoepfe: k}})
	}
	if len(tab) == 0 {
		m.leer(map[bool]string{true: "Noch keine Wandanzeige.", false: "Wandanzeigen sehen und anlegen nur Admins."}[admin])
	} else {
		m.tabelle([]sSpalte{{"Name", 22, false}, {"Zeigt", 17, false}, {"Nur aus Netz", 14, false}, {"Zuletzt da", 12, false},
			{"Aktion", 35, false}}, tab)
	}
	m.ende()
}

func wandKlick(z ziel, daten any) {
	f := a.f
	liste, _ := daten.([]wandAnzeige)
	var x *wandAnzeige
	for i := range liste {
		if liste[i].ID == z.wert {
			x = &liste[i]
		}
	}
	switch z.art {
	case "neu":
		wandAnlegen()
	case "vorschau":
		a.oeffnen("/anzeige/vorschau?id=" + z.wert)
	case "loeschen":
		if x == nil || !bestaetigenDialog(f.hwnd, "Wandanzeige „"+x.Name+"“ löschen?",
			"Die Anzeige ist danach sofort gesperrt; Bildschirme mit diesem Link zeigen nichts mehr.", "Löschen") {
			return
		}
		id := x.ID
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodDelete, "/api/v1/anzeigen/"+id, nil, nil)
		}, wandFertig("Löschen", "Wandanzeige gelöscht."))
	case "link":
		if x == nil || !bestaetigenDialog(f.hwnd, "Neuer Link für „"+x.Name+"“?",
			"Der alte Link und alle damit angemeldeten Bildschirme gelten sofort nicht mehr.", "Ja, alter Link ungültig") {
			return
		}
		id := x.ID
		var out struct {
			Name string `json:"name"`
			Link string `json:"link"`
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/anzeigen/"+id+"/neuer-link", nil, &out)
		}, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Wandanzeige", "Neuer Link fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			a.seiteNeu(seiteWandanzeigen)
			wandLinkZeigen(out.Name, out.Link)
		})
	case "ton":
		if x != nil {
			wandTonDialog(*x)
		}
	}
}

func wandFertig(was, gut string) func(error) {
	return func(err error) {
		if err != nil {
			hinweis(a.f.hwnd, "Wandanzeige", was+" fehlgeschlagen: "+fehlerText(err), true)
			return
		}
		setStatusText(a.f, gut)
		a.seiteNeu(seiteWandanzeigen)
	}
}

func wandAnlegen() {
	f := a.f
	mandant := f.mandant
	d := neuerDialog(f.hwnd, "Wandanzeige für „"+a.mandantName(mandant)+"“")
	d.okText = "Anlegen und Link erzeugen"
	d.werte["unter"] = "ja"
	d.aufbau = func(d *dialog) {
		d.feld("name", "Name", desktop.FeldText, "z. B. Büro Flur")
		d.feld("netz", "Nur aus diesem Netz (optional)", desktop.FeldText, "z. B. 10.10.0.0/23")
		d.feld("unter", "Untermandanten mit anzeigen", desktop.FeldJaNein, "")
	}
	var out struct {
		Link string `json:"link"`
	}
	name := ""
	d.speichern = func(d *dialog, fertig func(error)) {
		name = strings.TrimSpace(d.werte["name"])
		if name == "" {
			d.fehlerFeld = "name"
			fertig(errText("Name: bitte angeben."))
			return
		}
		body := map[string]any{"name": name, "mit_untermandanten": d.werte["unter"] == "ja", "netz": strings.TrimSpace(d.werte["netz"])}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten/"+mandant+"/anzeigen", body, &out)
		}, fertig)
	}
	if d.zeigen() {
		a.seiteNeu(seiteWandanzeigen)
		wandLinkZeigen(name, out.Link)
	}
}

// wandLinkZeigen: Den Link gibt es nur jetzt; kopieren oder schließen.
func wandLinkZeigen(name, link string) {
	f := a.f
	d := neuerDialog(f.hwnd, "Link für „"+name+"“")
	d.einleitung = "Den Link gibt es nur jetzt. Im Browser des Bildschirms öffnen (am besten im Vollbild- oder Kiosk-Modus); " +
		"danach steht er dort nicht mehr in der Adresszeile. Geht er verloren, mit „Neuer Link“ einen neuen erzeugen."
	d.werte["link"] = link
	d.okText, d.abbrText = "Link kopieren", "Fertig"
	d.aufbau = func(d *dialog) { d.feld("link", "Link", desktop.FeldText, "") }
	d.speichern = func(d *dialog, fertig func(error)) { fertig(zwischenablage(d.hwnd, link)) }
	if d.zeigen() {
		setStatusText(f, "Link kopiert.")
	}
}

func wandTonDialog(x wandAnzeige) {
	f := a.f
	t := wandTon{Ton: "krit", Klang: "bling", Lautstaerke: 70}
	if x.Ton != nil {
		t = *x.Ton
	}
	d := neuerDialog(f.hwnd, "Ton: "+x.Name)
	d.einleitung = "Am Bildschirm einmal „Ton einschalten“ anklicken; Browser spielen sonst keinen Ton ab."
	d.werte["ton"], d.werte["klang"], d.werte["laut"] = t.Ton, t.Klang, itoa(min(max((t.Lautstaerke+5)/10*10, 10), 100))
	if t.Entwarnung {
		d.werte["entwarnung"] = "ja"
	}
	d.aufbau = func(d *dialog) {
		d.auswahl("ton", "Ton bei neuen Alarmen", []string{"Aus", "Nur bei Kritisch", "Bei Warnung und Kritisch"}, []string{"aus", "krit", "warn"}, "")
		d.auswahl("klang", "Klang", []string{"Bling (zwei helle Töne)", "Gong (tief, lang)", "Doppelton (kurz)"}, []string{"bling", "gong", "doppel"}, "")
		d.auswahl("laut", "Lautstärke", []string{"10 %", "20 %", "30 %", "40 %", "50 %", "60 %", "70 %", "80 %", "90 %", "100 %"},
			[]string{"10", "20", "30", "40", "50", "60", "70", "80", "90", "100"}, "")
		d.feld("entwarnung", "Leiser Ton bei Entwarnung", desktop.FeldJaNein, "")
	}
	id := x.ID
	d.speichern = func(d *dialog, fertig func(error)) {
		laut := 70
		for i := 10; i <= 100; i += 10 {
			if d.werte["laut"] == itoa(i) {
				laut = i
			}
		}
		body := wandTon{Ton: d.werte["ton"], Klang: d.werte["klang"], Lautstaerke: laut, Entwarnung: d.werte["entwarnung"] == "ja"}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPut, "/api/v1/anzeigen/"+id+"/ton", body, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Ton gespeichert.")
		a.seiteNeu(seiteWandanzeigen)
	}
}

type errText string

func (e errText) Error() string { return string(e) }
