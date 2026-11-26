// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Sensor-Vorlagen wie web/src/SensorVorlagen.tsx mit den Kennfarben
// (web/src/Kennfarben.tsx) darunter: eigene und eingebaute Vorlagen nach
// „misst“ gruppiert, Vorlagensätze, Anwenden auf Geräte oder eine Gruppe.
// Die Suche oben rechts filtert wie das Suchfeld im Web.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

type vorlagenDaten struct {
	liste desktop.VorlagenListe
	kenn  []desktop.KennfarbeEintrag
}

var vorlagenSicht = struct{ eingebauteOffen bool }{}

func init() {
	seiten[seiteVorlagen] = &seitenDef{
		laden: func(ctx context.Context, cl desktop.Client, _ *fenster) (any, error) {
			var d vorlagenDaten
			if err := cl.Anfrage(ctx, http.MethodGet, "/api/v1/sensor-vorlagen", nil, &d.liste); err != nil {
				return nil, err
			}
			var k struct {
				Kennfarben []desktop.KennfarbeEintrag `json:"kennfarben"`
			}
			if err := cl.Anfrage(ctx, http.MethodGet, "/api/v1/kennfarben", nil, &k); err != nil {
				return nil, err
			}
			d.kenn = k.Kennfarben
			return d, nil
		},
		malen: vorlagenMalen,
		klick: vorlagenKlick,
	}
}

func vorlagenSuche() string { return strings.TrimSpace(getText(a.f.suche)) }

func vorlagenMalen(m *maler, daten any) {
	f := m.f
	ids, mehrere, rolle := a.bereich()
	darf := desktop.DarfAendern(rolle(f.mandant))
	var kopf []sKnopf
	if darf {
		kopf = append(kopf, sKnopf{text: "+ Vorlage", art: "neu", stil: kHaupt})
	}
	m.panel("Sensor-Vorlagen", kopf...)
	m.klein("Eine Vorlage ist eine Sensorart mit Vorbelegung. Anwenden legt je Gerät eine Kopie an, auch für alle Geräte einer " +
		"Gruppe; spätere Änderungen an der Vorlage ändern keine Sensoren. {adresse} steht für die Adresse des Geräts. Sensoren auf " +
		"dem Agent sind feste Messarten mit Parametern, keine Skripte, und messen nur, was am Rechner freigegeben ist. Die Suche " +
		"oben rechts filtert nach Name, Art und Notiz.")
	d, ok := daten.(vorlagenDaten)
	if !ok {
		m.klein("Lädt …")
		m.ende()
		return
	}
	such := vorlagenSuche()
	var eigene []desktop.Vorlage
	for _, v := range d.liste.Eigene {
		if v.MandantID != nil && ids[*v.MandantID] {
			eigene = append(eigene, v)
		}
	}
	var eigeneSaetze []desktop.VorlagenSatz
	for _, s := range d.liste.EigeneSaetze {
		if s.MandantID != nil && ids[*s.MandantID] {
			eigeneSaetze = append(eigeneSaetze, s)
		}
	}

	tabelle := func(l []desktop.Vorlage, eigen bool) {
		for _, g := range desktop.VorlagenGruppen(l, such) {
			m.text(fmt.Sprintf("%s (%d)", desktop.WoTitel(g[0].Wo()), len(g)), f.sch.t13b, th.f.Tinte)
			var tab [][]sZelle
			for _, v := range g {
				name := sZelle{text: v.Name, fett: true, klein: v.Notiz}
				if eigen && mehrere && v.MandantID != nil {
					name.mandant = a.mandantName(*v.MandantID)
				}
				var k []sKnopf
				if darf {
					k = append(k, sKnopf{text: "Anwenden", art: "anwenden", wert: v.ID, stil: kHaupt})
				}
				if darf && !eigen {
					k = append(k, sKnopf{text: "Als eigene", art: "kopie", wert: v.ID})
				}
				if eigen && v.MandantID != nil && desktop.DarfAendern(rolle(*v.MandantID)) {
					k = append(k, sKnopf{text: "Bearbeiten", art: "bearbeiten", wert: v.ID},
						sKnopf{text: "Löschen", art: "loeschen", wert: v.ID, stil: kGefahr})
				}
				tab = append(tab, []sZelle{name, {text: desktop.TypName(v.Typ)}, {text: v.Wo()},
					{text: desktop.ZielText(v.Typ, v.Ziel), farbe: th.f.Leise}, {text: vorlageTakt(v)}, {knoepfe: k}})
			}
			m.tabelle([]sSpalte{{"Vorlage", 22, false}, {"Art", 13, false}, {"misst", 8, false}, {"Vorbelegung", 21, false},
				{"Takt", 7, false}, {"", 29, false}}, tab)
		}
	}

	m.kleinTitel(fmt.Sprintf("Eigene Vorlagen (%d)", len(eigene)))
	if len(eigene) == 0 {
		m.klein("Noch keine. Mit „+ Vorlage“ oder „Als eigene“ bei einer eingebauten Vorlage anlegen.")
	} else {
		tabelle(eigene, true)
	}

	m.kleinTitel(fmt.Sprintf("Vorlagensätze (%d)", len(eigeneSaetze)+len(d.liste.Saetze)))
	if darf {
		m.knoepfe(sKnopf{text: "+ Vorlagensatz", art: "satzneu"})
	}
	m.klein("Ein Satz legt mehrere Sensoren für eine Anwendung auf einmal an, z. B. Dienste und Kennzahlen eines " +
		"Windows-Servers. Eigene Sätze stellst du aus Vorlagen zusammen; „Als eigenen“ kopiert einen eingebauten Satz zum Anpassen.")
	sortSaetze := func(l []desktop.VorlagenSatz) []desktop.VorlagenSatz {
		var out []desktop.VorlagenSatz
		for _, s := range l {
			namen := []string{s.Name, s.Notiz}
			for _, v := range s.Sensoren {
				namen = append(namen, v.Name)
			}
			if desktop.Passt(such, namen...) {
				out = append(out, s)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
		return out
	}
	var tab [][]sZelle
	for _, s := range append(sortSaetze(eigeneSaetze), sortSaetze(d.liste.Saetze)...) {
		name := sZelle{text: s.Name, fett: true, klein: s.Notiz}
		if s.MandantID != nil {
			name.marke, name.markeFg, name.markeBg, name.markeRand = "eigen", th.f.Tinte, th.f.Flaeche, th.f.Linie
			if mehrere {
				name.mandant = a.mandantName(*s.MandantID)
			}
		}
		var k []sKnopf
		if darf {
			k = append(k, sKnopf{text: "Anwenden", art: "satzanwenden", wert: s.ID, stil: kHaupt})
		}
		if darf && s.MandantID == nil {
			k = append(k, sKnopf{text: "Als eigenen", art: "satzkopie", wert: s.ID})
		}
		if s.MandantID != nil && desktop.DarfAendern(rolle(*s.MandantID)) {
			k = append(k, sKnopf{text: "Bearbeiten", art: "satzbearbeiten", wert: s.ID},
				sKnopf{text: "Löschen", art: "satzloeschen", wert: s.ID, stil: kGefahr})
		}
		tab = append(tab, []sZelle{name, {text: desktop.SatzSensorenText(s), farbe: th.f.Leise}, {knoepfe: k}})
	}
	if len(tab) > 0 {
		m.tabelle([]sSpalte{{"Satz", 28, false}, {"Sensoren", 42, false}, {"", 30, false}}, tab)
	}

	offen := vorlagenSicht.eingebauteOffen || such != ""
	m.kleinTitel(fmt.Sprintf("Eingebaute Vorlagen (%d)", len(d.liste.Eingebaut)))
	m.knoepfe(sKnopf{text: map[bool]string{true: "Ausblenden", false: "Zeigen"}[offen], art: "eingebaut"})
	if offen {
		tabelle(d.liste.Eingebaut, false)
	}
	m.ende()

	kennfarbenMalen(m, d.kenn, darf, mehrere, rolle)
}

func kennfarbenMalen(m *maler, liste []desktop.KennfarbeEintrag, darf, mehrere bool, rolle func(string) string) {
	var kopf []sKnopf
	if darf {
		kopf = append(kopf, sKnopf{text: "+ Kennfarbe", art: "kennneu", stil: kHaupt})
	}
	m.panel("Kennfarben", kopf...)
	m.klein("Eine Kennfarbe ersetzt Gelb und Rot eines Sensors, wenn er nicht OK ist, z. B. Pink für „Neustart verpasst“. Form " +
		"und Text der Schwere bleiben, Benachrichtigungen ebenso. Bei gleicher Schwere gewinnt am Gerät immer der Sensor ohne " +
		"Kennfarbe. Zuordnen lässt sie sich im Reiter „Sensoren“ eines Geräts und an Trap-Regeln (im Browser); die Wandanzeige " +
		"zeigt alle Kennfarben in der Legende.")
	if len(liste) == 0 {
		m.leer("Noch keine Kennfarben.")
		m.ende()
		return
	}
	var tab [][]sZelle
	for _, k := range liste {
		c, _ := k.RGB()
		marke := sZelle{marke: k.Name, markeFg: desktop.SchriftAuf(c), markeBg: c}
		mandant := a.mandantName(k.MandantID)
		if mandant == "" {
			mandant = "übergeordnet"
		}
		var kn []sKnopf
		if desktop.DarfAendern(rolle(k.MandantID)) {
			kn = []sKnopf{{text: "Ändern", art: "kennaendern", wert: k.ID}, {text: "Löschen", art: "kennloeschen", wert: k.ID, stil: kGefahr}}
		}
		tab = append(tab, []sZelle{marke, {text: k.Farbe}, {text: mandant}, {text: itoa(k.Verwendet)}, {knoepfe: kn}})
	}
	m.tabelle([]sSpalte{{"Kennfarbe", 30, false}, {"Farbe", 14, false}, {"Mandant", 22, false}, {"verwendet", 12, false}, {"", 22, false}}, tab)
	m.ende()
}

func vorlagenKlick(z ziel, daten any) {
	f := a.f
	d, _ := daten.(vorlagenDaten)
	alle := append(append([]desktop.Vorlage{}, d.liste.Eingebaut...), d.liste.Eigene...)
	finde := func(id string) *desktop.Vorlage {
		for i := range alle {
			if alle[i].ID == id {
				return &alle[i]
			}
		}
		return nil
	}
	saetze := append(append([]desktop.VorlagenSatz{}, d.liste.Saetze...), d.liste.EigeneSaetze...)
	satz := func(id string) *desktop.VorlagenSatz {
		for i := range saetze {
			if saetze[i].ID == id {
				return &saetze[i]
			}
		}
		return nil
	}
	switch z.art {
	case "eingebaut":
		vorlagenSicht.eingebauteOffen = !(vorlagenSicht.eingebauteOffen || vorlagenSuche() != "")
	case "neu":
		vorlageDialog(nil, false)
	case "kopie":
		if v := finde(z.wert); v != nil {
			vorlageDialog(v, false)
		}
	case "bearbeiten":
		if v := finde(z.wert); v != nil {
			vorlageDialog(v, true)
		}
	case "loeschen":
		if v := finde(z.wert); v != nil && bestaetigenDialog(f.hwnd, "Vorlage „"+v.Name+"“ löschen?",
			"Sensoren, die daraus angelegt wurden, bleiben.", "Löschen") {
			vorlagenAufruf(http.MethodDelete, "/api/v1/sensor-vorlagen/"+v.ID, nil, "Vorlage gelöscht.")
		}
	case "anwenden":
		if v := finde(z.wert); v != nil {
			anwendenDialog(v.Name, []desktop.Vorlage{*v}, map[string]any{"vorlage_id": v.ID}, false)
		}
	case "satzanwenden":
		if s := satz(z.wert); s != nil {
			anwendenDialog(s.Name, s.Sensoren, map[string]any{"satz_id": s.ID}, true)
		}
	case "satzneu":
		satzDialog(nil, false, d)
	case "satzkopie":
		if s := satz(z.wert); s != nil {
			satzDialog(s, true, d)
		}
	case "satzbearbeiten":
		if s := satz(z.wert); s != nil {
			satzDialog(s, false, d)
		}
	case "satzloeschen":
		if s := satz(z.wert); s != nil && bestaetigenDialog(f.hwnd, "Vorlagensatz „"+s.Name+"“ löschen?",
			"Sensoren, die daraus angelegt wurden, bleiben.", "Löschen") {
			vorlagenAufruf(http.MethodDelete, "/api/v1/sensor-vorlagensaetze/"+s.ID, nil, "Vorlagensatz gelöscht.")
		}
	case "kennneu":
		kennfarbeDialog(nil)
	case "kennaendern", "kennloeschen":
		for i := range d.kenn {
			k := d.kenn[i]
			if k.ID != z.wert {
				continue
			}
			if z.art == "kennaendern" {
				kennfarbeDialog(&k)
				return
			}
			text := "Sie wird nirgends verwendet."
			if k.Verwendet > 0 {
				text = fmt.Sprintf("%d Sensoren bzw. Regeln zeigen danach wieder Gelb und Rot; sie selbst bleiben.", k.Verwendet)
			}
			if bestaetigenDialog(f.hwnd, "Kennfarbe „"+k.Name+"“ löschen?", text, "Löschen") {
				vorlagenAufruf(http.MethodDelete, "/api/v1/kennfarben/"+k.ID, nil, "Kennfarbe gelöscht.")
			}
		}
	}
}

// vorlagenAufruf: einfache Änderung, danach neu laden und melden.
func vorlagenAufruf(methode, pfad string, body any, gut string) {
	f := a.f
	a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
		return cl.Anfrage(ctx, methode, pfad, body, nil)
	}, func(err error) {
		if err != nil {
			hinweis(f.hwnd, "Sensor-Vorlagen", fehlerText(err), true)
			return
		}
		setStatusText(f, gut)
		a.seiteNeu(seiteVorlagen)
	})
}

// vorlageDialog: neue Vorlage (v == nil), Kopie einer Vorlage oder bearbeiten.
func vorlageDialog(v *desktop.Vorlage, bearbeiten bool) {
	f := a.f
	mandant := f.mandant
	titel := "Neue Vorlage für „" + a.mandantName(mandant) + "“"
	switch {
	case bearbeiten:
		titel = "Vorlage „" + v.Name + "“ bearbeiten"
	case v != nil:
		titel = "Eigene Vorlage aus „" + v.Name + "“"
	}
	d := neuerDialog(f.hwnd, titel)
	typ := "ping"
	d.werte["intervall"], d.werte["fehlversuche"] = "300", "0"
	notiz := ""
	if v != nil {
		typ, notiz = v.Typ, v.Notiz
		d.werte["name"], d.werte["intervall"] = v.Name, strconv.Itoa(v.Intervall)
		if v.Fehlversuche != nil {
			d.werte["fehlversuche"] = strconv.Itoa(*v.Fehlversuche)
		}
		if t, ok := desktop.TypNach(v.Typ); ok {
			for k, w := range desktop.WerteAusZiel(t, v.Ziel) {
				d.werte["z:"+k] = w
			}
		}
	}
	d.werte["typ"] = typ
	vorbelegen := func(t desktop.Typ) {
		for _, fe := range t.Felder {
			k := "z:" + fe.Schluessel
			if fe.Adresse && d.werte[k] == "" {
				d.werte[k] = "{adresse}"
				if fe.Schluessel == "url" {
					d.werte[k] = "https://{adresse}/"
				}
			}
		}
	}
	if t, ok := desktop.TypNach(typ); ok && v == nil {
		vorbelegen(t)
	}
	var typTexte, typWerte []string
	for _, t := range desktop.Typen {
		n := t.Name
		if t.AmAgent {
			n += " (Agent)"
		}
		typTexte, typWerte = append(typTexte, n), append(typWerte, t.Schluessel)
	}
	var ivTexte, ivWerte []string
	drin := false
	for _, iv := range desktop.Intervalle {
		ivTexte, ivWerte = append(ivTexte, iv.Text), append(ivWerte, strconv.Itoa(iv.Sekunden))
		drin = drin || strconv.Itoa(iv.Sekunden) == d.werte["intervall"]
	}
	if !drin {
		n, _ := strconv.Atoi(d.werte["intervall"])
		ivTexte, ivWerte = append(ivTexte, desktop.IntervallText(n)), append(ivWerte, d.werte["intervall"])
	}
	d.aufbau = func(d *dialog) {
		d.einleitung = "{adresse} steht für die Adresse des Geräts, auf das die Vorlage angewendet wird."
		tf := d.auswahl("typ", "Typ", typTexte, typWerte, "")
		tf.aenderung = func() {
			if t, ok := desktop.TypNach(d.werte["typ"]); ok {
				vorbelegen(t)
			}
			d.aufbauen()
		}
		d.feld("name", "Name", desktop.FeldText, "leer = automatisch aus Typ und Ziel")
		t, _ := desktop.TypNach(d.werte["typ"])
		for _, fe := range t.Felder {
			x := d.feld("z:"+fe.Schluessel, fe.Beschriftung, fe.Art, fe.Hinweis)
			x.halb = paar(fe.Schluessel)
			if fe.Art == desktop.FeldAuswahl {
				for _, o := range fe.Optionen {
					txt := o
					if o == "" {
						txt = "(keine Angabe)"
					}
					x.texte, x.werte = append(x.texte, txt), append(x.werte, o)
				}
			}
		}
		d.auswahl("intervall", "Intervall", ivTexte, ivWerte, "").halb = true
		fvTexte, fvWerte := desktop.FehlversucheAuswahl()
		d.auswahl("fehlversuche", "Alarm nach", fvTexte, fvWerte, "").halb = true
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		t, ok := desktop.TypNach(d.werte["typ"])
		if !ok {
			fertig(errText("Unbekannter Typ."))
			return
		}
		w := map[string]string{}
		for k, x := range d.werte {
			if s, ok := strings.CutPrefix(k, "z:"); ok {
				w[s] = x
			}
		}
		ziel, err := desktop.ZielAusWerten(t, w)
		if err != nil {
			fertig(err)
			return
		}
		iv, _ := strconv.Atoi(d.werte["intervall"])
		fv, _ := strconv.Atoi(d.werte["fehlversuche"])
		body := map[string]any{"name": strings.TrimSpace(d.werte["name"]), "typ": t.Schluessel, "ziel": ziel,
			"intervall_sekunden": iv, "notiz": notiz, "fehlversuche": fv}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if bearbeiten {
				return cl.Anfrage(ctx, http.MethodPut, "/api/v1/sensor-vorlagen/"+v.ID, body, nil)
			}
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten/"+mandant+"/sensor-vorlagen", body, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Vorlage gespeichert.")
		a.seiteNeu(seiteVorlagen)
	}
}

// anwendenDialog wie Anwenden im Web: einzelne Geräte oder alle einer Gruppe.
func anwendenDialog(name string, sensoren []desktop.Vorlage, auswahl map[string]any, satz bool) {
	f := a.f
	ids, mehrere, _ := a.bereich()
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	var gs []desktop.Geraet
	for _, g := range st.Geraete {
		if ids[g.MandantID] {
			gs = append(gs, g)
		}
	}
	sort.SliceStable(gs, func(i, j int) bool { return strings.ToLower(gs[i].Name) < strings.ToLower(gs[j].Name) })
	var gTexte, gWerte []string
	for _, g := range gs {
		t := g.Name
		if g.Adresse != nil && *g.Adresse != "" {
			t += " · " + *g.Adresse
		}
		gTexte, gWerte = append(gTexte, t), append(gWerte, g.ID)
	}
	var grTexte, grWerte []string
	for m := range ids {
		t, w := gruppenPfade(st.Gruppen, m)
		for i := 1; i < len(t); i++ { // ohne „(keine Gruppe)“
			if mehrere {
				t[i] += " (" + a.mandantName(m) + ")"
			}
			grTexte, grWerte = append(grTexte, t[i]), append(grWerte, w[i])
		}
	}
	text := "Legt je Gerät einen Sensor „" + name + "“ an. "
	if satz {
		text = fmt.Sprintf("Legt je Gerät %d Sensoren an. ", len(sensoren))
	}
	adr, agent, snmp := false, false, false
	for _, s := range sensoren {
		adr, agent, snmp = adr || s.BrauchtAdresse, agent || s.AmAgent, snmp || s.Typ == "snmp_oid"
	}
	if adr {
		text += "Geräte ohne Adresse werden dabei übersprungen. "
	}
	if agent {
		text += "Sensoren auf dem Agent nur bei Geräten mit Agent; gemessen wird erst nach Freigabe am Rechner. "
	}
	if snmp {
		text += "SNMP-Sensoren nur bei Geräten mit SNMP-Abfrage. "
	}
	d := neuerDialog(f.hwnd, "„"+name+"“ anwenden")
	d.okText = "Anlegen"
	d.werte["ziel"], d.werte["unter"] = "geraete", "ja"
	d.aufbau = func(d *dialog) {
		d.einleitung = strings.TrimSpace(text)
		x := d.auswahl("ziel", "Ziel", []string{"Einzelne Geräte", "Alle Geräte einer Gruppe"}, []string{"geraete", "gruppe"}, "")
		x.aenderung = func() { d.aufbauen() }
		if d.werte["ziel"] == "geraete" {
			x := d.feld("geraete", "Geräte (anklicken zum Wählen)", desktop.FeldMehrfach, "")
			x.texte, x.werte = gTexte, gWerte
		} else {
			d.auswahl("gruppe", "Gruppe", append([]string{"Bitte wählen"}, grTexte...), append([]string{""}, grWerte...),
				"Gilt einmalig für die Geräte, die jetzt in der Gruppe sind.")
			d.feld("unter", "mit Untergruppen", desktop.FeldJaNein, "")
		}
	}
	var erg struct {
		Angelegt      int `json:"angelegt"`
		Uebersprungen []struct {
			Geraet string `json:"geraet"`
			Sensor string `json:"sensor"`
			Grund  string `json:"grund"`
		} `json:"uebersprungen"`
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		body := map[string]any{}
		for k, v := range auswahl {
			body[k] = v
		}
		if d.werte["ziel"] == "gruppe" {
			if d.werte["gruppe"] == "" {
				d.fehlerFeld = "gruppe"
				fertig(errText("Bitte eine Gruppe wählen."))
				return
			}
			body["gruppe_id"], body["mit_untergruppen"] = d.werte["gruppe"], d.werte["unter"] == "ja"
		} else {
			var l []string
			for _, x := range strings.Split(d.werte["geraete"], ",") {
				if x != "" {
					l = append(l, x)
				}
			}
			if len(l) == 0 {
				d.fehlerFeld = "geraete"
				fertig(errText("Bitte mindestens ein Gerät wählen."))
				return
			}
			body["geraete"] = l
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/sensor-vorlagen/anwenden", body, &erg)
		}, fertig)
	}
	if !d.zeigen() {
		return
	}
	t := fmt.Sprintf("%d Sensoren angelegt", erg.Angelegt)
	if erg.Angelegt == 1 {
		t = "1 Sensor angelegt"
	}
	if len(erg.Uebersprungen) == 0 {
		setStatusText(f, t+".")
		a.jetztAbfragen()
		return
	}
	t += fmt.Sprintf(", %d übersprungen:", len(erg.Uebersprungen))
	for _, u := range erg.Uebersprungen {
		t += "\n• " + u.Geraet
		if u.Sensor != "" {
			t += " · " + u.Sensor
		}
		t += ": " + u.Grund
	}
	hinweis(f.hwnd, "„"+name+"“ angewendet", t, false)
	a.jetztAbfragen()
}

// satzDialog: eigenen Satz anlegen, aus einem eingebauten kopieren oder bearbeiten.
func satzDialog(s *desktop.VorlagenSatz, kopie bool, d0 vorlagenDaten) {
	f := a.f
	mandant := f.mandant
	neu := s == nil || kopie
	titel := "Neuer Vorlagensatz für „" + a.mandantName(mandant) + "“"
	if !neu {
		titel = "Vorlagensatz „" + s.Name + "“ bearbeiten"
	}
	// Auswahl: bisherige Einträge (behalten ihre Kennfarbe), dann alle Vorlagen
	type quelle struct {
		text string
		v    desktop.Vorlage
	}
	var q []quelle
	gewaehlt := []string{}
	if s != nil {
		for i, v := range s.Sensoren {
			q = append(q, quelle{v.Name + " (" + desktop.TypName(v.Typ) + ")", v})
			gewaehlt = append(gewaehlt, "e"+itoa(i))
		}
	}
	n0 := len(q)
	ids, _, _ := a.bereich()
	for _, v := range d0.liste.Eigene {
		if v.MandantID != nil && ids[*v.MandantID] {
			q = append(q, quelle{"Eigene: " + v.Name, v})
		}
	}
	for _, v := range d0.liste.Eingebaut {
		q = append(q, quelle{"Eingebaut: " + v.Name, v})
	}
	for _, st := range d0.liste.Saetze {
		for _, v := range st.Sensoren {
			q = append(q, quelle{"Satz " + st.Name + ": " + v.Name, v})
		}
	}
	var texte, werte []string
	for i, x := range q {
		texte = append(texte, x.text)
		if i < n0 {
			werte = append(werte, "e"+itoa(i))
		} else {
			werte = append(werte, "q"+itoa(i))
		}
	}
	d := neuerDialog(f.hwnd, titel)
	if s != nil {
		d.werte["name"], d.werte["notiz"] = s.Name, s.Notiz
		if kopie {
			d.werte["name"] = s.Name + " (eigen)"
		}
	}
	d.werte["eintraege"] = strings.Join(gewaehlt, ",")
	d.aufbau = func(d *dialog) {
		d.einleitung = "Höchstens 50 Sensoren. Jeder Eintrag ist eine Kopie; spätere Änderungen an der Vorlage ändern den Satz " +
			"nicht. Die bisherigen Einträge stehen oben und behalten ihre Kennfarbe; Kennfarben neuer Einträge wählst du im Browser."
		d.feld("name", "Name", desktop.FeldText, "")
		d.feld("notiz", "Notiz (optional)", desktop.FeldText, "")
		x := d.feld("eintraege", "Sensoren (anklicken zum Wählen)", desktop.FeldMehrfach, "")
		x.texte, x.werte = texte, werte
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		if strings.TrimSpace(d.werte["name"]) == "" {
			d.fehlerFeld = "name"
			fertig(errText("Name: bitte angeben."))
			return
		}
		var eintraege []desktop.Vorlage
		namen := map[string]bool{}
		for _, w := range strings.Split(d.werte["eintraege"], ",") {
			for i, x := range werte {
				if x == w && w != "" && !namen[strings.ToLower(q[i].v.Name)] {
					namen[strings.ToLower(q[i].v.Name)] = true
					eintraege = append(eintraege, q[i].v)
				}
			}
		}
		if len(eintraege) == 0 {
			d.fehlerFeld = "eintraege"
			fertig(errText("Bitte mindestens einen Sensor wählen."))
			return
		}
		body := desktop.SatzEingabe(d.werte["name"], d.werte["notiz"], eintraege)
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if neu {
				return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten/"+mandant+"/sensor-vorlagensaetze", body, nil)
			}
			return cl.Anfrage(ctx, http.MethodPut, "/api/v1/sensor-vorlagensaetze/"+s.ID, body, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Vorlagensatz gespeichert.")
		a.seiteNeu(seiteVorlagen)
	}
}

// kennfarbeDialog: neue Kennfarbe oder ändern; prüft den Kontrast wie das Web.
func kennfarbeDialog(k *desktop.KennfarbeEintrag) {
	f := a.f
	mandant := f.mandant
	titel := "Neue Kennfarbe für " + a.mandantName(mandant)
	if k != nil {
		titel = "Kennfarbe ändern"
	}
	d := neuerDialog(f.hwnd, titel)
	d.werte["farbe"] = desktop.KennVorschlaege[0]
	if k != nil {
		d.werte["name"], d.werte["farbe"] = k.Name, k.Farbe
	}
	vt := []string{"(eigene Farbe oben)"}
	vw := []string{""}
	for _, v := range desktop.KennVorschlaege {
		vt, vw = append(vt, v), append(vw, v)
	}
	d.aufbau = func(d *dialog) {
		hell, dunkel, fehler := desktop.KennfarbePruefen(strings.TrimSpace(d.werte["farbe"]))
		d.einleitung = "Die Farbe braucht auf hellem und dunklem Grund je mindestens 3:1 Kontrast."
		if fehler == "" || hell > 0 {
			d.einleitung += fmt.Sprintf(" Jetzt: hell %s:1, dunkel %s:1.", komma(hell), komma(dunkel))
		}
		d.feld("name", "Name (erscheint in Legende und Tooltip)", desktop.FeldText, "z. B. Neustart verpasst")
		d.feld("farbe", "Farbe als #rrggbb", desktop.FeldText, "#c0307a").halb = true
		x := d.auswahl("vorschlag", "Vorschlag", vt, vw, "")
		x.halb = true
		x.aenderung = func() {
			if v := d.werte["vorschlag"]; v != "" {
				d.werte["farbe"] = v
			}
			d.aufbauen()
		}
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		farbe := strings.ToLower(strings.TrimSpace(d.werte["farbe"]))
		if _, _, fehler := desktop.KennfarbePruefen(farbe); fehler != "" {
			d.fehlerFeld = "farbe"
			fertig(errText(fehler))
			return
		}
		name := strings.TrimSpace(d.werte["name"])
		if name == "" {
			d.fehlerFeld = "name"
			fertig(errText("Name: bitte angeben."))
			return
		}
		body := map[string]string{"name": name, "farbe": farbe}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if k != nil {
				return cl.Anfrage(ctx, http.MethodPut, "/api/v1/kennfarben/"+k.ID, body, nil)
			}
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten/"+mandant+"/kennfarben", body, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Kennfarbe gespeichert.")
		a.seiteNeu(seiteVorlagen)
	}
}

func komma(x float64) string { return strings.Replace(strconv.FormatFloat(x, 'f', 1, 64), ".", ",", 1) }

// vorlageTakt: „5 Min.“, mit eigenen Fehlversuchen „5 Min. · 5×“ (1.0.6).
func vorlageTakt(v desktop.Vorlage) string {
	t := desktop.IntervallKurz(v.Intervall)
	if v.Fehlversuche != nil && *v.Fehlversuche > 0 {
		t += " · " + strconv.Itoa(*v.Fehlversuche) + "×"
	}
	return t
}
