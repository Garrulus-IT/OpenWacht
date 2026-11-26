// SPDX-License-Identifier: AGPL-3.0-only

package main

// Befehle des Hauptfensters (1.0.6): Geräte und Sensoren anlegen, ändern,
// löschen, pausieren, Wartung, Alarme bestätigen. Jede Änderung geht an die
// Zentrale, die Rolle und Eingaben prüft; danach wird sofort neu abgefragt.

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/garrulus-it/openwacht/internal/desktop"
	"github.com/garrulus-it/openwacht/internal/version"
)

// imHintergrund führt fn mit dem Client aus und ruft danach im
// Oberflächen-Thread fertig auf.
func (a *app) imHintergrund(fn func(ctx context.Context, c desktop.Client) error, fertig func(error)) {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		err := fn(ctx, c)
		cancel()
		a.ergebnisse <- func() { fertig(err) }
		pPostMessageW.Call(uintptr(a.hwnd), wmAktion, 0, 0)
	}()
}

// fehlerText: Meldung für Menschen, bei fehlenden Rechten mit Hinweis aufs Token.
func fehlerText(err error) string {
	if errors.Is(err, desktop.ErrToken) {
		return "Das API-Token ist ungültig, abgelaufen oder widerrufen. Melde dich neu an: links unten „Abmelden“ oder Rechtsklick aufs Symbol im Infobereich › Anmeldung ändern."
	}
	var fz *desktop.FehlerZentrale
	if errors.As(err, &fz) && fz.Code == 403 {
		t := fz.Text
		if t == "" {
			t = "Keine Berechtigung."
		}
		return t + " Zum Ändern braucht die App ein API-Token mit der Rolle Operator."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Die Zentrale hat nicht rechtzeitig geantwortet."
	}
	return err.Error()
}

// gemacht: nach einer Änderung neu abfragen und Ergebnis melden.
func (a *app) gemacht(text string) {
	setStatusText(a.f, text)
	a.jetztAbfragen()
}

func (a *app) befehlFenster(id int) {
	f := a.f
	if f == nil || id == 0 {
		return
	}
	k := f.knoten()
	z := f.gewaehlteZeile()
	var c *desktop.Check
	if z != nil {
		c = z.check
	}
	switch id {
	case cmdAktualisieren:
		setStatusText(f, "Frage ab …")
		a.jetztAbfragen()
	case cmdNurProbleme:
		if f.seite == seiteAlarme {
			return // zeigt ohnehin nur Probleme
		}
		f.nurProbleme = !f.nurProbleme
		pInvalidateRect.Call(uintptr(f.befehle), 0, 0)
		a.auswahlZeigen(true)
	case cmdMehr:
		a.mehrMenue()
	case cmdSchliessen:
		if f.seite == seiteDashboard && f.dashHost != "" {
			a.geraetOeffnen(f.dashHost)
		}
	case cmdAbmelden:
		a.abmelden()
	case cmdUeber:
		a.ueber()
	case cmdImBrowser:
		switch {
		case z != nil:
			a.oeffnen(desktop.GeraetPfad(z.GeraetID))
		case k != nil && k.Art == desktop.KnotenGeraet:
			a.oeffnen(desktop.GeraetPfad(k.ID))
		default:
			a.oeffnen(desktop.WebPfad(f.seitePfad(), f.mandant, f.mitUnter))
		}
	case cmdNeuSensor:
		gid := ""
		switch {
		case z != nil:
			gid = z.GeraetID
		case k != nil && k.Art == desktop.KnotenGeraet:
			gid = k.ID
		}
		g := a.geraet(gid)
		if g == nil {
			hinweis(f.hwnd, "Sensor hinzufügen", "Kein Gerät gewählt. Wähle links im Baum das Gerät, an dem der Sensor messen soll.", false)
			return
		}
		a.sensorDialog(g, nil)
	case cmdBearbeiten:
		switch {
		case c != nil:
			a.sensorDialog(a.geraet(c.GeraetID), c)
		case z != nil:
			if bestaetigenFrage(f.hwnd, "Im Browser bearbeiten?", "Diesen Wert liefert der Agent bzw. die SNMP-Abfrage des Geräts. Seine Grenzen stellst du in OpenWacht im Browser ein.", "Im Browser öffnen") {
				a.oeffnen(desktop.GeraetPfad(z.GeraetID))
			}
		case k != nil && k.Art == desktop.KnotenGeraet:
			a.geraetDialog(k.MandantID, k.Geraet)
		}
	case cmdGeraetBearbeiten:
		if k != nil && k.Art == desktop.KnotenGeraet {
			a.geraetDialog(k.MandantID, k.Geraet)
		}
	case cmdNeuGeraet:
		mandant := f.mandant
		if k != nil {
			mandant = k.MandantID
		}
		a.geraetDialog(mandant, nil)
	case cmdJetzt:
		if c == nil {
			return
		}
		id := c.ID
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.CheckJetzt(ctx, id) }, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Jetzt abfragen", "Abfragen fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			setStatusText(f, "„"+c.Name+"“ wird abgefragt …")
			time.AfterFunc(4*time.Second, a.jetztAbfragen)
		})
	case cmdPause:
		if c == nil {
			return
		}
		ch, aktiv := *c, !c.Aktiv
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.CheckAktiv(ctx, ch, aktiv) }, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Pausieren", "Ändern fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			if aktiv {
				a.gemacht("„" + ch.Name + "“ wird wieder abgefragt.")
			} else {
				a.gemacht("„" + ch.Name + "“ pausiert.")
			}
		})
	case cmdWartung:
		switch {
		case c != nil:
			if c.Wartung != nil && c.Wartung.UeberGeraet {
				hinweis(f.hwnd, "Wartung", "Das ganze Gerät ist in Wartung. Beende sie über das Gerät im Baum (Rechtsklick).", false)
				return
			}
			a.wartung("checks", c.ID, c.Name, c.Wartung)
		case k != nil && k.Art == desktop.KnotenGeraet:
			a.wartung("geraete", k.ID, k.Name, k.Geraet.Wartung)
		}
	case cmdGeraetWartung:
		if k != nil && k.Art == desktop.KnotenGeraet {
			a.wartung("geraete", k.ID, k.Name, k.Geraet.Wartung)
		}
	case cmdBestaetigen:
		if z == nil || !z.AlarmNeu {
			return
		}
		a.bestaetigen(z.AlarmID, z.Geraet+" – "+z.Sensor, z.Meldung)
	case cmdLoeschen:
		switch {
		case c != nil:
			if !bestaetigenDialog(f.hwnd, "Sensor löschen?", "Der Sensor „"+c.Name+"“ an "+z.Geraet+" verschwindet mit seinem Verlauf. Das Alarmprotokoll bleibt. Das lässt sich nicht rückgängig machen.", c.Name+" löschen") {
				return
			}
			id, name := c.ID, c.Name
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.CheckLoeschen(ctx, id) }, func(err error) {
				if err != nil {
					hinweis(f.hwnd, "Sensor löschen", "Löschen fehlgeschlagen: "+fehlerText(err), true)
					return
				}
				a.gemacht("Sensor „" + name + "“ gelöscht.")
			})
		case z == nil && k != nil && k.Art == desktop.KnotenGeraet:
			a.geraetLoeschen(k.Geraet)
		}
	case cmdGeraetLoeschen:
		if k != nil && k.Art == desktop.KnotenGeraet {
			a.geraetLoeschen(k.Geraet)
		}
	}
}

func (a *app) geraet(id string) *desktop.Geraet {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.stand.Geraete {
		if a.stand.Geraete[i].ID == id {
			g := a.stand.Geraete[i]
			return &g
		}
	}
	return nil
}

// sensorDialog: anlegen (c == nil) oder ändern.
func (a *app) sensorDialog(g *desktop.Geraet, c *desktop.Check) {
	f := a.f
	if g == nil {
		return
	}
	adresse := ""
	if g.Adresse != nil {
		adresse = *g.Adresse
	}
	d := neuerDialog(f.hwnd, "Sensor hinzufügen")
	d.okText = "Sensor anlegen"
	typ := "ping"
	if c != nil {
		d.titel, d.okText, typ = "Sensor bearbeiten", "Sensor speichern", c.Typ
		d.werte["name"], d.werte["intervall"] = c.Name, strconv.Itoa(c.Intervall)
		if c.Aktiv {
			d.werte["aktiv"] = "ja"
		}
		if t, ok := desktop.TypNach(c.Typ); ok {
			for k, v := range desktop.WerteAusZiel(t, c.Ziel) {
				d.werte["z:"+k] = v
			}
		}
	} else {
		d.werte["intervall"], d.werte["aktiv"] = "300", "ja"
	}
	d.werte["typ"] = typ
	vorbelegt := map[string]bool{}
	vorbelegen := func(t desktop.Typ) {
		if c != nil || adresse == "" {
			return
		}
		for _, fe := range t.Felder {
			k := "z:" + fe.Schluessel
			if !fe.Adresse || (d.werte[k] != "" && !vorbelegt[k]) {
				continue
			}
			v := adresse
			if fe.Schluessel == "url" {
				h := adresse
				if strings.Contains(h, ":") {
					h = "[" + h + "]"
				}
				v = "https://" + h + "/"
			}
			d.werte[k], vorbelegt[k] = v, true
		}
	}
	if t, ok := desktop.TypNach(typ); ok {
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
	if _, ok := desktop.TypNach(typ); !ok {
		typTexte, typWerte = append(typTexte, typ), append(typWerte, typ)
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
		tf := d.auswahl("typ", "Typ", typTexte, typWerte, "")
		tf.aus = c != nil
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
		d.feld("aktiv", "Sensor ist aktiv", desktop.FeldJaNein, "").halb = true
		if t.AmAgent {
			d.einleitung = "Gerät " + g.Name + ". Diesen Sensor misst der Agent auf dem Gerät; ohne Agent lehnt die Zentrale ihn ab."
		} else {
			d.einleitung = "Gerät " + g.Name
			if adresse != "" {
				d.einleitung += " · " + adresse
			}
		}
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		t, ok := desktop.TypNach(d.werte["typ"])
		if !ok {
			fertig(errors.New("Unbekannter Typ."))
			return
		}
		w := map[string]string{}
		for k, v := range d.werte {
			if s, ok := strings.CutPrefix(k, "z:"); ok {
				w[s] = v
			}
		}
		ziel, err := desktop.ZielAusWerten(t, w)
		if err != nil {
			for _, fe := range t.Felder {
				if strings.HasPrefix(err.Error(), fe.Beschriftung+":") {
					d.fehlerFeld = "z:" + fe.Schluessel
				}
			}
			fertig(err)
			return
		}
		iv, _ := strconv.Atoi(d.werte["intervall"])
		aktiv := d.werte["aktiv"] == "ja"
		in := desktop.CheckEingabe{Name: strings.TrimSpace(d.werte["name"]), Typ: t.Schluessel, Ziel: ziel, Intervall: iv, Aktiv: &aktiv}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if c == nil {
				return cl.CheckAnlegen(ctx, g.ID, in)
			}
			return cl.CheckAendern(ctx, c.ID, in)
		}, fertig)
	}
	if d.zeigen() {
		if c == nil {
			a.gemacht("Sensor angelegt.")
		} else {
			a.gemacht("Gespeichert.")
		}
	}
}

// gruppenPfade: Gruppen eines Mandanten als „Server / Linux“, sortiert.
func gruppenPfade(gs []desktop.Gruppe, mandant string) (texte, werte []string) {
	byID := map[string]desktop.Gruppe{}
	for _, g := range gs {
		byID[g.ID] = g
	}
	pfad := func(g desktop.Gruppe) string {
		teile := []string{g.Name}
		for i := 0; g.ElternID != nil && i < 20; i++ {
			e, ok := byID[*g.ElternID]
			if !ok {
				break
			}
			teile = append([]string{e.Name}, teile...)
			g = e
		}
		return strings.Join(teile, " / ")
	}
	type tw struct{ t, w string }
	var l []tw
	for _, g := range gs {
		if g.MandantID == mandant {
			l = append(l, tw{pfad(g), g.ID})
		}
	}
	sort.Slice(l, func(i, j int) bool { return strings.ToLower(l[i].t) < strings.ToLower(l[j].t) })
	texte, werte = []string{"(keine Gruppe)"}, []string{""}
	for _, x := range l {
		texte, werte = append(texte, x.t), append(werte, x.w)
	}
	return texte, werte
}

// geraetDialog: anlegen (g == nil) oder ändern.
func (a *app) geraetDialog(mandant string, g *desktop.Geraet) {
	f := a.f
	a.mu.Lock()
	st := a.stand
	a.mu.Unlock()
	mName := ""
	for _, m := range st.Mandanten {
		if m.ID == mandant {
			mName = m.Name
		}
	}
	d := neuerDialog(f.hwnd, "Gerät hinzufügen")
	d.okText = "Gerät anlegen"
	d.einleitung = "Mandant " + mName
	if k := f.knoten(); g == nil && k != nil {
		switch k.Art {
		case desktop.KnotenGruppe:
			d.werte["gruppe"] = k.ID
		case desktop.KnotenGeraet:
			if k.Geraet.GruppeID != nil {
				d.werte["gruppe"] = *k.Geraet.GruppeID
			}
		}
	}
	if g != nil {
		d.titel, d.okText = "Gerät bearbeiten", "Gerät speichern"
		d.werte["name"] = g.Name
		if g.Adresse != nil {
			d.werte["adresse"] = *g.Adresse
		}
		if g.GruppeID != nil {
			d.werte["gruppe"] = *g.GruppeID
		}
	}
	gt, gw := gruppenPfade(st.Gruppen, mandant)
	d.aufbau = func(d *dialog) {
		d.feld("name", "Name", desktop.FeldText, "z. B. dc01")
		d.feld("adresse", "Adresse", desktop.FeldText, "Name oder IP, für Sensoren der Zentrale")
		d.auswahl("gruppe", "Gruppe", gt, gw, "")
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		grp := d.werte["gruppe"]
		in := desktop.GeraetEingabe{Name: strings.TrimSpace(d.werte["name"]), Adresse: strings.TrimSpace(d.werte["adresse"]), GruppeID: &grp}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if g == nil {
				return cl.GeraetAnlegen(ctx, mandant, in)
			}
			return cl.GeraetAendern(ctx, g.ID, in)
		}, fertig)
	}
	if d.zeigen() {
		a.gemacht("Gespeichert.")
	}
}

func (a *app) geraetLoeschen(g *desktop.Geraet) {
	f := a.f
	leer := g.Checks == 0 && g.AgentID == nil && g.SNMPID == nil
	d := neuerDialog(f.hwnd, "Gerät löschen?")
	d.okText, d.gefahr = g.Name+" löschen", true
	if leer {
		d.einleitung = "Das Gerät „" + g.Name + "“ hat keine Sensoren und verschwindet aus dem Baum."
		d.aufbau = func(*dialog) {}
	} else {
		d.einleitung = "Mit „" + g.Name + "“ verschwinden seine Sensoren, Abfragen und deren Verlauf; ein Agent wird gesperrt. " +
			"Das Alarmprotokoll bleibt. Zum Bestätigen tippe den Namen des Geräts ein."
		d.aufbau = func(d *dialog) { d.feld("name", "Name des Geräts", desktop.FeldText, g.Name) }
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		name := ""
		if !leer {
			name = strings.TrimSpace(d.werte["name"])
			if name == "" {
				d.fehlerFeld = "name"
				fertig(errors.New("Der Name fehlt. Tippe „" + g.Name + "“ ein."))
				return
			}
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.GeraetLoeschen(ctx, g.ID, name) }, fertig)
	}
	if d.zeigen() {
		a.gemacht("Gerät „" + g.Name + "“ gelöscht.")
	}
}

var wartungsDauer = []struct {
	min  int
	text string
}{{15, "15 Minuten"}, {30, "30 Minuten"}, {60, "1 Stunde"}, {120, "2 Stunden"}, {240, "4 Stunden"}, {480, "8 Stunden"},
	{1440, "1 Tag"}, {4320, "3 Tage"}, {10080, "7 Tage"}}

// wartung: art "geraete" oder "checks". Läuft schon eine, wird sie beendet.
func (a *app) wartung(art, id, name string, w *desktop.Wartung) {
	f := a.f
	if w != nil {
		if !bestaetigenFrage(f.hwnd, "Wartung beenden?", "„"+name+"“ ist in Wartung bis "+desktop.ZeitText(w.Bis)+". Danach lösen Probleme wieder Alarme aus.", "Wartung beenden") {
			return
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.WartungBeenden(ctx, art, id) }, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Wartung beenden", "Beenden fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			a.gemacht("Wartung für „" + name + "“ beendet.")
		})
		return
	}
	d := neuerDialog(f.hwnd, "Wartung für "+name)
	d.okText = "Wartung starten"
	d.einleitung = "In dieser Zeit lösen Probleme keine Alarme aus."
	var tx, wx []string
	for _, x := range wartungsDauer {
		tx, wx = append(tx, x.text), append(wx, strconv.Itoa(x.min))
	}
	d.werte["dauer"] = "60"
	d.aufbau = func(d *dialog) {
		d.auswahl("dauer", "Dauer ab jetzt", tx, wx, "")
		d.feld("grund", "Grund", desktop.FeldText, "z. B. Patchday")
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		n, _ := strconv.Atoi(d.werte["dauer"])
		grund := strings.TrimSpace(d.werte["grund"])
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.WartungSetzen(ctx, art, id, n, grund) }, fertig)
	}
	if d.zeigen() {
		a.gemacht("Wartung gestartet.")
	}
}

func (a *app) bestaetigen(alarm, titel, meldungText string) {
	f := a.f
	d := neuerDialog(f.hwnd, "Alarm bestätigen")
	d.okText = "Alarm bestätigen"
	d.einleitung = titel
	if meldungText != "" {
		d.einleitung += "\n" + desktop.Kuerzen(meldungText, 160)
	}
	d.aufbau = func(d *dialog) {
		d.feld("kommentar", "Kommentar", desktop.FeldText, "optional, z. B. wer sich kümmert")
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		k := strings.TrimSpace(d.werte["kommentar"])
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.AlarmBestaetigen(ctx, alarm, k) }, fertig)
	}
	if d.zeigen() {
		a.gemacht("Alarm bestätigt.")
	}
}

// bestaetigenFrage: Rückfrage ohne Gefahr (z. B. „Im Browser öffnen“).
func bestaetigenFrage(owner syscall.Handle, titel, text, knopf string) bool {
	d := neuerDialog(owner, titel)
	d.einleitung, d.okText = text, knopf
	d.aufbau = func(*dialog) {}
	return d.zeigen()
}

// ueber: Version, Herkunft und Lizenzen (die OFL verlangt, dass die
// Lizenztexte mit den Schriften weitergegeben werden: openwacht-desktop
// lizenzen legt sie ab).
func (a *app) ueber() {
	d := neuerDialog(a.f.hwnd, "OpenWacht Desktop")
	d.einleitung = version.String("openwacht-desktop") + "\n\n" +
		"Open-Source-Monitoring aus Europa, AGPL-3.0-only.\n" +
		"Schriften: D-DIN, © 2017 Datto Inc.; JetBrains Mono, © 2020 The JetBrains Mono Project Authors; " +
		"beide unter der SIL Open Font License 1.1. Die Lizenztexte legt „openwacht-desktop lizenzen“ ab."
	d.okText = "Lizenztexte ablegen"
	d.aufbau = func(*dialog) {}
	if d.zeigen() {
		lizenzenAblegen()
	}
}
