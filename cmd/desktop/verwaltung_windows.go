// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite Benutzer und Mandanten wie web/src/Verwaltung.tsx mit den Reitern
// Mandanten, Benutzer, Agent-Tokens, Agent-Updates (web/src/AgentUpdates.tsx),
// API-Tokens (web/src/ApiTokens.tsx) und Anmeldung über AD und SSO
// (web/src/Verzeichnisse.tsx). Der Mandant ist der in der Seitenleiste
// gewählte. Heikle Änderungen (API-Token, Anbindungen) verlangen wie im Web
// den Code aus der Authenticator-App bzw. das eigene Passwort. Verwalten geht
// nur mit Anmeldung über ein Konto; ein API-Token darf das nicht.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

var verwReiter = []string{"Mandanten", "Benutzer", "Agent-Tokens", "Agent-Updates", "API-Tokens", "Anmeldung (AD, SSO)"}

var verw = struct{ unter int }{}

var rollenName = map[string]string{"leser": "Leser", "operator": "Operator", "admin": "Admin"}

type ich struct {
	ID          string `json:"id"`
	ZweiFaktor  bool   `json:"zwei_faktor_aktiv"`
	Betreiber   bool   `json:"betreiber"`
	Anzeigename string `json:"anzeigename"`
}

type antrag struct {
	ID              string     `json:"id"`
	Mandant         string     `json:"mandant"`
	Name            string     `json:"name"`
	Begruendung     string     `json:"begruendung"`
	Zustand         string     `json:"zustand"`
	BeantragtVon    string     `json:"beantragt_von"`
	BeantragtAm     time.Time  `json:"beantragt_am"`
	EntschiedenVon  string     `json:"entschieden_von"`
	EntschiedenAm   *time.Time `json:"entschieden_am"`
	Notiz           string     `json:"notiz"`
	DarfEntscheiden bool       `json:"darf_entscheiden"`
}

type benutzer struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Anzeigename string     `json:"anzeigename"`
	Deaktiviert bool       `json:"deaktiviert"`
	LoeschtAm   *time.Time `json:"loescht_am"`
	ZweiFaktor  bool       `json:"zwei_faktor_aktiv"`
	Verzeichnis bool       `json:"verzeichnis"`
	Rollen      []struct {
		MandantID string `json:"mandant_id"`
		Rolle     string `json:"rolle"`
	} `json:"rollen"`
}

type agentToken struct {
	ID        string    `json:"id"`
	Notiz     string    `json:"notiz"`
	Rest      int       `json:"restanzahl"`
	LaeuftAb  time.Time `json:"laeuft_ab"`
	Erstellt  time.Time `json:"erstellt"`
	MandantID string    `json:"-"`
}

type apiToken struct {
	ID          string     `json:"id"`
	MandantName string     `json:"mandant_name"`
	Name        string     `json:"name"`
	Rolle       string     `json:"rolle"`
	Ablauf      time.Time  `json:"ablauf"`
	Angelegt    time.Time  `json:"angelegt"`
	Zuletzt     *time.Time `json:"zuletzt"`
	Widerrufen  *time.Time `json:"widerrufen"`
	Von         string     `json:"von"`
	Gueltig     bool       `json:"gueltig"`
}

type updates struct {
	Schluesselbund []struct {
		Kennung string `json:"kennung"`
		Zustand string `json:"zustand"`
	} `json:"schluesselbund"`
	Widerrufen []struct {
		Kennung string    `json:"kennung"`
		Durch   string    `json:"durch"`
		Version string    `json:"version"`
		Am      time.Time `json:"am"`
	} `json:"widerrufen"`
	Pakete []struct {
		ID        string `json:"id"`
		Version   string `json:"version"`
		Plattform string `json:"plattform"`
		SHA256    string `json:"sha256"`
		Groesse   int64  `json:"groesse"`
	} `json:"pakete"`
	Agents []struct {
		ID          string     `json:"id"`
		Mandant     string     `json:"mandant"`
		Hostname    string     `json:"hostname"`
		Version     string     `json:"version"`
		Plattform   string     `json:"plattform"`
		Fehler      string     `json:"fehler"`
		Zuletzt     *time.Time `json:"zuletzt"`
		Freigegeben *string    `json:"freigegeben"`
		Automatisch bool       `json:"automatisch"`
	} `json:"agents"`
}

type autoRegel struct {
	MandantID   string  `json:"mandant_id"`
	Aktiv       bool    `json:"aktiv"`
	Pilotgruppe *string `json:"pilotgruppe"`
	Wartezeit   int     `json:"wartezeit_stunden"`
	Tage        []int   `json:"tage"`
	Von         int     `json:"von"`
	Bis         int     `json:"bis"`
}

type vzGruppe struct {
	Gruppe  string `json:"gruppe"`
	Mandant string `json:"mandant"`
	Rolle   string `json:"rolle"`
}

type anbindung struct {
	ID             string            `json:"id"`
	Art            string            `json:"art"`
	Mandant        string            `json:"mandant"`
	MandantName    string            `json:"mandant_name"`
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	EigeneCA       bool              `json:"eigene_ca"`
	BindDN         string            `json:"bind_dn"`
	BaseDN         string            `json:"base_dn"`
	NetBIOS        *string           `json:"netbios"`
	Verschachtelt  bool              `json:"verschachtelt"`
	ZweiFaktor     bool              `json:"zwei_faktor"`
	Aktiv          bool              `json:"aktiv"`
	Domaenen       []string          `json:"domaenen"`
	Gruppen        []vzGruppe        `json:"gruppen"`
	Konten         int               `json:"konten"`
	AdressClaim    string            `json:"adress_claim"`
	DomaenenStatus map[string]string `json:"domaenen_status"`
	NetBIOSStatus  string            `json:"netbios_status"`
	SitzungStunden int               `json:"sitzung_stunden"`
}

type verwDaten struct {
	unter, mandant string
	ich            *ich
	antraege       []antrag
	benutzer       []benutzer
	tokens         []agentToken
	updates        *updates
	auto           *autoRegel
	api            []apiToken
	vz             []anbindung
	rueckkehr      string
	test           map[string]string
}

func init() {
	seiten[seiteVerwaltung] = &seitenDef{laden: verwLaden, malen: verwMalen, klick: verwKlick}
}

func verwSchluessel(f *fenster) string { return itoa(verw.unter) + "|" + f.mandant }

func verwLaden(ctx context.Context, cl desktop.Client, f *fenster) (any, error) {
	d := verwDaten{unter: itoa(verw.unter), mandant: f.mandant, test: map[string]string{}}
	if cl.Sitzung == nil {
		return d, nil // mit API-Token keine Verwaltung
	}
	var i ich
	if err := cl.Anfrage(ctx, http.MethodGet, "/api/v1/ich", nil, &i); err != nil {
		return nil, err
	}
	d.ich = &i
	get := func(pfad string, out any) error { return cl.Anfrage(ctx, http.MethodGet, pfad, nil, out) }
	switch verw.unter {
	case 0:
		var r struct {
			Antraege []antrag `json:"antraege"`
		}
		if err := get("/api/v1/mandanten-antraege", &r); err != nil {
			return nil, err
		}
		d.antraege = r.Antraege
	case 1:
		var r struct {
			Benutzer []benutzer `json:"benutzer"`
		}
		if err := get("/api/v1/benutzer?mandant="+url.QueryEscape(f.mandant), &r); err != nil {
			return nil, err
		}
		d.benutzer = r.Benutzer
	case 2:
		ids, _, rolle := a.bereich()
		for id := range ids {
			if !desktop.DarfAendern(rolle(id)) {
				continue
			}
			var r struct {
				Tokens []agentToken `json:"tokens"`
			}
			if err := get("/api/v1/mandanten/"+id+"/agent-tokens", &r); err != nil {
				return nil, err
			}
			for _, t := range r.Tokens {
				t.MandantID = id
				d.tokens = append(d.tokens, t)
			}
		}
		sort.Slice(d.tokens, func(i, j int) bool { return d.tokens[i].Erstellt.After(d.tokens[j].Erstellt) })
	case 3:
		var u updates
		if err := get("/api/v1/agent-updates", &u); err != nil {
			return nil, err
		}
		d.updates = &u
		var r struct {
			Regeln []autoRegel `json:"regeln"`
		}
		if err := get("/api/v1/agent-updates/automatik", &r); err != nil {
			return nil, err
		}
		d.auto = &autoRegel{MandantID: f.mandant, Wartezeit: 24, Tage: []int{1, 2, 3, 4, 5, 6, 7}}
		for _, x := range r.Regeln {
			if x.MandantID == f.mandant {
				x := x
				d.auto = &x
			}
		}
	case 4:
		var r struct {
			Tokens []apiToken `json:"tokens"`
		}
		if err := get("/api/v1/api-tokens", &r); err != nil {
			return nil, err
		}
		d.api = r.Tokens
	case 5:
		var r struct {
			Verzeichnisse []anbindung `json:"verzeichnisse"`
			Rueckkehr     string      `json:"sso_rueckkehr"`
		}
		if err := get("/api/v1/verzeichnisse", &r); err != nil {
			return nil, err
		}
		d.vz, d.rueckkehr = r.Verzeichnisse, r.Rueckkehr
	}
	return d, nil
}

func tag(t time.Time) string { return t.Local().Format("02.01.2006") }

func verwMalen(m *maler, daten any) {
	f := m.f
	m.umschalter(verwReiter, verw.unter, "reiter")
	if !a.cfg.MitKonto() {
		m.leer("Benutzer und Mandanten verwaltest du in der App nur mit Anmeldung über dein Konto (links unten „Abmelden“, " +
			"dann „Konto (wie im Browser)“). Ein API-Token darf nicht verwalten; im Browser geht es immer.")
		return
	}
	d, ok := daten.(verwDaten)
	if !ok || d.unter != itoa(verw.unter) || d.mandant != f.mandant {
		m.klein("Lädt …")
		return
	}
	_, mehrere, rolle := a.bereich()
	admin := rolle(f.mandant) == "admin"
	name := a.mandantName(f.mandant)
	switch verw.unter {
	case 0:
		verwMandant(m, d, admin, name, rolle)
	case 1:
		var kopf []sKnopf
		if admin {
			kopf = append(kopf, sKnopf{text: "Benutzer anlegen", art: "bneu"})
		}
		m.panel("Benutzer in "+name, kopf...)
		if len(d.benutzer) == 0 {
			m.leer(map[bool]string{true: "Noch keine Benutzer. Lege den ersten über „Benutzer anlegen“ an.",
				false: "Keine Benutzer in diesem Mandanten."}[admin])
		} else {
			var tab [][]sZelle
			for _, b := range d.benutzer {
				hier := ""
				for _, r := range b.Rollen {
					if r.MandantID == f.mandant {
						hier = r.Rolle
					}
				}
				rText := rollenName[hier]
				if rText == "" {
					rText = "keine"
				}
				anm := "nur Passwort"
				switch {
				case b.Deaktiviert:
					anm = "deaktiviert"
					if b.LoeschtAm != nil {
						anm += ", wird am " + tag(*b.LoeschtAm) + " gelöscht"
					}
				case b.Verzeichnis && b.ZweiFaktor:
					anm = "AD und App"
				case b.Verzeichnis:
					anm = "AD"
				case b.ZweiFaktor:
					anm = "Passwort und App"
				}
				zn := sZelle{text: b.Anzeigename, fett: true, klein: b.Email}
				if b.Deaktiviert {
					zn.farbe = th.f.Leise
				}
				var k []sKnopf
				selbst := d.ich != nil && b.ID == d.ich.ID
				switch {
				case !admin:
				case selbst:
					zn.klein += " · du selbst"
				default:
					if !b.Verzeichnis {
						k = append(k, sKnopf{text: "Rolle …", art: "brolle", wert: b.ID}, sKnopf{text: "Passwort …", art: "bpasswort", wert: b.ID})
					}
					k = append(k, sKnopf{text: map[bool]string{true: "Aktivieren", false: "Deaktivieren"}[b.Deaktiviert], art: "baktiv", wert: b.ID})
					if b.Deaktiviert {
						k = append(k, sKnopf{text: "Löschen …", art: "bloeschen", wert: b.ID, stil: kGefahr})
					}
				}
				tab = append(tab, []sZelle{zn, {text: rText}, {text: anm}, {knoepfe: k}})
			}
			m.tabelle([]sSpalte{{"Name", 30, false}, {"Rolle hier", 12, false}, {"Anmeldung", 20, false}, {"", 38, false}}, tab)
		}
		m.klein("Benutzer gehören einem Mandanten; ihre Rolle gilt dort und in allen Mandanten darunter. Konten aus dem AD " +
			"bekommen ihre Rechte aus den AD-Gruppen.")
		m.ende()
	case 2:
		m.panel("Offene Agent-Tokens")
		m.klein("Neue Tokens erzeugst du unter Hosts › „Host hinzufügen“ oder beim Gerät mit „Agent hinzufügen“ (im Browser). " +
			"Hier siehst du alle, die noch gelten, und kannst sie widerrufen.")
		switch {
		case len(d.tokens) == 0:
			m.leer("Keine offenen Tokens.")
		default:
			var tab [][]sZelle
			for _, t := range d.tokens {
				n := t.Notiz
				if n == "" {
					n = "ohne Notiz"
				}
				z := sZelle{text: n}
				if mehrere {
					z.klein = a.mandantName(t.MandantID)
				}
				tab = append(tab, []sZelle{z, {text: itoa(t.Rest) + "×"}, {text: t.LaeuftAb.Local().Format("02.01.06, 15:04")},
					{knoepfe: []sKnopf{{text: "Widerrufen", art: "atwiderruf", wert: t.ID, stil: kGefahr}}}})
			}
			m.tabelle([]sSpalte{{"Notiz", 40, false}, {"Noch", 12, false}, {"Gilt bis", 22, false}, {"", 26, false}}, tab)
		}
		m.ende()
	case 3:
		verwUpdates(m, d, admin, mehrere, rolle)
	case 4:
		var kopf []sKnopf
		if admin {
			kopf = append(kopf, sKnopf{text: "Token anlegen", art: "apineu"})
		}
		m.panel("API-Tokens", kopf...)
		m.klein("Für Skripte und andere Werkzeuge: Anfragen an /api/v1/… mit dem Kopf „Authorization: Bearer owt1.…“. Ein Token " +
			"sieht und darf, was seine Rolle im Mandanten und darunter erlaubt; Verwaltung und Einstellungen gehen damit nicht.")
		if !admin {
			m.leer("Nur Admins des Mandanten legen API-Tokens an.")
		}
		if len(d.api) == 0 {
			if admin {
				m.leer("Noch keine API-Tokens.")
			}
		} else {
			var tab [][]sZelle
			jetzt := time.Now()
			for _, t := range d.api {
				k := "angelegt " + tag(t.Angelegt)
				if t.Von != "" {
					k += " von " + t.Von
				}
				bis := tag(t.Ablauf)
				switch {
				case t.Widerrufen != nil:
					bis = "widerrufen"
				case !t.Gueltig:
					bis = "abgelaufen"
				}
				zul := "nie"
				if t.Zuletzt != nil {
					zul = desktop.Vor(*t.Zuletzt, jetzt)
				}
				var kn []sKnopf
				if t.Gueltig {
					kn = []sKnopf{{text: "Widerrufen", art: "apiwiderruf", wert: t.ID, stil: kGefahr}}
				}
				z := sZelle{text: t.Name, fett: true, klein: k}
				if !t.Gueltig {
					z.farbe = th.f.Leise
				}
				tab = append(tab, []sZelle{z, {text: t.MandantName}, {text: rollenName[t.Rolle]}, {text: bis}, {text: zul}, {knoepfe: kn}})
			}
			m.tabelle([]sSpalte{{"Name", 26, false}, {"Mandant", 16, false}, {"Rolle", 10, false}, {"Gültig bis", 13, false},
				{"Zuletzt benutzt", 15, false}, {"", 20, false}}, tab)
		}
		m.ende()
	case 5:
		verwAnmeldung(m, d, admin, name)
	}
}

func verwMandant(m *maler, d verwDaten, admin bool, name string, rolle func(string) string) {
	f := m.f
	a.mu.Lock()
	ms := a.stand.Mandanten
	a.mu.Unlock()
	var eltern *desktop.Mandant
	hauptAdmin := false
	for i := range ms {
		if ms[i].Ueber == nil && ms[i].Rolle == "admin" {
			hauptAdmin = true
		}
	}
	for i := range ms {
		if ms[i].ID == f.mandant && ms[i].Ueber != nil {
			for j := range ms {
				if ms[j].ID == *ms[i].Ueber {
					eltern = &ms[j]
				}
			}
		}
	}
	m.panel(name)
	if eltern != nil {
		m.klein("Unter " + eltern.Name)
	}
	r := rollenName[rolle(f.mandant)]
	if r == "" {
		r = "keine"
	}
	m.text("Deine Rolle hier: "+r+". Den Mandanten wählst du links oben.", f.sch.t13, th.f.Tinte)
	var k []sKnopf
	if hauptAdmin && admin {
		k = append(k, sKnopf{text: "Untermandant anlegen", art: "mneu"})
	}
	if !hauptAdmin && admin {
		k = append(k, sKnopf{text: "Untermandant beantragen", art: "mantrag"})
	}
	if admin {
		k = append(k, sKnopf{text: "Umbenennen", art: "mumbenennen"}, sKnopf{text: "Rezertifizierung (PDF)", art: "mrezpdf"},
			sKnopf{text: "Rezertifizierung (CSV)", art: "mrezcsv"})
	}
	if eltern != nil && eltern.Rolle == "admin" {
		k = append(k, sKnopf{text: "Löschen", art: "mloeschen", stil: kGefahr})
	}
	if len(k) > 0 {
		m.abstand(4)
		m.knoepfe(k...)
	}
	m.ende()
	if len(d.antraege) > 0 {
		m.panel("Anträge auf Untermandanten")
		zText := map[string]string{"beantragt": "offen", "freigegeben": "freigegeben", "abgelehnt": "abgelehnt"}
		var tab [][]sZelle
		for _, x := range d.antraege {
			z := sZelle{text: zText[x.Zustand]}
			if x.EntschiedenVon != "" {
				z.klein = x.EntschiedenVon
				if x.EntschiedenAm != nil {
					z.klein += " · " + tag(*x.EntschiedenAm)
				}
				if x.Notiz != "" {
					z.klein += " · " + x.Notiz
				}
			}
			var kn []sKnopf
			if x.DarfEntscheiden {
				kn = []sKnopf{{text: "Freigeben …", art: "afrei", wert: x.ID, stil: kHaupt}, {text: "Ablehnen …", art: "aab", wert: x.ID, stil: kGefahr}}
			}
			tab = append(tab, []sZelle{{text: x.Name, fett: true, klein: x.Begruendung}, {text: x.Mandant},
				{text: x.BeantragtVon + " · " + tag(x.BeantragtAm)}, z, {knoepfe: kn}})
		}
		m.tabelle([]sSpalte{{"Neuer Mandant", 24, false}, {"Unter", 15, false}, {"Beantragt", 21, false}, {"Zustand", 16, false},
			{"", 24, false}}, tab)
		m.ende()
	}
}

func verwUpdates(m *maler, d verwDaten, admin, mehrere bool, rolle func(string) string) {
	f := m.f
	u := d.updates
	if u == nil {
		return
	}
	m.panel("Agent-Updates")
	t := "Agents installieren nur Versionen, die mit dem Offline-Schlüssel signiert sind, und nur nach Freigabe hier. "
	if len(u.Schluesselbund) > 0 {
		var l []string
		for _, k := range u.Schluesselbund {
			l = append(l, k.Kennung+" ("+k.Zustand+")")
		}
		t += "Schlüssel dieses Builds: " + strings.Join(l, ", ") + ". "
	} else {
		t += "In diesem Build ist kein Update-Schlüssel eingetragen: Agent-Updates sind aus. "
	}
	t += "Agents vor 0.23 brauchen einmal „openwacht-agent updates-einrichten“ (root bzw. Administrator)."
	m.klein(t)
	for _, w := range u.Widerrufen {
		m.klein(fmt.Sprintf("Widerrufen: %s durch %s mit Version %s am %s. Pakete dieses Schlüssels werden nicht mehr angeboten.",
			w.Kennung, w.Durch, w.Version, tag(w.Am)))
	}
	// Automatik
	r := d.auto
	auto := "aus"
	if r.Aktiv {
		var tg []string
		for _, x := range r.Tage {
			if x >= 1 && x <= 7 {
				tg = append(tg, []string{"Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"}[x-1])
			}
		}
		fenster := fmt.Sprintf("%02d:00–%02d:00", r.Von, r.Bis)
		if r.Von == r.Bis {
			fenster = "ganzer Tag"
		}
		auto = fmt.Sprintf("an, Wartezeit %d Std., %s, %s", r.Wartezeit, strings.Join(tg, " "), fenster)
	}
	m.text("Automatisch übernehmen ("+a.mandantName(f.mandant)+"): "+auto, f.sch.t13, th.f.Tinte)
	var k []sKnopf
	if admin {
		k = append(k, sKnopf{text: "Automatik …", art: "uauto"})
	}
	ids, _, _ := a.bereich()
	nAdmin := 0
	for _, ag := range u.Agents {
		if ids[ag.Mandant] && rolle(ag.Mandant) == "admin" {
			nAdmin++
		}
	}
	if nAdmin > 0 {
		k = append(k, sKnopf{text: "Freigeben oder zurücknehmen …", art: "ufrei", stil: kHaupt})
	}
	if len(k) > 0 {
		m.knoepfe(k...)
	}
	var tab [][]sZelle
	jetzt := time.Now()
	for _, ag := range u.Agents {
		if !ids[ag.Mandant] {
			continue
		}
		pl := ag.Plattform
		if pl == "" {
			pl = "Plattform unbekannt (Agent vor 0.23)"
		}
		if mehrere {
			pl = a.mandantName(ag.Mandant) + " · " + pl
		}
		ver := ag.Version
		if ver == "" {
			ver = "–"
		}
		frei := sZelle{text: "–"}
		if ag.Freigegeben != nil {
			frei.text = *ag.Freigegeben
			if ag.Automatisch {
				frei.klein = "automatisch"
			}
		}
		zu := sZelle{}
		switch {
		case ag.Fehler != "":
			zu.text, zu.farbe = ag.Fehler, th.f.TextWarn
		case ag.Freigegeben != nil && versionNeuer(*ag.Freigegeben, ag.Version):
			zu.text = "wird beim nächsten Melden aktualisiert"
		case ag.Freigegeben != nil:
			zu.text = "aktuell"
		}
		if ag.Zuletzt != nil {
			zu.klein = "gemeldet " + desktop.Vor(*ag.Zuletzt, jetzt)
			if zu.text == "" {
				zu.text, zu.klein = zu.klein, ""
			}
		}
		tab = append(tab, []sZelle{{text: ag.Hostname, fett: true, klein: pl}, {text: ver}, frei, zu})
	}
	if len(tab) == 0 {
		m.leer("Keine Agents in diesem Bereich.")
	} else {
		m.tabelle([]sSpalte{{"Rechner", 34, false}, {"Version", 14, false}, {"Freigegeben", 16, false}, {"Zustand", 36, false}}, tab)
	}
	m.ende()
	if d.ich != nil && d.ich.Betreiber {
		var kk []sKnopf
		for _, s := range u.Schluesselbund {
			if s.Zustand != "widerrufen" {
				kk = []sKnopf{{text: "Paket hochladen …", art: "uhoch"}}
			}
		}
		m.panel("Pakete (Betreiber)", kk...)
		if len(u.Pakete) == 0 {
			m.leer("Noch keine Pakete.")
		} else {
			var tp [][]sZelle
			for _, p := range u.Pakete {
				tp = append(tp, []sZelle{{text: p.Version}, {text: p.Plattform}, {text: komma(float64(p.Groesse)/1048576) + " MB"},
					{text: p.SHA256[:min(16, len(p.SHA256))] + "…", farbe: th.f.Leise},
					{knoepfe: []sKnopf{{text: "Löschen", art: "upaketweg", wert: p.ID, stil: kGefahr}}}})
			}
			m.tabelle([]sSpalte{{"Version", 15, false}, {"Plattform", 20, false}, {"Größe", 12, false}, {"SHA-256", 28, false}, {"", 25, false}}, tp)
		}
		m.ende()
	}
}

// versionNeuer: a > b bei „x.y.z“ (wie neuer() im Web).
func versionNeuer(a, b string) bool {
	p := func(v string) []int {
		t := strings.Split(v, ".")
		if len(t) != 3 {
			return nil
		}
		out := make([]int, 3)
		for i, x := range t {
			n, err := strconv.Atoi(x)
			if err != nil {
				return nil
			}
			out[i] = n
		}
		return out
	}
	x, y := p(a), p(b)
	if x == nil {
		return false
	}
	if y == nil {
		return true
	}
	for i := 0; i < 3; i++ {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

func verwAnmeldung(m *maler, d verwDaten, admin bool, name string) {
	f := m.f
	var kopf []sKnopf
	if admin {
		kopf = append(kopf, sKnopf{text: "AD anbinden", art: "vzneu"}, sKnopf{text: "SSO (OIDC) anbinden", art: "vzneuoidc"})
	}
	m.panel("Anmeldung über AD und SSO für "+name, kopf...)
	m.klein("Benutzer melden sich mit ihrem AD-Konto an (name@domäne oder DOMÄNE\\name) oder per Firmen-Login (OIDC: Keycloak, " +
		"ADFS, Entra ID) über „Mit Firmen-Login anmelden“ im Browser. Mitglieder der zugeordneten AD-Gruppen bekommen das Konto " +
		"beim ersten Anmelden; Rechte, Sperre und Name gleicht OpenWacht stündlich mit dem AD ab. Der Verzeichnisdienst muss in " +
		"der Netzfreigabe liegen. Lokale Konten mit gleicher Adresse gehen vor.")
	if !admin {
		m.leer("Nur Admins des Mandanten richten die Anmeldung über AD ein.")
		m.ende()
		return
	}
	var liste []anbindung
	for _, x := range d.vz {
		if x.Mandant == f.mandant {
			liste = append(liste, x)
		}
	}
	for _, x := range d.vz {
		if x.Mandant != f.mandant {
			liste = append(liste, x)
		}
	}
	if len(liste) == 0 {
		m.leer("Noch keine Anbindung.")
	}
	m.ende()
	for _, x := range liste {
		m.panel(x.Name + map[bool]string{true: "", false: " (aus)"}[x.Aktiv])
		konten := fmt.Sprintf("%d Konten", x.Konten)
		if x.Konten == 1 {
			konten = "1 Konto"
		}
		m.klein(x.MandantName + " · " + konten)
		oidc := x.Art == "oidc"
		var namen []string
		for _, dm := range x.Domaenen {
			namen = append(namen, "name@"+dm+freigabeText(x.DomaenenStatus[dm]))
		}
		if x.NetBIOS != nil && *x.NetBIOS != "" {
			namen = append(namen, *x.NetBIOS+"\\name"+freigabeText(x.NetBIOSStatus))
		}
		zeilen := [][2]string{
			{map[bool]string{true: "Issuer (OIDC)", false: "Server (LDAP)"}[oidc], x.URL},
			{"Anmeldung mit", strings.Join(namen, ", ")},
			{map[bool]string{true: "Client-ID", false: "Dienstkonto"}[oidc], x.BindDN},
			{map[bool]string{true: "Gruppen-Claim", false: "Suchbasis"}[oidc], x.BaseDN},
		}
		if oidc {
			zeilen = append(zeilen, [2]string{"Adresse aus Claim", x.AdressClaim})
		}
		zeilen = append(zeilen, [2]string{"Zwei-Faktor", map[bool]string{true: "Pflicht (Code aus der App zusätzlich zum AD-Passwort)", false: "nicht verlangt"}[x.ZweiFaktor]})
		sz := "12 Std. (Standard)"
		if x.SitzungStunden > 0 {
			sz = itoa(x.SitzungStunden) + " Std."
		}
		zeilen = append(zeilen, [2]string{"Sitzung höchstens", sz})
		for _, z := range zeilen {
			m.eigenschaft(z[0], z[1])
		}
		if len(x.Gruppen) == 0 {
			m.leer("Keine Gruppen zugeordnet: Niemand kann sich anmelden.")
		} else {
			var tab [][]sZelle
			for _, g := range x.Gruppen {
				tab = append(tab, []sZelle{{text: g.Gruppe}, {text: a.mandantName(g.Mandant)}, {text: rollenName[g.Rolle]}})
			}
			m.tabelle([]sSpalte{{map[bool]string{true: "Gruppe", false: "AD-Gruppe"}[oidc], 60, false}, {"Mandant", 25, false}, {"Rolle", 15, false}}, tab)
		}
		if t := d.test[x.ID]; t != "" {
			m.text(t, f.sch.t13, th.f.Tinte)
		}
		m.knoepfe(sKnopf{text: "Verbindung testen", art: "vztest", wert: x.ID}, sKnopf{text: "Bearbeiten", art: "vzbearbeiten", wert: x.ID},
			sKnopf{text: "Löschen …", art: "vzloeschen", wert: x.ID, stil: kGefahr})
		m.ende()
	}
}

func freigabeText(s string) string {
	switch s {
	case "beantragt":
		return " (beantragt)"
	case "abgelehnt":
		return " (abgelehnt)"
	}
	return ""
}

// eigenschaft: Zeile wie dl.eigenschaften (Begriff leise, Wert daneben).
func (m *maler) eigenschaft(begriff, wert string) {
	l, r := m.innen()
	bw := m.s(160)
	h := max(hoeheText(m.hdc, wert, m.f.sch.t13, r-l-bw), m.s(18))
	if m.zeichnen {
		schreiben(m.hdc, begriff, rect{l, m.y, l + bw, m.y + m.s(18)}, m.f.sch.t13, th.f.Leise, 0)
		schreiben(m.hdc, wert, rect{l + bw, m.y, r, m.y + h}, m.f.sch.t13, th.f.Tinte, dtWordBreak)
	}
	m.y += h + m.s(6)
}

// --- Klicks ----------------------------------------------------------------------

func verwKlick(z ziel, daten any) {
	f := a.f
	d, _ := daten.(verwDaten)
	mandant := f.mandant
	name := a.mandantName(mandant)
	neu := func(gut string) func(error) {
		return func(err error) {
			if err != nil {
				hinweis(f.hwnd, "Benutzer und Mandanten", fehlerText(err), true)
				return
			}
			if gut != "" {
				setStatusText(f, gut)
			}
			a.seiteNeu(seiteVerwaltung)
		}
	}
	aufruf := func(methode, pfad string, body any, gut string) {
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.Anfrage(ctx, methode, pfad, body, nil) }, neu(gut))
	}
	switch z.art {
	case "reiter":
		n, _ := strconv.Atoi(z.wert)
		if n != verw.unter {
			verw.unter = n
			f.seitenOff = 0
			a.seiteNeu(seiteVerwaltung)
		}
	// Mandanten
	case "mneu":
		if n, ok := textDialog("Untermandant anlegen", "Name des neuen Mandanten unter "+name, "", "Anlegen"); ok {
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
				return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten", map[string]string{"uebergeordnet_id": mandant, "name": n}, nil)
			}, func(err error) {
				neu("Mandant „" + n + "“ angelegt.")(err)
				a.jetztAbfragen()
			})
		}
	case "mantrag":
		dd := neuerDialog(f.hwnd, "Untermandant beantragen")
		dd.okText = "Beantragen"
		dd.aufbau = func(dd *dialog) {
			dd.einleitung = "Ein Admin des Hauptmandanten entscheidet; der Antrag steht danach unter „Mandanten“."
			dd.feld("name", "Name des neuen Mandanten unter "+name, desktop.FeldText, "")
			dd.feld("grund", "Begründung (optional)", desktop.FeldText, "")
		}
		dd.speichern = func(dd *dialog, fertig func(error)) {
			body := map[string]string{"name": strings.TrimSpace(dd.werte["name"]), "begruendung": strings.TrimSpace(dd.werte["grund"])}
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
				return cl.Anfrage(ctx, http.MethodPost, "/api/v1/mandanten/"+mandant+"/antraege", body, nil)
			}, fertig)
		}
		if dd.zeigen() {
			neu("Antrag gestellt.")(nil)
		}
	case "mumbenennen":
		if n, ok := textDialog("Mandant umbenennen", "Name", name, "Umbenennen"); ok {
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
				return cl.Anfrage(ctx, http.MethodPatch, "/api/v1/mandanten/"+mandant, map[string]string{"name": n}, nil)
			}, func(err error) {
				neu("Umbenannt.")(err)
				a.jetztAbfragen()
			})
		}
	case "mrezpdf", "mrezcsv":
		format := map[string]string{"mrezpdf": "pdf", "mrezcsv": "csv"}[z.art]
		var b []byte
		dname := "OpenWacht-Rezertifizierung-" + dateiName(name) + "-" + time.Now().Format("2006-01-02") + "." + format
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodGet, "/api/v1/mandanten/"+mandant+"/rezertifizierung?format="+format, nil, &b)
		}, func(err error) {
			if err == nil {
				var pfad string
				if pfad, err = downloadsSchreiben(dname, b); err == nil {
					setStatusText(f, "Gespeichert: "+pfad)
					pShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16("open"))), uintptr(unsafe.Pointer(utf16(pfad))), 0, 0, swShowNormal)
					return
				}
			}
			hinweis(f.hwnd, "Rezertifizierung", fehlerText(err), true)
		})
	case "mloeschen":
		if bestaetigenDialog(f.hwnd, "„"+name+"“ löschen?", "Das geht nur, solange der Mandant keine Untermandanten, Benutzer "+
			"oder Einträge im Audit-Log hat.", "Endgültig löschen") {
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
				return cl.Anfrage(ctx, http.MethodDelete, "/api/v1/mandanten/"+mandant, nil, nil)
			}, func(err error) {
				neu("Mandant gelöscht.")(err)
				a.jetztAbfragen()
			})
		}
	case "afrei", "aab":
		frei := z.art == "afrei"
		n, ok := textDialog(map[bool]string{true: "Antrag freigeben", false: "Antrag ablehnen"}[frei], "Notiz (optional)", "",
			map[bool]string{true: "Freigeben", false: "Ablehnen"}[frei])
		if ok {
			aufruf(http.MethodPost, "/api/v1/mandanten-antraege/"+z.wert+"/"+map[bool]string{true: "freigeben", false: "ablehnen"}[frei],
				map[string]string{"notiz": n}, "Entschieden.")
			if frei {
				a.jetztAbfragen()
			}
		}
	// Benutzer
	case "bneu":
		benutzerAnlegen(mandant, name)
	case "brolle", "bpasswort", "baktiv", "bloeschen":
		var b *benutzer
		for i := range d.benutzer {
			if d.benutzer[i].ID == z.wert {
				b = &d.benutzer[i]
			}
		}
		if b == nil {
			return
		}
		switch z.art {
		case "brolle":
			hier := ""
			for _, r := range b.Rollen {
				if r.MandantID == mandant {
					hier = r.Rolle
				}
			}
			dd := neuerDialog(f.hwnd, "Rolle von "+b.Anzeigename)
			dd.werte["rolle"] = hier
			dd.aufbau = func(dd *dialog) {
				dd.auswahl("rolle", "Rolle in "+name, []string{"keine", "Leser", "Operator", "Admin"}, []string{"", "leser", "operator", "admin"},
					"gilt dort und in allen Mandanten darunter")
			}
			dd.speichern = func(dd *dialog, fertig func(error)) {
				v := dd.werte["rolle"]
				a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
					if v == "" {
						return cl.Anfrage(ctx, http.MethodDelete, "/api/v1/benutzer/"+b.ID+"/rollen/"+mandant, nil, nil)
					}
					return cl.Anfrage(ctx, http.MethodPut, "/api/v1/benutzer/"+b.ID+"/rollen/"+mandant, map[string]string{"rolle": v}, nil)
				}, fertig)
			}
			if dd.zeigen() {
				neu("Rolle gespeichert.")(nil)
			}
		case "bpasswort":
			dd := neuerDialog(f.hwnd, "Passwort für "+b.Anzeigename)
			dd.einleitung = "Neues Passwort (mindestens 12 Zeichen), bitte sicher übergeben. „Setzen und kopieren“ legt es in die Zwischenablage."
			dd.okText = "Setzen und kopieren"
			dd.werte["pw"] = startPasswort()
			dd.aufbau = func(dd *dialog) { dd.feld("pw", "Neues Passwort", desktop.FeldText, "") }
			dd.speichern = func(dd *dialog, fertig func(error)) {
				pw := dd.werte["pw"]
				a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
					return cl.Anfrage(ctx, http.MethodPut, "/api/v1/benutzer/"+b.ID+"/passwort", map[string]string{"passwort": pw}, nil)
				}, func(err error) {
					if err == nil {
						err = zwischenablage(dd.hwnd, pw)
					}
					fertig(err)
				})
			}
			if dd.zeigen() {
				setStatusText(f, "Passwort gesetzt und kopiert.")
			}
		case "baktiv":
			aufruf(http.MethodPatch, "/api/v1/benutzer/"+b.ID, map[string]bool{"deaktiviert": !b.Deaktiviert},
				map[bool]string{true: "Aktiviert.", false: "Deaktiviert."}[b.Deaktiviert])
		case "bloeschen":
			if bestaetigenDialog(f.hwnd, "Konto "+b.Email+" löschen?", "Endgültig löschen? Rollen, Passkeys und API-Tokens gehen "+
				"verloren; das Audit-Log bleibt.", "Löschen") {
				aufruf(http.MethodDelete, "/api/v1/benutzer/"+b.ID, nil, "Konto gelöscht.")
			}
		}
	// Agent-Tokens
	case "atwiderruf":
		if bestaetigenDialog(f.hwnd, "Agent-Token widerrufen?", "Mit diesem Token kann sich danach kein Agent mehr registrieren.", "Widerrufen") {
			aufruf(http.MethodDelete, "/api/v1/agent-tokens/"+z.wert, nil, "Token widerrufen.")
		}
	// Agent-Updates
	case "uauto":
		if d.auto != nil {
			automatikDialog(*d.auto, name)
		}
	case "ufrei":
		if d.updates != nil {
			freigabeDialog(d.updates)
		}
	case "uhoch":
		paketHochladen()
	case "upaketweg":
		if bestaetigenDialog(f.hwnd, "Paket löschen?", "Agents, die diese Version noch nicht haben, bekommen sie dann nicht mehr.", "Löschen") {
			aufruf(http.MethodDelete, "/api/v1/agent-updates/"+z.wert, nil, "Paket gelöscht.")
		}
	// API-Tokens
	case "apineu":
		apiTokenAnlegen(mandant, name, d.ich)
	case "apiwiderruf":
		if bestaetigenDialog(f.hwnd, "API-Token widerrufen?", "Werkzeuge mit diesem Token bekommen danach keinen Zugriff mehr.", "Widerrufen") {
			aufruf(http.MethodDelete, "/api/v1/api-tokens/"+z.wert, nil, "Token widerrufen.")
		}
	// Anmeldung
	case "vzneu", "vzneuoidc":
		anbindungDialog(nil, map[bool]string{true: "oidc", false: "ldap"}[z.art == "vzneuoidc"], mandant, d)
	case "vzbearbeiten", "vzloeschen", "vztest":
		var x *anbindung
		for i := range d.vz {
			if d.vz[i].ID == z.wert {
				x = &d.vz[i]
			}
		}
		if x == nil {
			return
		}
		switch z.art {
		case "vzbearbeiten":
			anbindungDialog(x, x.Art, x.Mandant, d)
		case "vzloeschen":
			code, ok := codeDialog(d.ich, "„"+x.Name+"“ löschen?", fmt.Sprintf("Alle %d Konten aus diesem Verzeichnis werden gesperrt und abgemeldet.", x.Konten), "Endgültig löschen")
			if ok {
				aufruf(http.MethodDelete, "/api/v1/verzeichnisse/"+x.ID, map[string]string{"code": code}, "Anbindung gelöscht.")
			}
		case "vztest":
			d.test[x.ID] = "prüft …"
			var r struct {
				OK     bool   `json:"ok"`
				Fehler string `json:"fehler"`
			}
			id := x.ID
			a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
				return cl.Anfrage(ctx, http.MethodPost, "/api/v1/verzeichnisse/"+id+"/test", nil, &r)
			}, func(err error) {
				switch {
				case err != nil:
					d.test[id] = fehlerText(err)
				case r.OK:
					d.test[id] = "Verbindung und Dienstkonto in Ordnung"
				case r.Fehler != "":
					d.test[id] = r.Fehler
				default:
					d.test[id] = "fehlgeschlagen"
				}
				pInvalidateRect.Call(uintptr(f.seitenF), 0, 0)
			})
		}
	}
}

// textDialog: ein Textfeld, OK mit eigenem Text; liefert die Eingabe (getrimmt, nicht leer).
func textDialog(titel, beschriftung, start, knopf string) (string, bool) {
	d := neuerDialog(a.f.hwnd, titel)
	d.okText = knopf
	d.werte["t"] = start
	d.aufbau = func(d *dialog) { d.feld("t", beschriftung, desktop.FeldText, "") }
	var out string
	d.speichern = func(d *dialog, fertig func(error)) {
		out = strings.TrimSpace(d.werte["t"])
		if out == "" && !strings.Contains(beschriftung, "optional") {
			d.fehlerFeld = "t"
			fertig(errText("Bitte ausfüllen."))
			return
		}
		fertig(nil)
	}
	return out, d.zeigen()
}

// codeDialog: Bestätigung einer heiklen Änderung mit Code bzw. eigenem Passwort.
func codeDialog(i *ich, titel, text, knopf string) (string, bool) {
	d := neuerDialog(a.f.hwnd, titel)
	d.einleitung, d.okText, d.gefahr = text, knopf, true
	d.aufbau = func(d *dialog) { codeFeld(d, i) }
	var code string
	d.speichern = func(d *dialog, fertig func(error)) {
		code = strings.TrimSpace(d.werte["code"])
		if code == "" {
			d.fehlerFeld = "code"
			fertig(errText("Bitte zur Bestätigung ausfüllen."))
			return
		}
		fertig(nil)
	}
	return code, d.zeigen()
}

// codeFeld wie CodeFeld im Web: Code aus der App oder (ohne 2FA) eigenes Passwort.
func codeFeld(d *dialog, i *ich) {
	if i != nil && !i.ZweiFaktor {
		d.feld("code", "Eigenes Passwort zur Bestätigung", desktop.FeldText, "").geheim = true
		return
	}
	d.feld("code", "Code aus der Authenticator-App", desktop.FeldText, "6 Ziffern")
}

// startPasswort: 16 Zeichen in Vierergruppen aus dem Kryptografie-Zufall, wie im Web.
func startPasswort() string {
	const zeichen = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	for i := 0; i < 16; i++ {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(zeichen))))
		if err != nil {
			panic(err) // ohne Zufall kein Passwort
		}
		b.WriteByte(zeichen[n.Int64()])
	}
	return b.String()
}

func benutzerAnlegen(mandant, name string) {
	f := a.f
	d := neuerDialog(f.hwnd, "Benutzer anlegen in "+name)
	d.okText = "Benutzer anlegen"
	d.werte["pw"], d.werte["rolle"] = startPasswort(), "leser"
	d.aufbau = func(d *dialog) {
		d.feld("name", "Name", desktop.FeldText, "")
		d.feld("email", "E-Mail-Adresse", desktop.FeldText, "")
		d.feld("pw", "Startpasswort (bitte sicher übergeben)", desktop.FeldText, "")
		d.auswahl("rolle", "Rolle in "+name, []string{"Leser – sieht alles in diesem Bereich", "Operator – pflegt Sensoren und Agents",
			"Admin – verwaltet Benutzer und Rechte"}, []string{"leser", "operator", "admin"}, "")
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		body := map[string]string{"mandant_id": mandant, "email": strings.TrimSpace(d.werte["email"]),
			"anzeigename": strings.TrimSpace(d.werte["name"]), "passwort": d.werte["pw"]}
		rolle := d.werte["rolle"]
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			var neu struct {
				ID string `json:"id"`
			}
			if err := cl.Anfrage(ctx, http.MethodPost, "/api/v1/benutzer", body, &neu); err != nil {
				return err
			}
			return cl.Anfrage(ctx, http.MethodPut, "/api/v1/benutzer/"+neu.ID+"/rollen/"+mandant, map[string]string{"rolle": rolle}, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Benutzer angelegt.")
		a.seiteNeu(seiteVerwaltung)
	}
}

func apiTokenAnlegen(mandant, name string, i *ich) {
	f := a.f
	d := neuerDialog(f.hwnd, "API-Token anlegen")
	d.okText = "Token anlegen"
	d.werte["rolle"], d.werte["tage"] = "leser", "90"
	d.aufbau = func(d *dialog) {
		d.feld("name", "Name (wofür?)", desktop.FeldText, "z. B. Grafana")
		d.auswahl("rolle", "Rolle in "+name, []string{"Leser (nur lesen)", "Operator (Sensoren, Geräte, Alarme pflegen)"},
			[]string{"leser", "operator"}, "")
		d.feld("tage", "Gültig (Tage, höchstens 365)", desktop.FeldGanzzahl, "")
		codeFeld(d, i)
	}
	var token, tname string
	d.speichern = func(d *dialog, fertig func(error)) {
		tage, err := strconv.Atoi(strings.TrimSpace(d.werte["tage"]))
		if err != nil || tage < 1 || tage > 365 {
			d.fehlerFeld = "tage"
			fertig(errText("Gültig: 1 bis 365 Tage."))
			return
		}
		tname = strings.TrimSpace(d.werte["name"])
		body := map[string]any{"mandant": mandant, "name": tname, "rolle": d.werte["rolle"], "tage": tage, "code": strings.TrimSpace(d.werte["code"])}
		var r struct {
			Token string `json:"token"`
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/api-tokens", body, &r)
		}, func(err error) {
			if err != nil {
				d.leeren = "code"
			}
			token = r.Token
			fertig(err)
		})
	}
	if !d.zeigen() {
		return
	}
	a.seiteNeu(seiteVerwaltung)
	z := neuerDialog(f.hwnd, "Token „"+tname+"“")
	z.einleitung = "Jetzt kopieren, es wird nicht noch einmal angezeigt."
	z.werte["t"] = token
	z.okText, z.abbrText = "Kopieren", "Fertig"
	z.aufbau = func(z *dialog) { z.feld("t", "API-Token", desktop.FeldText, "") }
	z.speichern = func(z *dialog, fertig func(error)) { fertig(zwischenablage(z.hwnd, token)) }
	if z.zeigen() {
		setStatusText(f, "Token kopiert.")
	}
}

func automatikDialog(r autoRegel, name string) {
	f := a.f
	a.mu.Lock()
	gs := a.stand.Gruppen
	a.mu.Unlock()
	gt, gw := gruppenPfade(gs, r.MandantID)
	gt[0] = "keine (alle nach der Wartezeit)"
	d := neuerDialog(f.hwnd, "Automatisch übernehmen ("+name+")")
	d.einleitung = "Neue signierte Versionen gehen zuerst an die Agents der Pilotgruppe, nach der Wartezeit an alle übrigen " +
		"dieses Mandanten, aber nur, wenn kein Pilot einen Fehler meldet und mindestens ein Pilot die neue Version schon " +
		"fährt. Installiert wird nur im Zeitfenster; von = bis heißt ganzer Tag. Eine Freigabe von Hand geht immer vor."
	if r.Aktiv {
		d.werte["aktiv"] = "ja"
	}
	if r.Pilotgruppe != nil {
		d.werte["pilot"] = *r.Pilotgruppe
	}
	d.werte["warte"], d.werte["von"], d.werte["bis"] = itoa(r.Wartezeit), itoa(r.Von), itoa(r.Bis)
	var tg []string
	for _, x := range r.Tage {
		tg = append(tg, itoa(x))
	}
	d.werte["tage"] = strings.Join(tg, ",")
	var uhr, uw []string
	for h := 0; h < 24; h++ {
		uhr, uw = append(uhr, fmt.Sprintf("%02d:00", h)), append(uw, itoa(h))
	}
	d.aufbau = func(d *dialog) {
		d.feld("aktiv", "Neue Versionen automatisch übernehmen", desktop.FeldJaNein, "")
		d.auswahl("pilot", "Pilotgruppe", gt, gw, "")
		d.feld("warte", "Wartezeit (Stunden, 0 bis 720)", desktop.FeldGanzzahl, "")
		x := d.feld("tage", "Wochentage", desktop.FeldMehrfach, "")
		x.texte, x.werte = []string{"Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"}, []string{"1", "2", "3", "4", "5", "6", "7"}
		d.auswahl("von", "von (Uhr)", uhr, uw, "").halb = true
		d.auswahl("bis", "bis (Uhr)", uhr, uw, "").halb = true
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		w, err := strconv.Atoi(strings.TrimSpace(d.werte["warte"]))
		if err != nil || w < 0 || w > 720 {
			d.fehlerFeld = "warte"
			fertig(errText("Wartezeit: 0 bis 720 Stunden."))
			return
		}
		var tage []int
		for _, x := range strings.Split(d.werte["tage"], ",") {
			if n, err := strconv.Atoi(x); err == nil {
				tage = append(tage, n)
			}
		}
		if len(tage) == 0 {
			d.fehlerFeld = "tage"
			fertig(errText("Bitte mindestens einen Wochentag wählen."))
			return
		}
		von, _ := strconv.Atoi(d.werte["von"])
		bis, _ := strconv.Atoi(d.werte["bis"])
		n := autoRegel{MandantID: r.MandantID, Aktiv: d.werte["aktiv"] == "ja", Wartezeit: w, Tage: tage, Von: von, Bis: bis}
		if p := d.werte["pilot"]; p != "" {
			n.Pilotgruppe = &p
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			return cl.Anfrage(ctx, http.MethodPut, "/api/v1/mandanten/"+r.MandantID+"/agent-updates/automatik", n, nil)
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Gespeichert.")
		a.seiteNeu(seiteVerwaltung)
	}
}

func freigabeDialog(u *updates) {
	f := a.f
	ids, _, rolle := a.bereich()
	var versionen []string
	gesehen := map[string]bool{}
	for _, p := range u.Pakete {
		if !gesehen[p.Version] {
			gesehen[p.Version] = true
			versionen = append(versionen, p.Version)
		}
	}
	var at, aw []string
	for _, ag := range u.Agents {
		if ids[ag.Mandant] && rolle(ag.Mandant) == "admin" {
			v := ag.Version
			if v == "" {
				v = "–"
			}
			at, aw = append(at, ag.Hostname+" · "+v), append(aw, ag.ID)
		}
	}
	d := neuerDialog(f.hwnd, "Agent-Updates freigeben")
	d.okText = "Ausführen"
	d.werte["aktion"] = "freigeben"
	if len(versionen) > 0 {
		d.werte["version"] = versionen[0]
	}
	d.aufbau = func(d *dialog) {
		x := d.auswahl("aktion", "Aktion", []string{"Version freigeben", "Freigabe zurücknehmen"}, []string{"freigeben", "zuruecknehmen"}, "")
		x.aenderung = func() { d.aufbauen() }
		if d.werte["aktion"] == "freigeben" {
			if len(versionen) == 0 {
				d.auswahl("version", "Version", []string{"kein Paket hochgeladen"}, []string{""}, "")
			} else {
				d.auswahl("version", "Version", versionen, versionen, "")
			}
		}
		y := d.feld("agents", "Agents (anklicken zum Wählen)", desktop.FeldMehrfach, "")
		y.texte, y.werte = at, aw
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		var l []string
		for _, x := range strings.Split(d.werte["agents"], ",") {
			if x != "" {
				l = append(l, x)
			}
		}
		if len(l) == 0 {
			d.fehlerFeld = "agents"
			fertig(errText("Bitte mindestens einen Agent wählen."))
			return
		}
		frei, ver := d.werte["aktion"] == "freigeben", d.werte["version"]
		if frei && ver == "" {
			fertig(errText("Es ist noch kein Paket hochgeladen."))
			return
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			for _, id := range l {
				var err error
				if frei {
					err = cl.Anfrage(ctx, http.MethodPut, "/api/v1/agents/"+id+"/update", map[string]string{"version": ver}, nil)
				} else {
					err = cl.Anfrage(ctx, http.MethodDelete, "/api/v1/agents/"+id+"/update", nil, nil)
				}
				if err != nil {
					return err
				}
			}
			return nil
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, "Erledigt.")
		a.seiteNeu(seiteVerwaltung)
	}
}

// paketHochladen: Agent-Binary und .sig wählen und hochladen (nur Betreiber).
func paketHochladen() {
	f := a.f
	bin := dateiWaehlen(f.hwnd, "Agent-Binary wählen", "Alle Dateien\x00*.*\x00")
	if bin == "" {
		return
	}
	sig := dateiWaehlen(f.hwnd, "Signatur (.sig) wählen", "Signatur (*.sig)\x00*.sig\x00Alle Dateien\x00*.*\x00")
	if sig == "" {
		return
	}
	setStatusText(f, "Prüft …")
	a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
		b, err := os.ReadFile(bin)
		if err != nil {
			return err
		}
		s, err := os.ReadFile(sig)
		if err != nil {
			return err
		}
		kopf := map[string]string{"Content-Type": "application/octet-stream", "X-OpenWacht-Signatur": base64.StdEncoding.EncodeToString(s)}
		return cl.AnfrageDatei(ctx, http.MethodPost, "/api/v1/agent-updates", b, kopf, nil)
	}, func(err error) {
		if err != nil {
			hinweis(f.hwnd, "Paket hochladen", fehlerText(err), true)
			return
		}
		setStatusText(f, "Paket "+filepath.Base(bin)+" hochgeladen.")
		a.seiteNeu(seiteVerwaltung)
	})
}

func anbindungDialog(v *anbindung, art, heim string, d0 verwDaten) {
	f := a.f
	oidc := art == "oidc"
	// Ziele der Gruppen: der Mandant der Anbindung und alles darunter, soweit Admin
	a.mu.Lock()
	ms := a.stand.Mandanten
	a.mu.Unlock()
	var zt, zw []string
	start := -1
	for i, r := range desktop.MandantenReihe(ms) {
		if r.Mandant.ID == heim {
			start = r.Tiefe
		} else if start >= 0 && r.Tiefe <= start {
			break
		}
		if start >= 0 && r.Mandant.Rolle == "admin" {
			zt, zw = append(zt, strings.Repeat("  ", r.Tiefe-max(start, 0))+r.Mandant.Name), append(zw, r.Mandant.ID)
		}
		_ = i
	}
	titel := map[bool]string{true: "SSO (OIDC) anbinden", false: "AD anbinden"}[oidc]
	if v != nil {
		titel = "Anbindung „" + v.Name + "“ bearbeiten"
	}
	d := neuerDialog(f.hwnd, titel)
	d.okText = map[bool]string{true: "Speichern", false: "Anbinden"}[v != nil]
	w := d.werte
	w["name"], w["url"], w["claim"], w["stunden"] = map[bool]string{true: "Firmen-Login", false: "Active Directory"}[oidc],
		map[bool]string{true: "https://", false: "ldaps://"}[oidc], "email", ""
	if !oidc {
		w["versch"] = "ja"
	}
	w["aktiv"] = "ja"
	gruppen := []vzGruppe{}
	if v != nil {
		w["name"], w["url"], w["bind"], w["base"], w["claim"] = v.Name, v.URL, v.BindDN, v.BaseDN, v.AdressClaim
		if v.NetBIOS != nil {
			w["netbios"] = *v.NetBIOS
		}
		w["domaenen"] = strings.Join(v.Domaenen, ", ")
		w["versch"], w["zweif"], w["aktiv"] = map[bool]string{true: "ja"}[v.Verschachtelt], map[bool]string{true: "ja"}[v.ZweiFaktor], map[bool]string{true: "ja"}[v.Aktiv]
		if v.SitzungStunden > 0 {
			w["stunden"] = itoa(v.SitzungStunden)
		}
		gruppen = v.Gruppen
	}
	for i, g := range gruppen {
		w["g"+itoa(i)], w["gm"+itoa(i)], w["gr"+itoa(i)] = g.Gruppe, g.Mandant, g.Rolle
	}
	w["anzahl"] = itoa(max(len(gruppen), 1))
	var anz, anzW []string
	for i := 1; i <= 20; i++ {
		anz, anzW = append(anz, itoa(i)), append(anzW, itoa(i))
	}
	schritt := 1
	d.aufbau = func(d *dialog) {
		if schritt == 1 {
			d.okText = "Weiter"
			d.einleitung = "Schritt 1 von 2: Verbindung."
			if oidc {
				d.einleitung += " Beim Identity Provider einen vertraulichen Client anlegen (Authorization Code mit PKCE) und als " +
					"Weiterleitungsadresse " + d0.rueckkehr + " eintragen. Der Gruppen-Claim muss im ID-Token stehen."
			}
			d.feld("name", "Name", desktop.FeldText, "")
			d.feld("url", map[bool]string{true: "Issuer (https://sso.firma.de/realms/firma)", false: "Server (ldaps://dc1.firma.de oder ldap://…:389 mit StartTLS)"}[oidc], desktop.FeldText, "")
			ca := "CA-Zertifikat des Servers (PEM), leer = Zertifikate des Systems"
			if v != nil && v.EigeneCA {
				ca = "CA-Zertifikat des Servers (PEM), bei Änderung neu einfügen"
			}
			d.feld("ca", ca, desktop.FeldMehrzeilig, "")
			d.feld("bind", map[bool]string{true: "Client-ID", false: "Dienstkonto (DN, nur Leserechte)"}[oidc], desktop.FeldText,
				map[bool]string{true: "openwacht", false: "CN=svc-openwacht,OU=Dienste,DC=firma,DC=de"}[oidc])
			pw := map[bool]string{true: "Client-Secret", false: "Passwort des Dienstkontos"}[oidc]
			if v != nil {
				pw += " (leer = unverändert)"
			}
			d.feld("pw", pw, desktop.FeldText, "").geheim = true
			d.feld("base", map[bool]string{true: "Gruppen-Claim (leer = groups)", false: "Suchbasis (DN)"}[oidc], desktop.FeldText,
				map[bool]string{true: "groups", false: "DC=firma,DC=de"}[oidc])
			if oidc {
				d.auswahl("claim", "Adresse des Kontos aus dem Claim", []string{"email (Standard)", "upn (z. B. Entra ID)", "preferred_username"},
					[]string{"email", "upn", "preferred_username"}, "")
			}
			return
		}
		d.okText = map[bool]string{true: "Speichern", false: "Anbinden"}[v != nil]
		d.einleitung = "Schritt 2 von 2: Anmeldenamen, Gruppen und Bestätigung. Vor dem Speichern prüft OpenWacht die Verbindung. " +
			"Wer in keiner Gruppe ist, kommt nicht hinein; leere Gruppenzeilen entfallen."
		d.feld("domaenen", "Domänen für name@domäne", desktop.FeldText, "firma.de, durch Komma getrennt").halb = !oidc
		if !oidc {
			d.feld("netbios", "NetBIOS-Name (optional)", desktop.FeldText, "FIRMA").halb = true
			d.feld("versch", "Gruppen verschachtelt", desktop.FeldJaNein, "").halb = true
		}
		d.feld("zweif", "Zwei-Faktor verlangen", desktop.FeldJaNein, "").halb = !oidc
		d.auswahl("stunden", "Sitzung höchstens", []string{"12 Stunden (Standard)", "1 Stunde", "2 Stunden", "4 Stunden", "8 Stunden"},
			[]string{"", "1", "2", "4", "8"}, "").halb = true
		x := d.auswahl("anzahl", "Zahl der Gruppenzeilen", anz, anzW, "")
		x.halb = true
		x.aenderung = func() { d.aufbauen() }
		if v != nil {
			d.feld("aktiv", "Anmeldung über diese Anbindung erlauben", desktop.FeldJaNein, "")
		}
		n, _ := strconv.Atoi(d.werte["anzahl"])
		for i := 0; i < n; i++ {
			k := itoa(i)
			d.feld("g"+k, fmt.Sprintf("%s %d", map[bool]string{true: "Gruppe", false: "AD-Gruppe (DN)"}[oidc], i+1), desktop.FeldText, "")
			if d.werte["gm"+k] == "" && len(zw) > 0 {
				d.werte["gm"+k] = zw[0]
			}
			if d.werte["gr"+k] == "" {
				d.werte["gr"+k] = "leser"
			}
			d.auswahl("gm"+k, "Mandant", zt, zw, "").halb = true
			d.auswahl("gr"+k, "Rolle", []string{"Leser", "Operator", "Admin"}, []string{"leser", "operator", "admin"}, "").halb = true
		}
		codeFeld(d, d0.ich)
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		w := d.werte
		if schritt == 1 {
			if strings.TrimSpace(w["name"]) == "" || strings.TrimSpace(w["url"]) == "" || strings.TrimSpace(w["bind"]) == "" {
				fertig(errText("Name, Adresse und " + map[bool]string{true: "Client-ID", false: "Dienstkonto"}[oidc] + " bitte ausfüllen."))
				return
			}
			schritt = 2
			d.weiter()
			return
		}
		var doms []string
		for _, x := range strings.FieldsFunc(w["domaenen"], func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			if x = strings.TrimSpace(x); x != "" {
				doms = append(doms, x)
			}
		}
		n, _ := strconv.Atoi(w["anzahl"])
		var gs []vzGruppe
		for i := 0; i < n; i++ {
			k := itoa(i)
			if g := strings.TrimSpace(w["g"+k]); g != "" {
				gs = append(gs, vzGruppe{Gruppe: g, Mandant: w["gm"+k], Rolle: w["gr"+k]})
			}
		}
		stunden, _ := strconv.Atoi(w["stunden"])
		claim := "email"
		if oidc {
			claim = w["claim"]
		}
		body := map[string]any{
			"art": art, "client_id": strings.TrimSpace(w["bind"]), "gruppen_claim": strings.TrimSpace(w["base"]), "adress_claim": claim,
			"mandant": heim, "name": strings.TrimSpace(w["name"]), "url": strings.TrimSpace(w["url"]), "ca": strings.TrimSpace(w["ca"]),
			"bind_dn": strings.TrimSpace(w["bind"]), "passwort": w["pw"], "base_dn": strings.TrimSpace(w["base"]),
			"netbios": strings.TrimSpace(w["netbios"]), "domaenen": doms, "verschachtelt": w["versch"] == "ja",
			"zwei_faktor": w["zweif"] == "ja", "aktiv": v == nil || w["aktiv"] == "ja", "sitzung_stunden": stunden,
			"gruppen": gs, "code": strings.TrimSpace(w["code"]),
		}
		if body["code"] == "" {
			d.fehlerFeld = "code"
			fertig(errText("Bitte zur Bestätigung ausfüllen."))
			return
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if v != nil {
				return cl.Anfrage(ctx, http.MethodPut, "/api/v1/verzeichnisse/"+v.ID, body, nil)
			}
			return cl.Anfrage(ctx, http.MethodPost, "/api/v1/verzeichnisse", body, nil)
		}, func(err error) {
			if err != nil {
				d.leeren = "code"
			}
			fertig(err)
		})
	}
	if d.zeigen() {
		setStatusText(f, "Anbindung gespeichert.")
		a.seiteNeu(seiteVerwaltung)
	}
}
