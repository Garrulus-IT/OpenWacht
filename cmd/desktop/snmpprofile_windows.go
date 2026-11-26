// SPDX-License-Identifier: AGPL-3.0-only

package main

// Seite SNMP-Profile wie web/src/SnmpProfile.tsx: Liste der Profile mit
// Version, Zahl der Geräte und Änderung; Admins legen an, ändern und löschen.
// Die Zugangsdaten zeigt die Zentrale nie wieder an.

import (
	"context"
	"fmt"
	"time"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

func init() {
	seiten[seiteSNMP] = &seitenDef{
		laden: func(ctx context.Context, cl desktop.Client, _ *fenster) (any, error) {
			return cl.SNMPProfile(ctx)
		},
		malen: snmpMalen,
		klick: snmpKlick,
	}
}

func snmpMalen(m *maler, daten any) {
	f := m.f
	ids, mehrere, rolle := a.bereich()
	admin := rolle(f.mandant) == "admin"
	var kopf []sKnopf
	if admin {
		kopf = append(kopf, sKnopf{text: "Profil anlegen", art: "neu"})
	}
	m.panel("SNMP-Profile", kopf...)
	m.klein("Ein Profil hält Version und Zugangsdaten (Community oder SNMPv3-Benutzer) für viele Geräte. Am Gerät unter " +
		"SNMP „Profil“ wählen; ändert sich das Profil, übernehmen alle Geräte die neuen Zugangsdaten. Profile gelten für den " +
		"Mandanten und alle darunter.")
	if !admin {
		m.leer("SNMP-Profile sehen und pflegen nur Admins des Mandanten.")
	}
	liste, ok := daten.([]desktop.SNMPProfil)
	switch {
	case !ok:
		m.klein("Lädt …")
	default:
		var tab [][]sZelle
		jetzt := time.Now()
		for _, p := range liste {
			if !ids[p.MandantID] {
				continue
			}
			name := sZelle{text: p.Name, fett: true}
			if mehrere {
				name.klein = a.mandantName(p.MandantID)
			}
			ver := sZelle{text: p.VersionText()}
			if p.Version != "3" {
				ver = sZelle{text: p.VersionText(), marke: "Klartext", markeFg: th.f.AufWarn, markeBg: th.f.Warn}
			}
			var k []sKnopf
			if rolle(p.MandantID) == "admin" {
				k = []sKnopf{{text: "Bearbeiten", art: "bearbeiten", wert: p.ID}, {text: "Löschen", art: "loeschen", wert: p.ID, stil: kGefahr}}
			}
			tab = append(tab, []sZelle{name, ver, {text: itoa(p.Geraete)}, {text: desktop.Vor(p.Geaendert, jetzt)}, {knoepfe: k}})
		}
		if len(tab) == 0 {
			if admin {
				m.leer("Noch keine SNMP-Profile.")
			}
		} else {
			m.tabelle([]sSpalte{{"Name", 28, false}, {"Version", 30, false}, {"Geräte", 9, false}, {"Geändert", 13, false},
				{"Aktionen", 20, false}}, tab)
		}
	}
	m.ende()
}

func snmpKlick(z ziel, daten any) {
	f := a.f
	liste, _ := daten.([]desktop.SNMPProfil)
	var p *desktop.SNMPProfil
	for i := range liste {
		if liste[i].ID == z.wert {
			p = &liste[i]
		}
	}
	switch z.art {
	case "neu":
		snmpFormular(nil)
	case "bearbeiten":
		if p != nil {
			snmpFormular(p)
		}
	case "loeschen":
		if p == nil {
			return
		}
		text := "Kein Gerät nutzt dieses Profil."
		if p.Geraete == 1 {
			text = "1 Gerät behält seine Zugangsdaten und fragt weiter ab, nur ohne Bezug zum Profil."
		} else if p.Geraete > 1 {
			text = fmt.Sprintf("%d Geräte behalten ihre Zugangsdaten und fragen weiter ab, nur ohne Bezug zum Profil.", p.Geraete)
		}
		if !bestaetigenDialog(f.hwnd, "Profil „"+p.Name+"“ löschen?", text, "Löschen") {
			return
		}
		id := p.ID
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error { return cl.SNMPProfilLoeschen(ctx, id) }, func(err error) {
			if err != nil {
				hinweis(f.hwnd, "SNMP-Profil", "Löschen fehlgeschlagen: "+fehlerText(err), true)
				return
			}
			setStatusText(f, "Profil gelöscht.")
			a.seiteNeu(seiteSNMP)
		})
	}
}

// snmpFormular: Profil anlegen (p == nil) oder bearbeiten, Felder wie ProfilFormular im Web.
func snmpFormular(p *desktop.SNMPProfil) {
	f := a.f
	mandant := f.mandant
	titel := "Neues Profil in „" + a.mandantName(mandant) + "“"
	if p != nil {
		titel = "Profil „" + p.Name + "“ bearbeiten"
	}
	d := neuerDialog(f.hwnd, titel)
	d.werte["version"], d.werte["auth"], d.werte["priv"] = "3", "sha256", "aes"
	if p != nil {
		d.werte["name"], d.werte["version"] = p.Name, p.Version
		if p.V3Auth != nil {
			d.werte["auth"] = *p.V3Auth
		}
		if p.V3Priv != nil {
			d.werte["priv"] = *p.V3Priv
		}
	}
	paare := func(l [][2]string) (t, w []string) {
		for _, x := range l {
			w, t = append(w, x[0]), append(t, x[1])
		}
		return
	}
	d.aufbau = func(d *dialog) {
		neu := p == nil || p.Version != d.werte["version"]
		leer := map[bool]string{true: "", false: " (leer = unverändert)"}[neu]
		d.feld("name", "Name", desktop.FeldText, "z. B. Switches Hauptsitz")
		v := d.auswahl("version", "SNMP-Version", []string{"v3 (verschlüsselt, empfohlen)", "v2c", "v1 (nur für alte Geräte)"},
			[]string{"3", "2c", "1"}, "")
		v.aenderung = func() { d.aufbauen() }
		if d.werte["version"] == "3" {
			d.feld("benutzer", "Benutzer"+leer, desktop.FeldText, map[bool]string{true: "wie am Gerät eingestellt", false: "••••••••"}[neu])
			t, w := paare(desktop.SNMPAuth)
			x := d.auswahl("auth", "Authentifizierung", t, w, "")
			x.halb = true
			t, w = paare(desktop.SNMPPriv)
			x = d.auswahl("priv", "Verschlüsselung", t, w, "")
			x.halb = true
			d.feld("auth_passwort", "Passwort Authentifizierung", desktop.FeldText, "mindestens 8 Zeichen").geheim = true
			d.feld("priv_passwort", "Passwort Verschlüsselung", desktop.FeldText, "mindestens 8 Zeichen").geheim = true
			d.einleitung = "Nur authPriv. MD5 und DES sind nicht erlaubt; Geräte, die nur das können, bleiben bei v2c. " +
				"Benutzer, Verfahren oder Passwörter ändern heißt: alles neu eingeben."
		} else {
			d.feld("community", "Community"+leer, desktop.FeldText, map[bool]string{true: "wie an den Geräten eingestellt", false: "••••••••"}[neu]).geheim = true
			d.einleitung = "SNMP v1 und v2c senden die Community im Klartext; wo die Geräte es können, besser v3."
		}
		if p != nil && p.Geraete > 0 {
			d.einleitung += fmt.Sprintf(" Neue Zugangsdaten gehen sofort an %d %s; die Geräte selbst müssen sie schon kennen.",
				p.Geraete, map[bool]string{true: "Gerät", false: "Geräte"}[p.Geraete == 1])
		}
	}
	var ergebnis string
	d.speichern = func(d *dialog, fertig func(error)) {
		in := desktop.SNMPProfilAusWerten(d.werte)
		if in.Name == "" {
			d.fehlerFeld = "name"
			fertig(fmt.Errorf("Name: bitte angeben."))
			return
		}
		neu := p == nil || p.Version != in.Version
		if neu && in.Version == "3" && in.V3 == nil {
			d.fehlerFeld = "auth_passwort"
			fertig(fmt.Errorf("Für ein neues v3-Profil Benutzer und beide Passwörter eingeben."))
			return
		}
		if neu && in.Version != "3" && in.Community == "" {
			d.fehlerFeld = "community"
			fertig(fmt.Errorf("Community: bitte angeben."))
			return
		}
		a.imHintergrund(func(ctx context.Context, cl desktop.Client) error {
			if p == nil {
				ergebnis = "Profil „" + in.Name + "“ angelegt."
				return cl.SNMPProfilAnlegen(ctx, mandant, in)
			}
			n, err := cl.SNMPProfilAendern(ctx, p.ID, in)
			ergebnis = "Profil gespeichert."
			if n > 0 {
				ergebnis = fmt.Sprintf("Profil gespeichert; %d %s jetzt die neuen Zugangsdaten.", n,
					map[bool]string{true: "Gerät nutzt", false: "Geräte nutzen"}[n == 1])
			}
			return err
		}, fertig)
	}
	if d.zeigen() {
		setStatusText(f, ergebnis)
		a.seiteNeu(seiteSNMP)
	}
}
