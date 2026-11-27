// SPDX-License-Identifier: AGPL-3.0-only

package main

// Token in der Windows-Anmeldeinformationsverwaltung (Systemsteuerung →
// Anmeldeinformationsverwaltung → Windows-Anmeldeinformationen →
// „OpenWacht Desktop“), Autostart über HKCU\…\Run und das Fenster zum
// Anmelden.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
)

const credZiel = "OpenWacht Desktop"

func tokenSpeichern(token string) error {
	blob := []byte(token)
	c := credential{
		Type:       credTypeGeneric,
		TargetName: utf16(credZiel),
		Comment:    utf16("API-Token für openwacht-desktop"),
		BlobSize:   uint32(len(blob)),
		Blob:       &blob[0],
		Persist:    credPersistLocalMachine,
		UserName:   utf16("openwacht-desktop"),
	}
	r, _, err := pCredWriteW.Call(uintptr(unsafe.Pointer(&c)), 0)
	if r == 0 {
		return fmt.Errorf("Anmeldeinformation speichern: %w", err)
	}
	return nil
}

func tokenLesen() (string, error) {
	var p *credential
	r, _, err := pCredReadW.Call(uintptr(unsafe.Pointer(utf16(credZiel))), credTypeGeneric, 0, uintptr(unsafe.Pointer(&p)))
	if r == 0 {
		return "", err
	}
	defer pCredFree.Call(uintptr(unsafe.Pointer(p)))
	if p.BlobSize == 0 || p.BlobSize > 256 {
		return "", errors.New("Anmeldeinformation leer oder zu groß")
	}
	return string(unsafe.Slice(p.Blob, p.BlobSize)), nil
}

func tokenLoeschen() {
	pCredDeleteW.Call(uintptr(unsafe.Pointer(utf16(credZiel))), credTypeGeneric, 0)
}

const runSchluessel = `Software\Microsoft\Windows\CurrentVersion\Run`
const runWert = "OpenWacht"

func autostartAn() bool {
	var k syscall.Handle
	if r, _, _ := pRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(utf16(runSchluessel))), 0, keyQueryValue, uintptr(unsafe.Pointer(&k))); r != 0 {
		return false
	}
	defer pRegCloseKey.Call(uintptr(k))
	r, _, _ := pRegQueryValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(utf16(runWert))), 0, 0, 0, 0)
	return r == 0
}

func autostartSetzen(an bool) error {
	var k syscall.Handle
	if r, _, err := pRegOpenKeyExW.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(utf16(runSchluessel))), 0, keySetValue, uintptr(unsafe.Pointer(&k))); r != 0 {
		return fmt.Errorf("Registry öffnen: %w", err)
	}
	defer pRegCloseKey.Call(uintptr(k))
	if !an {
		pRegDeleteValueW.Call(uintptr(k), uintptr(unsafe.Pointer(utf16(runWert))))
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Beim Anmelden nur ins Infobereich, ohne Fenster.
	v, _ := syscall.UTF16FromString(`"` + exe + `" infobereich`)
	if r, _, err := pRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(utf16(runWert))), 0, regSZ,
		uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2)); r != 0 {
		return fmt.Errorf("Autostart setzen: %w", err)
	}
	return nil
}

// anmelden: Fenster „Bei OpenWacht anmelden“ mit Adresse der Zentrale und
// entweder Konto (E-Mail, Passwort, danach Code aus der Authenticator-App,
// wie im Browser) oder API-Token. Prüft die Anmeldung mit einer Abfrage.
// Mit Konto liefert es die Sitzung (nur im Speicher); mit Token speichert es
// das Token in der Anmeldeinformationsverwaltung. Die Adresse und die Art
// kommen in die Einstellungen. Liefert false bei Abbruch. hinweis steht über
// allem (z. B. „Sitzung abgelaufen“).
func anmelden(owner syscall.Handle, alt desktop.Config, hinweis string) (desktop.Config, *desktop.Sitzung, bool) {
	schriftenLaden()
	if owner == 0 {
		themaSetzen(dunkelNach(alt.Darstellung))
	}
	neu := alt
	var sitzung *desktop.Sitzung
	schritt := "passwort"
	art := "token"
	if alt.MitKonto() || alt.Zentrale == "" {
		art = "konto" // ab Werk wie im Browser
	}
	d := neuerDialog(owner, "Bei OpenWacht anmelden")
	d.okText = "Anmelden"
	d.werte["zentrale"] = alt.Zentrale
	d.werte["art"] = art
	d.werte["email"] = alt.Email
	if art == "konto" && alt.Email != "" && alt.Zentrale != "" {
		d.fokus = "passwort"
	}
	d.aufbau = func(d *dialog) {
		if schritt == "code" {
			d.einleitung = "Code aus der Authenticator-App für " + d.werte["email"] + "."
			d.okText = "Bestätigen"
			d.feld("code", "Code", desktop.FeldText, "6 Ziffern, oder ein Wiederherstellungscode")
			return
		}
		d.okText = "Anmelden"
		if d.werte["art"] == "konto" {
			d.einleitung = "Melde dich mit deinem Konto an, wie im Browser. Die App darf dann genau, was du im Browser " +
				"darfst; heikle Änderungen bestätigst du mit einem frischen Code. Die Anmeldung gilt, bis du die App " +
				"beendest oder die Zentrale die Sitzung beendet. Passwort und Sitzung speichert die App nicht."
		} else {
			d.einleitung = "Ein API-Token legst du in OpenWacht unter Benutzer und Mandanten › API-Tokens an: Rolle " +
				"Operator, um Geräte und Sensoren zu pflegen, Leser nur zum Ansehen. Windows bewahrt es in der " +
				"Anmeldeinformationsverwaltung auf. Gut für einen Rechner, der nur im Infobereich wacht."
		}
		if hinweis != "" {
			d.einleitung = hinweis + " " + d.einleitung
		}
		d.feld("zentrale", "Adresse der Zentrale (wie im Browser)", desktop.FeldText, "https://openwacht.firma.de")
		f := d.auswahl("art", "Anmelden mit", []string{"Konto (wie im Browser)", "API-Token"}, []string{"konto", "token"}, "")
		f.aenderung = func() { d.aufbauen() }
		if d.werte["art"] == "konto" {
			d.feld("email", "E-Mail", desktop.FeldText, "")
			d.feld("passwort", "Passwort", desktop.FeldText, "").geheim = true
		} else {
			d.feld("token", "API-Token", desktop.FeldText, "owt1.…").geheim = true
		}
	}
	var zentrale string
	speichernCfg := func() error {
		neu.Zentrale = zentrale
		if p, err := desktop.ConfigPath(); err == nil {
			if err := desktop.SaveConfig(p, neu); err != nil {
				return fmt.Errorf("Einstellungen nicht gespeichert: %w", err)
			}
		}
		return nil
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		if schritt == "code" {
			code := strings.TrimSpace(d.werte["code"])
			if code == "" {
				d.fehlerFeld = "code"
				fertig(errors.New("Bitte den Code aus der Authenticator-App eingeben."))
				return
			}
			email := d.werte["email"]
			d.imHintergrund(func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				return desktop.Client{Zentrale: zentrale, Sitzung: sitzung}.ZweiterFaktor(ctx, email, code)
			}, func(err error) {
				if err != nil {
					d.fehlerFeld, d.leeren = "code", "code"
					fertig(anmeldeFehler(err))
					return
				}
				tokenLoeschen() // mit Konto kein Token mehr in der Anmeldeinformationsverwaltung
				neu.Anmeldung, neu.Email = "konto", email
				fertig(speichernCfg())
			})
			return
		}
		var err error
		zentrale, err = desktop.CleanZentrale(d.werte["zentrale"])
		if err != nil {
			d.fehlerFeld = "zentrale"
			fertig(err)
			return
		}
		if desktop.AgentPort(zentrale) {
			d.fehlerFeld = "zentrale"
			fertig(errors.New("Port 8444 ist der Port für Agents. Die App braucht die Adresse der Weboberfläche, wie im Browser, z. B. " +
				strings.TrimSuffix(zentrale, ":8444") + "."))
			return
		}
		if d.werte["art"] == "konto" {
			email, pass := strings.TrimSpace(d.werte["email"]), d.werte["passwort"]
			if email == "" {
				d.fehlerFeld = "email"
				fertig(errors.New("Bitte die E-Mail-Adresse eingeben."))
				return
			}
			if pass == "" {
				d.fehlerFeld = "passwort"
				fertig(errors.New("Bitte das Passwort eingeben."))
				return
			}
			d.werte["email"] = email
			sitzung = &desktop.Sitzung{}
			var code bool
			d.imHintergrund(func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				var err error
				code, err = desktop.Client{Zentrale: zentrale, Sitzung: sitzung}.Anmelden(ctx, email, pass)
				return err
			}, func(err error) {
				if err != nil {
					d.fehlerFeld, d.leeren = "passwort", "passwort"
					fertig(anmeldeFehler(err))
					return
				}
				if code {
					// zweiter Schritt im selben Fenster
					schritt = "code"
					d.weiter()
					return
				}
				tokenLoeschen()
				neu.Anmeldung, neu.Email = "konto", email
				fertig(speichernCfg())
			})
			return
		}
		token, err := desktop.CleanToken(d.werte["token"])
		if err != nil {
			d.fehlerFeld = "token"
			fertig(err)
			return
		}
		d.imHintergrund(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			_, err := desktop.Client{Zentrale: zentrale, Token: token}.Alarme(ctx)
			return err
		}, func(err error) {
			if err != nil {
				fertig(anmeldeFehler(err))
				return
			}
			if err := tokenSpeichern(token); err != nil {
				fertig(err)
				return
			}
			neu.Anmeldung = ""
			sitzung = nil
			fertig(speichernCfg())
		})
	}
	d.fehlerPraefix = "Anmeldung fehlgeschlagen: "
	if !d.zeigen() {
		return alt, nil, false
	}
	if neu.MitKonto() && (sitzung == nil || !sitzung.Aktiv()) {
		return alt, nil, false
	}
	return neu, sitzung, true
}

// anmeldeFehler: Ursache in Worten, die beim Beheben hilft.
func anmeldeFehler(err error) error {
	if errors.Is(err, desktop.ErrToken) {
		return errors.New("Die Zentrale kennt dieses API-Token nicht, oder es ist abgelaufen oder widerrufen.")
	}
	var fz *desktop.FehlerZentrale
	if errors.As(err, &fz) && fz.Text != "" {
		return errors.New(fz.Text) // z. B. „E-Mail oder Passwort falsch.“
	}
	l := strings.ToLower(err.Error())
	if strings.Contains(l, "x509") || strings.Contains(l, "certificate") {
		return errors.New("Windows vertraut dem Zertifikat der Zentrale nicht. Die Zentrale braucht ein Zertifikat, " +
			"dem Windows vertraut (Adresse wie im Browser, nicht der Port 8444 für Agents; bei einer eigenen CA deren Stammzertifikat unter „Vertrauenswürdige Stammzertifizierungsstellen“ installieren).")
	}
	return errors.New(fehlerKurz(err.Error()))
}

// dunkelNach: Darstellung aus den Einstellungen, sonst wie Windows.
func dunkelNach(darstellung string) bool {
	switch darstellung {
	case "hell":
		return false
	case "dunkel":
		return true
	}
	return themaLesen()
}
