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
	r, _, err := pCredWriteW.Call(ptr(&c), 0)
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
// API-Token. Prüft beides mit einer Abfrage, speichert das Token in der
// Anmeldeinformationsverwaltung und die Adresse in den Einstellungen.
// Liefert false bei Abbruch. Läuft vor dem Hauptfenster und danach (Menü
// „Anmeldung ändern“, Knopf „Abmelden“).
func anmelden(owner syscall.Handle, alt desktop.Config) (desktop.Config, bool) {
	schriftenLaden()
	if owner == 0 {
		themaSetzen(dunkelNach(alt.Darstellung))
	}
	neu := alt
	d := neuerDialog(owner, "Bei OpenWacht anmelden")
	d.einleitung = "Die Desktop-App meldet sich mit einem API-Token an. Du legst es in OpenWacht unter Benutzer und " +
		"Mandanten › API-Tokens an: Rolle Operator, um Geräte und Sensoren zu pflegen, Leser nur zum Ansehen. " +
		"Windows bewahrt es in der Anmeldeinformationsverwaltung auf, nicht in einer Datei."
	d.okText = "Anmelden"
	d.werte["zentrale"] = alt.Zentrale
	d.aufbau = func(d *dialog) {
		d.feld("zentrale", "Adresse der Zentrale", desktop.FeldText, "https://openwacht.firma.de")
		d.feld("token", "API-Token", desktop.FeldText, "owt1.…").geheim = true
	}
	d.speichern = func(d *dialog, fertig func(error)) {
		zentrale, err := desktop.CleanZentrale(d.werte["zentrale"])
		if err != nil {
			d.fehlerFeld = "zentrale"
			fertig(err)
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
			neu.Zentrale = zentrale
			if p, err := desktop.ConfigPath(); err == nil {
				if err := desktop.SaveConfig(p, neu); err != nil {
					fertig(fmt.Errorf("Einstellungen nicht gespeichert: %w", err))
					return
				}
			}
			fertig(nil)
		})
	}
	d.fehlerPraefix = "Anmeldung fehlgeschlagen: "
	if !d.zeigen() {
		return alt, false
	}
	return neu, true
}

// anmeldeFehler: Ursache in Worten, die beim Beheben hilft.
func anmeldeFehler(err error) error {
	if errors.Is(err, desktop.ErrToken) {
		return errors.New("Die Zentrale kennt dieses API-Token nicht, oder es ist abgelaufen oder widerrufen.")
	}
	l := strings.ToLower(err.Error())
	if strings.Contains(l, "x509") || strings.Contains(l, "certificate") {
		return errors.New("Windows vertraut dem Zertifikat der Zentrale nicht. Die Zentrale braucht ein Zertifikat, " +
			"dem Windows vertraut (bei einer eigenen CA: deren Stammzertifikat unter „Vertrauenswürdige Stammzertifizierungsstellen“ installieren).")
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
