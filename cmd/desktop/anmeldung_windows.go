// SPDX-License-Identifier: AGPL-3.0-only

package main

// Token in der Windows-Anmeldeinformationsverwaltung (Systemsteuerung →
// Anmeldeinformationsverwaltung → Windows-Anmeldeinformationen →
// „OpenWacht Desktop“), Autostart über HKCU\…\Run und die Einrichtung in
// einem Konsolenfenster (das Token wird ohne Echo eingelesen).

import (
	"bufio"
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
		Comment:    utf16("API-Token (Leser) für openwacht-desktop"),
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
	v, _ := syscall.UTF16FromString(`"` + exe + `"`)
	if r, _, err := pRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(utf16(runWert))), 0, regSZ,
		uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2)); r != 0 {
		return fmt.Errorf("Autostart setzen: %w", err)
	}
	return nil
}

// einrichten fragt in einem Konsolenfenster Adresse und Token ab, prüft sie
// mit einer Abfrage und speichert sie. Liefert false bei Abbruch.
func einrichten(alt desktop.Config) (desktop.Config, bool) {
	pAllocConsole.Call()
	defer pFreeConsole.Call()
	in, err1 := os.OpenFile("CONIN$", os.O_RDWR, 0)
	out, err2 := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err1 != nil || err2 != nil {
		return alt, false
	}
	defer in.Close()
	defer out.Close()
	r := bufio.NewReader(in)
	zeile := func() string {
		s, _ := r.ReadString('\n')
		return strings.TrimSpace(s)
	}
	fmt.Fprintln(out, "OpenWacht Desktop einrichten")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Das Token legst du in OpenWacht unter Verwaltung → API-Tokens an, Rolle „Leser“.")
	fmt.Fprintln(out, "Es wird in der Windows-Anmeldeinformationsverwaltung gespeichert, nicht in einer Datei.")
	fmt.Fprintln(out, "Leere Eingabe bricht ab.")
	fmt.Fprintln(out, "")
	for {
		vorschlag := ""
		if alt.Zentrale != "" {
			vorschlag = " [" + alt.Zentrale + "]"
		}
		fmt.Fprintf(out, "Adresse der Zentrale%s: ", vorschlag)
		z := zeile()
		if z == "" {
			if alt.Zentrale == "" {
				return alt, false
			}
			z = alt.Zentrale
		}
		zentrale, err := desktop.CleanZentrale(z)
		if err != nil {
			fmt.Fprintln(out, err)
			continue
		}
		fmt.Fprint(out, "API-Token (Eingabe wird nicht angezeigt): ")
		t := ohneEcho(in, zeile)
		fmt.Fprintln(out)
		if t == "" {
			return alt, false
		}
		token, err := desktop.CleanToken(t)
		if err != nil {
			fmt.Fprintln(out, err)
			continue
		}
		fmt.Fprintln(out, "Prüfe die Verbindung …")
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		_, err = desktop.Client{Zentrale: zentrale, Token: token}.Alarme(ctx)
		cancel()
		if err != nil {
			fmt.Fprintln(out, "Das ging nicht:", err)
			fmt.Fprintln(out, "(Zertifikatsfehler: Die Zentrale braucht ein Zertifikat, dem Windows vertraut.)")
			continue
		}
		if err := tokenSpeichern(token); err != nil {
			fmt.Fprintln(out, err)
			continue
		}
		c := desktop.Config{Zentrale: zentrale}
		if p, err := desktop.ConfigPath(); err == nil {
			if err := desktop.SaveConfig(p, c); err != nil {
				fmt.Fprintln(out, "Einstellungen nicht gespeichert:", err)
			}
		}
		fmt.Fprintln(out, "Fertig. OpenWacht steht jetzt im Infobereich neben der Uhr. Dieses Fenster schließt sich gleich.")
		time.Sleep(2 * time.Second)
		return c, true
	}
}

// ohneEcho liest eine Zeile, ohne sie im Konsolenfenster anzuzeigen.
func ohneEcho(in *os.File, lesen func() string) string {
	h := in.Fd()
	var mode uint32
	if r, _, _ := pGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r != 0 {
		pSetConsoleMode.Call(h, uintptr(mode&^enableEchoInput))
		defer pSetConsoleMode.Call(h, uintptr(mode))
	}
	return lesen()
}
