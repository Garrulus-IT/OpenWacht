// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/garrulus-it/openwacht/internal/desktop"
	"github.com/garrulus-it/openwacht/internal/version"
)

const takt = 30 * time.Second

// Menüeinträge
const (
	cmdOeffnen = 1 + iota
	cmdAlarme
	cmdPruefen
	cmdAutostart
	cmdEinrichten
	cmdBeenden
)

type app struct {
	hwnd           syscall.Handle
	taskbarCreated uint32
	icons          map[desktop.Zustand]syscall.Handle
	jetzt          chan struct{} // sofort abfragen

	mu       sync.Mutex
	client   desktop.Client
	letzte   []desktop.Alarm // nil bis zur ersten Antwort
	z        desktop.Zusammenfassung
	fehler   string
	melden   []desktop.Ereignis
	gezeigt  desktop.Zustand // Symbol, das gerade steht
	stoerung bool            // Störung schon gemeldet
}

var a *app

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "entfernen":
			tokenLoeschen()
			if p, err := desktop.ConfigPath(); err == nil {
				os.Remove(p)
			}
			autostartSetzen(false)
			meldung("OpenWacht Desktop", "Token, Einstellungen und Autostart sind entfernt. Die Datei openwacht-desktop.exe kannst du jetzt löschen.", false)
			return 0
		case "einrichten", "-version", "--version", "version":
		default:
			meldung("OpenWacht Desktop", "Aufruf: openwacht-desktop [einrichten | entfernen]", true)
			return 2
		}
		if args[0] != "einrichten" {
			meldung("OpenWacht Desktop", version.String("openwacht-desktop"), false)
			return 0
		}
	}
	// Nur einmal je Benutzer.
	if _, _, err := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(utf16(`Local\OpenWachtDesktop`)))); err == syscall.Errno(errorAlreadyExists) {
		meldung("OpenWacht Desktop", "OpenWacht läuft schon im Infobereich neben der Uhr.", false)
		return 0
	}
	pfad, err := desktop.ConfigPath()
	if err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return 1
	}
	cfg, err := desktop.LoadConfig(pfad)
	token, terr := tokenLesen()
	if err != nil || terr != nil || cfg.Zentrale == "" || (len(args) > 0 && args[0] == "einrichten") {
		var ok bool
		if cfg, ok = einrichten(cfg); !ok {
			return 1
		}
		if token, err = tokenLesen(); err != nil {
			meldung("OpenWacht Desktop", "Token nicht lesbar: "+err.Error(), true)
			return 1
		}
	}
	runtime.LockOSThread()
	a = &app{icons: map[desktop.Zustand]syscall.Handle{}, jetzt: make(chan struct{}, 1),
		client: desktop.Client{Zentrale: cfg.Zentrale, Token: token}, gezeigt: "start"}
	if err := a.fenster(); err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return 1
	}
	a.symbolHinzufuegen()
	go a.abfragen()
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(ptr(&m), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(ptr(&m))
		pDispatchMessageW.Call(ptr(&m))
	}
	return 0
}

func meldung(titel, text string, warnung bool) {
	art := uintptr(mbOK | mbIconInformation)
	if warnung {
		art = mbOK | mbIconWarning
	}
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(titel))), art)
}

func (a *app) fenster() error {
	inst, _, _ := pGetModuleHandleW.Call(0)
	klasse := utf16("OpenWachtDesktop")
	wc := wndClassEx{WndProc: syscall.NewCallback(wndProc), Instance: syscall.Handle(inst), ClassName: klasse}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassExW.Call(ptr(&wc)); r == 0 {
		return fmt.Errorf("Fensterklasse: %w", err)
	}
	h, _, err := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(klasse)), uintptr(unsafe.Pointer(utf16("OpenWacht"))), 0,
		0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return fmt.Errorf("Fenster: %w", err)
	}
	a.hwnd = syscall.Handle(h)
	// Startet der Explorer neu, muss das Symbol neu angemeldet werden.
	tc, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	a.taskbarCreated = uint32(tc)
	return nil
}

func (a *app) icon(z desktop.Zustand) syscall.Handle {
	if h, ok := a.icons[z]; ok {
		return h
	}
	res := desktop.IconRessource(desktop.Bild(z, 32))
	h, _, _ := pCreateIconFromResourceEx.Call(uintptr(unsafe.Pointer(&res[0])), uintptr(len(res)), 1, 0x00030000, 32, 32, lrDefaultColor)
	a.icons[z] = syscall.Handle(h)
	return syscall.Handle(h)
}

func (a *app) nid() notifyIconData {
	n := notifyIconData{Hwnd: a.hwnd, ID: 1}
	n.Size = uint32(unsafe.Sizeof(n))
	return n
}

func (a *app) symbolHinzufuegen() {
	n := a.nid()
	n.Flags = nifMessage | nifIcon | nifTip | nifShowTip
	n.CallbackMessage = wmTray
	n.Icon = a.icon(desktop.ZustandStoerung)
	setUTF16(n.Tip[:], "OpenWacht: verbinde …")
	pShellNotifyIconW.Call(nimAdd, ptr(&n))
	n.TimeoutOrVersion = notifyIconVersion4
	pShellNotifyIconW.Call(nimSetVersion, ptr(&n))
	a.gezeigt = desktop.ZustandStoerung
}

// abfragen läuft in einer eigenen Goroutine und meldet jeden Stand per
// PostMessage an den Oberflächen-Thread.
func (a *app) abfragen() {
	t := time.NewTicker(takt)
	defer t.Stop()
	for {
		a.mu.Lock()
		c := a.client
		a.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		alarme, err := c.Alarme(ctx)
		cancel()
		a.mu.Lock()
		if err != nil {
			a.fehler = err.Error()
			if errors.Is(err, desktop.ErrToken) {
				a.fehler = "API-Token ungültig, abgelaufen oder widerrufen. Rechtsklick → Einrichten."
			}
		} else {
			a.fehler = ""
			a.melden = append(a.melden, desktop.Vergleichen(a.letzte, alarme)...)
			if a.letzte == nil {
				a.letzte = []desktop.Alarm{}
			}
			a.letzte = alarme
			a.z = desktop.Zusammenfassen(alarme)
		}
		a.mu.Unlock()
		pPostMessageW.Call(uintptr(a.hwnd), wmStand, 0, 0)
		select {
		case <-t.C:
		case <-a.jetzt:
		}
	}
}

func (a *app) standZeigen() {
	a.mu.Lock()
	z, fehler, melden := a.z, a.fehler, a.melden
	a.melden = nil
	a.mu.Unlock()
	n := a.nid()
	n.Flags = nifIcon | nifTip | nifShowTip
	tip := z.Tooltip()
	zust := z.Zustand
	if fehler != "" {
		zust = desktop.ZustandStoerung
		tip = desktop.Kuerzen("OpenWacht: keine Verbindung – "+fehler, 127)
	}
	n.Icon = a.icon(zust)
	setUTF16(n.Tip[:], tip)
	pShellNotifyIconW.Call(nimModify, ptr(&n))
	a.gezeigt = zust

	// Störung einmal melden, Erholung still.
	if fehler != "" && !a.stoerung {
		a.stoerung = true
		a.blase("OpenWacht nicht erreichbar", fehler, niifWarning)
	} else if fehler == "" {
		a.stoerung = false
	}
	switch {
	case len(melden) > 3:
		text := ""
		for _, e := range melden[:3] {
			text += e.Titel() + ": " + e.Alarm.Name + "\n"
		}
		a.blase(fmt.Sprintf("OpenWacht: %d Ereignisse", len(melden)), text+"…", niifWarning)
	default:
		for _, e := range melden {
			art := uint32(niifInfo)
			switch {
			case e.Art == "entwarnung":
			case e.Alarm.Status == "crit":
				art = niifError
			default:
				art = niifWarning
			}
			a.blase(e.Titel(), e.Text(), art)
		}
	}
}

func (a *app) blase(titel, text string, art uint32) {
	n := a.nid()
	n.Flags = nifInfo
	n.InfoFlags = art
	setUTF16(n.InfoTitle[:], desktop.Kuerzen(titel, 63))
	setUTF16(n.Info[:], desktop.Kuerzen(text, 255))
	pShellNotifyIconW.Call(nimModify, ptr(&n))
}

func (a *app) oeffnen(pfad string) {
	a.mu.Lock()
	url := a.client.Zentrale + pfad
	a.mu.Unlock()
	pShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16("open"))), uintptr(unsafe.Pointer(utf16(url))), 0, 0, swShowNormal)
}

func (a *app) menue() {
	m, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(m)
	add := func(id int, text string, flags uintptr) {
		pAppendMenuW.Call(m, mfString|flags, uintptr(id), uintptr(unsafe.Pointer(utf16(text))))
	}
	add(cmdOeffnen, "OpenWacht öffnen", 0)
	add(cmdAlarme, "Alarme öffnen", 0)
	add(cmdPruefen, "Jetzt prüfen", 0)
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	auto := uintptr(0)
	if autostartAn() {
		auto = mfChecked
	}
	add(cmdAutostart, "Mit Windows starten", auto)
	add(cmdEinrichten, "Einrichten …", 0)
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	add(0, version.String("openwacht-desktop"), mfGrayed)
	add(cmdBeenden, "Beenden", 0)
	var p point
	pGetCursorPos.Call(ptr(&p))
	pSetForegroundWindow.Call(uintptr(a.hwnd))
	id, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd, uintptr(p.X), uintptr(p.Y), 0, uintptr(a.hwnd), 0)
	a.befehl(int(id))
}

func (a *app) befehl(id int) {
	switch id {
	case cmdOeffnen:
		a.oeffnen("/")
	case cmdAlarme:
		a.oeffnen("/alarme")
	case cmdPruefen:
		select {
		case a.jetzt <- struct{}{}:
		default:
		}
	case cmdAutostart:
		if err := autostartSetzen(!autostartAn()); err != nil {
			meldung("OpenWacht Desktop", err.Error(), true)
		}
	case cmdEinrichten:
		go func() {
			a.mu.Lock()
			alt := desktop.Config{Zentrale: a.client.Zentrale}
			a.mu.Unlock()
			cfg, ok := einrichten(alt)
			if !ok {
				return
			}
			token, err := tokenLesen()
			if err != nil {
				return
			}
			a.mu.Lock()
			a.client = desktop.Client{Zentrale: cfg.Zentrale, Token: token}
			a.letzte, a.melden = nil, nil
			a.mu.Unlock()
			select {
			case a.jetzt <- struct{}{}:
			default:
			}
		}()
	case cmdBeenden:
		n := a.nid()
		pShellNotifyIconW.Call(nimDelete, ptr(&n))
		pPostQuitMessage.Call(0)
	}
}

func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	if a == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	switch uint32(m) {
	case wmTray:
		switch uint32(lp & 0xffff) {
		case wmContextMenu, wmRButtonUp:
			a.menue()
		case ninSelect, wmLButtonUp:
			a.oeffnen("/")
		case ninBalloonUserClick:
			a.oeffnen("/alarme")
		}
		return 0
	case wmStand:
		a.standZeigen()
		return 0
	case wmDestroy:
		n := a.nid()
		pShellNotifyIconW.Call(nimDelete, ptr(&n))
		pPostQuitMessage.Call(0)
		return 0
	}
	if a.taskbarCreated != 0 && uint32(m) == a.taskbarCreated {
		a.symbolHinzufuegen()
		pPostMessageW.Call(uintptr(a.hwnd), wmStand, 0, 0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}
