// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	cmdBrowser
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
	cfg      desktop.Config  // nur im Oberflächen-Thread
	letzte   []desktop.Alarm // nil bis zur ersten Antwort
	z        desktop.Zusammenfassung
	fehler   string
	melden   []desktop.Ereignis
	gezeigt  desktop.Zustand // Symbol, das gerade steht
	stoerung bool            // Störung schon gemeldet

	// Hauptfenster (1.0.6): Baum und Sensoren nur abfragen, solange es offen ist.
	f            *fenster
	fensterOffen atomic.Bool
	sitzungWeg   atomic.Bool // Konto: Zentrale hat die Sitzung beendet
	stand        desktop.Stand
	standFehler  string
	baum         []*desktop.Knoten

	// Seite Wartung
	wartungen      desktop.Wartungen
	wartungGeladen bool
	wartungFehler  string
	wartungSicht   atomic.Bool

	// nachgebildete Seiten (seite_windows.go)
	seitenSt   seitenStand
	ergebnisse chan func() // Ergebnisse aus imHintergrund für den Oberflächen-Thread
}

func (a *app) zentrale() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client.Zentrale
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
		case "lizenzen":
			lizenzenAblegen()
			return 0
		case "einrichten", "infobereich", "-version", "--version", "version":
		default:
			meldung("OpenWacht Desktop", "Aufruf: openwacht-desktop [einrichten | infobereich | lizenzen | entfernen]", true)
			return 2
		}
		if args[0] != "einrichten" && args[0] != "infobereich" {
			meldung("OpenWacht Desktop", version.String("openwacht-desktop"), false)
			return 0
		}
	}
	// Nur einmal je Benutzer.
	nurSymbol := len(args) > 0 && args[0] == "infobereich"
	if _, _, err := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(utf16(`Local\OpenWachtDesktop`)))); err == syscall.Errno(errorAlreadyExists) {
		// Läuft schon: dessen Fenster nach vorn holen (Doppelklick auf die App).
		if h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(utf16("OpenWachtDesktop"))), 0); h != 0 {
			if !nurSymbol {
				pAllowSetForegroundWindow.Call(asfwAny)
				pPostMessageW.Call(h, wmZeigen, 0, 0)
			}
			return 0
		}
		meldung("OpenWacht Desktop", "OpenWacht läuft schon im Infobereich neben der Uhr.", false)
		return 0
	}
	pfad, err := desktop.ConfigPath()
	if err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return 1
	}
	cfg, err := desktop.LoadConfig(pfad)
	runtime.LockOSThread()
	var sitzung *desktop.Sitzung
	_, terr := tokenLesen()
	// Mit Konto gibt es keine gespeicherte Anmeldung: immer anmelden.
	if err != nil || cfg.Zentrale == "" || cfg.MitKonto() || terr != nil || (len(args) > 0 && args[0] == "einrichten") {
		var ok bool
		if cfg, sitzung, ok = anmelden(0, cfg, ""); !ok {
			return 1
		}
	}
	client, err := clientFuer(cfg, sitzung)
	if err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return 1
	}
	a = &app{cfg: cfg, icons: map[desktop.Zustand]syscall.Handle{}, jetzt: make(chan struct{}, 1), ergebnisse: make(chan func(), 64),
		client: client, gezeigt: "start"}
	if err := a.fenster(); err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return 1
	}
	a.symbolHinzufuegen()
	if autostartAn() {
		autostartSetzen(true) // Pfad und Aufruf „infobereich“ auf den Stand dieser Datei
	}
	go a.abfragen()
	if !nurSymbol {
		a.fensterZeigen()
	}
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if a.f != nil {
			// Kurzbefehle (F5, Strg+F, Strg+N, F2, Entf) im Hauptfenster
			if m.Message == wmKeyDown {
				if r, _, _ := pGetAncestor.Call(uintptr(m.Hwnd), gaRoot); syscall.Handle(r) == a.f.hwnd && a.taste(m.WParam) {
					continue
				}
			}
			// Tab und Pfeiltasten zwischen den Teilen des Fensters
			if d, _, _ := pIsDialogMessageW.Call(uintptr(a.f.hwnd), uintptr(unsafe.Pointer(&m))); d != 0 {
				continue
			}
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
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
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
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
	pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&n)))
	n.TimeoutOrVersion = notifyIconVersion4
	pShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&n)))
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
				a.fehler = "API-Token ungültig, abgelaufen oder widerrufen. Rechtsklick › Anmeldung ändern."
			}
			if errors.Is(err, desktop.ErrSitzung) {
				a.fehler = "Sitzung abgelaufen. Klicken, um dich neu anzumelden."
				if !a.sitzungWeg.Swap(true) {
					pPostMessageW.Call(uintptr(a.hwnd), wmSitzungWeg, 0, 0)
				}
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
		if a.fensterOffen.Load() {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			st, err := c.StandHolen(ctx)
			cancel()
			a.mu.Lock()
			if err != nil {
				a.standFehler = err.Error()
				if errors.Is(err, desktop.ErrToken) {
					a.standFehler = "API-Token ungültig, abgelaufen oder widerrufen (links unten „Abmelden“ und neu anmelden)"
				}
				if errors.Is(err, desktop.ErrSitzung) {
					a.standFehler = "Sitzung abgelaufen, bitte neu anmelden"
				}
			} else {
				a.stand, a.standFehler = st, ""
			}
			a.mu.Unlock()
			if a.wartungSicht.Load() {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				w, err := c.WartungenHolen(ctx, "")
				cancel()
				a.mu.Lock()
				if err == nil {
					a.wartungen, a.wartungGeladen, a.wartungFehler = w, true, ""
				}
				a.mu.Unlock()
			}
		}
		pPostMessageW.Call(uintptr(a.hwnd), wmStand, 0, 0)
		select {
		case <-t.C:
		case <-a.jetzt:
		}
	}
}

func (a *app) standZeigen() {
	if a.f != nil && a.fensterOffen.Load() && seiten[a.f.seite] != nil {
		a.seiteLaden(a.f.seite) // alle 30 s wie im Web
	}
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
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
	a.gezeigt = zust
	if a.fensterOffen.Load() {
		a.aktualisieren(false)
	}

	// Störung einmal melden, Erholung still.
	if fehler != "" && !a.stoerung {
		a.stoerung = true
		titel := "OpenWacht nicht erreichbar"
		if a.sitzungWeg.Load() {
			titel = "OpenWacht: neu anmelden"
		}
		a.blase(titel, fehler, niifWarning)
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
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func (a *app) oeffnen(pfad string) {
	if !strings.HasPrefix(pfad, "/") {
		return // nur Seiten der eingestellten Zentrale
	}
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
	add(cmdBrowser, "Im Browser öffnen", 0)
	add(cmdAlarme, "Alarme im Browser", 0)
	add(cmdPruefen, "Jetzt abfragen", 0)
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	auto := uintptr(0)
	if autostartAn() {
		auto = mfChecked
	}
	add(cmdAutostart, "Mit Windows starten", auto)
	add(cmdEinrichten, "Anmeldung ändern …", 0)
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	add(0, version.String("openwacht-desktop"), mfGrayed)
	add(cmdBeenden, "Beenden", 0)
	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	pSetForegroundWindow.Call(uintptr(a.hwnd))
	id, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd, uintptr(p.X), uintptr(p.Y), 0, uintptr(a.hwnd), 0)
	// Laut Microsoft nötig, damit das Menü beim nächsten Mal sauber öffnet
	// und schließt (Menüs von Symbolen im Infobereich).
	pPostMessageW.Call(uintptr(a.hwnd), wmNull, 0, 0)
	a.befehl(int(id))
}

func (a *app) befehl(id int) {
	switch id {
	case cmdOeffnen:
		a.fensterZeigen()
	case cmdBrowser:
		a.oeffnen("/")
	case cmdAlarme:
		a.oeffnen("/alarme")
	case cmdPruefen:
		select {
		case a.jetzt <- struct{}{}:
		default:
		}
	case cmdAutostart:
		// Rückmeldung nach dem Nachlesen: Der Haken im Menü allein zeigt nicht,
		// ob Windows den Eintrag wirklich hat.
		soll := !autostartAn()
		err := autostartSetzen(soll)
		switch {
		case err != nil:
			meldung("OpenWacht Desktop", "Autostart nicht geändert: "+err.Error(), true)
		case autostartAn() != soll:
			meldung("OpenWacht Desktop", "Autostart nicht geändert: Windows hat den Eintrag „OpenWacht“ unter "+
				`HKCU\`+runSchluessel+" nicht übernommen.", true)
		case soll:
			meldung("OpenWacht Desktop", "OpenWacht startet jetzt mit Windows.", false)
		default:
			meldung("OpenWacht Desktop", "OpenWacht startet nicht mehr mit Windows.", false)
		}
	case cmdEinrichten:
		var owner syscall.Handle
		if a.f != nil && a.fensterOffen.Load() {
			owner = a.f.hwnd
		}
		cfg, sitzung, ok := anmelden(owner, a.cfg, "")
		if ok {
			a.altAbmelden()
			a.neuAngemeldet(cfg, sitzung)
		}
	case cmdBeenden:
		n := a.nid()
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&n)))
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
		// Version 4 (nimSetVersion): Windows meldet Klicks als NIN_SELECT bzw.
		// WM_CONTEXTMENU und schickt die Mausnachrichten zusätzlich. Nur die
		// ersten auswerten, sonst öffnet ein Klick zwei Tabs.
		switch uint32(lp & 0xffff) {
		case wmContextMenu:
			a.menue()
		case ninSelect, ninKeySelect, ninBalloonUserClick:
			if a.sitzungWeg.Load() {
				a.sitzungNeu()
			}
			a.fensterZeigen()
		}
		return 0
	case wmStand:
		a.standZeigen()
		return 0
	case wmZeigen:
		a.fensterZeigen()
		return 0
	case wmSitzungWeg:
		a.sitzungNeu()
		return 0
	case wmAktion:
	leeren:
		for {
			select {
			case fn := <-a.ergebnisse:
				fn()
			default:
				break leeren
			}
		}
		return 0
	case wmDestroy:
		n := a.nid()
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&n)))
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

// lizenzenAblegen schreibt die Lizenztexte der eingebetteten Schriften nach
// %APPDATA%\OpenWacht\lizenzen und öffnet den Ordner.
func lizenzenAblegen() {
	d, err := os.UserConfigDir()
	if err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return
	}
	ordner := filepath.Join(d, "OpenWacht", "lizenzen")
	if err := os.MkdirAll(ordner, 0o700); err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return
	}
	for name, text := range desktop.Lizenztexte() {
		if err := os.WriteFile(filepath.Join(ordner, name), text, 0o600); err != nil {
			meldung("OpenWacht Desktop", err.Error(), true)
			return
		}
	}
	pShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16("open"))), uintptr(unsafe.Pointer(utf16(ordner))), 0, 0, swShowNormal)
}

// clientFuer: mit Konto die Sitzung, sonst das Token aus der Anmeldeinformationsverwaltung.
func clientFuer(cfg desktop.Config, sitzung *desktop.Sitzung) (desktop.Client, error) {
	if sitzung != nil {
		return desktop.Client{Zentrale: cfg.Zentrale, Sitzung: sitzung}, nil
	}
	token, err := tokenLesen()
	if err != nil {
		return desktop.Client{}, fmt.Errorf("Token nicht lesbar: %w", err)
	}
	return desktop.Client{Zentrale: cfg.Zentrale, Token: token}, nil
}

// altAbmelden beendet eine bestehende Sitzung auf der Zentrale (vor dem Wechsel).
func (a *app) altAbmelden() {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	if c.Sitzung != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c.Abmelden(ctx)
		cancel()
	}
}

// neuAngemeldet: neuer Client nach dem Anmelden, alles neu abfragen.
func (a *app) neuAngemeldet(cfg desktop.Config, sitzung *desktop.Sitzung) {
	c, err := clientFuer(cfg, sitzung)
	if err != nil {
		meldung("OpenWacht Desktop", err.Error(), true)
		return
	}
	a.cfg = cfg
	a.sitzungWeg.Store(false)
	dashVergessen() // das Layout gehört zum Konto
	a.mu.Lock()
	a.client = c
	a.letzte, a.melden = nil, nil
	a.stand, a.standFehler = desktop.Stand{}, ""
	a.mu.Unlock()
	if a.f != nil {
		a.f.dashHost, a.f.sonnenKey, a.f.gewaehlt = "", "", ""
		a.aktualisieren(true)
	}
	a.jetztAbfragen()
}

// abmelden: Sitzung beenden bzw. Token löschen und neu anmelden; ohne
// Anmeldung endet die App.
func (a *app) abmelden() {
	text := "Die App vergisst das API-Token. Danach meldest du dich neu an, oder die App beendet sich."
	if a.cfg.MitKonto() {
		text = "Die Sitzung endet auch auf der Zentrale. Danach meldest du dich neu an, oder die App beendet sich."
	}
	if !bestaetigenDialog(a.f.hwnd, "Abmelden?", text, "Abmelden") {
		return
	}
	a.altAbmelden()
	tokenLoeschen()
	pShowWindow.Call(uintptr(a.f.hwnd), swHide)
	a.fensterOffen.Store(false)
	cfg, sitzung, ok := anmelden(0, a.cfg, "")
	if !ok {
		a.befehl(cmdBeenden)
		return
	}
	a.neuAngemeldet(cfg, sitzung)
	a.fensterZeigen()
}

// sitzungNeu: Die Zentrale hat die Sitzung beendet (Leerlauf, Höchstdauer,
// im Browser abgemeldet): neu anmelden. Bei Abbruch bleibt die App ohne
// Verbindung, ein Klick aufs Symbol fragt wieder.
func (a *app) sitzungNeu() {
	var owner syscall.Handle
	if a.f != nil && a.fensterOffen.Load() {
		owner = a.f.hwnd
	}
	cfg, sitzung, ok := anmelden(owner, a.cfg, "Die Sitzung ist abgelaufen.")
	if !ok {
		return
	}
	a.neuAngemeldet(cfg, sitzung)
}
