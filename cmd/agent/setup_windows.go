// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/garrulus-it/openwacht/internal/agent"
)

const noServiceHint = "Ohne Administratorrechte wurde kein Dienst eingerichtet. Starten mit:\n  openwacht-agent starten -verzeichnis %s\n"

// prepareService prüft vor der Registrierung, ob der Dienst eingerichtet
// werden kann, und liefert den Schritt danach. Ohne erhöhte Rechte: nil.
func prepareService(out io.Writer) (func(dir string) error, error) {
	if !agent.IsAdmin() {
		return nil, nil
	}
	bin, err := executable()
	if err != nil {
		return nil, err
	}
	if err := agent.CheckBinary(bin); err != nil {
		return nil, err
	}
	return func(dir string) error {
		running := agent.ServiceRunning()
		if err := agent.InstallService(bin, dir); err != nil {
			return err
		}
		fmt.Fprintf(out, "Dienst %s eingerichtet (Konto %s).\n", agent.ServiceName, agent.ServiceAccount)
		if running {
			fmt.Fprintf(out, "Der Dienst läuft noch mit der alten Registrierung. Neu starten mit:\n  Restart-Service %s\n", agent.ServiceName)
		} else {
			fmt.Fprintf(out, "Starten mit:\n  Start-Service %s\n", agent.ServiceName)
		}
		return nil
	}, nil
}

// runAsService: Vom Dienststeuerungs-Manager gestartet, läuft der Agent als
// echter Dienst und schreibt ins Anwendungsprotokoll (Quelle openwacht-agent).
func runAsService(work func(context.Context) error) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	if el, err := eventlog.Open(agent.ServiceName); err == nil {
		defer el.Close()
		slog.SetDefault(slog.New(&eventLogHandler{log: el}))
	}
	return true, svc.Run(agent.ServiceName, &service{work: work})
}

type service struct{ work func(context.Context) error }

// Execute meldet sofort „läuft“ und beendet den Agent bei Stopp oder
// Herunterfahren. Endet er mit Fehler (z. B. nicht registriert), meldet
// der Dienst einen Fehlercode, und Windows startet ihn später neu.
func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.work(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				slog.Error("Agent beendet mit Fehler", "fehler", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// eventLogHandler schreibt slog-Meldungen als Text ins Ereignisprotokoll.
type eventLogHandler struct {
	log   *eventlog.Log
	attrs []slog.Attr
}

func (h *eventLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *eventLogHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &eventLogHandler{log: h.log, attrs: append(append([]slog.Attr{}, h.attrs...), a...)}
}

func (h *eventLogHandler) WithGroup(string) slog.Handler { return h }

func (h *eventLogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	switch {
	case r.Level >= slog.LevelError:
		return h.log.Error(3, b.String())
	case r.Level >= slog.LevelWarn:
		return h.log.Warning(2, b.String())
	default:
		return h.log.Info(1, b.String())
	}
}

// packageSetup: Aufruf aus dem MSI (Custom Action als SYSTEM, nach dem
// Kopieren der Dateien). Mehrfach ausführbar; bei einem Update startet der
// Dienst neu. Ohne Token und ohne Registrierung bleibt es beim Kopieren.
//
// Reihenfolge (1.0.6): erst den Dienst einrichten (ohne Start), dann
// registrieren, dann starten. So kostet ein Fehler beim Einrichten kein
// Token; scheitert die Registrierung, entfernt der Agent den Dienst wieder.
// Ein Fehler beim Start bricht nicht ab: Autostart und Neustart bei Fehlern
// holen ihn nach, die Meldung steht im Ereignisprotokoll.
func packageSetup(ctx context.Context, o packageOptions, out io.Writer) error {
	bin, err := executable()
	if err != nil {
		return err
	}
	if err := agent.CheckBinary(bin); err != nil {
		return err
	}
	war := agent.Registered(o.dir)
	if !war && o.token == "" {
		fmt.Fprintln(out, "OpenWacht-Agent installiert, noch nicht registriert (MSI-Eigenschaften ZENTRALE und TOKEN fehlen).")
		return nil
	}
	if err := agent.InstallService(bin, o.dir); err != nil {
		return err
	}
	fmt.Fprintf(out, "Dienst %s eingerichtet (Konto %s).\n", agent.ServiceName, agent.ServiceAccount)
	if err := registerFromPackage(ctx, o, out); err != nil {
		if !war {
			if rerr := agent.RemoveService(); rerr != nil {
				fmt.Fprintf(out, "Dienst nach dem Fehler nicht entfernt: %v\n", rerr)
			}
		}
		return err
	}
	if err := agent.StartService(); err != nil {
		fmt.Fprintf(out, "Warnung: Dienst nicht gestartet (%v). Windows startet ihn beim nächsten Systemstart; "+
			"von Hand: Start-Service %s\n", err, agent.ServiceName)
		return nil
	}
	fmt.Fprintf(out, "Dienst %s gestartet.\n", agent.ServiceName)
	return nil
}

// packageLog: Ausgabe und Fehler von paket-einrichten bzw. paket-entfernen
// ins Anwendungsprotokoll (Quelle openwacht-agent), denn Windows Installer
// zeigt die Ausgabe einer Programmaktion nirgends an. Das Token steht nie in
// der Ausgabe.
func packageLog(befehl, ausgabe string, err error) {
	if e := eventlog.InstallAsEventCreate(agent.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); e != nil &&
		!strings.Contains(e.Error(), "already exists") {
		return
	}
	el, e := eventlog.Open(agent.ServiceName)
	if e != nil {
		return
	}
	defer el.Close()
	text := befehl + ":\n" + strings.TrimSpace(ausgabe)
	if err != nil {
		el.Error(3, text+"\nFehler: "+err.Error())
		return
	}
	el.Info(1, text)
}

func packageRemove(out io.Writer) error {
	if err := agent.RemoveService(); err != nil {
		return err
	}
	fmt.Fprintln(out, "Dienst und geplante Aufgabe entfernt.")
	return nil
}
