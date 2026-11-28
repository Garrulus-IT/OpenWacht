// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Zentrale als Windows-Dienst (1.0.14).
//
//	openwacht-zentrale dienst-einrichten [-daten <ordner>] [Optionen von starten …]
//	openwacht-zentrale dienst-entfernen
//
// Der Dienst läuft als LocalSystem und ruft `dienst` auf; Einstellungen
// stehen in <daten>\zentrale.env (Handbuch Kapitel 1, Windows Server). Das
// Protokoll schreibt er nach <daten>\zentrale.log.

const dienstName = "OpenWacht-Zentrale"

// dienstStarten: vom Dienststeuerungs-Manager gestartet? Dann als Dienst.
func dienstStarten(ctx context.Context, args []string, out io.Writer) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return cmdDienst(ctx, args, out)
	}
	daten, rest := datenArg(args)
	os.MkdirAll(daten, 0o700)
	if f, err := os.OpenFile(filepath.Join(daten, "zentrale.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		defer f.Close()
		slog.SetDefault(slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})))
		out = f
	}
	return svc.Run(dienstName, &zentraleDienst{work: func(ctx context.Context) error {
		return runDienst(ctx, daten, rest, out)
	}})
}

type zentraleDienst struct{ work func(context.Context) error }

func (s *zentraleDienst) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.work(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("Zentrale beendet mit Fehler", "fehler", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				select {
				case <-done:
				case <-time.After(30 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func cmdDienstEinrichten(_ context.Context, args []string, out io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Dienststeuerung (als Administrator aufrufen): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(dienstName); err == nil {
		s.Close()
		return fmt.Errorf("Dienst %s gibt es schon (erst dienst-entfernen)", dienstName)
	}
	s, err := m.CreateService(dienstName, exe, mgr.Config{
		DisplayName:      "OpenWacht Zentrale",
		Description:      "Zentrale von OpenWacht (Monitoring); Einstellungen in zentrale.env im Datenordner",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true, // nach PostgreSQL
		ErrorControl:     mgr.ErrorNormal,
	}, append([]string{"dienst"}, args...)...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, 86400); err != nil {
		return err
	}
	fmt.Fprintf(out, "Dienst %s eingerichtet. Einstellungen in %s, dann:\n  Start-Service %s\n",
		dienstName, filepath.Join(datenStandard(), "zentrale.env"), dienstName)
	return nil
}

func cmdDienstEntfernen(_ context.Context, _ []string, out io.Writer) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Dienststeuerung (als Administrator aufrufen): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(dienstName)
	if err != nil {
		return fmt.Errorf("Dienst %s: %w", dienstName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Fprintf(out, "Dienst %s entfernt. Daten, Schlüssel und Datenbank bleiben.\n", dienstName)
	return nil
}
