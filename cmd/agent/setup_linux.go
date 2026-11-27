// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/garrulus-it/openwacht/internal/agent"
)

const noServiceHint = "Ohne root wurde kein Dienst eingerichtet. Starten mit:\n  openwacht-agent starten -verzeichnis %s\n"

// prepareService prüft vor der Registrierung, ob der Dienst eingerichtet
// werden kann, und liefert den Schritt danach. Ohne root: nil.
func prepareService(out io.Writer) (func(dir string) error, error) {
	if !agent.IsRoot() {
		return nil, nil
	}
	bin, err := executable()
	if err != nil {
		return nil, err
	}
	if err := agent.CheckBinary(bin); err != nil {
		return nil, err
	}
	uid, gid, err := agent.EnsureUser()
	if err != nil {
		return nil, err
	}
	return func(dir string) error {
		if err := agent.HandOver(dir, uid, gid); err != nil {
			return err
		}
		if err := agent.InstallUnit(bin, dir); err != nil {
			return err
		}
		if !agent.SystemdRunning() {
			fmt.Fprintf(out, "Unit geschrieben (%s), aber auf diesem System läuft kein systemd.\nDen Agent dann so starten (als Benutzer %s):\n  %s starten -verzeichnis %s\n",
				agent.UnitPath, agent.ServiceUser, bin, dir)
			return nil
		}
		unit := agent.UnitPath
		if agent.Packaged(bin, dir) {
			unit = agent.PackagedUnitDir + "/openwacht-agent.service"
		}
		fmt.Fprintf(out, "Dienst eingerichtet (%s). Starten mit:\n  systemctl enable --now openwacht-agent\n", unit)
		return nil
	}, nil
}

// runAsService: unter Linux kümmert sich systemd um alles.
func runAsService(func(context.Context) error) (bool, error) { return false, nil }

// packageSetup: nach dem Auspacken von .deb/.rpm (postinst bzw. %post).
// Mehrfach ausführbar; bei einem Update startet der Dienst neu.
func packageSetup(ctx context.Context, o packageOptions, out io.Writer) error {
	bin, err := executable()
	if err != nil {
		return err
	}
	if err := agent.CheckBinary(bin); err != nil {
		return err
	}
	if !agent.Packaged(bin, o.dir) {
		return fmt.Errorf("paket-einrichten erwartet %s und %s (Installation aus dem Paket); ohne Paket: openwacht-agent registrieren",
			agent.PackagedBinary, agent.PackagedDir)
	}
	moved, foreign, err := agent.RetireOldUnits()
	if err != nil {
		return err
	}
	for _, p := range moved {
		fmt.Fprintf(out, "Unit der früheren Einrichtung %s nach %s verschoben (die Units kommen jetzt aus dem Paket).\n", p, agent.OldUnitsDir)
	}
	for _, p := range foreign {
		fmt.Fprintf(out, "Warnung: %s verdeckt die Unit des Pakets; bitte prüfen und entfernen.\n", p)
	}
	uid, gid, err := agent.EnsureUser()
	if err != nil {
		return err
	}
	if err := registerFromPackage(ctx, o, out); err != nil {
		return err
	}
	if !agent.Registered(o.dir) {
		if err := agent.InstallUnit(bin, o.dir); err != nil {
			return err
		}
		fmt.Fprintf(out, "OpenWacht-Agent installiert, noch nicht registriert. Registrieren mit:\n  openwacht-agent registrieren -zentrale https://<zentrale>:8444 -token <token>\n  systemctl enable --now openwacht-agent\n")
		return nil
	}
	if err := agent.HandOver(o.dir, uid, gid); err != nil {
		return err
	}
	if err := agent.InstallUnit(bin, o.dir); err != nil {
		return err
	}
	if !agent.SystemdRunning() {
		fmt.Fprintf(out, "Kein systemd: Den Agent als Benutzer %s starten:\n  %s starten -verzeichnis %s\n", agent.ServiceUser, bin, o.dir)
		return nil
	}
	if b, err := exec.Command("systemctl", "reenable", "openwacht-agent.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reenable: %v: %s", err, b)
	}
	// restart startet auch einen angehaltenen Dienst; nach einem Update läuft so die neue Version.
	if b, err := exec.Command("systemctl", "restart", "openwacht-agent.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, b)
	}
	fmt.Fprintln(out, "Dienst openwacht-agent läuft.")
	return nil
}

// packageRemove: unter Linux erledigen das die Skripte des Pakets.
func packageRemove(io.Writer) error {
	return errors.New("unter Linux entfernt der Paketmanager den Dienst (apt remove bzw. dnf remove)")
}

// packageLog: Die Ausgabe des Paketmanagers zeigt alles an; nichts zu tun.
func packageLog(string, string, error) {}
