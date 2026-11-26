// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package main

import (
	"context"
	"errors"
	"io"
)

const noServiceHint = "Auf diesem System wird kein Dienst eingerichtet. Starten mit:\n  openwacht-agent starten -verzeichnis %s\n"

func prepareService(io.Writer) (func(dir string) error, error) { return nil, nil }

func runAsService(func(context.Context) error) (bool, error) { return false, nil }

func packageSetup(context.Context, packageOptions, io.Writer) error {
	return errors.New("Pakete gibt es nur für Linux und Windows")
}

func packageRemove(io.Writer) error { return errors.New("Pakete gibt es nur für Linux und Windows") }

// packageLog: Die Ausgabe des Paketmanagers zeigt alles an; nichts zu tun.
func packageLog(string, string, error) {}
