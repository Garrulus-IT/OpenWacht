// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

// Die Zentrale läuft nur unter Linux; Installation, Sicherung und Umstieg gibt es dort.
var errLinuxOnly = errors.New("nur unter Linux")

func cmdInstall(context.Context, []string, io.Writer) error        { return errLinuxOnly }
func cmdSetupLink(context.Context, []string, io.Writer) error      { return errLinuxOnly }
func cmdBackup(context.Context, []string, io.Writer) error         { return errLinuxOnly }
func cmdInternPostgres(context.Context, []string, io.Writer) error { return errLinuxOnly }
func cmdInternSetup(context.Context, []string, io.Writer) error    { return errLinuxOnly }
func cmdRestore(context.Context, []string, io.Writer) error        { return errLinuxOnly }
func cmdHTTPSSwitch(context.Context, []string, io.Writer) error    { return errLinuxOnly }
func cmdInternHTTPS(context.Context, io.Reader) error              { return errLinuxOnly }
func cmdRekey(context.Context, []string, io.Writer) error          { return errLinuxOnly }
