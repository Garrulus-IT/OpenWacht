// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import "os"

// Die Zentrale läuft nur unter Linux; anderswo wird das Passwort sichtbar gelesen.
func echoOff(*os.File) (func(), bool) { return nil, false }
