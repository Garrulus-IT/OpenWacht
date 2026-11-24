// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

// Aus einer Pipe (wie im Runbook mit printf) wird genau eine Zeile gelesen,
// ohne Zeilenende und ohne Rückfrage.
func TestReadPasswordPipe(t *testing.T) {
	for in, want := range map[string]string{
		"Sehr-geheim-1234\n":         "Sehr-geheim-1234",
		"Sehr-geheim-1234\r\nrest\n": "Sehr-geheim-1234",
		"ohne-zeilenende":            "ohne-zeilenende",
		"":                           "",
	} {
		var out bytes.Buffer
		got, err := readPassword(strings.NewReader(in), &out)
		if err != nil || got != want {
			t.Errorf("readPassword(%q) = %q, %v; erwartet %q", in, got, err, want)
		}
		if strings.Contains(out.String(), "wiederholen") {
			t.Errorf("Pipe darf nicht nach Wiederholung fragen: %q", out.String())
		}
	}
}
