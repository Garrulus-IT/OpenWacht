// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/checks"
)

func TestSystemctlAuswertung(t *testing.T) {
	for _, tc := range []struct{ out, status, msg string }{
		{"LoadState=loaded\nActiveState=active\nSubState=running\n", checks.OK, "Dienst läuft"},
		{"LoadState=not-found\nActiveState=inactive\nSubState=dead\n", checks.Crit, "nicht gefunden"},
		{"LoadState=loaded\nActiveState=failed\nSubState=failed\n", checks.Crit, "fehlgeschlagen"},
		{"LoadState=loaded\nActiveState=inactive\nSubState=dead\n", checks.Crit, "gestoppt"},
		{"LoadState=loaded\nActiveState=activating\nSubState=start\n", checks.Warn, "wechselt"},
		{"Müll", checks.Unknown, "unbekannt"},
	} {
		res := serviceResult(parseSystemctlShow([]byte(tc.out)))
		if res.Status != tc.status || !strings.Contains(res.Message, tc.msg) {
			t.Errorf("%q: %+v", tc.out, res)
		}
	}
}

func TestProcNamen(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()
	// ohne Prozess 1: ProtectProc verbirgt fremde Prozesse
	if _, err := procNames(context.Background()); err == nil {
		t.Error("ohne /proc/1 kein Fehler")
	}
	for pid, comm := range map[string]string{"1": "systemd", "42": "nginx", "43": "nginx", "self": "x"} {
		os.MkdirAll(filepath.Join(root, pid), 0o755)
		os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644)
	}
	names, err := procNames(context.Background())
	if err != nil || len(names) != 3 {
		t.Errorf("Namen: %v %v", names, err)
	}
	// echtes /proc: mindestens der eigene Prozess
	procRoot = "/proc"
	if names, err := procNames(context.Background()); err != nil || len(names) == 0 {
		t.Errorf("/proc: %d %v", len(names), err)
	}
}
