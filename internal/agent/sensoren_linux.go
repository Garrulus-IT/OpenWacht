// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
)

func defaultSensorEnv() *sensorEnv {
	return &sensorEnv{docker: dockerContainerState, service: systemdService, processes: procNames, now: time.Now}
}

// systemctlPaths: fester Pfad statt Suche im PATH.
var systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}

// systemdService fragt den Zustand einer Unit ab: ein festes Programm mit
// geprüftem Namen als Argument, ohne Shell, nur lesend (systemctl show).
// Das ist kein Befehl der Zentrale: Was ausgeführt wird, steht hier im Code.
func systemdService(ctx context.Context, name string) checks.Result {
	bin := ""
	for _, p := range systemctlPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return checks.Result{Status: checks.Unknown, Message: "systemctl nicht gefunden (kein systemd?)"}
	}
	cmd := exec.CommandContext(ctx, bin, "show", "--no-pager", "--property=LoadState,ActiveState,SubState", "--", name)
	cmd.Env = []string{"LANG=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		why := strings.TrimSpace(strings.SplitN(errOut.String(), "\n", 2)[0])
		if why == "" {
			why = err.Error()
		}
		return checks.Result{Status: checks.Unknown, Message: "Zustand nicht abfragbar: " + clipText(why, 150)}
	}
	return serviceResult(parseSystemctlShow(out.Bytes()))
}

func parseSystemctlShow(b []byte) map[string]string {
	props := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && len(props) < 10 {
			props[k] = clipText(v, 40)
		}
	}
	return props
}

// serviceResult bewertet LoadState/ActiveState/SubState.
func serviceResult(p map[string]string) checks.Result {
	sub := p["SubState"]
	switch {
	case p["LoadState"] == "not-found":
		return checks.Result{Status: checks.Crit, Message: "Dienst nicht gefunden"}
	case p["ActiveState"] == "active":
		return checks.Result{Status: checks.OK, Message: "Dienst läuft", Metric: sub}
	case p["ActiveState"] == "failed":
		return checks.Result{Status: checks.Crit, Message: "Dienst fehlgeschlagen", Metric: sub}
	case p["ActiveState"] == "activating", p["ActiveState"] == "reloading", p["ActiveState"] == "deactivating":
		return checks.Result{Status: checks.Warn, Message: "Dienst wechselt den Zustand", Metric: p["ActiveState"]}
	case p["ActiveState"] == "inactive":
		return checks.Result{Status: checks.Crit, Message: "Dienst gestoppt", Metric: sub}
	}
	return checks.Result{Status: checks.Unknown, Message: "Zustand unbekannt", Metric: clipText(p["ActiveState"], 40)}
}

// procRoot: in Tests ersetzbar.
var procRoot = "/proc"

// procNames liest nur /proc/<pid>/comm: den Programmnamen, ohne Benutzer und
// Kommandozeile (Leitprinzip 5). Sieht der Dienst Prozess 1 nicht, verbirgt
// ProtectProc die Prozesse anderer Benutzer.
func procNames(context.Context) ([]string, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(procRoot + "/1"); err != nil && !isOwnPID1() {
		return nil, errors.New("Prozesse anderer Benutzer sind nicht sichtbar; als root „openwacht-agent sensoren -arten …,prozess“ erneut ausführen (setzt ProtectProc=default)")
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		b, err := os.ReadFile(procRoot + "/" + n + "/comm")
		if err != nil {
			continue // Prozess inzwischen beendet
		}
		names = append(names, strings.TrimRight(string(b), "\n"))
		if len(names) >= 100000 {
			break
		}
	}
	return names, nil
}

// isOwnPID1: im Container ist der Agent selbst manchmal Prozess 1.
func isOwnPID1() bool { return os.Getpid() == 1 }
