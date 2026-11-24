// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package agent

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/garrulus-it/openwacht/internal/checks"
)

func defaultSensorEnv() *sensorEnv {
	return &sensorEnv{docker: dockerContainerState, service: windowsService, processes: windowsProcesses, hyperv: windowsHyperV, perf: windowsPerf, now: time.Now}
}

// windowsService fragt nur den Zustand ab: Dienststeuerung mit
// SC_MANAGER_CONNECT und SERVICE_QUERY_STATUS, ohne Rechte zum Ändern.
func windowsService(_ context.Context, name string) checks.Result {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Dienststeuerung nicht erreichbar: " + clipText(err.Error(), 120)}
	}
	defer windows.CloseServiceHandle(scm)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Dienstname ungültig"}
	}
	h, err := windows.OpenService(scm, n, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		// 0.44.0: auch der Anzeigename (z. B. „SwyxServer“ oder „IQ4docs
		// MongoDB“) führt zum Dienst; Hersteller nennen oft nur ihn.
		if key, ok := serviceKeyName(scm, n); ok {
			h, err = windows.OpenService(scm, key, windows.SERVICE_QUERY_STATUS)
		}
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return checks.Result{Status: checks.Crit, Message: "Dienst nicht gefunden"}
	}
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Dienst nicht abfragbar: " + clipText(err.Error(), 120)}
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Zustand nicht abfragbar: " + clipText(err.Error(), 120)}
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return checks.Result{Status: checks.OK, Message: "Dienst läuft"}
	case windows.SERVICE_STOPPED:
		return checks.Result{Status: checks.Crit, Message: "Dienst gestoppt"}
	case windows.SERVICE_PAUSED:
		return checks.Result{Status: checks.Warn, Message: "Dienst angehalten"}
	}
	return checks.Result{Status: checks.Warn, Message: "Dienst wechselt den Zustand"}
}

var procGetServiceKeyName = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetServiceKeyNameW")

// serviceKeyName sucht den Dienstnamen zu einem Anzeigenamen (nur lesend).
func serviceKeyName(scm windows.Handle, display *uint16) (*uint16, bool) {
	buf := make([]uint16, 257)
	size := uint32(len(buf))
	r, _, _ := procGetServiceKeyName.Call(uintptr(scm), uintptr(unsafe.Pointer(display)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, false
	}
	return &buf[0], true
}

// windowsProcesses: nur die Programmnamen aus einem Prozess-Schnappschuss,
// ohne Benutzer und Kommandozeile (Leitprinzip 5).
func windowsProcesses(context.Context) ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var names []string
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		names = append(names, windows.UTF16ToString(e.ExeFile[:]))
		if len(names) >= 100000 {
			break
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) && err != nil {
		return nil, err
	}
	return names, nil
}

// hypervCommand: fester Lesebefehl, ohne Eingaben von außen. UTF-8-Ausgabe,
// damit Umlaute in VM-Namen ankommen; @() liefert immer eine Liste.
const hypervCommand = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; ` +
	`ConvertTo-Json -Compress -InputObject @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -ErrorAction Stop | ` +
	`Select-Object ElementName,Name,EnabledState)`

// windowsHyperV startet PowerShell aus dem Systemordner (nie über PATH) mit
// dem festen Befehl und liest höchstens maxHypervList Bytes.
func windowsHyperV(ctx context.Context) ([]hypervVM, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Restricted", "-Command", hypervCommand)
	cmd.Dir = sys
	var out, errOut limitedBuffer
	out.max, errOut.max = maxHypervList+1, 4096
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		switch {
		case strings.Contains(msg, "Ungültiger Namespace"), strings.Contains(msg, "Invalid namespace"):
			return nil, errors.New("Hyper-V ist auf diesem Rechner nicht installiert")
		case strings.Contains(msg, "Zugriff verweigert"), strings.Contains(msg, "Access denied"), strings.Contains(msg, "Access is denied"):
			return nil, errors.New("kein Lesezugriff auf root\\virtualization\\v2 für das Dienstkonto NT SERVICE\\openwacht-agent (WMI-Recht „Konto aktivieren“, sonst Gruppe Hyper-V-Administratoren)")
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New("Hyper-V-Abfrage fehlgeschlagen: " + clipText(msg, 200))
	}
	return parseHyperV(out.Bytes())
}
