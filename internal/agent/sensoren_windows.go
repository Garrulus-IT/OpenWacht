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
	return &sensorEnv{docker: dockerContainerState, service: windowsService, processes: windowsProcesses, hyperv: windowsHyperV, perf: windowsPerf,
		autoSvc: windowsAutoServices, now: time.Now}
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

// maxServices: mehr Dienste liest der Sensor „automatische Dienste“ nicht.
const maxServices = 4000

// windowsAutoServices listet die Dienste mit Starttyp „Automatisch“. Nur
// lesend: SC_MANAGER_ENUMERATE_SERVICE, je Dienst SERVICE_QUERY_CONFIG.
// Dienste je Benutzer (Vorlage und Instanzen) zählen nicht: Sie hängen an
// Anmeldungen und tragen eine Sitzungskennung im Namen.
func windowsAutoServices(context.Context) ([]autoService, time.Duration, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, 0, errors.New("Dienststeuerung nicht erreichbar: " + clipText(err.Error(), 120))
	}
	defer windows.CloseServiceHandle(scm)
	var need, count, resume uint32
	var buf []byte
	for range 4 {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &need, &count, &resume, nil)
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			break
		}
		if need > 16<<20 {
			return nil, 0, errors.New("Dienstliste zu groß")
		}
		buf = make([]byte, need+4096)
		resume = 0
	}
	if err != nil {
		return nil, 0, errors.New("Dienste nicht lesbar: " + clipText(err.Error(), 120))
	}
	if count == 0 {
		return nil, windows.DurationSinceBoot(), nil
	}
	if count > maxServices {
		count = maxServices
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
	var out []autoService
	for _, e := range entries {
		if e.ServiceStatusProcess.ServiceType&(serviceUserService|serviceUserServiceInstance) != 0 {
			continue
		}
		name := windows.UTF16PtrToString(e.ServiceName)
		auto, delayed, trigger, ok := serviceStart(scm, e.ServiceName)
		if !ok || !auto {
			continue
		}
		out = append(out, autoService{
			Name: name, Display: windows.UTF16PtrToString(e.DisplayName),
			Running: e.ServiceStatusProcess.CurrentState == windows.SERVICE_RUNNING,
			Delayed: delayed, Trigger: trigger,
		})
	}
	return out, windows.DurationSinceBoot(), nil
}

// Diensttypen für Dienste je Benutzer (fehlen in x/sys/windows).
const (
	serviceUserService         = 0x40
	serviceUserServiceInstance = 0x80
)

// serviceStart liest Starttyp, verzögerten Start und Auslöser eines Dienstes.
// ok = false: nicht lesbar (zählt nicht, statt einen Fehlalarm auszulösen).
func serviceStart(scm windows.Handle, name *uint16) (auto, delayed, trigger, ok bool) {
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return false, false, false, false
	}
	defer windows.CloseServiceHandle(h)
	var need uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &need)
	if need == 0 || need > 64<<10 {
		return false, false, false, false
	}
	b := make([]byte, need)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
	if windows.QueryServiceConfig(h, cfg, need, &need) != nil {
		return false, false, false, false
	}
	if cfg.StartType != windows.SERVICE_AUTO_START {
		return false, false, false, true
	}
	var d windows.SERVICE_DELAYED_AUTO_START_INFO
	if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
		(*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d)), &need) == nil {
		delayed = d.IsDelayedAutoStartUp != 0
	}
	// SERVICE_TRIGGER_INFO beginnt mit der Zahl der Auslöser (uint32).
	_ = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_TRIGGER_INFO, nil, 0, &need)
	if need >= 4 && need <= 64<<10 {
		t := make([]byte, need)
		if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_TRIGGER_INFO, &t[0], need, &need) == nil {
			trigger = *(*uint32)(unsafe.Pointer(&t[0])) > 0
		}
	}
	return true, delayed, trigger, true
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
