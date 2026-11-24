// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Hyper-V-Sensor (Etappe 26): Der Windows-Agent liest mit einem festen
// Lesebefehl (WMI-Klasse Msvm_ComputerSystem im Namensraum
// root\virtualization\v2) nur Name und Zustand der VMs. Die Zentrale schickt
// nur den VM-Namen; der Agent vergleicht ihn selbst, in den Befehl gelangt
// nichts von außen. Freigabe am Rechner: openwacht-agent sensoren -arten hyperv.
//
// Leitprinzip 5: keine Konfiguration, keine Benutzer, keine Inhalte der VMs.

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
)

// hypervVM: ein Eintrag aus Msvm_ComputerSystem.
type hypervVM struct {
	ElementName  string `json:"ElementName"` // Anzeigename
	Name         string `json:"Name"`        // GUID bei VMs, Rechnername beim Host selbst
	EnabledState int    `json:"EnabledState"`
}

// maxHypervList: mehr liest der Agent von der Ausgabe nicht.
const maxHypervList = 1 << 20

// hypervCacheFor: Mehrere Hyper-V-Sensoren teilen sich eine Abfrage.
const hypervCacheFor = 20 * time.Second

var guidName = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// parseHyperV liest die JSON-Ausgabe (Liste oder einzelnes Objekt) und lässt
// den Host-Eintrag (kein GUID als Name) weg.
func parseHyperV(b []byte) ([]hypervVM, error) {
	if len(b) > maxHypervList {
		return nil, errors.New("Ausgabe zu groß")
	}
	t := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if t == "" {
		return []hypervVM{}, nil
	}
	var list []hypervVM
	if strings.HasPrefix(t, "{") {
		var one hypervVM
		if err := json.Unmarshal([]byte(t), &one); err != nil {
			return nil, errors.New("Ausgabe unlesbar")
		}
		list = []hypervVM{one}
	} else if err := json.Unmarshal([]byte(t), &list); err != nil {
		return nil, errors.New("Ausgabe unlesbar")
	}
	out := list[:0]
	for _, v := range list {
		if guidName.MatchString(v.Name) {
			out = append(out, v)
		}
	}
	return out, nil
}

// hypervStateText: EnabledState (CIM_EnabledLogicalElement) bzw. die
// Hyper-V-eigenen Werte ab 32768.
func hypervStateText(st int) (string, string) {
	switch st {
	case 2:
		return checks.OK, "läuft"
	case 3:
		return checks.Crit, "ausgeschaltet"
	case 6, 32769:
		return checks.Warn, "gespeichert"
	case 9, 32768:
		return checks.Warn, "angehalten"
	case 32770:
		return checks.Warn, "startet"
	case 32773:
		return checks.Warn, "wird gespeichert"
	case 32774, 4:
		return checks.Warn, "fährt herunter"
	case 32776:
		return checks.Warn, "wird angehalten"
	case 32777:
		return checks.Warn, "wird fortgesetzt"
	}
	return checks.Unknown, "Zustand unbekannt"
}

// hypervResult bewertet die Liste; der Name zählt ohne Groß/Klein wie im
// Hyper-V-Manager. Zwei VMs mit gleichem Namen sind möglich: dann zählt die
// schlechteste.
func hypervResult(list []hypervVM, name string) checks.Result {
	found := 0
	res := checks.Result{}
	rank := map[string]int{checks.Crit: 0, checks.Unknown: 1, checks.Warn: 2, checks.OK: 3}
	for _, v := range list {
		if !strings.EqualFold(strings.TrimSpace(v.ElementName), name) {
			continue
		}
		found++
		st, text := hypervStateText(v.EnabledState)
		if found == 1 || rank[st] < rank[res.Status] {
			res = checks.Result{Status: st, Message: "VM " + text}
		}
	}
	switch {
	case found == 0:
		return checks.Result{Status: checks.Crit, Message: "VM nicht gefunden"}
	case found > 1:
		res.Message += " (mehrere VMs mit diesem Namen)"
	}
	return res
}

func (e *sensorEnv) hypervState(ctx context.Context, name string) checks.Result {
	if e.hyperv == nil {
		return checks.Result{Status: checks.Unknown, Message: "Hyper-V-Sensoren gibt es nur unter Windows"}
	}
	list, err := e.hypervList(ctx)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: clipText(err.Error(), 250)}
	}
	return hypervResult(list, name)
}

// hypervList fragt höchstens alle hypervCacheFor ab.
func (e *sensorEnv) hypervList(ctx context.Context) ([]hypervVM, error) {
	e.hvMu.Lock()
	defer e.hvMu.Unlock()
	now := e.now()
	if !e.hvAt.IsZero() && !now.Before(e.hvAt) && now.Sub(e.hvAt) < hypervCacheFor {
		return e.hvList, e.hvErr
	}
	e.hvList, e.hvErr = e.hyperv(ctx)
	e.hvAt = now
	return e.hvList, e.hvErr
}

// limitedBuffer nimmt höchstens max Bytes an und verwirft den Rest (der
// Prozess läuft trotzdem zu Ende, ohne zu blockieren).
type limitedBuffer struct {
	buf []byte
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte  { return b.buf }
func (b *limitedBuffer) String() string { return string(b.buf) }
