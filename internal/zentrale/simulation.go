// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"

	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Simulation ersetzt die Abfragen über das Netz: Sensoren der Zentrale (Ping,
// HTTP, TLS …) und Abfragequellen (SNMP, Proxmox, FRITZ!Box …). Nur für die
// Klick-Demo im Browser (cmd/openwacht-demo), wo es kein Netz gibt; im Betrieb
// ist sie nil. Alles danach (Speichern, Schwellen, Alarme, Verlauf) läuft
// unverändert.
type Simulation interface {
	// Check: Ergebnis eines Sensors der Zentrale (id: Sensor, kind: Art).
	Check(ctx context.Context, id, kind string, spec checks.Spec) checks.Result
	// Poll: Messwerte einer Abfragequelle (id: Quelle, version: "2c", "3",
	// "pve", "tr064", "ontap", …; host: Adresse).
	Poll(ctx context.Context, id, version, host string) (*snmp.Snapshot, error)
}
