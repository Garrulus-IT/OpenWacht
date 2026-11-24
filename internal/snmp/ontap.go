// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// ONTAP: Ergebnis einer Abfrage der ONTAP-REST-API (Paket ontap, 0.41.0).
// Wie bei Proxmox und FRITZ!Box liegt es im selben Snapshot: Belegung der
// Aggregate und Volumes steht zusätzlich unter Platten (Alarm, Verlauf,
// Prognose), die Laufzeit des längsten Knotens unter System.
//
// Datensparsam: Seriennummern, Konten, Freigaben, Dateien, Clients und
// Inhalte von Volumes werden nicht gelesen bzw. nicht gespeichert. Von
// EMS-Ereignissen nur Name, Schwere, Knoten, Zeit und der gekürzte Text.
type ONTAP struct {
	Cluster string `json:"cluster"`
	Version string `json:"version"`
	// Fingerprint: SHA-256 des Zertifikats (hex), mit dem abgefragt wurde
	Fingerprint string           `json:"fingerabdruck,omitempty"`
	Nodes       []ONTAPNode      `json:"knoten"`
	Aggregates  []ONTAPAggregate `json:"aggregate"`
	Volumes     []ONTAPVolume    `json:"volumes"`
	Disks       ONTAPDisks       `json:"platten"`
	Shelves     []ONTAPShelf     `json:"shelves"`
	Mirrors     []ONTAPMirror    `json:"snapmirror"`
	Events      []ONTAPEvent     `json:"ems"`
}

// ONTAPNode: ein Controller (Knoten) mit HA-Zustand und Hardware.
type ONTAPNode struct {
	Name    string `json:"name"`
	State   string `json:"zustand"` // up, booting, down, taken_over, waiting_for_giveback, degraded, unknown
	Model   string `json:"modell,omitempty"`
	UptimeS uint64 `json:"laufzeit_s"`
	// HA: Speicher-Failover eingeschaltet; Partner: Name des HA-Partners
	HA       bool   `json:"ha"`
	Partner  string `json:"partner,omitempty"`
	Takeover string `json:"uebernahme,omitempty"` // not_possible, not_attempted, in_takeover, in_progress, failed
	Giveback string `json:"rueckgabe,omitempty"`  // nothing_to_giveback, not_attempted, in_progress, failed
	OverTemp bool   `json:"uebertemperatur"`
	// FailedFans, FailedPSUs: ausgefallene Lüfter und Netzteile im Controller
	FailedFans int `json:"luefter_ausgefallen"`
	FailedPSUs int `json:"netzteile_ausgefallen"`
}

// ONTAPAggregate: ein Aggregat (lokale Ebene). Belegung zusätzlich unter Platten.
type ONTAPAggregate struct {
	Name       string `json:"name"`
	Node       string `json:"knoten,omitempty"`
	State      string `json:"zustand"` // online, offline, restricted, failed, …
	TotalBytes uint64 `json:"gesamt"`
	UsedBytes  uint64 `json:"belegt"`
	// Leistung (nur Graph): IOPS gesamt und Latenz in Millisekunden; nil = keine gültige Messung
	IOPS      *float64 `json:"iops,omitempty"`
	LatencyMs *float64 `json:"latenz_ms,omitempty"`
}

// ONTAPVolume: ein Volume. Name als „SVM/Volume“.
type ONTAPVolume struct {
	Name       string `json:"name"`
	State      string `json:"zustand"` // online, offline, restricted, mixed, error
	Type       string `json:"typ"`     // rw, dp, ls
	TotalBytes uint64 `json:"gesamt"`
	UsedBytes  uint64 `json:"belegt"`
}

// ONTAPDisks: Zusammenfassung der Platten; nur auffällige einzeln.
type ONTAPDisks struct {
	Total  int         `json:"gesamt"`
	Spares int         `json:"ersatz"`
	Bad    []ONTAPDisk `json:"auffaellig"`
}

// ONTAPDisk: eine ausgefallene oder auffällige Platte.
type ONTAPDisk struct {
	Name      string `json:"name"`
	State     string `json:"zustand"`   // broken, copy, reconstructing, removed, …
	Container string `json:"behaelter"` // aggregate, broken, spare, shared, …
	Shelf     string `json:"shelf,omitempty"`
	Bay       *int   `json:"schacht,omitempty"`
	Model     string `json:"modell,omitempty"`
}

// ONTAPShelf: ein Shelf mit Netzteilen, Modulen, Lüftern und Temperaturen.
type ONTAPShelf struct {
	ID    string      `json:"id"`
	Model string      `json:"modell,omitempty"`
	State string      `json:"zustand"` // ok, error, unknown
	Parts []ONTAPPart `json:"teile"`
	Temps []ONTAPTemp `json:"temperaturen"`
}

// ONTAPPart: Netzteil (psu), Modul (module) oder Lüfter (fan).
type ONTAPPart struct {
	Kind  string `json:"art"` // psu, module, fan
	ID    string `json:"id"`
	State string `json:"zustand"` // ok, error
}

// ONTAPTemp: ein Temperaturfühler mit den Schwellen des Shelfs.
type ONTAPTemp struct {
	ID      string `json:"id"`
	Celsius *int   `json:"grad,omitempty"`
	Warn    *int   `json:"warnung_ab,omitempty"`
	Crit    *int   `json:"kritisch_ab,omitempty"`
	State   string `json:"zustand"` // ok, error
}

// ONTAPMirror: eine SnapMirror-Beziehung, deren Ziel dieser Cluster ist.
type ONTAPMirror struct {
	Source      string `json:"quelle"`
	Destination string `json:"ziel"`
	State       string `json:"zustand"`
	Healthy     bool   `json:"gesund"`
	// LagS: Verzögerung in Sekunden; nil = unbekannt (noch nicht initialisiert)
	LagS   *int64 `json:"verzoegerung_s,omitempty"`
	Reason string `json:"grund,omitempty"`
}

// ONTAPEvent: ein EMS-Ereignis der Schwere emergency oder alert.
type ONTAPEvent struct {
	Time     string `json:"zeit"`
	Name     string `json:"name"`
	Severity string `json:"schwere"`
	Node     string `json:"knoten,omitempty"`
	Message  string `json:"meldung"`
}
