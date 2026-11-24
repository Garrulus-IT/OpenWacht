// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// FritzBox: Ergebnis einer TR-064-Abfrage (Paket tr064, Etappe 18c). Wie bei
// Proxmox liegt es im selben Snapshot wie SNMP-Daten: Die Internetverbindung
// steht zusätzlich als Schnittstelle „WAN“ darin (Verkehr als Rate und
// Graph), Modell und Laufzeit unter System (Neustart).
//
// Datensparsam: Seriennummer, Ereignisprotokoll, Geräte im Heimnetz und
// Telefonie werden nicht gelesen bzw. nicht gespeichert.
type FritzBox struct {
	Model   string `json:"modell"`
	Version string `json:"fritzos"`
	// AccessType: DSL, Ethernet, X_AVM-DE_Fiber, X_AVM-DE_UMTS, …
	AccessType string `json:"zugang,omitempty"`
	// Connection: Zustand laut FRITZ!Box (Connected, Disconnected, Connecting, …)
	Connection string `json:"verbindung,omitempty"`
	Connected  bool   `json:"verbunden"`
	// LastError: letzter Verbindungsfehler laut FRITZ!Box (ERROR_NONE = keiner)
	LastError    string `json:"letzter_fehler,omitempty"`
	ConnUptimeS  uint64 `json:"verbunden_seit_s,omitempty"`
	ExternalIP   string `json:"externe_ip,omitempty"`
	Layer1UpBps  uint64 `json:"leitung_auf_bps,omitempty"`
	Layer1DnBps  uint64 `json:"leitung_ab_bps,omitempty"`
	PhysicalLink string `json:"leitung,omitempty"` // Up, Down, Initializing, Unavailable
	DSL          *DSL   `json:"dsl,omitempty"`
	// Missing: Teile, die die FRITZ!Box nicht liefert (Recht fehlt, Aktion
	// unbekannt); die Oberfläche zeigt sie als „nicht verfügbar“.
	Missing []string `json:"nicht_verfuegbar,omitempty"`
	// Reasons: je fehlendem Teil Aktion und UPnP-Code, z. B.
	// „Verkehr: WANCommonInterfaceConfig.GetTotalBytesSent: Recht fehlt (606)“.
	Reasons []string `json:"nicht_verfuegbar_grund,omitempty"`
	// TLS: abgefragt über HTTPS mit festem Fingerabdruck (SHA-256, hex)
	TLS         bool   `json:"tls"`
	Fingerprint string `json:"fingerabdruck,omitempty"`
}

// DSL: Synchronisation der DSL-Leitung (WANDSLInterfaceConfig).
type DSL struct {
	Status  string `json:"status"` // Up, Down, Initializing, …
	UpBps   uint64 `json:"auf_bps"`
	DownBps uint64 `json:"ab_bps"`
	// Leitungskapazität (maximal mögliche Rate)
	UpMaxBps   uint64 `json:"auf_max_bps"`
	DownMaxBps uint64 `json:"ab_max_bps"`
}
