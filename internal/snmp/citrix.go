// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// Citrix: Ergebnis einer Abfrage des Citrix Monitor Service (OData v4) an
// einem Delivery Controller (1.0.6, Paket citrix). Liegt im selben Snapshot
// wie die übrigen Abfragen.
//
// Datensparsam (Leitprinzip 5): Von Maschinen nur Zahlen und die Namen der
// nicht registrierten VDAs (Entscheidung 25.11.2026); von fehlgeschlagenen
// Verbindungen nur die Zahl je Fehlerart, nie Benutzer, Sitzungen oder
// Clients.
type Citrix struct {
	// Fingerprint: SHA-256 des Zertifikats des Controllers (hex)
	Fingerprint string `json:"fingerabdruck,omitempty"`
	// Machines: alle aktiven Maschinen (VDAs) der Site
	Machines    int `json:"vdas"`
	Registered  int `json:"registriert"`
	Maintenance int `json:"wartung"`
	// Unregistered: nicht registriert und nicht im Wartungsmodus
	Unregistered int `json:"nicht_registriert"`
	// UnregisteredNames: deren Namen (DOMÄNE\NAME), höchstens MaxCitrixNames
	UnregisteredNames []string `json:"nicht_registriert_namen,omitempty"`
	// Failures: fehlgeschlagene Verbindungen der letzten FailureWindowMin
	// Minuten je Fehlerart (ConnectionFailureEnumValue), ohne „None“
	FailureWindowMin int             `json:"fehler_minuten"`
	Failures         []CitrixFailure `json:"fehler,omitempty"`
	FailureTotal     int             `json:"fehler_gesamt"`
}

// CitrixFailure: Zahl der Fehlschläge einer Fehlerart.
type CitrixFailure struct {
	Code  int `json:"code"`
	Count int `json:"anzahl"`
}

// MaxCitrixNames: so viele Namen nicht registrierter VDAs werden gespeichert.
const MaxCitrixNames = 50
