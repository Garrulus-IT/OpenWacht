// SPDX-License-Identifier: AGPL-3.0-only

package snmp

// XAPI: Ergebnis einer Abfrage eines XenServer- bzw. XCP-ng-Pools über XAPI
// (Paket xapi, 0.42.0). Wie bei Proxmox und NetApp liegt es im selben
// Snapshot: Belegung der Storage-Repositories steht zusätzlich unter Platten
// (Alarm, Verlauf, Prognose), CPU und RAM des ganzen Pools unter CPU und
// Speicher, die Laufzeit des Pool-Masters unter System.
//
// Datensparsam: Von VMs nur Name, Zustand, Host und Zahlen (CPU, RAM, vCPUs),
// keine Konfiguration, keine Gastdaten, keine Konsolen. Konten, Subjekte,
// Lizenzen, Seriennummern und Gerätekonfiguration der Speicher
// (PBD.device_config, kann Passwörter enthalten) werden nicht gelesen bzw.
// nicht gespeichert.
type XAPI struct {
	Pool    string `json:"pool"`
	Product string `json:"produkt"` // z. B. „XenServer 8.4.0“ oder „XCP-ng 8.3.0“
	// Fingerprint: SHA-256 des Zertifikats des Pool-Masters (hex)
	Fingerprint string     `json:"fingerabdruck,omitempty"`
	Master      string     `json:"master"`
	HA          XAPIHA     `json:"ha"`
	Hosts       []XAPIHost `json:"hosts"`
	VMs         []XAPIVM   `json:"vms"`
	// VMCount: alle VMs (ohne Vorlagen, Snapshots und dom0), auch die nicht
	// einzeln gespeicherten
	VMCount XAPICount `json:"vm_anzahl"`
	SRs     []XAPISR  `json:"speicher"`
}

// XAPIHA: Hochverfügbarkeit des Pools.
type XAPIHA struct {
	Enabled bool `json:"an"`
	// Tolerate: so viele Hosts dürfen ausfallen (Einstellung); Plan: für so
	// viele Ausfälle reicht der Plan gerade
	Tolerate      int  `json:"tolerieren"`
	Plan          int  `json:"plan_fuer"`
	Overcommitted bool `json:"ueberbucht"`
}

// XAPIHost: ein Host des Pools.
type XAPIHost struct {
	Name        string `json:"name"`
	Master      bool   `json:"master"`
	Live        bool   `json:"erreichbar"`
	Enabled     bool   `json:"aktiviert"`
	Maintenance bool   `json:"wartung"`
	UptimeS     uint64 `json:"laufzeit_s"`
	// CPUPct: Mittel der letzten Minuten über alle CPUs; nil = keine Messwerte
	CPUPct *float64 `json:"cpu_prozent,omitempty"`
	// Speicher in Byte; 0 = unbekannt
	MemTotal uint64 `json:"ram_gesamt"`
	MemFree  uint64 `json:"ram_frei"`
	// Updates: „aktuell“, „ausstehend“ oder leer (unbekannt, z. B. XCP-ng)
	Updates string `json:"updates,omitempty"`
	// Pending: ausstehende Schritte nach Updates (reboot_host, restart_toolstack, …)
	Pending []string `json:"ausstehend,omitempty"`
	// MetricsError: warum keine Messwerte vorliegen (leer = vorhanden)
	MetricsError string `json:"messwerte_fehler,omitempty"`
}

// XAPIVM: eine VM (keine Vorlage, kein Snapshot, nicht dom0).
type XAPIVM struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	State string `json:"zustand"` // running, halted, paused, suspended
	Host  string `json:"host,omitempty"`
	// AutoStart: soll laufen (HA-Neustart „restart“ oder „automatisch starten“)
	AutoStart bool     `json:"soll_laufen"`
	VCPUs     int      `json:"vcpus"`
	CPUPct    *float64 `json:"cpu_prozent,omitempty"`
	MemBytes  uint64   `json:"ram"`
}

// XAPICount: Zahl der VMs je Zustand.
type XAPICount struct {
	Running   int `json:"laufend"`
	Halted    int `json:"aus"`
	Paused    int `json:"angehalten"`
	Suspended int `json:"ausgesetzt"`
}

// XAPISR: ein Storage-Repository mit Belegung und Anbindung.
type XAPISR struct {
	Name   string `json:"name"`
	Type   string `json:"typ"`
	Shared bool   `json:"geteilt"`
	// Total, Used: physische Größe und Belegung; 0/0 bei ISO- und Wechselmedien
	Total uint64 `json:"gesamt"`
	Used  uint64 `json:"belegt"`
	// Detached: Hosts, auf denen das SR nicht angebunden ist (PBD nicht verbunden)
	Detached []string `json:"nicht_angebunden,omitempty"`
}
