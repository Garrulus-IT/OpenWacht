// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import "time"

// Proxmox: Ergebnis einer Abfrage der Proxmox-VE-API (Paket pve). Es liegt im
// selben Snapshot wie SNMP-Daten, damit Verlauf, Alarme, Wartung und
// Oberfläche beide Arten gleich behandeln: Die Speicher eines Knotens stehen
// zusätzlich als Platten im Snapshot (Belegung, Prognose, Alarme 90/95 %).
//
// Datensparsam: Benutzer, die Aufgaben gestartet haben, Notizen, Tags und
// Konfiguration der Gäste werden nicht gespeichert, nur Name, Art, Status,
// „beim Booten starten“ und der Stand der Backups.
type Proxmox struct {
	Node    string `json:"knoten"`
	Version string `json:"version"`
	// Gäste (VMs und LXC) des Knotens, nach VMID sortiert
	Guests    []Guest    `json:"gaeste"`
	Storages  []Storage  `json:"speicherorte"`
	ThinPools []ThinPool `json:"thin_pools"`
	// BackupInfo: ob bekannt ist, welche Gäste in einem Backup-Job stehen
	BackupInfo bool `json:"backup_jobs_bekannt"`
	// TasksUntil: vzdump-Aufgaben bis zu diesem Ende sind ausgewertet
	TasksUntil time.Time `json:"aufgaben_bis"`
	// ExtraPrivs: Rechte des Tokens, die über reines Lesen hinausgehen
	ExtraPrivs []string `json:"zu_viele_rechte,omitempty"`
}

// Guest: eine VM (qemu) oder ein Container (lxc).
type Guest struct {
	VMID     int    `json:"vmid"`
	Type     string `json:"typ"` // qemu | lxc
	Name     string `json:"name"`
	Status   string `json:"status"` // running | stopped | paused | …
	Template bool   `json:"vorlage,omitempty"`
	// OnBoot: „beim Booten starten“; nil = unbekannt
	OnBoot   *bool     `json:"beim_booten,omitempty"`
	ConfigAt time.Time `json:"konfiguration_am"`
	UptimeS  uint64    `json:"laufzeit_s"`
	// InJob: steht in einem Backup-Job; nil = unbekannt
	InJob *bool `json:"im_backup_job,omitempty"`
	// letzter erfolgreicher und letzter Versuch (Ende der vzdump-Aufgabe)
	BackupOK    *time.Time `json:"backup_ok,omitempty"`
	BackupTry   *time.Time `json:"backup_versucht,omitempty"`
	BackupError string     `json:"backup_fehler,omitempty"`
}

// Storage: ein Proxmox-Speicher (local, local-lvm, nas-backup, …).
type Storage struct {
	Name       string `json:"name"`
	Type       string `json:"typ"`
	Active     bool   `json:"aktiv"`
	Enabled    bool   `json:"eingeschaltet"`
	Shared     bool   `json:"geteilt"`
	TotalBytes uint64 `json:"gesamt"`
	UsedBytes  uint64 `json:"belegt"`
}

// ThinPool: ein LVM-Thin-Pool mit Daten- und Metadatenbelegung.
type ThinPool struct {
	Name          string `json:"name"` // VG/LV
	SizeBytes     uint64 `json:"gesamt"`
	UsedBytes     uint64 `json:"belegt"`
	MetaSizeBytes uint64 `json:"metadaten_gesamt"`
	MetaUsedBytes uint64 `json:"metadaten_belegt"`
}

// MetaPercent: Belegung der Metadaten in Prozent; ok=false ohne Angabe.
func (t ThinPool) MetaPercent() (float64, bool) {
	if t.MetaSizeBytes == 0 || t.MetaUsedBytes > t.MetaSizeBytes {
		return 0, false
	}
	return float64(t.MetaUsedBytes) / float64(t.MetaSizeBytes) * 100, true
}
