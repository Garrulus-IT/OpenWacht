// SPDX-License-Identifier: AGPL-3.0-only

// Package traps empfängt SNMP-Traps und -Informs (v1, v2c, v3) als eigener
// Dienst (openwacht-zentrale traps), getrennt von der Zentrale.
//
// Der Dienst öffnet selbst keinen Port: systemd reicht ihm den UDP-Socket
// (Port 162) per Socket-Aktivierung weiter. Er hat eine eigene
// Datenbankrolle (openwacht_traps), die nur die Funktionen traps_* aufrufen
// darf, und einen eigenen, vom Hauptschlüssel abgeleiteten Trap-Schlüssel.
// Angenommen werden nur Traps von Adressen bekannter SNMP-Geräte, bei denen
// ein Admin Traps eingeschaltet hat; v3 nur mit authPriv.
package traps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Secret: die Zugangsdaten einer Quelle, wie sie verschlüsselt in der
// Datenbank liegen (secret_enc und trap_secret_enc haben denselben Inhalt).
type Secret struct {
	Community string       `json:"community,omitempty"`
	V3        *snmp.V3Auth `json:"v3,omitempty"`
}

// KeyPurpose: Zweck für die Ableitung des Trap-Schlüssels aus dem
// Hauptschlüssel (HMAC-SHA256, wie die übrigen Schlüssel der Zentrale).
const KeyPurpose = "openwacht traps v1"

// DeriveKey leitet den Trap-Schlüssel aus dem Hauptschlüssel ab.
func DeriveKey(master []byte) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(KeyPurpose))
	return m.Sum(nil)
}

// AAD bindet die Trap-Zugangsdaten an Quelle, Mandant, Adresse, Port und
// Version: In eine andere Zeile kopiert, lassen sie sich nicht entschlüsseln.
func AAD(id, tenant, host string, port int, version string) []byte {
	return []byte("openwacht snmp trap v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port) + "|" + version)
}

// Seal verschlüsselt die Zugangsdaten für den Trap-Dienst.
func Seal(key []byte, sec Secret, id, tenant, host string, port int, version string) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(key, pt, AAD(id, tenant, host, port, version))
}

// Open entschlüsselt und prüft die Zugangsdaten passend zur Version.
func Open(key, box []byte, id, tenant, host string, port int, version string) (Secret, error) {
	var sec Secret
	pt, err := auth.Open(key, box, AAD(id, tenant, host, port, version))
	if err != nil {
		return sec, errors.New("Trap-Zugangsdaten nicht entschlüsselbar (Trap-Schlüssel falsch oder Daten manipuliert)")
	}
	if err := json.Unmarshal(pt, &sec); err != nil {
		return sec, errors.New("Trap-Zugangsdaten ungültig")
	}
	if err := sec.Check(version); err != nil {
		return Secret{}, err
	}
	return sec, nil
}

// Check prüft, ob die Zugangsdaten zur Version passen.
func (s Secret) Check(version string) error {
	switch version {
	case snmp.V1, snmp.V2c:
		if s.V3 != nil || !snmp.ValidCommunity(s.Community) {
			return errors.New("Community ungültig, bitte neu eingeben")
		}
	case snmp.V3:
		if s.Community != "" {
			return errors.New("SNMPv3-Zugangsdaten ungültig, bitte neu eingeben")
		}
		if err := s.V3.Validate(); err != nil {
			return errors.New("SNMPv3-Zugangsdaten ungültig, bitte neu eingeben")
		}
	default:
		return errors.New("SNMP-Version ungültig")
	}
	return nil
}
