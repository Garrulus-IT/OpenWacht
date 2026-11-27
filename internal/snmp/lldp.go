// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// LLDP-Nachbarn je Port (1.0.11), für die Einzelheiten eines Ports im Bild
// der Ports. Gelesen werden aus der LLDP-MIB (IEEE 802.1AB) nur der Name des
// Nachbarn und sein Port, sonst nichts (keine Beschreibung, keine Adressen,
// keine Fähigkeiten). Die Tabelle ist freiwillig: Fehlt sie oder scheitert
// die Abfrage, bleibt die Liste leer.

// LLDPNeighbor: ein Nachbar an einer Schnittstelle des Geräts.
type LLDPNeighbor struct {
	// Index: ifIndex der eigenen Schnittstelle
	Index int `json:"index"`
	// Name: lldpRemSysName, leer, wenn der Nachbar keinen nennt
	Name string `json:"name,omitempty"`
	// Port: lldpRemPortDesc, sonst lldpRemPortId (Text oder MAC-Adresse)
	Port string `json:"port,omitempty"`
}

const (
	// MaxLLDPNeighbors: so viele Nachbarn liest eine Abfrage höchstens.
	MaxLLDPNeighbors = 512
	// MaxLLDPText: Länge von Name und Port eines Nachbarn.
	MaxLLDPText = 64

	oidLldpLocPortId   = "1.0.8802.1.1.2.1.3.7.1.3"
	oidLldpRemPortId   = "1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemPortDesc = "1.0.8802.1.1.2.1.4.1.1.8"
	oidLldpRemSysName  = "1.0.8802.1.1.2.1.4.1.1.9"
)

// lldpText: Text eines LLDP-Felds; eine MAC-Adresse (6 Bytes, nicht
// druckbar) wird als aa:bb:cc:dd:ee:ff geschrieben.
func lldpText(v value) string {
	b, ok := v.pdu.Value.([]byte)
	if v.pdu.Type != gosnmp.OctetString || !ok {
		return ""
	}
	druckbar := true
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			druckbar = false
			break
		}
	}
	if !druckbar && len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return cleanBytes(b, MaxLLDPText)
}

// lldpLocalPort: die Portnummer aus dem Index einer Zeile von lldpRemTable
// (Zeitmarke.Portnummer.Index).
func lldpLocalPort(index string) (int, bool) {
	parts := strings.Split(index, ".")
	if len(parts) != 3 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[1])
	return n, err == nil && n > 0
}

// lldp liest die Nachbarn und ordnet sie den Schnittstellen zu. Die
// LLDP-Portnummer ist nicht überall der ifIndex: Passt die Portkennung des
// Geräts (lldpLocPortId) zu Name oder Beschreibung einer Schnittstelle, gilt
// diese; sonst die Schnittstelle mit dem ifIndex der Portnummer. Nachbarn
// ohne passende Schnittstelle fallen weg.
func (s *session) lldp(snap *Snapshot) {
	names, order, err := s.column(oidLldpRemSysName, MaxLLDPNeighbors)
	if err != nil || len(order) == 0 {
		return
	}
	desc, _, err := s.column(oidLldpRemPortDesc, MaxLLDPNeighbors)
	if err != nil {
		if errors.Is(err, ErrTooMuch) {
			return
		}
		desc = nil
	}
	ids, _, err := s.column(oidLldpRemPortId, MaxLLDPNeighbors)
	if err != nil {
		if errors.Is(err, ErrTooMuch) {
			return
		}
		ids = nil
	}
	loc, _, err := s.column(oidLldpLocPortId, MaxInterfaces)
	if err != nil {
		if errors.Is(err, ErrTooMuch) {
			return
		}
		loc = nil
	}
	byIndex := map[int]bool{}
	byName := map[string]int{}
	for _, it := range snap.Interfaces {
		byIndex[it.Index] = true
		// Die Beschreibung gilt nur, wenn kein Name sie schon belegt.
		if _, ok := byName[it.Name]; !ok && it.Name != "" {
			byName[it.Name] = it.Index
		}
	}
	ifIndex := func(port int) (int, bool) {
		if v, ok := loc[strconv.Itoa(port)]; ok {
			if i, ok := byName[lldpText(v)]; ok {
				return i, true
			}
		}
		return port, byIndex[port]
	}
	for _, idx := range order {
		port, ok := lldpLocalPort(idx)
		if !ok {
			continue
		}
		i, ok := ifIndex(port)
		if !ok {
			continue
		}
		n := LLDPNeighbor{Index: i, Name: lldpText(names[idx])}
		if v, ok := desc[idx]; ok {
			n.Port = lldpText(v)
		}
		if v, ok := ids[idx]; ok && n.Port == "" {
			n.Port = lldpText(v)
		}
		if n.Name == "" && n.Port == "" {
			continue
		}
		snap.LLDP = append(snap.LLDP, n)
	}
}

// validateLLDP prüft, was ein Sammler als Nachbarn schickt.
func validateLLDP(list []LLDPNeighbor) error {
	if len(list) > MaxLLDPNeighbors {
		return fmt.Errorf("lldp: höchstens %d", MaxLLDPNeighbors)
	}
	for i, n := range list {
		if n.Index < 0 || n.Index > 1<<30 || n.Name == "" && n.Port == "" ||
			clean(n.Name, MaxLLDPText) != n.Name || clean(n.Port, MaxLLDPText) != n.Port {
			return fmt.Errorf("lldp[%d]: unplausibel", i)
		}
	}
	return nil
}
