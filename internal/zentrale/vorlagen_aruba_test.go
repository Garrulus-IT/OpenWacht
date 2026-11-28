// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"strings"
	"testing"
)

// Aruba-Sätze (1.0.13): die 2530 hat keinen Temperaturfühler, das Chassis
// 5400R prüft zusätzlich die Netzteile; PoE zählt über alle Gruppen.
func TestVorlagensaetzeAruba(t *testing.T) {
	hat := func(id, name string) bool {
		s, ok := builtinSet(id)
		if !ok {
			t.Fatalf("Satz %s fehlt", id)
		}
		for _, v := range s.Sensoren {
			if v.Name == name {
				return true
			}
		}
		return false
	}
	if hat("satz-aruba-2530", "Aruba: Temperatur") || !hat("satz-aruba-2930", "Aruba: Temperatur") ||
		!hat("satz-aruba-5400r", "Aruba: Temperatur") {
		t.Error("Temperatur")
	}
	if hat("satz-aruba-2930", "Aruba: Netzteile mit Strom") || !hat("satz-aruba-5400r", "Aruba: Netzteile mit Strom") {
		t.Error("Netzteile")
	}
	s, _ := builtinSet("satz-aruba-5400r")
	for _, v := range s.Sensoren {
		if strings.Contains(v.Name, "PoE-Leistung") && !strings.Contains(string(v.Ziel), `"zusammenfassung":"summe"`) {
			t.Errorf("PoE muss über alle Karten summieren: %s", v.Ziel)
		}
	}
}
