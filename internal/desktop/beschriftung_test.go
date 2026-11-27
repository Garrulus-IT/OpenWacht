// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import (
	"math"
	"strings"
	"testing"
)

// TestBeschriftungSchrumpftStattKuerzen (1.0.7): Fehlen nur wenige Zeichen,
// wird die Schrift kleiner und der Name bleibt ganz.
func TestBeschriftungSchrumpftStattKuerzen(t *testing.T) {
	// Ring 300–400 (Dicke 100): radial ist Platz für 90 Einheiten. Bei
	// Schrift 10,7 passen 15 Zeichen; „Garage Feuerwehr“ hat 16.
	spanne := 10.7 / 0.8 / 300 // Bogen am Innenrand → Schrift 10,7
	b := SonnenBeschriftungIn("Garage Feuerwehr", 300, 400, 0, spanne, 6.5, 19)
	if b == nil || b.Text != "Garage Feuerwehr" || !b.Radial || b.Schrift >= 10.69 || b.Schrift < 10.7*0.8 {
		t.Fatalf("knapp zu lang: %+v", b)
	}
	if float64(len([]rune(b.Text)))*b.Schrift*0.56 > 90.0001 {
		t.Errorf("passt nicht in den Platz: Schrift %v", b.Schrift)
	}
	// Viel zu lang: weiter kürzen, Schrift bleibt.
	b = SonnenBeschriftungIn("Garage Feuerwehr Hauptwache Nord", 300, 400, 0, spanne, 6.5, 19)
	if b == nil || !strings.HasSuffix(b.Text, "…") || math.Abs(b.Schrift-10.7) > 1e-9 {
		t.Errorf("viel zu lang: %+v", b)
	}
	// Passt ohnehin: unverändert.
	if b = SonnenBeschriftungIn("Garage", 300, 400, 0, spanne, 6.5, 19); b == nil || b.Text != "Garage" || math.Abs(b.Schrift-10.7) > 1e-9 {
		t.Errorf("kurz: %+v", b)
	}
	// Schrumpfen ginge unter die Untergrenze: kürzen.
	b = SonnenBeschriftungIn("Garage Feuerwehr", 300, 400, 0, spanne, 10.5, 19)
	if b == nil || !strings.HasSuffix(b.Text, "…") {
		t.Errorf("an der Untergrenze: %+v", b)
	}
}
