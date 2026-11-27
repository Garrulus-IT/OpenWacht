// SPDX-License-Identifier: AGPL-3.0-only

package desktop

import "testing"

func TestFehlversucheAuswahl(t *testing.T) {
	texte, werte := FehlversucheAuswahl()
	if len(texte) != 11 || len(werte) != 11 || werte[0] != "0" || texte[0] != "Standard (3 Fehlschläge)" ||
		werte[1] != "1" || texte[1] != "1 Fehlschlag (sofort)" || werte[10] != "10" || texte[5] != "5 Fehlschlägen in Folge" {
		t.Errorf("%q %q", texte, werte)
	}
}
