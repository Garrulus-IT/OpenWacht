package desktop

import (
	"testing"
	"time"
)

func TestBerichtHilfen(t *testing.T) {
	m := Monate(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))
	if len(m) != 13 || m[0] != "2026-01" || m[1] != "2025-12" || m[12] != "2025-01" {
		t.Errorf("Monate: %v", m)
	}
	if MonatName("2026-03") != "März 2026" || Prozent(99.95) != "99,950 %" || Dauer(45) != "45 Min." || Dauer(125) != "2:05 Std." {
		t.Error("Texte")
	}
	if z, err := ZielLesen("99,5 %"); err != nil || *z != 99.5 {
		t.Errorf("ZielLesen: %v %v", z, err)
	}
	if z, err := ZielLesen(" "); err != nil || z != nil {
		t.Error("leer muss erben")
	}
	if _, err := ZielLesen("viel"); err == nil {
		t.Error("Unsinn angenommen")
	}
	if q := BerichtAbfrage("m 1", "2026-10", false); q != "mandant=m+1&monat=2026-10&untermandanten=0" {
		t.Error(q)
	}
}
