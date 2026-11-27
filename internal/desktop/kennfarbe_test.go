package desktop

import (
	"testing"
	"time"
)

func TestKennfarbenImBaum(t *testing.T) {
	blau := &Kennfarbe{ID: "k1", Name: "Kunde Blau", Farbe: "#2f6fdb"}
	gruen := &Kennfarbe{ID: "k2", Name: "Labor", Farbe: "#1b8a5a"}
	jetzt := time.Now()
	st := Stand{
		Mandanten: []Mandant{{ID: "m", Name: "Firma"}},
		Gruppen:   []Gruppe{{ID: "g1", MandantID: "m", Name: "A"}, {ID: "g2", MandantID: "m", Name: "B"}},
		Geraete: []Geraet{
			{ID: "d1", MandantID: "m", Name: "nur-kenn", GruppeID: sp("g1")},
			{ID: "d2", MandantID: "m", Name: "rot-gewinnt", GruppeID: sp("g2")},
			{ID: "d3", MandantID: "m", Name: "bestaetigt", GruppeID: sp("g2")},
			{ID: "d4", MandantID: "m", Name: "ok-mit-kenn"},
		},
		Sensoren: []Sensor{
			{GeraetID: "d1", Status: "crit", Kennfarbe: blau}, {GeraetID: "d1", Status: "warn"},
			{GeraetID: "d2", Status: "crit", Kennfarbe: blau}, {GeraetID: "d2", Status: "crit"},
			{GeraetID: "d3", Status: "crit", Kennfarbe: gruen, Alarm: &Alarm{ID: "a", Bestaetigt: &jetzt}},
			{GeraetID: "d4", Status: "ok", Kennfarbe: blau},
		},
	}
	w := BaumBauen(st)
	kenn := func(id string, art KnotenArt) *Kennfarbe { return Finden(w, art, id).Kenn }
	if kenn("d1", KnotenGeraet) != blau {
		t.Error("d1: Kennfarbe des kritischen Sensors erwartet")
	}
	if kenn("d2", KnotenGeraet) != nil {
		t.Error("d2: Rot ohne Kennfarbe muss gewinnen")
	}
	if kenn("d3", KnotenGeraet) != gruen {
		t.Error("d3: Kennfarbe gilt auch bei Bestätigt")
	}
	if kenn("d4", KnotenGeraet) != nil {
		t.Error("d4: bei OK keine Kennfarbe")
	}
	if kenn("g1", KnotenGruppe) != blau || kenn("g2", KnotenGruppe) != nil || w[0].Kenn != nil {
		t.Errorf("Gruppen/Mandant: g1=%v g2=%v m=%v", kenn("g1", KnotenGruppe), kenn("g2", KnotenGruppe), w[0].Kenn)
	}
	seg, _ := Sonne(w[0])
	for _, s := range seg {
		if s.Knoten.ID == "d1" && s.Kenn != blau {
			t.Error("Segment ohne Kennfarbe")
		}
	}
}

func TestSegmentFarbe(t *testing.T) {
	k := &Kennfarbe{Farbe: "#2f6fdb"}
	if f, s := SegmentFarbe("crit", k); f != 0x2f6fdb || s != 0xffffff {
		t.Errorf("crit: %06x %06x", f, s)
	}
	if f, s := SegmentFarbe("quittiert", k); f != Mischen(0x2f6fdb, 0x060c14, 55) || s != Wand.AufSignal {
		t.Errorf("quittiert: %06x %06x", f, s)
	}
	if f, _ := SegmentFarbe("ok", k); f != Wand.OK {
		t.Error("ok mit Kennfarbe")
	}
	if f, _ := SegmentFarbe("crit", &Kennfarbe{Farbe: "red"}); f != Wand.Krit {
		t.Error("ungültige Farbe übernommen")
	}
	if SchriftAuf(0xe0b041) != 0x0a121c || SchriftAuf(0x102238) != 0xffffff {
		t.Error("SchriftAuf")
	}
	if Mischen(0xffffff, 0x000000, 50) != 0x808080 {
		t.Errorf("Mischen %06x", Mischen(0xffffff, 0x000000, 50))
	}
}
