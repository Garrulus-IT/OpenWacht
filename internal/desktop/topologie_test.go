package desktop

import "testing"

func TestTopoBaeume(t *testing.T) {
	s := func(x string) *string { return &x }
	g := []Geraet{
		{ID: "sw", Name: "Switch"},
		{ID: "dr", Name: "drucker", AbhaengigVon: s("sw")},
		{ID: "ap", Name: "Ärger-AP", AbhaengigVon: s("sw"), NichtErreichbarWegen: s("sw")},
		{ID: "ka", Name: "Kamera", AbhaengigVon: s("ap")},
		{ID: "x", Name: "allein"},
		{ID: "y", Name: "verwaist", AbhaengigVon: s("fehlt")},
		{ID: "w", Name: "wartung", Wartung: &Wartung{}},
	}
	sen := []Sensor{{GeraetID: "sw", Status: "ok"}, {GeraetID: "sw", Status: "warn"}, {GeraetID: "dr", Status: "crit"}}
	w, ohne := TopoBaeume(g, sen)
	if len(w) != 1 || w[0].Geraet.ID != "sw" || ohne != 3 {
		t.Fatalf("Wurzeln %d ohne %d", len(w), ohne)
	}
	k := w[0]
	if k.Stand != "warn" || len(k.Kinder) != 2 || k.Kinder[0].Geraet.ID != "ap" || k.Kinder[1].Stand != "crit" {
		t.Errorf("Kinder: %+v", k.Kinder)
	}
	if !k.Kinder[0].Gestrichelt() || len(k.Kinder[0].Kinder) != 1 || k.Kinder[0].Kinder[0].Stand != "neu" {
		t.Error("ap")
	}
	if TopoStand(g[6], nil) != "wartung" {
		t.Error("Wartung")
	}
}
