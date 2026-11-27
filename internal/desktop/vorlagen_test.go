package desktop

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVorlagen(t *testing.T) {
	l := []Vorlage{
		{Name: "Zertifikat", Typ: "tls"},
		{Name: "Dienst W32Time", Typ: "dienst", AmAgent: true},
		{Name: "Ping", Typ: "ping", Notiz: "Erreichbarkeit"},
		{Name: "OID", Typ: "snmp_oid"},
	}
	g := VorlagenGruppen(l, "")
	if len(g) != 3 || g[0][0].Wo() != "Zentrale" || len(g[0]) != 2 || g[1][0].Wo() != "Agent" || g[2][0].Wo() != "SNMP" {
		t.Fatalf("Gruppen: %+v", g)
	}
	if g := VorlagenGruppen(l, "erreich"); len(g) != 1 || g[0][0].Name != "Ping" {
		t.Errorf("Suche Notiz: %+v", g)
	}
	if IntervallKurz(300) != "5 Min." || IntervallKurz(3600) != "1 Std." || IntervallKurz(45) != "45 s" {
		t.Error("IntervallKurz")
	}
	s := VorlagenSatz{Sensoren: []Vorlage{{Name: "Windows: Ping"}, {Name: "Dienst DNS"}}}
	if SatzSensorenText(s) != "2 Sensoren: Ping · Dienst DNS" {
		t.Error(SatzSensorenText(s))
	}
	b := SatzEingabe(" S ", "", []Vorlage{{Name: "a", Typ: "ping", Intervall: 60, KennfarbeID: "k"}})
	if b["name"] != "S" || b["sensoren"].([]map[string]any)[0]["kennfarbe_id"] != "k" {
		t.Errorf("SatzEingabe: %v", b)
	}
	for _, v := range KennVorschlaege {
		if _, _, f := KennfarbePruefen(v); f != "" {
			t.Errorf("Vorschlag %s: %s", v, f)
		}
	}
	if _, _, f := KennfarbePruefen("#ffff00"); f == "" {
		t.Error("Gelb auf Weiß angenommen")
	}
	if _, _, f := KennfarbePruefen("#101010"); f == "" {
		t.Error("Fast-Schwarz auf Dunkel angenommen")
	}
}

// Die Vorschläge der App und des Webs sind dieselben (und bestehen beide Prüfungen).
func TestKennVorschlaegeWieImWeb(t *testing.T) {
	b, err := os.ReadFile("../../web/src/Kennfarben.tsx")
	if err != nil {
		t.Skip(err)
	}
	m := regexp.MustCompile(`const VORSCHLAEGE = \[([^\]]*)\]`).FindSubmatch(b)
	if m == nil {
		t.Fatal("VORSCHLAEGE im Web nicht gefunden")
	}
	web := regexp.MustCompile(`#[0-9a-fA-F]{6}`).FindAllString(string(m[1]), -1)
	if strings.Join(web, ",") != strings.Join(KennVorschlaege, ",") {
		t.Errorf("Web %v, App %v", web, KennVorschlaege)
	}
}
