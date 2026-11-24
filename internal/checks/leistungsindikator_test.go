// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"strings"
	"testing"
)

func TestLeistungsindikatorParse(t *testing.T) {
	good := map[string]string{
		`{"objekt":"SwyxServer","indikator":"Active Calls"}`:                                                         "",
		`{"objekt":" SwyxServer ","indikator":"% Channels used","instanz":"*"}`:                                      "summe",
		`{"objekt":"Swyx Trunk","indikator":"Trunk registered at server","instanz":"*","zusammenfassung":"Minimum"}`: "minimum",
		`{"objekt":"APP_POOL_WAS","indikator":"Current Application Pool State","instanz":"IQ4docs WebAdmin"}`:        "",
		`{"objekt":"SwyxServer","indikator":"Logged-in users","bezug":"Licenced users","kritisch_ueber":98}`:         "",
		`{"objekt":"SwyxServer","indikator":"SwyxIt! Classic"}`:                                                      "",
		`{"objekt":"Netzwerkschnittstelle","indikator":"Bytes/s"}`:                                                   "",
	}
	for raw, agg := range good {
		s, err := Parse("leistungsindikator", []byte(raw))
		if err != nil || s.Aggregate != agg || strings.HasPrefix(s.Object, " ") {
			t.Errorf("%s: %+v %v", raw, s, err)
		}
	}
	bad := []string{
		`{"indikator":"Active Calls"}`,
		`{"objekt":"SwyxServer"}`,
		`{"objekt":"Swyx\\Server","indikator":"x"}`,
		`{"objekt":"Swyx(Server)","indikator":"x"}`,
		`{"objekt":"SwyxServer","indikator":"x(*)"}`,
		`{"objekt":"SwyxServer","indikator":"x\\y"}`,
		`{"objekt":"SwyxServer","indikator":"*"}`,
		`{"objekt":"SwyxServer","indikator":"?"}`,
		`{"objekt":"*","indikator":"x"}`,
		`{"objekt":"SwyxServer","indikator":"x","instanz":"a*"}`,
		`{"objekt":"SwyxServer","indikator":"x","instanz":"a)"}`,
		`{"objekt":"SwyxServer","indikator":"x","instanz":"_Total","zusammenfassung":"summe"}`,
		`{"objekt":"SwyxServer","indikator":"x","instanz":"*","zusammenfassung":"mittel"}`,
		`{"objekt":"SwyxServer","indikator":"x","instanz":"*","zusammenfassung":"maximum","bezug":"y"}`,
		`{"objekt":"SwyxServer","indikator":"x","bezug":"X"}`,
		`{"objekt":"SwyxServer","indikator":"x","bezug":"y*"}`,
		`{"objekt":"SwyxServer","indikator":"x","bezug":"y\\z"}`,
		`{"objekt":"SwyxServer","indikator":"x","gleich":"1"}`,
		`{"objekt":"SwyxServer","indikator":"x","warnung_ueber":5,"kritisch_ueber":5}`,
		`{"objekt":"SwyxServer","indikator":"x","name":"y"}`,
		`{"objekt":"` + strings.Repeat("a", 129) + `","indikator":"x"}`,
		`{"objekt":"SwyxServer\u0000","indikator":"x"}`,
		`{"objekt":"-SwyxServer","indikator":"x"}`,
	}
	for _, raw := range bad {
		if _, err := Parse("leistungsindikator", []byte(raw)); err == nil {
			t.Errorf("angenommen: %s", raw)
		}
	}
	// Felder der neuen Art passen zu keiner anderen
	if _, err := Parse("dienst", []byte(`{"name":"x","objekt":"y"}`)); err == nil {
		t.Error("objekt am Dienst angenommen")
	}
	if !IsAgentKind("leistungsindikator") {
		t.Error("keine Agent-Art")
	}
}

func TestLeistungsindikatorPfadUndName(t *testing.T) {
	if p := PerfPath("Swyx Trunk", "*", "% Channels used"); p != `\Swyx Trunk(*)\% Channels used` {
		t.Errorf("Pfad: %s", p)
	}
	if p := PerfPath("SwyxServer", "", "Trunks"); p != `\SwyxServer\Trunks` {
		t.Errorf("Pfad: %s", p)
	}
	s, _ := Parse("leistungsindikator", []byte(`{"objekt":"SwyxServer","indikator":"Trunks"}`))
	if n := DefaultName("leistungsindikator", s); n != "SwyxServer Trunks" {
		t.Errorf("Name: %s", n)
	}
	f := func(v float64) *float64 { return &v }
	sp := Spec{WarnAbove: f(10), CritAbove: f(20), WarnBelow: f(2), CritBelow: f(1)}
	for x, want := range map[float64]string{25: Crit, 15: Warn, 5: OK, 1.5: Warn, 0: Crit} {
		if r := JudgeNumber(sp, x, ""); r.Status != want {
			t.Errorf("%v: %+v", x, r)
		}
	}
	if r := JudgeNumber(Spec{}, 3, "3"); r.Status != OK || r.Message != "Wert gelesen" {
		t.Errorf("ohne Schwellen: %+v", r)
	}
	if GermanNumber(87.456) != "87,46" {
		t.Errorf("Zahl: %s", GermanNumber(87.456))
	}
}
