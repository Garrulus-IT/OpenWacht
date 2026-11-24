// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
)

// fakePerf: Attrappe nach der Swyx-Doku (Objekte SwyxServer und Swyx Trunk)
// und IIS (APP_POOL_WAS mit _Total). Instanznamen sind erfunden.
type fakePerf struct {
	data  map[string][]perfValue // Pfad (ohne Groß/Klein) → Werte
	err   error
	paths []string
}

func (f *fakePerf) read(_ context.Context, paths []string) ([][]perfValue, error) {
	f.paths = append(f.paths, paths...)
	if f.err != nil {
		return nil, f.err
	}
	out := make([][]perfValue, len(paths))
	for i, p := range paths {
		v, ok := f.data[strings.ToLower(p)]
		if !ok {
			return nil, errPerfNoCounter
		}
		out[i] = v
	}
	return out, nil
}

func swyxFake() *fakePerf {
	one := func(x float64) []perfValue { return []perfValue{{Value: x}} }
	return &fakePerf{data: map[string][]perfValue{
		`\swyxserver\server active`:   one(1),
		`\swyxserver\trunks`:          one(2),
		`\swyxserver\active calls`:    one(7),
		`\swyxserver\logged-in users`: one(46),
		`\swyxserver\licenced users`:  one(50),
		`\swyx trunk(*)\trunk registered at server`: {
			{"Leitung Beispiel 1", 1}, {"Leitung Beispiel 2", 0}},
		`\swyx trunk(*)\% channels used`:    {{"Leitung Beispiel 1", 20}, {"Leitung Beispiel 2", 87.5}},
		`\swyx trunk(*)\active trunk calls`: {{"Leitung Beispiel 1", 3}, {"Leitung Beispiel 2", 4}},
		`\app_pool_was(*)\current application pool state`: {
			{"_Total", 9}, {"IQ4docsWebAdmin", 3}, {"IQ4docsWebClient", 3}},
		`\app_pool_was(iq4docswebadmin)\current application pool state`: {{"", 3}},
	}}
}

func perfEnv(f *fakePerf) *sensorEnv {
	e := testEnv(time.Now())
	if f != nil {
		e.perf = f.read
	}
	return e
}

var perfRelease = &agentproto.SensorRelease{Kinds: []string{"leistungsindikator"}, Counters: []string{"SwyxServer", "swyx trunk", "APP_POOL_WAS"}}

func TestLeistungsindikatorBewertung(t *testing.T) {
	f := swyxFake()
	e := perfEnv(f)
	for _, c := range []struct{ target, status, metric, msg string }{
		{`{"objekt":"SwyxServer","indikator":"Server active","kritisch_unter":1}`, checks.OK, "1", "im Rahmen"},
		{`{"objekt":"SwyxServer","indikator":"Active Calls"}`, checks.OK, "7", "gelesen"},
		{`{"objekt":"SwyxServer","indikator":"Logged-in users","bezug":"Licenced users","warnung_ueber":90,"kritisch_ueber":98}`,
			checks.Warn, "92 %", "über 90"},
		{`{"objekt":"Swyx Trunk","indikator":"Trunk registered at server","instanz":"*","zusammenfassung":"minimum","kritisch_unter":1}`,
			checks.Crit, "minimum 0 (2 Instanzen)", "unter 1"},
		{`{"objekt":"Swyx Trunk","indikator":"% Channels used","instanz":"*","zusammenfassung":"maximum","warnung_ueber":80,"kritisch_ueber":95}`,
			checks.Warn, "maximum 87,5 (2 Instanzen)", "über 80"},
		{`{"objekt":"Swyx Trunk","indikator":"Active Trunk Calls","instanz":"*"}`, checks.OK, "summe 7 (2 Instanzen)", "gelesen"},
		{`{"objekt":"Swyx Trunk","indikator":"Active Trunk Calls","instanz":"*","zusammenfassung":"anzahl","kritisch_unter":3}`,
			checks.Crit, "2 Instanzen", "unter 3"},
		// _Total zählt bei „*“ nicht mit
		{`{"objekt":"APP_POOL_WAS","indikator":"Current Application Pool State","instanz":"*","zusammenfassung":"maximum","kritisch_ueber":3}`,
			checks.OK, "maximum 3 (2 Instanzen)", "im Rahmen"},
		{`{"objekt":"APP_POOL_WAS","indikator":"Current Application Pool State","instanz":"IQ4docsWebAdmin","gleich_nicht":1}`,
			checks.Unknown, "", "Parameter ungültig"},
	} {
		res := e.measure(context.Background(), perfRelease, job("leistungsindikator", c.target))
		if res.Status != c.status || res.Metric != c.metric || !strings.Contains(res.Message, c.msg) {
			t.Errorf("%s: %+v", c.target, res)
		}
		// Leitprinzip 5: keine Instanznamen in Meldung oder Messwert
		if strings.Contains(res.Message+res.Metric, "Beispiel") || strings.Contains(res.Message+res.Metric, "IQ4docsWeb") {
			t.Errorf("Instanzname gemeldet: %+v", res)
		}
	}
	// Pfade: englische Namen, Instanz in Klammern
	want := `\APP_POOL_WAS(*)\Current Application Pool State`
	found := false
	for _, p := range f.paths {
		found = found || p == want
	}
	if !found {
		t.Errorf("Pfade: %v", f.paths)
	}
}

func TestLeistungsindikatorFreigabeUndFehler(t *testing.T) {
	target := `{"objekt":"SwyxServer","indikator":"Active Calls"}`
	f := swyxFake()
	e := perfEnv(f)
	// Art nicht freigegeben
	res := e.measure(context.Background(), &agentproto.SensorRelease{Kinds: []string{"dienst"}}, job("leistungsindikator", target))
	if res.Status != checks.Unknown || !strings.Contains(res.Message, "-arten leistungsindikator -indikatoren") {
		t.Errorf("Art: %+v", res)
	}
	// Objekt nicht freigegeben: es wird gar nicht gelesen
	f.paths = nil
	res = e.measure(context.Background(), perfRelease, job("leistungsindikator", `{"objekt":"Process","indikator":"Working Set","instanz":"*"}`))
	if res.Status != checks.Unknown || !strings.Contains(res.Message, "nicht freigegeben") || len(f.paths) != 0 {
		t.Errorf("Objekt: %+v %v", res, f.paths)
	}
	// Bezug aus einem anderen Objekt gibt es nicht (gleiches Objekt erzwungen)
	res = e.measure(context.Background(), perfRelease, job("leistungsindikator", `{"objekt":"SwyxServer","indikator":"Trunks","bezug":"Trunks"}`))
	if res.Status != checks.Unknown {
		t.Errorf("Bezug gleich: %+v", res)
	}
	// nicht Windows
	res = perfEnv(nil).measure(context.Background(), perfRelease, job("leistungsindikator", target))
	if res.Status != checks.Unknown || !strings.Contains(res.Message, "nur unter Windows") {
		t.Errorf("ohne pdh: %+v", res)
	}
	// Fehler des Systems
	for err, status := range map[error]string{errPerfNoInstance: checks.Crit, errPerfNoObject: checks.Unknown,
		errPerfDenied: checks.Unknown, errors.New("PDH-Status 0x1"): checks.Unknown} {
		f.err = err
		res = e.measure(context.Background(), perfRelease, job("leistungsindikator", target))
		if res.Status != status {
			t.Errorf("%v: %+v", err, res)
		}
	}
	f.err = nil
	// Indikator fehlt in der Attrappe
	res = e.measure(context.Background(), perfRelease, job("leistungsindikator", `{"objekt":"SwyxServer","indikator":"Unbekannt"}`))
	if res.Status != checks.Unknown || !strings.Contains(res.Message, "Indikator nicht vorhanden") {
		t.Errorf("fehlt: %+v", res)
	}
}

func TestLeistungsindikatorSonderwerte(t *testing.T) {
	s := func(target string) checks.Spec {
		sp, err := checks.Parse("leistungsindikator", []byte(target))
		if err != nil {
			t.Fatal(err)
		}
		return sp
	}
	all := s(`{"objekt":"Swyx Trunk","indikator":"Trunks","instanz":"*","zusammenfassung":"minimum","kritisch_unter":1}`)
	if r := perfResult(all, nil, nil); r.Status != checks.Unknown || r.Message != "keine Instanz vorhanden" {
		t.Errorf("leer: %+v", r)
	}
	if r := perfResult(all, []perfValue{{"_Total", 5}}, nil); r.Status != checks.Unknown {
		t.Errorf("nur _Total: %+v", r)
	}
	if r := perfResult(all, []perfValue{{"a", math.NaN()}, {"b", math.Inf(1)}, {"c", 2}}, nil); r.Status != checks.OK || r.Metric != "minimum 2 (1 Instanzen)" {
		t.Errorf("NaN: %+v", r)
	}
	rel := s(`{"objekt":"SwyxServer","indikator":"Logged-in users","bezug":"Licenced users"}`)
	if r := perfResult(rel, []perfValue{{"", 3}}, []perfValue{{"", 0}}); r.Status != checks.Unknown || !strings.Contains(r.Message, "ist 0") {
		t.Errorf("Bezug 0: %+v", r)
	}
	if r := perfResult(rel, []perfValue{{"", 3}}, nil); r.Status != checks.Unknown {
		t.Errorf("Bezug fehlt: %+v", r)
	}
	one := s(`{"objekt":"SwyxServer","indikator":"Trunks"}`)
	if r := perfResult(one, []perfValue{{"", math.NaN()}}, nil); r.Status != checks.Unknown {
		t.Errorf("NaN einzeln: %+v", r)
	}
	// viele Instanzen: begrenzt
	many := make([]perfValue, maxPerfInstances+50)
	for i := range many {
		many[i] = perfValue{"x", 1}
	}
	cnt := s(`{"objekt":"Swyx Trunk","indikator":"Trunks","instanz":"*","zusammenfassung":"anzahl"}`)
	if r := perfResult(cnt, many, nil); r.Metric != "10000 Instanzen" {
		t.Errorf("Grenze: %+v", r)
	}
}

func TestSensorFreigabeIndikatoren(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []*agentproto.SensorRelease{
		{Kinds: []string{"leistungsindikator"}},
		{Kinds: []string{"dienst"}, Counters: []string{"SwyxServer"}},
		{Kinds: []string{"leistungsindikator"}, Counters: []string{`Swyx\Server`}},
		{Kinds: []string{"leistungsindikator"}, Counters: []string{"*"}},
		{Kinds: []string{"leistungsindikator"}, Counters: []string{"SwyxServer", "swyxserver"}},
	} {
		if _, err := WriteSensorRelease(dir, bad); err == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
	rel, err := WriteSensorRelease(dir, &agentproto.SensorRelease{Kinds: []string{"leistungsindikator"}, Counters: []string{"SwyxServer", "Swyx Trunk"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := ReadSensorConfig(dir)
	if err != nil || back == nil || !back.CounterReleased("SWYX TRUNK") || back.CounterReleased("Process") || len(rel.Counters) != 2 {
		t.Errorf("gelesen: %+v %v", back, err)
	}
}

func TestPerfLaufzeit(t *testing.T) {
	lim := 93600.0
	s := checks.Spec{Object: "System", Counter: "System Up Time", CritAbove: &lim}
	r := perfResult(s, []perfValue{{Value: 273600}}, nil)
	if r.Status != checks.Crit || r.Metric != "3 Tage 4 Std." || r.Message != "Laufzeit über 26 Std. (kritisch)" {
		t.Errorf("%+v", r)
	}
	s.Counter = "% Processor Time"
	if r := perfResult(s, []perfValue{{Value: 50}}, nil); r.Metric != "50" {
		t.Errorf("anderer Indikator: %+v", r)
	}
}
