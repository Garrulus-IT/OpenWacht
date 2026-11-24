// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Windows-Leistungsindikatoren (0.44.0): Der Agent liest einen Indikator
// (\Objekt(Instanz)\Indikator) mit den englischen Namen über die
// Windows-Bibliothek pdh.dll. Damit überwacht OpenWacht z. B. SwyxWare
// (Objekte „SwyxServer“, „SwyxWare Trunk“) oder IIS-Anwendungspools
// („APP_POOL_WAS“), ohne SNMP und ohne offenen Port.
//
// Leitprinzip 1: Die Zentrale schickt nur Objekt-, Indikator- und
// Instanznamen als Daten. Gelesen wird nur aus Objekten, die am Rechner
// freigegeben sind (openwacht-agent sensoren -indikatoren SwyxServer,…);
// Platzhalter kommen nur als ganze Instanz „*“ an.
//
// Leitprinzip 5: Mit „*“ fasst der Agent alle Instanzen zu einer Zahl
// zusammen (Summe, Minimum, Maximum, Anzahl). Namen von Instanzen (etwa
// Leitungen oder Anwendungspools) meldet er nie.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/garrulus-it/openwacht/internal/checks"
)

// perfValue: ein gelesener Wert; Instance nur intern (zum Filtern von _Total).
type perfValue struct {
	Instance string
	Value    float64
}

// Fehler beim Lesen, je Betriebssystem auf diese abgebildet.
var (
	errPerfNoObject   = errors.New("Objekt nicht vorhanden (Software installiert und gestartet?)")
	errPerfNoCounter  = errors.New("Indikator nicht vorhanden (Name englisch wie in der Herstellerdoku?)")
	errPerfNoInstance = errors.New("Instanz nicht vorhanden")
	errPerfDenied     = errors.New("kein Zugriff: Dienstkonto NT SERVICE\\openwacht-agent in die Gruppe Leistungsüberwachungsbenutzer (S-1-5-32-558) aufnehmen")
)

// maxPerfInstances: mehr Instanzen wertet der Agent nicht aus.
const maxPerfInstances = 10000

func (e *sensorEnv) perfCounter(ctx context.Context, s checks.Spec) checks.Result {
	if e.perf == nil {
		return checks.Result{Status: checks.Unknown, Message: "Leistungsindikatoren gibt es nur unter Windows"}
	}
	paths := []string{checks.PerfPath(s.Object, s.Instance, s.Counter)}
	if s.Relative != "" {
		paths = append(paths, checks.PerfPath(s.Object, s.Instance, s.Relative))
	}
	vals, err := e.perf(ctx, paths)
	if err != nil {
		return perfError(err)
	}
	if len(vals) != len(paths) {
		return checks.Result{Status: checks.Unknown, Message: "Leistungsindikator lieferte keine Werte"}
	}
	var rel []perfValue
	if s.Relative != "" {
		rel = vals[1]
	}
	return perfResult(s, vals[0], rel)
}

func perfError(err error) checks.Result {
	switch {
	case errors.Is(err, errPerfNoInstance):
		return checks.Result{Status: checks.Crit, Message: errPerfNoInstance.Error()}
	case errors.Is(err, errPerfNoObject), errors.Is(err, errPerfNoCounter), errors.Is(err, errPerfDenied):
		return checks.Result{Status: checks.Unknown, Message: err.Error()}
	}
	return checks.Result{Status: checks.Unknown, Message: "Leistungsindikator nicht lesbar: " + clipText(err.Error(), 200)}
}

// usable: endliche Werte; bei „*“ ohne die Sammelinstanz _Total (sonst
// zählte alles doppelt).
func usable(list []perfValue, all bool) []float64 {
	out := make([]float64, 0, len(list))
	for i, v := range list {
		if i >= maxPerfInstances {
			break
		}
		if all && strings.EqualFold(v.Instance, "_Total") {
			continue
		}
		if math.IsNaN(v.Value) || math.IsInf(v.Value, 0) {
			continue
		}
		out = append(out, v.Value)
	}
	return out
}

func sum(xs []float64) float64 {
	t := 0.0
	for _, x := range xs {
		t += x
	}
	return t
}

// perfResult fasst die Werte zusammen und bewertet sie. Der Messwert nennt
// nur Zahlen, nie Instanzen.
func perfResult(s checks.Spec, main, relative []perfValue) checks.Result {
	all := s.Instance == "*"
	xs := usable(main, all)
	var x float64
	metric := ""
	switch {
	case all && s.Aggregate == "anzahl":
		x = float64(len(xs))
		metric = fmt.Sprintf("%d Instanzen", len(xs))
	case len(xs) == 0 && all:
		return checks.Result{Status: checks.Unknown, Message: "keine Instanz vorhanden"}
	case len(xs) == 0:
		return checks.Result{Status: checks.Unknown, Message: "kein gültiger Wert"}
	case !all:
		x = xs[0]
	case s.Aggregate == "minimum":
		x = xs[0]
		for _, v := range xs[1:] {
			x = math.Min(x, v)
		}
	case s.Aggregate == "maximum":
		x = xs[0]
		for _, v := range xs[1:] {
			x = math.Max(x, v)
		}
	default: // summe
		x = sum(xs)
	}
	if s.Relative != "" {
		bs := usable(relative, all)
		if len(bs) == 0 {
			return checks.Result{Status: checks.Unknown, Message: "Bezug " + clipText(s.Relative, 60) + " ohne Wert"}
		}
		b := bs[0]
		if all {
			b = sum(bs)
		}
		if b <= 0 {
			return checks.Result{Status: checks.Unknown, Message: "Bezug " + clipText(s.Relative, 60) + " ist 0"}
		}
		x = 100 * x / b
		metric = checks.GermanNumber(x) + " %"
	}
	if metric == "" && s.Relative == "" && !all && isUptimeCounter(s.Counter) {
		// Laufzeit in Sekunden lesbar zeigen (0.99.2): „3 Tage 4 Std.“ statt „273600“
		return checks.JudgeSeconds(s, x, clipText(checks.DurationText(x), 50))
	}
	if metric == "" {
		metric = checks.GermanNumber(x)
		if all {
			metric = fmt.Sprintf("%s %s (%d Instanzen)", s.Aggregate, metric, len(xs))
		}
	}
	return checks.JudgeNumber(s, x, clipText(metric, 50))
}

// isUptimeCounter: Indikatoren, die eine Laufzeit in Sekunden melden
// (System/System Up Time, Process/Elapsed Time, Dienste mit „Uptime“).
func isUptimeCounter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "system up time" || n == "elapsed time" || strings.HasSuffix(n, " up time") || strings.HasSuffix(n, " uptime")
}
