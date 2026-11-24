// SPDX-License-Identifier: AGPL-3.0-only

// Package safe fängt Programmfehler (Panik) in Parsern und Abfragen ab,
// damit ein einzelnes kaputtes oder bösartiges Paket weder den Trap-Dienst
// noch die Zentrale oder den Agent beendet (Befund M3).
//
// Die Logzeile nennt nur den Bereich und die Stelle im Code, nie den
// Inhalt des Pakets oder der Antwort: Der Wert einer Panik kann Daten von
// außen enthalten, deshalb steht er nur bei Laufzeitfehlern im Log, deren
// Text fest vorgegeben ist (z. B. „index out of range [5] with length 3“).
package safe

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrPanic: Rückgabe, wenn eine Abfrage mit einer Panik endete.
var ErrPanic = errors.New("interner Fehler beim Auswerten der Antwort")

var counters sync.Map // Bereich → *atomic.Int64

func counter(area string) *atomic.Int64 {
	if c, ok := counters.Load(area); ok {
		return c.(*atomic.Int64)
	}
	c, _ := counters.LoadOrStore(area, new(atomic.Int64))
	return c.(*atomic.Int64)
}

// Counts liefert die Zahl der abgefangenen Paniken je Bereich seit dem Start.
func Counts() map[string]int64 {
	out := map[string]int64{}
	counters.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// Total: Summe über alle Bereiche.
func Total() int64 {
	var n int64
	for _, v := range Counts() {
		n += v
	}
	return n
}

// Areas: Bereiche mit mindestens einer Panik, sortiert.
func Areas() []string {
	var out []string
	for k, v := range Counts() {
		if v > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Handle wertet einen Wert von recover() aus: Zähler, Logzeile.
// Gibt true zurück, wenn p eine Panik war.
func Handle(area string, p any) bool {
	if p == nil {
		return false
	}
	n := counter(area).Add(1)
	attrs := []any{"bereich", area, "anzahl", n, "stelle", where()}
	if re, ok := p.(runtime.Error); ok {
		attrs = append(attrs, "fehler", clip(re.Error(), 200))
	} else {
		attrs = append(attrs, "art", fmt.Sprintf("%T", p))
	}
	slog.Error("Programmfehler abgefangen", attrs...)
	return true
}

// Recover für `defer safe.Recover("snmp", &err)` in Funktionen mit
// benannter Fehler-Rückgabe: setzt err auf ErrPanic.
func Recover(area string, err *error) {
	if Handle(area, recover()) && err != nil {
		*err = ErrPanic
	}
}

// Run führt fn aus und fängt eine Panik ab (für Schleifen je Paket).
func Run(area string, fn func()) (panicked bool) {
	defer func() {
		if Handle(area, recover()) {
			panicked = true
		}
	}()
	fn()
	return false
}

// where: erste Stelle im Aufrufstapel außerhalb von runtime und safe.
func where() string {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, "runtime.") && !ownFrame(f.Function) {
			file := f.File
			if i := strings.LastIndex(file, "/internal/"); i >= 0 {
				file = file[i+1:]
			}
			return fmt.Sprintf("%s:%d", file, f.Line)
		}
		if !more {
			return "unbekannt"
		}
	}
}

// ownFrame: Rahmen dieses Pakets (Recover, Run, Handle), nicht die Stelle des Fehlers.
func ownFrame(fn string) bool {
	i := strings.LastIndex(fn, "/internal/safe.")
	if i < 0 {
		return false
	}
	name := fn[i+len("/internal/safe."):]
	for _, p := range []string{"Recover", "Run", "Handle"} {
		if name == p || strings.HasPrefix(name, p+".") {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ResetForTest setzt alle Zähler zurück (nur für Tests).
func ResetForTest() {
	counters.Range(func(k, _ any) bool { counters.Delete(k); return true })
}
