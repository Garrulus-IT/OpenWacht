// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// runPool arbeitet fällige Aufgaben (Checks, SNMP-Abfragen) mit höchstens
// size gleichzeitig ab.
//
// Bis 0.33 holte der Planer nur einmal je Takt (2 s) neue Aufgaben, höchstens
// so viele, wie gerade Plätze frei waren. Das deckelte den Durchsatz auf
// size je Takt (16 je Sekunde): Im Lasttest (Etappe 35) kamen 2000
// SNMP-Geräte mit 60-s-Intervall nur alle 125 s dran. Jetzt gilt: War die
// letzte Abfrage voll (es ist vermutlich mehr fällig), holt der Planer nach,
// sobald ein Viertel der Plätze frei ist; sonst wartet er auf den Takt. So
// fragt er die Datenbank nie öfter als nötig und nie im Leerlauf.
func runPool[T any](ctx context.Context, what string, size int, every time.Duration, onTick func(),
	claim func(ctx context.Context, n int) ([]T, error), work func(ctx context.Context, item T)) {
	if size < 1 {
		size = 1
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	done := make(chan struct{}, size)
	tick := time.NewTicker(every)
	defer tick.Stop()
	running, more := 0, false
	batch := max(1, size/4)
	for {
		ticked := false
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if onTick != nil {
				onTick()
			}
			ticked = true
		case <-done:
			running--
		}
		// weitere fertige Aufgaben einsammeln, ohne zu warten
		for drained := false; !drained; {
			select {
			case <-done:
				running--
			default:
				drained = true
			}
		}
		free := size - running
		// erst nach dem Einsammeln entscheiden, sonst bleibt der Planer bis
		// zum nächsten Takt stehen, wenn mehrere Aufgaben zugleich fertig werden
		if free == 0 || !ticked && !(more && free >= batch) {
			continue
		}
		items, err := claim(ctx, free)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn(what+": fällige nicht lesbar", "fehler", err)
			}
			more = false
			continue
		}
		more = len(items) == free
		for _, it := range items {
			running++
			wg.Add(1)
			go func() {
				defer func() {
					wg.Done()
					done <- struct{}{}
				}()
				work(ctx, it)
			}()
		}
	}
}
