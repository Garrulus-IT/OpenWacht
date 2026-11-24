// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPlanerDurchsatz: Mit vielen fälligen Aufgaben darf der Planer nicht
// auf den Takt warten (Befund aus dem Lasttest, Etappe 35).
func TestPlanerDurchsatz(t *testing.T) {
	var mu sync.Mutex
	pending := 400
	var claims, done, maxRunning, running atomic.Int64
	claim := func(_ context.Context, n int) ([]int, error) {
		claims.Add(1)
		mu.Lock()
		defer mu.Unlock()
		k := min(n, pending)
		pending -= k
		return make([]int, k), nil
	}
	work := func(_ context.Context, _ int) {
		r := running.Add(1)
		for m := maxRunning.Load(); r > m && !maxRunning.CompareAndSwap(m, r); m = maxRunning.Load() {
		}
		time.Sleep(2 * time.Millisecond)
		running.Add(-1)
		done.Add(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	start := time.Now()
	go func() {
		runPool(ctx, "Test", 8, time.Second, nil, claim, work)
		close(finished)
	}()
	for done.Load() < 400 && time.Since(start) < 10*time.Second {
		time.Sleep(5 * time.Millisecond)
	}
	took := time.Since(start)
	cancel()
	<-finished
	// alter Planer: 8 je Takt (1 s), also 50 s; neuer: kurz nach dem ersten Takt
	if done.Load() != 400 || took > 2500*time.Millisecond {
		t.Fatalf("%d von 400 in %s (zu langsam)", done.Load(), took)
	}
	if maxRunning.Load() > 8 {
		t.Errorf("mehr als 8 gleichzeitig: %d", maxRunning.Load())
	}
	if c := claims.Load(); c > 400/2+10 {
		t.Errorf("zu viele Abfragen der Datenbank: %d", c)
	}
}

// TestPlanerLeerlauf: Ohne Fälliges fragt der Planer nur einmal je Takt.
func TestPlanerLeerlauf(t *testing.T) {
	var claims atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	ticks := 0
	runPool(ctx, "Test", 8, 50*time.Millisecond, func() { ticks++ },
		func(context.Context, int) ([]int, error) { claims.Add(1); return nil, nil },
		func(context.Context, int) {})
	if c := claims.Load(); c < 4 || c > 8 || int(c) != ticks {
		t.Fatalf("Abfragen im Leerlauf: %d bei %d Takten", c, ticks)
	}
}
