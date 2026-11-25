// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestUserGateParallel(t *testing.T) {
	g := newUserGate(userRate)
	g.wait = 50 * time.Millisecond
	now := time.Now()
	var rel []func()
	for i := range userParallel {
		r, ok, _ := g.enter(context.Background(), "a", now)
		if !ok {
			t.Fatalf("Platz %d abgelehnt", i)
		}
		rel = append(rel, r)
	}
	if _, ok, _ := g.enter(context.Background(), "a", now); ok {
		t.Error("mehr als userParallel gleichzeitig")
	}
	// anderer Benutzer ist nicht betroffen
	r, ok, _ := g.enter(context.Background(), "b", now)
	if !ok {
		t.Fatal("anderer Benutzer gesperrt")
	}
	r()
	// wartende Anfrage bekommt den frei werdenden Platz
	g.wait = 2 * time.Second
	var wg sync.WaitGroup
	wg.Add(1)
	got := false
	go func() {
		defer wg.Done()
		if r, ok, _ := g.enter(context.Background(), "a", now); ok {
			got = true
			r()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	rel[0]()
	wg.Wait()
	if !got {
		t.Error("Wartende Anfrage nicht durchgelassen")
	}
	for _, r := range rel[1:] {
		r()
	}
	g.mu.Lock()
	n := len(g.slots)
	g.mu.Unlock()
	if n != 0 {
		t.Errorf("%d Einträge bleiben liegen", n)
	}
	// abgebrochene Anfrage wartet nicht weiter
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range userParallel {
		r, _, _ := g.enter(context.Background(), "c", now)
		defer r()
	}
	if _, ok, _ := g.enter(ctx, "c", now); ok {
		t.Error("abgebrochene Anfrage durchgelassen")
	}
}

func TestUserGateRate(t *testing.T) {
	g := newUserGate(userRate)
	now := time.Now()
	for i := range userRate {
		r, ok, _ := g.enter(context.Background(), "a", now)
		if !ok {
			t.Fatalf("Anfrage %d abgelehnt", i)
		}
		r()
	}
	if _, ok, rate := g.enter(context.Background(), "a", now); ok || !rate {
		t.Error("mehr als userRate je Minute")
	}
	if r, ok, _ := g.enter(context.Background(), "a", now.Add(time.Minute)); !ok {
		t.Error("neue Minute gesperrt")
	} else {
		r()
	}
}

// Jede Transaktion eines Benutzers hat ein statement_timeout (H4).
func TestUserStatementTimeout(t *testing.T) {
	agentServer(t)
	var v string
	if err := vServer.withUser(context.Background(), ids["v_oa"], func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SHOW statement_timeout`).Scan(&v)
	}); err != nil {
		t.Fatal(err)
	}
	if v != "1min" {
		t.Errorf("statement_timeout = %q", v)
	}
	// Eine zu lange Abfrage bricht ab (hier mit kurzer Grenze geprüft).
	err := vServer.withUser(context.Background(), ids["v_oa"], func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SET LOCAL statement_timeout = '100ms'`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `SELECT pg_sleep(2)`)
		return err
	})
	if err == nil {
		t.Error("lange Abfrage nicht abgebrochen")
	}
}
