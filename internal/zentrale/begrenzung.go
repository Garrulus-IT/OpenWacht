// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Grenzen für angemeldete Benutzer (1.0.5, Pentest-Hinweis H4).
//
// Ein angemeldeter Benutzer, auch ein Leser, konnte bisher beliebig viele
// teure Abfragen (Berichte, Verlauf) gleichzeitig stellen. Jetzt gilt je
// Benutzer, für Sitzungen und API-Tokens gleich:
//   - höchstens userParallel Anfragen gleichzeitig; weitere warten kurz auf
//     einen freien Platz und bekommen sonst 429,
//   - höchstens UserRequestsPerMinute Anfragen je Minute (Standard 1200,
//     API-Tokens zusätzlich 300),
//   - jede Abfrage in einer Transaktion des Benutzers bricht nach
//     userStatementTimeout ab (statement_timeout, siehe withUser).
// Die Grenzen sind so weit, dass mehrere offene Fenster und ein Dashboard
// mit vielen Kacheln nicht daran stoßen.

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const (
	userParallel         = 8
	userRate             = 1200
	userWait             = 15 * time.Second
	userStatementTimeout = "60s"
)

type userGate struct {
	mu    sync.Mutex
	slots map[string]*gateSlot
	rate  *rateWindow
	wait  time.Duration
}

type gateSlot struct {
	sem  chan struct{}
	refs int
}

func newUserGate(perMinute int) *userGate {
	return &userGate{slots: map[string]*gateSlot{}, rate: newRateWindow(perMinute), wait: userWait}
}

// enter wartet auf einen freien Platz; release gibt ihn wieder frei.
// ok = false: zu viele Anfragen (rate: je Minute), nichts zu releasen.
func (g *userGate) enter(ctx context.Context, user string, now time.Time) (release func(), ok, rate bool) {
	if !g.rate.allow(user, now) {
		return nil, false, true
	}
	g.mu.Lock()
	s := g.slots[user]
	if s == nil {
		s = &gateSlot{sem: make(chan struct{}, userParallel)}
		g.slots[user] = s
	}
	s.refs++
	g.mu.Unlock()
	drop := func() {
		g.mu.Lock()
		s.refs--
		if s.refs == 0 {
			delete(g.slots, user)
		}
		g.mu.Unlock()
	}
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem; drop() }, true, false
	case <-t.C:
	case <-ctx.Done():
	}
	drop()
	return nil, false, false
}

// gated lässt die Anfrage nur innerhalb der Grenzen des Benutzers durch.
func (s *Server) gated(w http.ResponseWriter, r *http.Request, user string, next http.Handler) {
	release, ok, rate := s.users.enter(r.Context(), user, s.now())
	if !ok {
		msg := "Zu viele Anfragen gleichzeitig. Bitte kurz warten."
		if rate {
			msg = "Zu viele Anfragen in der letzten Minute. Bitte kurz warten."
		}
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, msg)
		return
	}
	defer release()
	next.ServeHTTP(w, r)
}
