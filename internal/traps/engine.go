// SPDX-License-Identifier: AGPL-3.0-only

package traps

// Zeitfenster nach RFC 3414 (3.2.7) und Schutz gegen wiederholte Pakete.
//
// Bei v3-Traps ist der Absender die maßgebliche Engine: Der Dienst merkt sich
// je Quelle und Engine-ID die zuletzt gesehenen engineBoots/engineTime und
// lehnt ältere Pakete ab. Bei v3-Informs ist OpenWacht maßgeblich: Boots und
// Zeit müssen zur eigenen Engine passen. Zusätzlich verwirft ein kleiner
// Speicher identische Pakete innerhalb des Zeitfensters.

import (
	"crypto/sha256"
	"sync"
	"time"
)

// TimeWindow: erlaubte Abweichung (RFC 3414: 150 Sekunden).
const TimeWindow = 150

const maxBoots = 2147483647

// localEngine ist die eigene Engine (für Informs).
type localEngine struct {
	id    string // Engine-ID als Bytes in einem String (wie gosnmp)
	boots uint32
	start time.Time
}

func (e *localEngine) time(now time.Time) uint32 {
	d := now.Sub(e.start)
	if d < 0 {
		return 0
	}
	s := d / time.Second
	if s > maxBoots {
		return maxBoots
	}
	return uint32(s)
}

// inWindow prüft einen Inform gegen die eigene Engine (RFC 3414 3.2.7 a).
func (e *localEngine) inWindow(boots, t uint32, now time.Time) bool {
	if e.boots >= maxBoots || boots != e.boots {
		return false
	}
	own := int64(e.time(now))
	d := int64(t) - own
	return d >= -TimeWindow && d <= TimeWindow
}

// remoteState: zuletzt gesehene Zeiten einer Absender-Engine.
type remoteState struct {
	boots, time uint32
	at          time.Time // wann time empfangen wurde
	saved       time.Time // zuletzt in der Datenbank gespeichert
}

// checkRemote prüft einen v3-Trap gegen den gemerkten Stand (RFC 3414
// 3.2.7 b) und liefert den neuen Stand. ok = false: Paket verwerfen.
func checkRemote(st *remoteState, boots, t uint32, now time.Time) (next remoteState, ok bool) {
	if st == nil {
		return remoteState{boots: boots, time: t, at: now}, boots < maxBoots
	}
	if st.boots >= maxBoots || boots < st.boots || boots >= maxBoots {
		return *st, false
	}
	if boots > st.boots {
		return remoteState{boots: boots, time: t, at: now, saved: st.saved}, true
	}
	elapsed := now.Sub(st.at) / time.Second
	if elapsed < 0 {
		elapsed = 0
	}
	estimated := int64(st.time) + int64(elapsed)
	if int64(t)+TimeWindow < estimated {
		return *st, false
	}
	if t > st.time {
		return remoteState{boots: boots, time: t, at: now, saved: st.saved}, true
	}
	return *st, true
}

// replayCache merkt sich Prüfsummen authentifizierter Pakete für das
// doppelte Zeitfenster; ein identisches Paket wird nur einmal angenommen.
type replayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
	max  int
}

func newReplayCache(max int) *replayCache {
	return &replayCache{seen: map[[32]byte]time.Time{}, max: max}
}

// first meldet true beim ersten Mal. Ist der Speicher voll, werden
// abgelaufene Einträge entfernt; bleibt er voll, wird das Paket abgelehnt
// (lieber ein Trap zu wenig als eine Wiederholung).
func (c *replayCache) first(msg []byte, now time.Time) bool {
	h := sha256.Sum256(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[h]; ok && now.Sub(t) < 2*TimeWindow*time.Second {
		return false
	}
	if len(c.seen) >= c.max {
		for k, t := range c.seen {
			if now.Sub(t) >= 2*TimeWindow*time.Second {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			return false
		}
	}
	c.seen[h] = now
	return true
}

// tokenBucket begrenzt die Rate (je Absender und gesamt).
type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(rate, burst float64, now time.Time) bool {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens += d * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
