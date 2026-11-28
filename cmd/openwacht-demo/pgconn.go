// SPDX-License-Identifier: AGPL-3.0-only

//go:build js && wasm

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall/js"
	"time"
)

// pgConn ist eine Verbindung zu PGlite, die sich für pgx wie ein Socket
// verhält. Nachrichten des Clients werden gesammelt, bis eine Nachricht eine
// Antwort verlangt (Sync, Query, Flush, Startup, Copy-Ende); dann gehen sie als
// ein Block an PGlite. PGlite hat nur ein Backend: Alle Blöcke laufen
// nacheinander über einen einzigen Arbeiter (siehe worker).
type pgConn struct {
	pg js.Value

	mu       sync.Mutex
	wbuf     []byte // noch nicht vollständige oder nicht abgeschickte Nachrichten
	pending  []byte // vollständige Nachrichten seit dem letzten Abschicken
	rbuf     []byte // Antworten, noch nicht gelesen
	started  bool
	closed   bool
	err      error // Fehler von PGlite, an Read weitergegeben
	deadline time.Time
	signal   chan struct{}
}

func newPGConn(pg js.Value) *pgConn {
	return &pgConn{pg: pg, signal: make(chan struct{}, 1)}
}

type job struct {
	c       *pgConn
	msg     []byte
	cleanup bool
}

var (
	jobs       = make(chan job, 64)
	workerOnce sync.Once
	// txStatus: Stand des einen Backends nach der letzten ReadyForQuery
	// ('I' frei, 'T' in Transaktion, 'E' Transaktion abgebrochen).
	txStatus byte = 'I'
	// debug: jeden Block mit Art und Stand ausgeben (ocDemo.debug).
	debug bool
)

func zeige(format string, a ...any) {
	if debug {
		fmt.Fprintf(os.Stderr, "pg: "+format+"\n", a...)
	}
}

// Mehrere Verbindungen, ein Backend: Die Verbindung, die eine Transaktion
// beginnt, ist ihr Besitzer, bis das Backend wieder frei ist ('I'). Die
// Zentrale fragt aber mitten in manchen Transaktionen über eine zweite
// Verbindung aus dem Pool (etwa Alarmkanäle im Alarmdurchlauf). Im Betrieb
// ist das eine eigene Sitzung; hier läuft so eine Anfrage in einem
// Sicherungspunkt innerhalb der fremden Transaktion: Schlägt sie fehl, wird
// nur sie zurückgerollt, und sie sieht für sich den Stand 'I'. Will eine
// fremde Verbindung selbst eine Transaktion beginnen, wartet sie, bis der
// Besitzer fertig ist.
var owner *pgConn

func worker() {
	var waiting []job
	for {
		var j job
		if owner == nil && len(waiting) > 0 {
			j, waiting = waiting[0], waiting[1:]
		} else {
			j = <-jobs
		}
		if j.cleanup {
			// Eine Verbindung wurde mitten in einer Transaktion geschlossen
			// (etwa nach abgebrochenem Kontext). Das Backend ist geteilt,
			// also hier zurückrollen, sonst liefe die nächste Verbindung in
			// der alten Transaktion weiter.
			zeige("%p geschlossen, Stand %c, Besitzer %v", j.c, txStatus, owner == j.c)
			if owner == j.c || owner == nil {
				if txStatus != 'I' {
					if resp, err := roundTrip(j.c.pg, append(syncMsg(), queryMsg("ROLLBACK")...)); err == nil {
						noteStatus(resp)
					}
				}
				owner = nil
			}
			continue
		}
		if owner != nil && owner != j.c && !isStartup(j.msg) {
			if beginsTx(j.msg) || txStatus != 'T' {
				waiting = append(waiting, j)
				continue
			}
			nested(j)
			continue
		}
		resp, err := roundTrip(j.c.pg, j.msg)
		if err == nil {
			noteStatus(resp)
		}
		if txStatus == 'I' {
			owner = nil
		} else if !isStartup(j.msg) {
			owner = j.c
		}
		if debug {
			zeige("%p %s → %d Byte, Stand %c, Fehler %v %s", j.c, kinds(j.msg), len(resp), txStatus, err, fehlerText(resp))
		}
		j.c.deliver(resp, err)
	}
}

// nested: Anfrage einer fremden Verbindung in der Transaktion des Besitzers
// (siehe oben).
func nested(j job) {
	if _, err := roundTrip(j.c.pg, queryMsg("SAVEPOINT demo_fremd")); err != nil {
		j.c.deliver(nil, err)
		return
	}
	resp, err := roundTrip(j.c.pg, j.msg)
	ende := "RELEASE SAVEPOINT demo_fremd"
	if err != nil || fehlerText(resp) != "" && bytes.Contains(resp, []byte{'Z', 0, 0, 0, 5, 'E'}) {
		ende = "ROLLBACK TO SAVEPOINT demo_fremd; RELEASE SAVEPOINT demo_fremd"
	}
	if r2, err2 := roundTrip(j.c.pg, queryMsg(ende)); err2 == nil {
		noteStatus(r2)
	}
	if debug {
		zeige("%p fremd in Transaktion %s → %d Byte, Fehler %v %s", j.c, kinds(j.msg), len(resp), err, fehlerText(resp))
	}
	j.c.deliver(asIdle(resp), err)
}

// asIdle: ReadyForQuery mit Stand 'I' (die fremde Verbindung ist in keiner
// Transaktion).
func asIdle(b []byte) []byte {
	for i := 0; i+5 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i+1:]))
		if n < 4 || i+1+n > len(b) {
			break
		}
		if b[i] == 'Z' && n == 5 {
			b[i+5] = 'I'
		}
		i += 1 + n
	}
	return b
}

func isStartup(b []byte) bool { return len(b) >= 8 && b[0] == 0 }

// beginsTx: einfache Anfrage BEGIN (so beginnt pgx Transaktionen).
func beginsTx(b []byte) bool {
	for i := 0; i+5 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i+1:]))
		if n < 4 || i+1+n > len(b) {
			return false
		}
		if b[i] == 'Q' {
			q := strings.ToLower(strings.TrimSpace(string(b[i+5 : i+n])))
			if strings.HasPrefix(q, "begin") || strings.HasPrefix(q, "start transaction") {
				return true
			}
		}
		i += 1 + n
	}
	return false
}

func roundTrip(pg js.Value, msg []byte) ([]byte, error) {
	arr := js.Global().Get("Uint8Array").New(len(msg))
	js.CopyBytesToJS(arr, msg)
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	var then, catch js.Func
	then = js.FuncOf(func(this js.Value, args []js.Value) any {
		v := args[0]
		b := make([]byte, v.Length())
		js.CopyBytesToGo(b, v)
		done <- result{b: b}
		then.Release()
		catch.Release()
		return nil
	})
	catch = js.FuncOf(func(this js.Value, args []js.Value) any {
		done <- result{err: errors.New("pglite: " + args[0].Call("toString").String())}
		then.Release()
		catch.Release()
		return nil
	})
	pg.Invoke(arr).Call("then", then).Call("catch", catch)
	r := <-done
	return r.b, r.err
}

// noteStatus merkt sich den Transaktionsstand aus der letzten ReadyForQuery.
func noteStatus(b []byte) {
	for i := 0; i+5 <= len(b); {
		t := b[i]
		n := int(binary.BigEndian.Uint32(b[i+1:]))
		if n < 4 || i+1+n > len(b) {
			return
		}
		if t == 'Z' && n == 5 {
			txStatus = b[i+5]
		}
		i += 1 + n
	}
}

// kinds: Arten der Nachrichten eines Blocks, für debug.
func kinds(b []byte) string {
	var out []byte
	for i := 0; i+5 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i+1:]))
		if b[i] == 0 { // Startup
			return "Startup"
		}
		out = append(out, b[i])
		if b[i] == 'Q' && n > 4 {
			q := string(b[i+5 : i+1+n-1])
			if len(q) > 40 {
				q = q[:40]
			}
			out = append(out, "("+q+")"...)
		}
		if b[i] == 'P' && n > 4 {
			rest := b[i+5 : i+1+n]
			if k := bytes.IndexByte(rest, 0); k >= 0 {
				rest = rest[k+1:]
				if k2 := bytes.IndexByte(rest, 0); k2 >= 0 {
					q := string(rest[:k2])
					if len(q) > 50 {
						q = q[:50]
					}
					out = append(out, "("+q+")"...)
				}
			}
		}
		i += 1 + n
	}
	return string(out)
}

// fehlerText: erste ErrorResponse einer Antwort, für debug.
func fehlerText(b []byte) string {
	for i := 0; i+5 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i+1:]))
		if n < 4 || i+1+n > len(b) {
			return ""
		}
		if b[i] == 'E' || b[i] == 'N' {
			return string(b[i]) + ":" + strings.ReplaceAll(string(b[i+5:i+1+n]), "\x00", " ")
		}
		i += 1 + n
	}
	return ""
}

func syncMsg() []byte { return []byte{'S', 0, 0, 0, 4} }

func queryMsg(q string) []byte {
	b := make([]byte, 5, 6+len(q))
	b[0] = 'Q'
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(q)+1))
	b = append(b, q...)
	return append(b, 0)
}

func (c *pgConn) deliver(b []byte, err error) {
	c.mu.Lock()
	if err != nil {
		c.closed = true
		c.err = err
	} else {
		c.rbuf = append(c.rbuf, b...)
	}
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
}

func (c *pgConn) Write(p []byte) (int, error) {
	workerOnce.Do(func() { go worker() })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.wbuf = append(c.wbuf, p...)
	for {
		if !c.started {
			if len(c.wbuf) < 8 {
				return len(p), nil
			}
			n := int(binary.BigEndian.Uint32(c.wbuf))
			if len(c.wbuf) < n {
				return len(p), nil
			}
			if binary.BigEndian.Uint32(c.wbuf[4:]) == 80877102 {
				// CancelRequest: PGlite kann nicht abbrechen, die Anfrage
				// läuft ohnehin zu Ende.
				c.wbuf = c.wbuf[n:]
				c.closed = true
				return len(p), nil
			}
			c.started = true
			c.send(c.wbuf[:n])
			c.wbuf = c.wbuf[n:]
			continue
		}
		if len(c.wbuf) < 5 {
			return len(p), nil
		}
		t := c.wbuf[0]
		n := 1 + int(binary.BigEndian.Uint32(c.wbuf[1:]))
		if len(c.wbuf) < n {
			return len(p), nil
		}
		msg := c.wbuf[:n]
		c.wbuf = c.wbuf[n:]
		if t == 'X' {
			// Terminate nicht an PGlite: das Backend bleibt für die nächste
			// Verbindung bestehen.
			c.pending = nil
			continue
		}
		c.pending = append(c.pending, msg...)
		switch t {
		case 'S', 'Q', 'H', 'c', 'f':
			c.send(c.pending)
			c.pending = nil
		}
	}
}

func (c *pgConn) send(b []byte) {
	jobs <- job{c: c, msg: append([]byte(nil), b...)}
}

func (c *pgConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			err := c.err
			c.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		dl := c.deadline
		c.mu.Unlock()
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			timeout = t.C
			defer t.Stop()
		}
		select {
		case <-c.signal:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *pgConn) Close() error {
	c.mu.Lock()
	was := c.closed
	c.closed = true
	started := c.started
	c.mu.Unlock()
	if !was && started {
		jobs <- job{c: c, cleanup: true}
	}
	select {
	case c.signal <- struct{}{}:
	default:
	}
	return nil
}

func (c *pgConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *pgConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
	return nil
}

func (c *pgConn) SetWriteDeadline(time.Time) error { return nil }

type pgAddr struct{}

func (pgAddr) Network() string { return "pglite" }
func (pgAddr) String() string  { return "pglite" }

func (c *pgConn) LocalAddr() net.Addr  { return pgAddr{} }
func (c *pgConn) RemoteAddr() net.Addr { return pgAddr{} }
