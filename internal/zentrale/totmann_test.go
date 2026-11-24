// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

type fakeHC struct {
	*httptest.Server
	mu     sync.Mutex
	paths  []string
	bodies int
	status int
}

func newFakeHC() *fakeHC {
	f := &fakeHC{status: 200}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		if r.ContentLength > 0 {
			f.bodies++
		}
		w.WriteHeader(f.status)
	}))
	return f
}

func (f *fakeHC) take() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := strings.Join(f.paths, ",")
	f.paths = nil
	return s
}

func TestTotmannURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hc-ping.com/1b4e28ba-2fa1-11d2-883f-0016d3cca427": true,
		"https://hc-ping.com/schluessel/openwacht":                 true,
		"http://127.0.0.1:8000/ping/x":                             true,
		"http://localhost/ping/x":                                  true,
		"http://hc-ping.com/x":                                     false, // ohne TLS ins Netz
		"http://172.16.0.5/ping/x":                                 false,
		"ftp://hc-ping.com/x":                                      false,
		"https://user:pw@hc-ping.com/x":                            false,
		"https://hc-ping.com/x?rid=1":                              false,
		"https://hc-ping.com/x#y":                                  false,
		"https://hc-ping.com/x y":                                  false,
		"hc-ping.com/x":                                            false,
		"":                                                         false,
		"https://hc-ping.com/" + strings.Repeat("x", 500):          false,
	} {
		if _, err := ParseDeadManURL(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "totmann")
	os.WriteFile(p, []byte("https://hc-ping.com/abc\n"), 0o640)
	if _, err := LoadDeadManFile(p); err == nil {
		t.Error("für die Gruppe lesbare Datei angenommen")
	}
	os.Chmod(p, 0o600)
	if u, err := LoadDeadManFile(p); err != nil || u != "https://hc-ping.com/abc" {
		t.Errorf("Datei: %q %v", u, err)
	}
	os.WriteFile(p, []byte("http://hc-ping.com/abc"), 0o600)
	if _, err := LoadDeadManFile(p); err == nil || strings.Contains(err.Error(), "abc") {
		t.Errorf("ungültige Adresse: %v", err)
	}
}

func TestTotmannMeldet(t *testing.T) {
	hc := newFakeHC()
	defer hc.Close()
	ctx := context.Background()
	d, err := newDeadMan(hc.URL+"/uuid/", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	step := func(at time.Duration, ok bool) string {
		d.report(ctx, t0.Add(at), ok)
		d.wait()
		return hc.take()
	}
	if got := step(0, true); got != "POST /uuid" {
		t.Errorf("erster Ping: %q", got)
	}
	// Innerhalb einer Minute kein weiterer Ping, ein Fehler wird gemerkt.
	if got := step(15*time.Second, false); got != "" {
		t.Errorf("zu früh: %q", got)
	}
	if got := step(30*time.Second, true); got != "" {
		t.Errorf("zu früh: %q", got)
	}
	if got := step(61*time.Second, true); got != "POST /uuid/fail" {
		t.Errorf("Fehler nicht gemeldet: %q", got)
	}
	if got := step(122*time.Second, true); got != "POST /uuid" {
		t.Errorf("wieder Erfolg: %q", got)
	}
	// Dienst antwortet nicht: Der Durchlauf läuft weiter, beim nächsten Mal erneut.
	hc.mu.Lock()
	hc.status = 500
	hc.mu.Unlock()
	if got := step(183*time.Second, true); got != "POST /uuid" {
		t.Errorf("bei Fehler des Dienstes: %q", got)
	}
	if hc.bodies != 0 {
		t.Errorf("%d Pings mit Inhalt", hc.bodies)
	}
	var nilD *deadMan
	nilD.report(ctx, t0, false) // aus: nichts passiert
	nilD.wait()
	if d, err := newDeadMan("", time.Minute); d != nil || err != nil {
		t.Errorf("leer: %v %v", d, err)
	}
	if _, err := newDeadMan("http://hc-ping.com/x", time.Minute); err == nil {
		t.Error("http ins Netz angenommen")
	}
}

// Ende zu Ende: Ein Durchlauf mit gescheiterter Zustellung meldet /fail.
func TestTotmannMitAlarmdurchlauf(t *testing.T) {
	cid, _, _ := wartungZiele(t, "WT")
	ctx := context.Background()
	hc := newFakeHC()
	defer hc.Close()
	f := newFakeNtfy()
	defer f.Close()
	cfg := vServer.cfg
	cfg.AlertTargets = alarm.NewTargets(f.URL)
	cfg.DeadManURL = hc.URL + "/hc"
	cfg.AlertPoll = 20 * time.Millisecond
	cfg.DeadManEvery = time.Millisecond
	s, err := New(cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := alarm.NormalizeServer(f.URL)
	chID, _ := newUUID()
	if _, err := owner.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, server, topic)
		VALUES ($1, $2, 'Totmann', $3, 'wt')`, chID, ids["Lager Nord"], server); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1`, chID) })
	run := func() string {
		t.Helper()
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { s.RunAlerts(rctx); close(done) }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			hc.mu.Lock()
			n := len(hc.paths)
			hc.mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
		s.deadMan.Load().wait()
		return strings.Split(hc.take(), ",")[0]
	}
	if got := run(); got != "POST /hc" {
		t.Errorf("ohne Probleme: %q", got)
	}
	// ntfy nimmt nicht an: /fail.
	f.setFail("wt", true)
	for range 2 {
		var ok bool
		pool.QueryRow(ctx, `SELECT openwacht.check_record($1, 1, 'crit', 'x', '', NULL)`, cid).Scan(&ok)
	}
	if got := run(); got != "POST /hc/fail" {
		t.Errorf("Zustellung gescheitert: %q", got)
	}
	f.setFail("wt", false)
	f.take()
	if got := run(); got != "POST /hc" {
		t.Errorf("wieder zugestellt: %q", got)
	}
}

// TestTotmannOhneUmleitungUndProxy (Befund N3): Der Ping folgt keiner
// Umleitung und nutzt keinen Proxy aus der Umgebung.
func TestTotmannOhneUmleitungUndProxy(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer target.Close()
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusFound, http.StatusPermanentRedirect} {
		redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/intern", code)
		}))
		d, err := newDeadMan(redir.URL+"/uuid", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.ping(context.Background(), false); err == nil || !strings.Contains(err.Error(), "Antwort") {
			t.Errorf("Umleitung %d: Fehler %v, erwartet „Antwort %d“", code, err, code)
		}
		redir.Close()
		tr, ok := d.client.Transport.(*http.Transport)
		if !ok || tr.Proxy != nil {
			t.Errorf("Totmann-Client nutzt einen Proxy aus der Umgebung (Transport %T)", d.client.Transport)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("%d Anfragen am Umleitungsziel", hits)
	}
}
