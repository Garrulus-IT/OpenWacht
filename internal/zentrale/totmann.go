// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Totmannschalter: Die Zentrale meldet sich regelmäßig bei einem externen
// Dienst (healthchecks.io). Bleibt die Meldung aus, weil Zentrale, Datenbank
// oder LXC ausgefallen sind, alarmiert der Dienst selbst (Mail), unabhängig
// von ntfy im selben LXC.
//
// Gemeldet wird nach jedem Alarmdurchlauf, höchstens einmal je Intervall
// (healthchecks.io nimmt höchstens 5 Pings je Minute an):
//   - Erfolg, wenn alle Durchläufe seit dem letzten Ping geklappt haben und
//     jede Meldung zugestellt wurde;
//   - sonst <url>/fail: Der Dienst meldet dann sofort, statt bis zum Ablauf
//     der Karenzzeit zu warten.
//
// Das eigene Netz verlässt dabei nur eine HTTPS-Anfrage ohne Inhalt. Die Adresse
// enthält die geheime Kennung des Checks und erscheint deshalb nie im Log.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/garrulus-it/openwacht/internal/version"
)

type deadMan struct {
	url    string
	host   string // nur für das Log
	every  time.Duration
	client *http.Client

	mu      sync.Mutex
	last    time.Time // letzter Ping
	failed  bool      // seit dem letzten Ping ist etwas schiefgegangen
	busy    bool
	broken  bool // letzter Ping nicht angekommen (nur für das Log)
	failing bool // zuletzt /fail gemeldet (nur für das Log)
	wg      sync.WaitGroup
}

func newDeadMan(rawURL string, every time.Duration) (*deadMan, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := ParseDeadManURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &deadMan{url: strings.TrimSuffix(u.String(), "/"), host: u.Host, every: every,
		client: deadManClient()}, nil
}

// deadManClient: ohne Proxy aus der Umgebung und ohne Umleitungen, wie der
// Versand an ntfy (Befund N3). Eine Umleitung (3xx) gilt als Fehler.
func deadManClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          2,
			IdleConnTimeout:       time.Minute,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ParseDeadManURL prüft die Ping-Adresse: https, http nur für Loopback
// (Tests, eigener Dienst auf demselben Rechner), ohne Zugangsdaten und
// Fragment.
func ParseDeadManURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 500 || strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return nil, errors.New("Ping-Adresse: 1 bis 500 Zeichen ohne Leer- und Steuerzeichen")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, errors.New("Ping-Adresse: erwartet z. B. https://hc-ping.com/<uuid>, ohne Zugangsdaten, Parameter und #")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("Ping-Adresse: http nur für Loopback, sonst https")
		}
	default:
		return nil, errors.New("Ping-Adresse: nur https")
	}
	return u, nil
}

// LoadDeadManFile liest die Ping-Adresse aus einer Datei, die nur der Dienst
// lesen darf (wie die Schlüsseldatei).
func LoadDeadManFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("Datei %s ist für andere lesbar (Rechte %o); erwartet 0600 oder 0400", path, fi.Mode().Perm())
	}
	if fi.Size() > 1024 {
		return "", fmt.Errorf("Datei %s ist zu groß für eine Ping-Adresse", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(string(b))
	if _, err := ParseDeadManURL(raw); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}

// report vermerkt das Ergebnis eines Alarmdurchlaufs und pingt, wenn fällig.
// Blockiert nicht: Der Ping läuft nebenher, höchstens einer zugleich.
func (d *deadMan) report(ctx context.Context, now time.Time, ok bool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !ok {
		d.failed = true
	}
	if d.busy || !d.last.IsZero() && now.Sub(d.last) < d.every {
		return
	}
	fail := d.failed
	d.failed, d.last, d.busy = false, now, true
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		err := d.ping(ctx, fail)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.busy = false
		switch {
		case err != nil && ctx.Err() != nil:
		case err != nil && !d.broken:
			d.broken = true
			slog.Warn("Totmannschalter: Ping nicht angekommen", "ziel", d.host, "fehler", err)
		case err == nil && d.broken:
			d.broken = false
			slog.Info("Totmannschalter: Ping kommt wieder an", "ziel", d.host)
		}
		if err == nil && fail != d.failing {
			d.failing = fail
			if fail {
				slog.Warn("Totmannschalter: Fehler gemeldet (Alarmdurchlauf oder Zustellung gescheitert)", "ziel", d.host)
			} else {
				slog.Info("Totmannschalter: wieder Erfolg gemeldet", "ziel", d.host)
			}
		}
	}()
}

func (d *deadMan) ping(ctx context.Context, fail bool) error {
	u := d.url
	if fail {
		u += "/fail"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return errors.New("Anfrage ungültig")
	}
	req.Header.Set("User-Agent", "openwacht-zentrale/"+version.Version)
	resp, err := d.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // ohne die Adresse mit der geheimen Kennung
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Antwort %d", resp.StatusCode)
	}
	return nil
}

// wait: für Tests, bis laufende Pings fertig sind.
func (d *deadMan) wait() {
	if d != nil {
		d.wg.Wait()
	}
}
