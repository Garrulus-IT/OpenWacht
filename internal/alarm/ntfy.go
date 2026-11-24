// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Freigegebene Benachrichtigungsziele
//
// Die ntfy-Adresse eines Kanals legt ein Mandanten-Admin fest. Damit wäre sie
// ein Ziel aus dem Netz der Zentrale (SSRF). Deshalb gibt der Betreiber die
// erlaubten Server ausdrücklich frei (-alarm-ziele); ein Kanal kann nur einen
// davon wählen, geprüft beim Speichern und vor jedem Versand.

// NormalizeServer prüft eine Server-Adresse und bringt sie in eine
// vergleichbare Form: Schema und Host klein, ohne abschließenden Schrägstrich.
// https ist Pflicht, http nur für Loopback (ntfy im selben Container).
func NormalizeServer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 300 {
		return "", errors.New("Server-Adresse fehlt oder ist zu lang")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("%q ist keine gültige Adresse (Form https://ntfy.example)", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%q: keine Zugangsdaten, Parameter oder Anker in der Adresse", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("%q: http nur für Loopback, sonst https", raw)
		}
	default:
		return "", fmt.Errorf("%q: nur https (oder http für Loopback)", raw)
	}
	if strings.ContainsFunc(u.Path, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("%q: ungültiger Pfad", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Targets ist die Liste der freigegebenen Server.
type Targets struct {
	mu   sync.RWMutex
	list []string
}

// Set übernimmt die Liste aus other (zur Laufzeit, Seite Einstellungen).
func (t *Targets) Set(other *Targets) {
	l := other.List()
	t.mu.Lock()
	t.list = l
	t.mu.Unlock()
}

// ParseTargets liest die kommagetrennte Liste aus -alarm-ziele.
func ParseTargets(s string) (*Targets, error) {
	t := &Targets{}
	for _, p := range strings.Split(s, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		n, err := NormalizeServer(p)
		if err != nil {
			return nil, err
		}
		if !t.Allowed(n) {
			t.list = append(t.list, n)
		}
	}
	return t, nil
}

// NewTargets für bereits normalisierte Adressen (Tests, Konfiguration).
func NewTargets(servers ...string) *Targets {
	t, err := ParseTargets(strings.Join(servers, ","))
	if err != nil {
		panic(err)
	}
	return t
}

// Allowed meldet, ob der (normalisierte) Server freigegeben ist.
func (t *Targets) Allowed(server string) bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, x := range t.list {
		if x == server {
			return true
		}
	}
	return false
}

// List liefert eine Kopie der freigegebenen Server.
func (t *Targets) List() []string {
	if t == nil {
		return []string{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]string{}, t.list...)
}

var (
	topicPattern = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)
	tokenPattern = regexp.MustCompile(`^[\x21-\x7e]{1,200}$`)
)

// ValidTopic: ntfy-Topics bestehen aus Buchstaben, Ziffern, - und _.
func ValidTopic(s string) bool { return topicPattern.MatchString(s) }

// ValidToken: druckbares ASCII ohne Leerzeichen (sonst wäre der
// Authorization-Header angreifbar).
func ValidToken(s string) bool { return tokenPattern.MatchString(s) }

// Sender verschickt Nachrichten an ntfy.
type Sender struct {
	Client  *http.Client
	Targets *Targets
}

// NewSender: ohne Proxy, ohne Weiterleitungen, mit festen Zeitlimits.
func NewSender(t *Targets) *Sender {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       time.Minute,
		ForceAttemptHTTP2:     true,
	}
	return &Sender{
		Targets: t,
		Client: &http.Client{
			Transport: tr,
			Timeout:   20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Send schickt m an topic auf server. Der Server muss freigegeben sein; das
// wird hier erneut geprüft (die Datenbank ist nicht die einzige Schutzschicht).
// Fehlertexte enthalten nie das Token.
func (s *Sender) Send(ctx context.Context, server, topic, token string, m Message) error {
	n, err := NormalizeServer(server)
	if err != nil || n != server || !s.Targets.Allowed(n) {
		return errors.New("Server ist nicht (mehr) als Alarmziel freigegeben")
	}
	if !ValidTopic(topic) {
		return errors.New("ungültiges Topic")
	}
	if token != "" && !ValidToken(token) {
		return errors.New("ungültiges Token")
	}
	body, err := json.Marshal(struct {
		Topic string `json:"topic"`
		Message
	}{topic, m})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n+"/", bytes.NewReader(body))
	if err != nil {
		return errors.New("Anfrage nicht erstellbar")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "openwacht")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // ohne URL; die steht ohnehin am Kanal
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("Zeitüberschreitung")
		}
		return fmt.Errorf("nicht erreichbar: %s", Clean(err.Error(), 200))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	// ntfy antwortet bei Fehlern mit {"error": "..."}.
	var e struct {
		Error string `json:"error"`
	}
	msg := fmt.Sprintf("ntfy antwortete mit HTTP %d", resp.StatusCode)
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		msg += ": " + Clean(e.Error, 150)
	}
	return errors.New(msg)
}
