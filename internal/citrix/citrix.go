// SPDX-License-Identifier: AGPL-3.0-only

// Package citrix fragt den Citrix Monitor Service (OData v4) eines Delivery
// Controllers ab (1.0.6).
//
//   - Nur lesend: ausschließlich GET auf zwei feste Entitäten (Machines,
//     ConnectionFailureLogs). Ein Konto mit der Rolle „Read Only
//     Administrator“ genügt.
//   - Anmeldung per NTLM (Citrix: on-prem nur Windows-Anmeldung) über
//     github.com/Azure/go-ntlmssp; nie Basic, das Passwort verlässt die
//     Zentrale nicht im Klartext.
//   - Nur HTTPS mit festem Fingerabdruck des Zertifikats (wie XenServer);
//     ohne TLS lägen die NTLM-Antworten offen im Netz.
//   - Verbindungen nur über den Guard der Zentrale (Netzfreigabe vor
//     connect()), keine Weiterleitungen, Weiterblättern nur auf derselben
//     Adresse, Grenzen für Größe, Seiten und Laufzeit.
//   - Datensparsam: von Maschinen nur Name, Registrierung, Wartungsmodus;
//     von Fehlschlägen nur die Fehlerart.
package citrix

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Azure/go-ntlmssp"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
)

// Pfad des Monitor Service (on-prem, OData v4).
const basePath = "/Citrix/Monitor/OData/v4/Data/"

// Grenzen
const (
	maxBody        = 8 << 20 // je Seite
	maxPages       = 30      // je Entität
	maxMachines    = 20000
	maxFailures    = 20000
	failureWindow  = 60 * time.Minute
	defaultTimeout = 20 * time.Second
)

// Config: Verbindung zu einem Delivery Controller.
type Config struct {
	Host     string
	Port     uint16 // Standard 443
	User     string // DOMÄNE\name oder name@domäne
	Password string
	Pin      string // SHA-256 des Zertifikats, 64 kleine Hexziffern (Pflicht)
}

var userPattern = regexp.MustCompile(`^([A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._ -]{1,104}|[A-Za-z0-9._-]{1,104}@[A-Za-z0-9.-]{1,190})$`)

// ValidUser: AD-Konto als DOMÄNE\name oder name@domäne.
func ValidUser(s string) bool { return userPattern.MatchString(s) }

// ValidPassword: 1 bis 256 Zeichen, gültiges UTF-8, ohne Steuerzeichen.
func ValidPassword(s string) bool {
	return utf8.RuneCountInString(s) >= 1 && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// Fingerabdrücke wie bei der FRITZ!Box (SHA-256 des Zertifikats).
var (
	ValidPin     = tr064.ValidPin
	NormalizePin = tr064.NormalizePin
	FormatPin    = tr064.FormatPin
)

// Dialer verbindet nur zu freigegebenen Adressen.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Client fragt den Monitor Service ab.
type Client struct {
	Guard   Dialer
	Timeout time.Duration
	Now     func() time.Time
}

var (
	ErrLogin   = errors.New("Anmeldung abgelehnt: Benutzer und Passwort prüfen (Windows-Anmeldung/NTLM)")
	ErrNoRole  = errors.New("Kein Zugriff auf den Monitor Service: Das Konto braucht in Citrix mindestens die Rolle „Read Only Administrator“")
	ErrTooMuch = errors.New("Der Monitor Service liefert mehr Daten als erlaubt")
	ErrNoNTLM  = errors.New("Der Controller verlangt keine Windows-Anmeldung (NTLM); andere Verfahren nutzt OpenWacht nicht")
)

// PinError: Das Zertifikat passt nicht zum hinterlegten Fingerabdruck.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	if e.Got == "" {
		return "TLS: kein Zertifikat erhalten"
	}
	return "TLS: Zertifikat des Controllers passt nicht zum hinterlegten Fingerabdruck (jetzt " + FormatPin(e.Got) + ")"
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func hostOnly(h string) string { return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]") }

func port(p uint16) uint16 {
	if p == 0 {
		return 443
	}
	return p
}

// tlsConfig prüft statt der Kette den Fingerabdruck. pin leer = jedes
// Zertifikat annehmen (nur für Fingerprint, dann ohne Anmeldung).
func tlsConfig(host, pin string, seen *string, mu *sync.Mutex) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: hostOnly(host),
		// InsecureSkipVerify schaltet nur die Standardprüfung ab; VerifyConnection
		// ersetzt sie und bricht ab, bevor eine Anfrage gesendet wird.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return &PinError{}
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(sum[:])
			mu.Lock()
			*seen = got
			mu.Unlock()
			if pin == "" {
				return nil
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return &PinError{Got: got}
			}
			return nil
		},
	}
}

// Fingerprint verbindet per TLS und liefert den Fingerabdruck des
// Zertifikats, ohne eine Anfrage und ohne Zugangsdaten zu senden.
func (c *Client) Fingerprint(ctx context.Context, host string, p uint16) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	conn, err := c.Guard.DialContext(ctx, "tcp", net.JoinHostPort(hostOnly(host), strconv.Itoa(int(port(p)))))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var seen string
	var mu sync.Mutex
	tc := tls.Client(conn, tlsConfig(host, "", &seen, &mu))
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("TLS: %v", err)
	}
	tc.Close()
	mu.Lock()
	defer mu.Unlock()
	if seen == "" {
		return "", errors.New("kein Zertifikat erhalten (HTTPS an diesem Port?)")
	}
	return seen, nil
}

type session struct {
	http  *http.Client
	base  *url.URL
	cfg   Config
	close func()
}

func (c *Client) session(cfg Config) *session {
	var seen string
	var mu sync.Mutex
	t := c.timeout()
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            c.Guard.DialContext,
		TLSClientConfig:        tlsConfig(cfg.Host, cfg.Pin, &seen, &mu),
		TLSHandshakeTimeout:    t,
		ResponseHeaderTimeout:  t,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		// NTLM ist an die Verbindung gebunden: nur HTTP/1.1, Verbindung halten.
		ForceAttemptHTTP2: false,
	}
	return &session{
		http: &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: tr}, Timeout: t,
			// Weiterleitungen nie folgen: Das Ziel läge womöglich außerhalb der Freigabe.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:  &url.URL{Scheme: "https", Host: net.JoinHostPort(hostOnly(cfg.Host), strconv.Itoa(int(port(cfg.Port)))), Path: basePath},
		cfg:   cfg,
		close: tr.CloseIdleConnections,
	}
}

// query baut die Abfrage mit %20 statt + für Leerzeichen.
func query(v url.Values) string { return strings.ReplaceAll(v.Encode(), "+", "%20") }

// get holt eine Seite. next ist die Fortsetzung (@odata.nextLink), nur auf
// derselben Adresse und unter dem Pfad des Monitor Service.
func (s *session) get(ctx context.Context, u *url.URL, out any) (next *url.URL, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json;odata.metadata=minimal")
	// Nur für den Negotiator: Er macht daraus NTLM und schickt nie Basic.
	req.SetBasicAuth(s.cfg.User, s.cfg.Password)
	resp, err := s.http.Do(req)
	if err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return nil, pe
		}
		return nil, fmt.Errorf("Verbindung: %v", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		if h := resp.Header.Values("Www-Authenticate"); len(h) > 0 && !slices.ContainsFunc(h, func(v string) bool {
			v = strings.ToLower(v)
			return strings.HasPrefix(v, "ntlm") || strings.HasPrefix(v, "negotiate")
		}) {
			return nil, ErrNoNTLM
		}
		return nil, ErrLogin
	case resp.StatusCode == http.StatusForbidden:
		return nil, ErrNoRole
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("Monitor Service nicht gefunden (Adresse des Delivery Controllers prüfen)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("Monitor Service antwortete mit HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("Antwort: %v", err)
	}
	if len(body) > maxBody {
		return nil, ErrTooMuch
	}
	var page struct {
		Value    json.RawMessage `json:"value"`
		NextLink string          `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(body, &page); err != nil || page.Value == nil {
		return nil, errors.New("Antwort ist kein OData-JSON")
	}
	if err := json.Unmarshal(page.Value, out); err != nil {
		return nil, errors.New("Antwort ist kein OData-JSON")
	}
	if page.NextLink == "" {
		return nil, nil
	}
	n, err := url.Parse(page.NextLink)
	if err != nil {
		return nil, errors.New("Fortsetzung der Antwort ungültig")
	}
	n = s.base.ResolveReference(n)
	if n.Scheme != s.base.Scheme || n.Host != s.base.Host || !strings.HasPrefix(n.Path, basePath) || n.User != nil {
		return nil, errors.New("Fortsetzung der Antwort zeigt auf eine andere Adresse")
	}
	return n, nil
}

// Machine: die gelesenen Felder einer Maschine.
type Machine struct {
	Name         string `json:"Name"`
	DNSName      string `json:"DnsName"`
	Registration int    `json:"CurrentRegistrationState"`
	Maintenance  bool   `json:"IsInMaintenanceMode"`
}

// Failure: das gelesene Feld eines Fehlschlags.
type Failure struct {
	Code int `json:"ConnectionFailureEnumValue"`
}

// Raw: gelesene Rohdaten (für Tests und Fuzzer).
type Raw struct {
	Machines []Machine
	Failures []Failure
	// FailuresErr: Fehlschläge nicht lesbar (die Abfrage gilt trotzdem)
	FailuresErr string
}

// registered: Wert von CurrentRegistrationState für „registriert“.
const registered = 1

// codeNone: ConnectionFailureEnumValue „None“ (kein Fehler).
const codeNone = 1

func (s *session) machines(ctx context.Context) ([]Machine, error) {
	u := *s.base
	u.Path += "Machines"
	u.RawQuery = query(url.Values{
		"$filter": {"LifecycleState eq 0"},
		"$select": {"Name,DnsName,CurrentRegistrationState,IsInMaintenanceMode"},
	})
	var out []Machine
	next := &u
	for page := 0; next != nil; page++ {
		if page >= maxPages {
			return nil, ErrTooMuch
		}
		var list []Machine
		var err error
		if next, err = s.get(ctx, next, &list); err != nil {
			return nil, err
		}
		out = append(out, list...)
		if len(out) > maxMachines {
			return nil, ErrTooMuch
		}
	}
	return out, nil
}

func (s *session) failures(ctx context.Context, since time.Time) ([]Failure, error) {
	u := *s.base
	u.Path += "ConnectionFailureLogs"
	u.RawQuery = query(url.Values{
		"$filter": {"FailureDate ge " + since.UTC().Format("2006-01-02T15:04:05Z")},
		"$select": {"ConnectionFailureEnumValue"},
	})
	var out []Failure
	next := &u
	for page := 0; next != nil; page++ {
		if page >= maxPages {
			return nil, ErrTooMuch
		}
		var list []Failure
		var err error
		if next, err = s.get(ctx, next, &list); err != nil {
			return nil, err
		}
		out = append(out, list...)
		if len(out) > maxFailures {
			return nil, ErrTooMuch
		}
	}
	return out, nil
}

// cleanName: Namen aus der Antwort sind fremde Daten.
func cleanName(m Machine) string {
	n := m.Name
	if n == "" {
		n = m.DNSName
	}
	n = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, n)
	if utf8.RuneCountInString(n) > 120 {
		n = string([]rune(n)[:120])
	}
	if !utf8.ValidString(n) || strings.TrimSpace(n) == "" {
		return "(ohne Namen)"
	}
	return n
}

// Build fasst die Rohdaten zusammen.
func Build(raw Raw, fingerprint string) *snmp.Citrix {
	c := &snmp.Citrix{Fingerprint: fingerprint, Machines: len(raw.Machines), FailureWindowMin: int(failureWindow / time.Minute)}
	for _, m := range raw.Machines {
		if m.Registration == registered {
			c.Registered++
		}
		switch {
		case m.Maintenance:
			c.Maintenance++
		case m.Registration != registered:
			c.Unregistered++
			c.UnregisteredNames = append(c.UnregisteredNames, cleanName(m))
		}
	}
	slices.SortFunc(c.UnregisteredNames, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	c.UnregisteredNames = slices.Compact(c.UnregisteredNames)
	if len(c.UnregisteredNames) > snmp.MaxCitrixNames {
		c.UnregisteredNames = c.UnregisteredNames[:snmp.MaxCitrixNames]
	}
	counts := map[int]int{}
	for _, f := range raw.Failures {
		if f.Code == codeNone {
			continue
		}
		counts[f.Code]++
		c.FailureTotal++
	}
	for code, n := range counts {
		c.Failures = append(c.Failures, snmp.CitrixFailure{Code: code, Count: n})
	}
	slices.SortFunc(c.Failures, func(a, b snmp.CitrixFailure) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return a.Code - b.Code
	})
	return c
}

// Poll fragt Maschinen und Fehlschläge ab.
func (c *Client) Poll(ctx context.Context, cfg Config) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("citrix", &err)
	if !ValidPin(cfg.Pin) {
		return nil, errors.New("Fingerabdruck des Zertifikats fehlt")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	s := c.session(cfg)
	defer s.close()
	now := c.now()
	var raw Raw
	if raw.Machines, err = s.machines(ctx); err != nil {
		return nil, fmt.Errorf("Maschinen: %w", err)
	}
	var partial []string
	if raw.Failures, err = s.failures(ctx, now.Add(-failureWindow)); err != nil {
		// Maschinen sind das Wichtigere; ohne Fehlschläge gilt die Abfrage.
		raw.Failures = nil
		raw.FailuresErr = err.Error()
		partial = append(partial, "fehler")
	}
	snap := &snmp.Snapshot{
		CollectedAt: now.UTC(),
		System:      snmp.System{Descr: "Citrix Monitor Service", Name: hostOnly(cfg.Host)},
		Disks:       []snmp.Disk{},
		Interfaces:  []snmp.Interface{},
		Supplies:    []snmp.Supply{},
		Partial:     partial,
		Citrix:      Build(raw, cfg.Pin),
	}
	return snap, nil
}

// Info: Ergebnis von „Verbindung prüfen“.
type Info struct {
	Machines     int    `json:"vdas"`
	Unregistered int    `json:"nicht_registriert"`
	Failures     int    `json:"fehler_gesamt"`
	FailuresErr  string `json:"fehler_nicht_lesbar,omitempty"`
	Fingerprint  string `json:"fingerabdruck"`
}

// Probe meldet sich an und liest einmal alles.
func (c *Client) Probe(ctx context.Context, cfg Config) (Info, error) {
	snap, err := c.Poll(ctx, cfg)
	if err != nil {
		return Info{}, err
	}
	x := snap.Citrix
	info := Info{Machines: x.Machines, Unregistered: x.Unregistered, Failures: x.FailureTotal, Fingerprint: x.Fingerprint}
	if len(snap.Partial) > 0 {
		info.FailuresErr = "Fehlgeschlagene Verbindungen nicht lesbar"
	}
	return info, nil
}
