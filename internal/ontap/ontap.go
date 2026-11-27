// SPDX-License-Identifier: AGPL-3.0-only

// Package ontap liest die REST-API eines NetApp-ONTAP-Clusters (0.41.0),
// ausschließlich lesend: Knoten und HA, Aggregate, Volumes, Platten,
// Shelves, SnapMirror und EMS-Ereignisse.
//
// Sicherheit:
//   - Nur GET-Anfragen auf Pfade aus einer festen Liste (allowedPath); andere
//     Methoden gibt es im Code nicht.
//   - HTTPS mit festem Fingerabdruck des Zertifikats (ONTAP hat ab Werk ein
//     selbstsigniertes), Passwort per Basic Auth erst nach geprüftem Handshake.
//   - Verbindungen nur über den Guard der Zentrale (Netzfreigabe vor connect()),
//     ohne Proxy, Weiterleitungen werden nie verfolgt.
//   - Vor jeder Abfrage prüft der Client die Rechte des Kontos und lehnt ein
//     Konto mit Schreibrecht ab (ab ONTAP 9.19 über whoami, davor über das
//     Konto und die Rechte seiner Rolle). Lässt sich das nicht prüfen, gilt
//     das Konto ebenfalls als abgelehnt.
//   - Antworten sind in Größe und Anzahl begrenzt, Texte bereinigt und gekürzt,
//     Zahlen auf Plausibilität geprüft.
//
// Endpunkte und Feldnamen nach der ONTAP-REST-Referenz (docs.netapp.com,
// ontap-restapi, Stand 9.18/9.19).
package ontap

import (
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
)

// Grenzen gegen kaputte oder bösartige Gegenstellen.
const (
	MaxNodes      = 24
	MaxAggregates = 200
	MaxVolumes    = 1000
	MaxDisks      = 2000
	MaxShelves    = 100
	MaxMirrors    = 1000
	MaxEvents     = 50
	MaxPrivileges = 1000
	MaxText       = 200
	maxBody       = 8 << 20
	// BadDisksShown: so viele auffällige Platten stehen einzeln im Snapshot
	BadDisksShown = 50
	// EventWindow: EMS-Ereignisse aus diesem Zeitraum
	EventWindow = time.Hour
)

// Config einer Abfrage.
type Config struct {
	Host     string
	Port     uint16 // Standard 443
	User     string
	Password string
	Pin      string // SHA-256 des Zertifikats, 64 kleine Hexziffern (Pflicht)
}

var userPattern = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{1,128}$`)

// ValidUser prüft die Form des Benutzernamens (lokal oder DOMÄNE\name).
func ValidUser(s string) bool { return userPattern.MatchString(s) }

// ValidPassword: 1 bis 256 Zeichen, gültiges UTF-8, ohne Steuerzeichen.
func ValidPassword(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
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

// Client fragt ONTAP ab.
type Client struct {
	Guard   Dialer
	Timeout time.Duration
	Now     func() time.Time
}

var (
	ErrLogin         = errors.New("Anmeldung abgelehnt (401): Benutzer und Passwort prüfen")
	ErrTooMuch       = errors.New("ONTAP liefert mehr Daten als erlaubt")
	ErrRightsUnknown = errors.New("Rechte des Kontos nicht lesbar: Die Rolle braucht Leserecht auf /api (auch /api/security); " +
		"ohne diese Prüfung fragt OpenWacht nicht ab")
)

// ForbiddenError: 403 auf einen Pfad (Rechte fehlen).
type ForbiddenError struct{ Path string }

func (e *ForbiddenError) Error() string {
	return "Rechte fehlen (403) für " + e.Path + ": Die Rolle braucht Leserecht auf /api"
}

// WritableError: Das Konto darf schreiben; OpenWacht lehnt es ab.
type WritableError struct {
	Path   string
	Access string
}

func (e *WritableError) Error() string {
	return fmt.Sprintf("Konto mit Schreibrecht abgelehnt (%s: %s): bitte ein Konto mit einer nur lesenden Rolle nehmen", e.Path, e.Access)
}

// PinError: Das Zertifikat passt nicht zum hinterlegten Fingerabdruck.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	if e.Got == "" {
		return "TLS: kein Zertifikat erhalten"
	}
	return "TLS: Zertifikat des Clusters passt nicht zum hinterlegten Fingerabdruck (jetzt " + FormatPin(e.Got) + ")"
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 20 * time.Second
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
		// ersetzt sie und bricht ab, bevor eine Anfrage (mit Passwort) gesendet wird.
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
	base  string
	cfg   Config
	close func()
	mu    sync.Mutex
	seen  string
	// Calls: alle gesendeten Pfade (für Tests und Fehlermeldungen)
	calls []string
}

func (c *Client) open(cfg Config) (*session, error) {
	if !ValidUser(cfg.User) || !ValidPassword(cfg.Password) {
		return nil, errors.New("Benutzer oder Passwort ungültig")
	}
	if !ValidPin(cfg.Pin) {
		return nil, errors.New("Fingerabdruck des Zertifikats fehlt oder ist ungültig")
	}
	s := &session{cfg: cfg}
	t := c.timeout()
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            c.Guard.DialContext,
		TLSClientConfig:        tlsConfig(cfg.Host, cfg.Pin, &s.seen, &s.mu),
		TLSHandshakeTimeout:    t,
		ResponseHeaderTimeout:  t,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      true,
	}
	s.http = &http.Client{Transport: tr, Timeout: t,
		// Weiterleitungen nie folgen: Das Ziel läge womöglich außerhalb der Freigabe.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.base = "https://" + net.JoinHostPort(hostOnly(cfg.Host), strconv.Itoa(int(port(cfg.Port))))
	s.close = tr.CloseIdleConnections
	return s, nil
}

// fixedPaths: alle Pfade, die der Client lesen darf (nur GET).
var fixedPaths = map[string]bool{
	"/api/cluster":                  true,
	"/api/cluster/nodes":            true,
	"/api/storage/aggregates":       true,
	"/api/storage/volumes":          true,
	"/api/storage/disks":            true,
	"/api/storage/shelves":          true,
	"/api/snapmirror/relationships": true,
	"/api/support/ems/events":       true,
	"/api/security/login/whoami":    true,
	"/api/security/accounts":        true,
}

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	rolePattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	privilegesRegex = regexp.MustCompile(`^/api/security/roles/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[A-Za-z0-9._-]{1,128}/privileges$`)
)

// AllowedPath: Darf der Client diesen Pfad lesen?
func AllowedPath(p string) bool { return fixedPaths[p] || privilegesRegex.MatchString(p) }

// apiError: Fehlertext von ONTAP ({"error":{"message":…,"code":…}}).
type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// get liest einen Pfad aus der festen Liste. Die Antwort wird erst nach dem
// Status ausgewertet und ist auf maxBody begrenzt.
func (s *session) get(ctx context.Context, path string, q url.Values, out any) (int, error) {
	if !AllowedPath(path) {
		return 0, fmt.Errorf("Pfad %s nicht erlaubt", path) // Programmfehler, nie von außen erreichbar
	}
	u := s.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(s.cfg.User, s.cfg.Password)
	req.Header.Set("Accept", "application/json")
	s.mu.Lock()
	s.calls = append(s.calls, path)
	s.mu.Unlock()
	resp, err := s.http.Do(req)
	if err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return 0, pe
		}
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(b) > maxBody {
		return resp.StatusCode, ErrTooMuch
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return resp.StatusCode, ErrLogin
	case http.StatusForbidden:
		return resp.StatusCode, &ForbiddenError{Path: path}
	default:
		var ae apiError
		msg := ""
		if json.Unmarshal(b, &ae) == nil {
			msg = clean(ae.Error.Message)
		}
		if msg != "" {
			return resp.StatusCode, fmt.Errorf("ONTAP antwortet mit HTTP %d: %s", resp.StatusCode, msg)
		}
		return resp.StatusCode, fmt.Errorf("ONTAP antwortet mit HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("Antwort von %s nicht lesbar", path)
	}
	return resp.StatusCode, nil
}

// collection: Antwort einer Liste.
type collection[T any] struct {
	Records    []T `json:"records"`
	NumRecords int `json:"num_records"`
	Links      struct {
		Next *struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
}

// list liest höchstens limit Einträge. more: Es gibt weitere (über der
// Grenze oder ONTAP hat wegen Zeitüberschreitung nicht alles geliefert).
func list[T any](ctx context.Context, s *session, path, fields string, limit int, extra url.Values) ([]T, bool, error) {
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	q.Set("fields", fields)
	q.Set("max_records", strconv.Itoa(limit+1))
	q.Set("return_timeout", "15")
	var c collection[T]
	if _, err := s.get(ctx, path, q, &c); err != nil {
		return nil, false, err
	}
	more := c.Links.Next != nil
	if len(c.Records) > limit {
		c.Records, more = c.Records[:limit], true
	}
	return c.Records, more, nil
}

func clean(s string) string { return cleanN(s, MaxText) }

func cleanN(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		// Steuerzeichen und Bidi-Steuerzeichen entfernen (Anzeige, Alarmtexte)
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		s = string(r[:n])
	}
	return strings.TrimSpace(s)
}

// lower: Zustände nur aus Kleinbuchstaben, Ziffern und _ (sonst „unbekannt“).
func lower(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 40 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return ""
	}
	return s
}

// --- Rechte -----------------------------------------------------------------

type privilege struct {
	Path   string `json:"path"`
	Access string `json:"access"`
}

// harmless: Befehle, die nur die eigene Sitzung betreffen (eigenes Passwort,
// Sitzungseinstellungen). Sie zählen nicht als Schreibrecht.
var harmless = map[string]bool{"set": true, "security login password": true}

// writable: erster Eintrag, der mehr als Lesen erlaubt.
func writable(privs []privilege) *WritableError {
	for _, p := range privs {
		access := strings.ToLower(strings.TrimSpace(p.Access))
		path := strings.TrimSpace(p.Path)
		if access == "none" || access == "readonly" {
			continue
		}
		if !strings.HasPrefix(path, "/") && harmless[path] {
			continue
		}
		return &WritableError{Path: clean(path), Access: clean(access)}
	}
	return nil
}

// checkReadOnly lehnt Konten mit Schreibrecht ab.
func (s *session) checkReadOnly(ctx context.Context) error {
	var who struct {
		Privileges []privilege `json:"privileges"`
	}
	status, err := s.get(ctx, "/api/security/login/whoami", nil, &who)
	switch {
	case err == nil && len(who.Privileges) > 0:
		if len(who.Privileges) > MaxPrivileges {
			return ErrRightsUnknown
		}
		if w := writable(who.Privileges); w != nil {
			return w
		}
		return nil
	case err == nil:
		// ONTAP 9.18 kennt whoami schon, liefert für REST-Rollen aber „{}“
		// ohne privileges (an einer AFF mit 9.18.1 gesehen): wie vor 9.19
		// über Konto und Rolle prüfen.
	case status == http.StatusNotFound:
		// vor ONTAP 9.19: über Konto und Rolle
	case errors.Is(err, ErrLogin):
		return err
	case status == http.StatusForbidden:
		return ErrRightsUnknown
	default:
		return err
	}
	type account struct {
		Scope string `json:"scope"`
		Owner struct {
			UUID string `json:"uuid"`
		} `json:"owner"`
		Role struct {
			Name string `json:"name"`
		} `json:"role"`
	}
	accounts, _, err := list[account](ctx, s, "/api/security/accounts", "scope,owner.uuid,role.name", 10,
		url.Values{"name": {s.cfg.User}})
	var fe *ForbiddenError
	if errors.As(err, &fe) {
		return ErrRightsUnknown
	}
	if err != nil {
		return err
	}
	var found []account
	for _, a := range accounts {
		if a.Scope == "cluster" {
			found = append(found, a)
		}
	}
	if len(found) != 1 || !uuidPattern.MatchString(found[0].Owner.UUID) || !rolePattern.MatchString(found[0].Role.Name) {
		return ErrRightsUnknown
	}
	privs, more, err := list[privilege](ctx, s, "/api/security/roles/"+found[0].Owner.UUID+"/"+found[0].Role.Name+"/privileges",
		"path,access", MaxPrivileges, nil)
	if errors.As(err, &fe) {
		return ErrRightsUnknown
	}
	if err != nil {
		return err
	}
	if more || len(privs) == 0 {
		return ErrRightsUnknown
	}
	if w := writable(privs); w != nil {
		return w
	}
	return nil
}

// --- Abfrage -----------------------------------------------------------------

type cluster struct {
	Name    string `json:"name"`
	Version struct {
		Full string `json:"full"`
	} `json:"version"`
}

type node struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Model  string `json:"model"`
	Uptime *int64 `json:"uptime"`
	HA     struct {
		Enabled  bool `json:"enabled"`
		Partners []struct {
			Name string `json:"name"`
		} `json:"partners"`
		Takeover struct {
			State string `json:"state"`
		} `json:"takeover"`
		Giveback struct {
			State string `json:"state"`
		} `json:"giveback"`
	} `json:"ha"`
	Controller struct {
		OverTemperature string `json:"over_temperature"`
		FailedFan       struct {
			Count *int `json:"count"`
		} `json:"failed_fan"`
		FailedPowerSupply struct {
			Count *int `json:"count"`
		} `json:"failed_power_supply"`
	} `json:"controller"`
}

type aggregate struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Node  struct {
		Name string `json:"name"`
	} `json:"node"`
	Space struct {
		BlockStorage struct {
			Size *int64 `json:"size"`
			Used *int64 `json:"used"`
		} `json:"block_storage"`
	} `json:"space"`
	Metric struct {
		Status string `json:"status"`
		IOPS   struct {
			Total *float64 `json:"total"`
		} `json:"iops"`
		Latency struct {
			Total *float64 `json:"total"` // Mikrosekunden
		} `json:"latency"`
	} `json:"metric"`
}

type volume struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Type  string `json:"type"`
	SVM   struct {
		Name string `json:"name"`
	} `json:"svm"`
	Space struct {
		Used      *int64 `json:"used"`
		Available *int64 `json:"available"`
	} `json:"space"`
}

type disk struct {
	Name          string `json:"name"`
	State         string `json:"state"`
	ContainerType string `json:"container_type"`
	Model         string `json:"model"`
}

type shelf struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model"`
	State string `json:"state"`
	Frus  []struct {
		ID        *int   `json:"id"`
		Type      string `json:"type"`
		State     string `json:"state"`
		Installed *bool  `json:"installed"`
	} `json:"frus"`
	Fans []struct {
		ID        *int   `json:"id"`
		State     string `json:"state"`
		Installed *bool  `json:"installed"`
	} `json:"fans"`
	Temps []struct {
		ID          *int   `json:"id"`
		State       string `json:"state"`
		Temperature *int   `json:"temperature"`
		Installed   *bool  `json:"installed"`
		Threshold   struct {
			High struct {
				Warning  *int `json:"warning"`
				Critical *int `json:"critical"`
			} `json:"high"`
		} `json:"threshold"`
	} `json:"temperature_sensors"`
}

type mirror struct {
	Source struct {
		Path string `json:"path"`
	} `json:"source"`
	Destination struct {
		Path string `json:"path"`
	} `json:"destination"`
	State           string `json:"state"`
	Healthy         *bool  `json:"healthy"`
	LagTime         string `json:"lag_time"`
	UnhealthyReason []struct {
		Message string `json:"message"`
	} `json:"unhealthy_reason"`
}

type event struct {
	Time    string `json:"time"`
	Message struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"message"`
	Node struct {
		Name string `json:"name"`
	} `json:"node"`
	LogMessage string `json:"log_message"`
}

// Raw: die rohen Antworten einer Abfrage (für Build und Fuzz-Tests).
type Raw struct {
	Cluster    cluster
	Nodes      []node
	Aggregates []aggregate
	Volumes    []volume
	Disks      []disk
	Shelves    []shelf
	Mirrors    []mirror
	Events     []event
	// Truncated: Listen über der Grenze; Partial: Teile, die fehlen
	Truncated, Partial []string
}

// Info: was „Verbindung prüfen“ zeigt.
type Info struct {
	Cluster     string `json:"cluster"`
	Version     string `json:"version"`
	Nodes       int    `json:"knoten"`
	Aggregates  int    `json:"aggregate"`
	Volumes     int    `json:"volumes"`
	Disks       int    `json:"platten"`
	Shelves     int    `json:"shelves"`
	Mirrors     int    `json:"snapmirror"`
	Fingerprint string `json:"fingerabdruck"`
}

// Probe prüft Rechte und liest einmal alles (wie Poll).
func (c *Client) Probe(ctx context.Context, cfg Config) (Info, error) {
	snap, err := c.Poll(ctx, cfg)
	if err != nil {
		return Info{}, err
	}
	o := snap.ONTAP
	return Info{Cluster: o.Cluster, Version: o.Version, Nodes: len(o.Nodes), Aggregates: len(o.Aggregates),
		Volumes: len(o.Volumes), Disks: o.Disks.Total, Shelves: len(o.Shelves), Mirrors: len(o.Mirrors),
		Fingerprint: o.Fingerprint}, nil
}

// Poll prüft die Rechte des Kontos und liest dann alles als Snapshot.
func (c *Client) Poll(ctx context.Context, cfg Config) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("ontap", &err)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	s, err := c.open(cfg)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err := s.checkReadOnly(ctx); err != nil {
		return nil, err
	}
	var raw Raw
	if _, err := s.get(ctx, "/api/cluster", url.Values{"fields": {"name,version.full"}}, &raw.Cluster); err != nil {
		return nil, fmt.Errorf("Cluster: %w", err)
	}
	// Pflicht: Knoten und Aggregate. Fehlt einer davon, ist die Abfrage gescheitert.
	var more bool
	if raw.Nodes, more, err = list[node](ctx, s, "/api/cluster/nodes", "name,state,model,uptime,ha.enabled,ha.partners.name,"+
		"ha.takeover.state,ha.giveback.state,controller.over_temperature,controller.failed_fan.count,"+
		"controller.failed_power_supply.count", MaxNodes, nil); err != nil {
		return nil, fmt.Errorf("Knoten: %w", err)
	} else if more {
		return nil, ErrTooMuch
	}
	if raw.Aggregates, more, err = list[aggregate](ctx, s, "/api/storage/aggregates", "name,state,node.name,"+
		"space.block_storage.size,space.block_storage.used,metric.status,metric.iops.total,metric.latency.total",
		MaxAggregates, nil); err != nil {
		return nil, fmt.Errorf("Aggregate: %w", err)
	} else if more {
		return nil, ErrTooMuch
	}
	// Übrige Teile: Ein Fehler (z. B. 403 auf Shelves) lässt den Rest stehen.
	part := func(name string, more bool, err error) error {
		switch {
		case errors.Is(err, ErrLogin), errors.Is(err, ErrTooMuch):
			return err
		case err != nil:
			var pe *PinError
			if errors.As(err, &pe) || ctx.Err() != nil {
				return err
			}
			raw.Partial = append(raw.Partial, name)
		case more:
			raw.Truncated = append(raw.Truncated, name)
		}
		return nil
	}
	raw.Volumes, more, err = list[volume](ctx, s, "/api/storage/volumes", "name,state,type,svm.name,space.used,space.available", MaxVolumes, nil)
	if err := part("Volumes", more, err); err != nil {
		return nil, fmt.Errorf("Volumes: %w", err)
	}
	raw.Disks, more, err = list[disk](ctx, s, "/api/storage/disks", "name,state,container_type,model", MaxDisks, nil)
	if err := part("Platten", more, err); err != nil {
		return nil, fmt.Errorf("Platten: %w", err)
	}
	raw.Shelves, more, err = list[shelf](ctx, s, "/api/storage/shelves", "id,name,model,state,frus,fans,temperature_sensors", MaxShelves, nil)
	if err := part("Shelves", more, err); err != nil {
		return nil, fmt.Errorf("Shelves: %w", err)
	}
	raw.Mirrors, more, err = list[mirror](ctx, s, "/api/snapmirror/relationships",
		"source.path,destination.path,state,healthy,lag_time,unhealthy_reason", MaxMirrors, nil)
	if err := part("SnapMirror", more, err); err != nil {
		return nil, fmt.Errorf("SnapMirror: %w", err)
	}
	since := c.now().Add(-EventWindow).UTC().Format(time.RFC3339)
	raw.Events, more, err = list[event](ctx, s, "/api/support/ems/events", "time,message.name,message.severity,node.name,log_message",
		MaxEvents, url.Values{"message.severity": {"emergency|alert"}, "time": {">" + since}})
	if err := part("EMS", more, err); err != nil {
		return nil, fmt.Errorf("EMS: %w", err)
	}
	snap := Build(raw, c.now())
	s.mu.Lock()
	snap.ONTAP.Fingerprint = s.seen
	s.mu.Unlock()
	snap.System.Name = clean(cfg.Host)
	if snap.ONTAP.Cluster != "" {
		snap.System.Name = snap.ONTAP.Cluster
	}
	return snap, nil
}

func nonNeg(p *int64) (uint64, bool) {
	if p == nil || *p < 0 {
		return 0, false
	}
	return uint64(*p), true
}

func intID(p *int) string {
	if p == nil || *p < 0 || *p > 1<<20 {
		return "?"
	}
	return strconv.Itoa(*p)
}

func temp(p *int) *int {
	if p == nil || *p < -50 || *p > 200 {
		return nil
	}
	v := *p
	return &v
}

// Build bildet die rohen Antworten auf den Snapshot ab. Ungültige Einträge
// (ohne Namen, unplausible Zahlen) fallen weg.
func Build(raw Raw, now time.Time) *snmp.Snapshot {
	o := &snmp.ONTAP{Cluster: clean(raw.Cluster.Name), Version: cleanN(raw.Cluster.Version.Full, 120),
		Nodes: []snmp.ONTAPNode{}, Aggregates: []snmp.ONTAPAggregate{}, Volumes: []snmp.ONTAPVolume{},
		Disks: snmp.ONTAPDisks{Bad: []snmp.ONTAPDisk{}}, Shelves: []snmp.ONTAPShelf{}, Mirrors: []snmp.ONTAPMirror{},
		Events: []snmp.ONTAPEvent{}}
	snap := &snmp.Snapshot{CollectedAt: now, Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{},
		Truncated: raw.Truncated, Partial: raw.Partial}
	seen := map[string]bool{}
	var uptime uint64
	for _, n := range raw.Nodes {
		name := clean(n.Name)
		if name == "" || seen["n"+name] {
			continue
		}
		seen["n"+name] = true
		st := lower(n.State)
		if st == "" {
			st = "unknown"
		}
		on := snmp.ONTAPNode{Name: name, State: st, Model: clean(n.Model), HA: n.HA.Enabled,
			Takeover: lower(n.HA.Takeover.State), Giveback: lower(n.HA.Giveback.State),
			OverTemp: lower(n.Controller.OverTemperature) == "over"}
		if u, ok := nonNeg(n.Uptime); ok {
			on.UptimeS = u
			uptime = max(uptime, u)
		}
		if len(n.HA.Partners) > 0 {
			on.Partner = clean(n.HA.Partners[0].Name)
		}
		if c := n.Controller.FailedFan.Count; c != nil && *c > 0 && *c < 1000 {
			on.FailedFans = *c
		}
		if c := n.Controller.FailedPowerSupply.Count; c != nil && *c > 0 && *c < 1000 {
			on.FailedPSUs = *c
		}
		o.Nodes = append(o.Nodes, on)
	}
	for _, a := range raw.Aggregates {
		name := clean(a.Name)
		if name == "" || seen["a"+name] {
			continue
		}
		seen["a"+name] = true
		st := lower(a.State)
		if st == "" {
			st = "unknown"
		}
		ag := snmp.ONTAPAggregate{Name: name, Node: clean(a.Node.Name), State: st}
		size, ok1 := nonNeg(a.Space.BlockStorage.Size)
		used, ok2 := nonNeg(a.Space.BlockStorage.Used)
		if ok1 && ok2 && size > 0 && used <= size {
			ag.TotalBytes, ag.UsedBytes = size, used
			snap.Disks = append(snap.Disks, snmp.Disk{Mount: "Aggregat " + name, FSType: "aggregat", TotalBytes: size, FreeBytes: size - used})
		}
		if a.Metric.Status == "ok" {
			if v := a.Metric.IOPS.Total; v != nil && *v >= 0 && *v < 1e9 {
				x := *v
				ag.IOPS = &x
			}
			if v := a.Metric.Latency.Total; v != nil && *v >= 0 && *v < 1e9 {
				x := *v / 1000 // µs → ms
				ag.LatencyMs = &x
			}
		}
		o.Aggregates = append(o.Aggregates, ag)
	}
	for _, v := range raw.Volumes {
		name := clean(v.Name)
		if name == "" {
			continue
		}
		if svm := clean(v.SVM.Name); svm != "" {
			name = cleanN(svm+"/"+name, MaxText)
		}
		if seen["v"+name] {
			continue
		}
		seen["v"+name] = true
		st := lower(v.State)
		if st == "" {
			st = "unknown"
		}
		vol := snmp.ONTAPVolume{Name: name, State: st, Type: lower(v.Type)}
		used, ok1 := nonNeg(v.Space.Used)
		avail, ok2 := nonNeg(v.Space.Available)
		if ok1 && ok2 && used+avail > 0 && used+avail >= used {
			vol.TotalBytes, vol.UsedBytes = used+avail, used
			// Nur beschreibbare Volumes zählen für „voll“ (Spiegelziele füllt die Quelle).
			if st == "online" && vol.Type == "rw" {
				snap.Disks = append(snap.Disks, snmp.Disk{Mount: "Volume " + name, FSType: "volume", TotalBytes: vol.TotalBytes, FreeBytes: avail})
			}
		}
		o.Volumes = append(o.Volumes, vol)
	}
	for _, d := range raw.Disks {
		name := clean(d.Name)
		if name == "" || seen["d"+name] {
			continue
		}
		seen["d"+name] = true
		o.Disks.Total++
		st, ct := lower(d.State), lower(d.ContainerType)
		if ct == "spare" || st == "spare" {
			o.Disks.Spares++
		}
		if DiskProblem(st, ct) != "" && len(o.Disks.Bad) < BadDisksShown {
			o.Disks.Bad = append(o.Disks.Bad, snmp.ONTAPDisk{Name: name, State: st, Container: ct, Model: clean(d.Model)})
		}
	}
	for _, sh := range raw.Shelves {
		id := clean(sh.ID)
		if id == "" {
			id = clean(sh.Name)
		}
		if id == "" || seen["s"+id] {
			continue
		}
		seen["s"+id] = true
		st := lower(sh.State)
		if st == "" {
			st = "unknown"
		}
		os := snmp.ONTAPShelf{ID: id, Model: clean(sh.Model), State: st, Parts: []snmp.ONTAPPart{}, Temps: []snmp.ONTAPTemp{}}
		for _, f := range sh.Frus {
			if f.Installed != nil && !*f.Installed {
				continue
			}
			kind := lower(f.Type)
			if kind != "psu" && kind != "module" {
				continue
			}
			os.Parts = append(os.Parts, snmp.ONTAPPart{Kind: kind, ID: intID(f.ID), State: lower(f.State)})
		}
		for _, f := range sh.Fans {
			if f.Installed != nil && !*f.Installed {
				continue
			}
			os.Parts = append(os.Parts, snmp.ONTAPPart{Kind: "fan", ID: intID(f.ID), State: lower(f.State)})
		}
		for _, t := range sh.Temps {
			if t.Installed != nil && !*t.Installed {
				continue
			}
			os.Temps = append(os.Temps, snmp.ONTAPTemp{ID: intID(t.ID), Celsius: temp(t.Temperature), Warn: temp(t.Threshold.High.Warning),
				Crit: temp(t.Threshold.High.Critical), State: lower(t.State)})
		}
		if len(os.Parts) > 64 {
			os.Parts = os.Parts[:64]
		}
		if len(os.Temps) > 64 {
			os.Temps = os.Temps[:64]
		}
		o.Shelves = append(o.Shelves, os)
	}
	for _, m := range raw.Mirrors {
		dst := clean(m.Destination.Path)
		if dst == "" || seen["m"+dst] {
			continue
		}
		seen["m"+dst] = true
		mr := snmp.ONTAPMirror{Source: clean(m.Source.Path), Destination: dst, State: lower(m.State), Healthy: m.Healthy == nil || *m.Healthy}
		if lag, ok := ParseDuration(m.LagTime); ok {
			mr.LagS = &lag
		}
		if !mr.Healthy && len(m.UnhealthyReason) > 0 {
			mr.Reason = clean(m.UnhealthyReason[0].Message)
		}
		o.Mirrors = append(o.Mirrors, mr)
	}
	for _, e := range raw.Events {
		sev := lower(e.Message.Severity)
		name := clean(e.Message.Name)
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.Time))
		if (sev != "emergency" && sev != "alert") || !EventName(name) || err != nil {
			continue
		}
		o.Events = append(o.Events, snmp.ONTAPEvent{Time: t.UTC().Format(time.RFC3339), Name: name, Severity: sev,
			Node: clean(e.Node.Name), Message: cleanN(e.LogMessage, 300)})
	}
	sort.Slice(o.Nodes, func(i, j int) bool { return o.Nodes[i].Name < o.Nodes[j].Name })
	sort.Slice(o.Aggregates, func(i, j int) bool { return o.Aggregates[i].Name < o.Aggregates[j].Name })
	sort.Slice(o.Volumes, func(i, j int) bool { return o.Volumes[i].Name < o.Volumes[j].Name })
	sort.Slice(o.Disks.Bad, func(i, j int) bool { return o.Disks.Bad[i].Name < o.Disks.Bad[j].Name })
	sort.Slice(o.Shelves, func(i, j int) bool { return o.Shelves[i].ID < o.Shelves[j].ID })
	sort.Slice(o.Mirrors, func(i, j int) bool { return o.Mirrors[i].Destination < o.Mirrors[j].Destination })
	sort.SliceStable(o.Events, func(i, j int) bool { return o.Events[i].Time > o.Events[j].Time })
	sort.Slice(snap.Disks, func(i, j int) bool { return snap.Disks[i].Mount < snap.Disks[j].Mount })
	snap.ONTAP = o
	snap.System.UptimeS = uptime
	model := ""
	if len(o.Nodes) > 0 {
		model = " " + o.Nodes[0].Model
	}
	snap.System.Descr = cleanN(fmt.Sprintf("NetApp%s, ONTAP %s (%d Knoten, %d Aggregate, %d Volumes)", model,
		strings.TrimPrefix(o.Version, "NetApp Release "), len(o.Nodes), len(o.Aggregates), len(o.Volumes)), 255)
	return snap
}

// DiskProblem: Kurztext, wenn eine Platte ausgefallen oder auffällig ist.
// Kritisch ist „ausgefallen“; die übrigen sind Warnungen.
func DiskProblem(state, container string) string {
	switch {
	case state == "broken" || container == "broken":
		return "ausgefallen"
	case state == "copy":
		return "wird ersetzt (Daten werden kopiert, Platte fällt voraussichtlich aus)"
	case state == "reconstructing":
		return "wird neu aufgebaut"
	case state == "removed":
		return "entfernt"
	case state == "unfail":
		return "wird wieder in Betrieb genommen"
	}
	return ""
}

var eventPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,120}$`)

// EventName: Name einer EMS-Meldung (z. B. „callhome.spares.low“).
func EventName(s string) bool { return eventPattern.MatchString(s) }

var durPattern = regexp.MustCompile(`^P(?:(\d{1,5})D)?(?:T(?:(\d{1,6})H)?(?:(\d{1,8})M)?(?:(\d{1,10})(?:\.\d+)?S)?)?$`)

// ParseDuration liest eine Dauer nach ISO 8601 (PT8H35M42S, P2DT1H) in Sekunden.
func ParseDuration(s string) (int64, bool) {
	m := durPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || s == "P" || strings.HasSuffix(s, "T") {
		return 0, false
	}
	var total int64
	for i, mul := range []int64{86400, 3600, 60, 1} {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil {
			return 0, false
		}
		total += n * mul
	}
	if total < 0 || total > 10*365*86400 {
		return 0, false
	}
	return total, true
}

// Rebooted: Ein Knoten läuft kürzer als bei der letzten Abfrage und lief
// vorher lange genug (snmp.MinUptimeForReboot).
func Rebooted(prev, cur *snmp.ONTAP) bool {
	if prev == nil || cur == nil {
		return false
	}
	before := map[string]uint64{}
	for _, n := range prev.Nodes {
		before[n.Name] = n.UptimeS
	}
	for _, n := range cur.Nodes {
		if b, ok := before[n.Name]; ok && snmp.RebootCounts(b) && n.UptimeS > 0 && n.UptimeS+60 < b {
			return true
		}
	}
	return false
}
