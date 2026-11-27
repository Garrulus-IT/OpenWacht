// SPDX-License-Identifier: AGPL-3.0-only

// Package xapi liest einen XenServer- bzw. XCP-ng-Pool über XAPI (0.42.0),
// ausschließlich lesend: Pool und HA, Hosts, VMs, Storage-Repositories und
// Messwerte (CPU, RAM) über /rrd_updates.
//
// Sicherheit:
//   - Nur JSON-RPC-Methoden aus einer festen Liste (allowedMethods), alle
//     lesend; dazu GET /rrd_updates. Andere Aufrufe gibt es im Code nicht.
//   - HTTPS mit festem Fingerabdruck des Zertifikats (XenServer hat ab Werk ein
//     selbstsigniertes), das Passwort geht erst nach geprüftem Handshake hinaus.
//     Andere Hosts des Pools fragt der Client nur mit dem Fingerabdruck ab, den
//     der Pool-Master für sie meldet (Zertifikate vom Typ „host“).
//   - Verbindungen nur über den Guard der Zentrale (Netzfreigabe vor connect()),
//     ohne Proxy; Weiterleitungen werden nie verfolgt. Meldet die Adresse
//     HOST_IS_SLAVE, folgt der Client dem neuen Pool-Master nicht (die
//     Zugangsdaten sind an die Adresse gebunden), sondern meldet ihn.
//   - root wird abgelehnt, ohne dass das Passwort gesendet wird. Nach der
//     Anmeldung prüft der Client die Sitzung: Lokaler Superuser oder Rechte
//     über die Rolle „read-only“ hinaus werden abgelehnt; lassen sich die
//     Rechte nicht lesen, ebenfalls.
//   - Die Sitzung wird am Ende immer abgemeldet und geht bei /rrd_updates als
//     Cookie mit, nicht in der Adresse.
//   - Antworten sind in Größe und Anzahl begrenzt, Texte bereinigt und
//     gekürzt, Zahlen auf Plausibilität geprüft.
//
// Methoden, Feldnamen und Aufzählungswerte nach dem XAPI-Datenmodell
// (xapi-project/xen-api, ocaml/idl) und der XenServer-8-Doku (SDK-Guide,
// RBAC).
package xapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
	MaxHosts       = 64
	MaxVMs         = 2000
	MaxSRs         = 500
	MaxPBDs        = 2000
	MaxPermissions = 20000
	MaxText        = 200
	// VMsShown: so viele VMs stehen einzeln im Snapshot (gezählt werden alle)
	VMsShown = 500
	// maxBody: größte Antwort eines Aufrufs (VM-Listen großer Pools)
	maxBody = 24 << 20
	// maxRRD: größte Antwort von /rrd_updates
	maxRRD = 8 << 20
	// RRDWindow: Messwerte dieses Zeitraums (Mittel)
	RRDWindow = 10 * time.Minute
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

// ValidUser prüft die Form des Benutzernamens (AD: name@domäne oder DOMÄNE\name).
func ValidUser(s string) bool { return userPattern.MatchString(s) }

// IsRoot: der lokale Superuser (wird abgelehnt).
func IsRoot(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "root") }

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

// Client fragt XAPI ab.
type Client struct {
	Guard   Dialer
	Timeout time.Duration
	Now     func() time.Time
}

var (
	ErrLogin   = errors.New("Anmeldung abgelehnt: Benutzer und Passwort prüfen")
	ErrNoRole  = errors.New("Das Konto hat keinen Zugang zum Pool (keine Rolle zugewiesen)")
	ErrTooMuch = errors.New("XAPI liefert mehr Daten als erlaubt")
	ErrRoot    = errors.New("root wird abgelehnt: bitte ein AD-Konto mit der Rolle „read-only“ nehmen " +
		"(root hat alle Rechte, auch Schreibrecht)")
	ErrSuperuser = errors.New("Das Konto meldet sich als lokaler Superuser an (alle Rechte) und wird abgelehnt: " +
		"bitte ein AD-Konto mit der Rolle „read-only“ nehmen")
	ErrRightsUnknown = errors.New("Rechte der Sitzung nicht lesbar: ohne diese Prüfung fragt OpenWacht nicht ab " +
		"(nötig ist ein AD-Konto mit der Rolle „read-only“)")
)

// WritableError: Die Sitzung darf mehr als lesen; OpenWacht lehnt sie ab.
type WritableError struct{ Permission string }

func (e *WritableError) Error() string {
	return "Konto mit Schreibrecht abgelehnt (" + e.Permission + "): bitte nur die Rolle „read-only“ zuweisen"
}

// NotMasterError: Die Adresse ist nicht (mehr) der Pool-Master.
type NotMasterError struct{ Master string }

func (e *NotMasterError) Error() string {
	if e.Master == "" {
		return "Die Adresse ist nicht der Pool-Master (HOST_IS_SLAVE): bitte die Adresse des Pool-Masters eintragen"
	}
	return "Pool-Master gewechselt: Die Adresse ist nicht mehr der Pool-Master, neuer Master ist " + e.Master +
		" (HOST_IS_SLAVE). Bitte die Adresse ändern; OpenWacht folgt nicht von selbst"
}

// APIError: Fehler von XAPI (Name und Parameter).
type APIError struct {
	Name   string
	Method string
}

func (e *APIError) Error() string { return "XAPI meldet " + e.Name + " bei " + e.Method }

// PinError: Das Zertifikat passt nicht zum hinterlegten Fingerabdruck.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	if e.Got == "" {
		return "TLS: kein Zertifikat erhalten"
	}
	return "TLS: Zertifikat des Pool-Masters passt nicht zum hinterlegten Fingerabdruck (jetzt " + FormatPin(e.Got) + ")"
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

// endpoint: eine HTTPS-Gegenstelle mit festem Fingerabdruck.
type endpoint struct {
	http  *http.Client
	base  string
	close func()
	mu    sync.Mutex
	seen  string
}

func (c *Client) endpoint(host string, p uint16, pin string) *endpoint {
	e := &endpoint{}
	t := c.timeout()
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            c.Guard.DialContext,
		TLSClientConfig:        tlsConfig(host, pin, &e.seen, &e.mu),
		TLSHandshakeTimeout:    t,
		ResponseHeaderTimeout:  t,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      false, // XAPI spricht HTTP/1.1
	}
	e.http = &http.Client{Transport: tr, Timeout: t,
		// Weiterleitungen nie folgen: Das Ziel läge womöglich außerhalb der Freigabe.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	e.base = "https://" + net.JoinHostPort(hostOnly(host), strconv.Itoa(int(port(p))))
	e.close = tr.CloseIdleConnections
	return e
}

// allowedMethods: alle JSON-RPC-Methoden, die der Client aufrufen darf.
// Ausnahmen vom reinen Lesen sind nur An- und Abmelden der eigenen Sitzung.
var allowedMethods = map[string]bool{
	"session.login_with_password":       true,
	"session.logout":                    true,
	"session.get_is_local_superuser":    true,
	"session.get_rbac_permissions":      true,
	"role.get_by_name_label":            true,
	"role.get_permissions_name_label":   true,
	"pool.get_all_records":              true,
	"host.get_all_records":              true,
	"host_metrics.get_all_records":      true,
	"VM.get_all_records_where":          true,
	"SR.get_all_records":                true,
	"PBD.get_currently_attached":        true,
	"certificate.get_all_records_where": true,
}

// AllowedMethod: Darf der Client diese Methode aufrufen?
func AllowedMethod(m string) bool { return allowedMethods[m] }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// session: eine angemeldete XAPI-Sitzung am Pool-Master.
type session struct {
	*endpoint
	cfg   Config
	ref   string
	id    int
	calls []string
}

var nonFinite = regexp.MustCompile(`([:\[,]\s*)(-?Infinity|NaN)(\s*[,\]}])`)

// call ruft eine Methode aus der festen Liste auf. Die Antwort wird erst nach
// dem Status ausgewertet und ist auf maxBody begrenzt.
func (s *session) call(ctx context.Context, method string, out any, params ...any) error {
	if !AllowedMethod(method) {
		return fmt.Errorf("Methode %s nicht erlaubt", method) // Programmfehler, nie von außen erreichbar
	}
	s.id++
	if method != "session.login_with_password" {
		params = append([]any{s.ref}, params...)
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: s.id})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/jsonrpc", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	s.mu.Lock()
	s.calls = append(s.calls, method)
	s.mu.Unlock()
	resp, err := s.http.Do(req)
	if err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return pe
		}
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return ErrTooMuch
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return fmt.Errorf("XAPI antwortet mit einer Weiterleitung (HTTP %d), der OpenWacht nicht folgt", resp.StatusCode)
		}
		return fmt.Errorf("XAPI antwortet mit HTTP %d", resp.StatusCode)
	}
	// XAPI schreibt nicht endliche Zahlen ohne Anführungszeichen (wie das SDK ersetzen)
	b = nonFinite.ReplaceAll(b, []byte(`${1}null${3}`))
	var r rpcResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("Antwort auf %s nicht lesbar", method)
	}
	if r.Error != nil {
		return rpcError(method, r.Error.Message, r.Error.Data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(r.Result, out); err != nil {
		return fmt.Errorf("Antwort auf %s nicht lesbar", method)
	}
	return nil
}

var addrPattern = regexp.MustCompile(`^[A-Za-z0-9.:\-\[\]]{1,253}$`)

// rpcError übersetzt einen XAPI-Fehler ({"message": NAME, "data": [Parameter]}).
func rpcError(method, name string, data json.RawMessage) error {
	var params []string
	_ = json.Unmarshal(data, &params)
	switch name {
	case "SESSION_AUTHENTICATION_FAILED":
		return ErrLogin
	case "SESSION_AUTHORIZATION_FAILED":
		return ErrNoRole
	case "RBAC_PERMISSION_DENIED":
		if method == "session.login_with_password" {
			return ErrNoRole
		}
	case "HOST_IS_SLAVE":
		m := ""
		if len(params) > 0 && addrPattern.MatchString(strings.TrimSpace(params[0])) {
			m = strings.TrimSpace(params[0])
		}
		return &NotMasterError{Master: m}
	}
	n := strings.ToUpper(strings.TrimSpace(name))
	if n == "" || len(n) > 80 || strings.Trim(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
		n = "einen unbekannten Fehler"
	}
	return &APIError{Name: n, Method: method}
}

// login meldet an. root lehnt OpenWacht vorher ab, ohne das Passwort zu senden.
func (c *Client) login(ctx context.Context, cfg Config) (*session, error) {
	if IsRoot(cfg.User) {
		return nil, ErrRoot
	}
	if !ValidUser(cfg.User) || !ValidPassword(cfg.Password) {
		return nil, errors.New("Benutzer oder Passwort ungültig")
	}
	if !ValidPin(cfg.Pin) {
		return nil, errors.New("Fingerabdruck des Zertifikats fehlt oder ist ungültig")
	}
	s := &session{endpoint: c.endpoint(cfg.Host, cfg.Port, cfg.Pin), cfg: cfg}
	var ref string
	if err := s.call(ctx, "session.login_with_password", &ref, cfg.User, cfg.Password, "1.0", "OpenWacht"); err != nil {
		s.close()
		return nil, err
	}
	if !refPattern.MatchString(ref) || ref == nullRef {
		s.close()
		return nil, errors.New("Anmeldung: keine gültige Sitzung erhalten")
	}
	s.ref = ref
	return s, nil
}

// logout meldet die Sitzung ab, auch wenn der Kontext schon abgelaufen ist.
func (s *session) logout() {
	if s.ref == "" {
		s.close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.call(ctx, "session.logout", nil)
	s.ref = ""
	s.close()
}

// checkReadOnly lehnt Sitzungen mit mehr Rechten als „read-only“ ab.
func (s *session) checkReadOnly(ctx context.Context) error {
	var super bool
	if err := s.call(ctx, "session.get_is_local_superuser", &super, s.ref); err != nil {
		return rightsErr(err)
	}
	if super {
		return ErrSuperuser
	}
	var perms []string
	if err := s.call(ctx, "session.get_rbac_permissions", &perms, s.ref); err != nil {
		return rightsErr(err)
	}
	if len(perms) == 0 || len(perms) > MaxPermissions {
		return ErrRightsUnknown
	}
	var roles []string
	if err := s.call(ctx, "role.get_by_name_label", &roles, ReadOnlyRole); err != nil {
		return rightsErr(err)
	}
	if len(roles) != 1 || !refPattern.MatchString(roles[0]) {
		return ErrRightsUnknown
	}
	var allowed []string
	if err := s.call(ctx, "role.get_permissions_name_label", &allowed, roles[0]); err != nil {
		return rightsErr(err)
	}
	if len(allowed) == 0 || len(allowed) > MaxPermissions {
		return ErrRightsUnknown
	}
	return Writable(perms, allowed)
}

// ReadOnlyRole: die feste Rolle mit nur lesendem Zugriff (XAPI-Rollen sind
// unveränderlich).
const ReadOnlyRole = "read-only"

// Writable prüft die Rechte einer Sitzung gegen die der Rolle „read-only“:
// Die Sitzung muss die Rolle haben und darf nichts darüber hinaus.
func Writable(session, readOnly []string) error {
	allowed := make(map[string]bool, len(readOnly)+1)
	for _, p := range readOnly {
		allowed[p] = true
	}
	allowed[ReadOnlyRole] = true
	has := false
	extra := []string{}
	for _, p := range session {
		if p == ReadOnlyRole {
			has = true
		}
		if !allowed[p] {
			extra = append(extra, clean(p))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return &WritableError{Permission: extra[0]}
	}
	if !has {
		return ErrRightsUnknown
	}
	return nil
}

func rightsErr(err error) error {
	var pe *PinError
	var ae *APIError
	switch {
	case errors.As(err, &pe), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	case errors.As(err, &ae):
		return ErrRightsUnknown
	}
	return err
}

const nullRef = "OpaqueRef:NULL"

var (
	refPattern  = regexp.MustCompile(`^OpaqueRef:[0-9A-Za-z-]{1,64}$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

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

// flexInt: XAPI-Ganzzahl (JSON-Zahl oder Text).
type flexInt struct {
	V  int64
	OK bool
}

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// Gleitkomma wie 1.0e12 (manche Versionen)
		x, err2 := strconv.ParseFloat(s, 64)
		if err2 != nil || x != x || x > 9e18 || x < -9e18 {
			return nil
		}
		n = int64(x)
	}
	f.V, f.OK = n, true
	return nil
}

func (f flexInt) nonNeg() (uint64, bool) {
	if !f.OK || f.V < 0 {
		return 0, false
	}
	return uint64(f.V), true
}

// --- Rohdaten -----------------------------------------------------------------

type poolRec struct {
	Name         string  `json:"name_label"`
	Master       string  `json:"master"`
	HAEnabled    bool    `json:"ha_enabled"`
	HATolerate   flexInt `json:"ha_host_failures_to_tolerate"`
	HAPlan       flexInt `json:"ha_plan_exists_for"`
	HAOvercommit bool    `json:"ha_overcommitted"`
}

type hostRec struct {
	UUID            string            `json:"uuid"`
	Name            string            `json:"name_label"`
	Enabled         bool              `json:"enabled"`
	OtherConfig     map[string]string `json:"other_config"`
	SoftwareVersion map[string]string `json:"software_version"`
	Metrics         string            `json:"metrics"`
	Address         string            `json:"address"`
	PBDs            []string          `json:"PBDs"`
	UpdatesApplied  string            `json:"latest_synced_updates_applied"`
	Pending         []string          `json:"pending_guidances"`
}

type hostMetricsRec struct {
	Live     bool    `json:"live"`
	MemTotal flexInt `json:"memory_total"`
}

type vmRec struct {
	UUID          string            `json:"uuid"`
	Name          string            `json:"name_label"`
	PowerState    string            `json:"power_state"`
	Template      bool              `json:"is_a_template"`
	Snapshot      bool              `json:"is_a_snapshot"`
	ControlDomain bool              `json:"is_control_domain"`
	ResidentOn    string            `json:"resident_on"`
	HARestart     string            `json:"ha_restart_priority"`
	OtherConfig   map[string]string `json:"other_config"`
	VCPUs         flexInt           `json:"VCPUs_max"`
	MemTarget     flexInt           `json:"memory_dynamic_max"`
}

type srRec struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name_label"`
	Type        string   `json:"type"`
	ContentType string   `json:"content_type"`
	Shared      bool     `json:"shared"`
	Size        flexInt  `json:"physical_size"`
	Used        flexInt  `json:"physical_utilisation"`
	PBDs        []string `json:"PBDs"`
}

type certRec struct {
	Type      string `json:"type"`
	Host      string `json:"host"`
	SHA256    string `json:"fingerprint_sha256"`
	SHA256Old string `json:"fingerprint"`
}

// Raw: die rohen Antworten einer Abfrage (für Build und Fuzz-Tests).
type Raw struct {
	Pools    map[string]poolRec
	Hosts    map[string]hostRec
	Metrics  map[string]hostMetricsRec
	VMs      map[string]vmRec
	SRs      map[string]srRec
	Attached map[string]bool // PBD → angebunden
	// RRD: Messwerte je Host-UUID (aus /rrd_updates)
	RRD map[string]RRDValues
	// RRDError: Host-UUID → Grund, warum Messwerte fehlen
	RRDError map[string]string
	// Partial: Teile, die fehlen
	Partial []string
}

// Info: was „Verbindung prüfen“ zeigt.
type Info struct {
	Pool        string `json:"pool"`
	Product     string `json:"produkt"`
	Master      string `json:"master"`
	Hosts       int    `json:"hosts"`
	VMs         int    `json:"vms"`
	SRs         int    `json:"speicher"`
	HA          bool   `json:"ha"`
	Metrics     int    `json:"hosts_mit_messwerten"`
	Fingerprint string `json:"fingerabdruck"`
}

// Probe prüft Rechte und liest einmal alles (wie Poll).
func (c *Client) Probe(ctx context.Context, cfg Config) (Info, error) {
	snap, err := c.Poll(ctx, cfg)
	if err != nil {
		return Info{}, err
	}
	x := snap.XAPI
	n := 0
	for _, h := range x.Hosts {
		if h.CPUPct != nil {
			n++
		}
	}
	return Info{Pool: x.Pool, Product: x.Product, Master: x.Master, Hosts: len(x.Hosts),
		VMs: x.VMCount.Running + x.VMCount.Halted + x.VMCount.Paused + x.VMCount.Suspended, SRs: len(x.SRs), HA: x.HA.Enabled,
		Metrics: n, Fingerprint: x.Fingerprint}, nil
}

// Poll meldet an, prüft die Rechte der Sitzung, liest alles als Snapshot und
// meldet wieder ab.
func (c *Client) Poll(ctx context.Context, cfg Config) (_ *snmp.Snapshot, err error) {
	defer safe.Recover("xapi", &err)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	s, err := c.login(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer s.logout()
	if err := s.checkReadOnly(ctx); err != nil {
		return nil, err
	}
	raw := Raw{Attached: map[string]bool{}, RRD: map[string]RRDValues{}, RRDError: map[string]string{}}
	// Pflicht: Pool und Hosts. Fehlt einer davon, ist die Abfrage gescheitert.
	if err := s.call(ctx, "pool.get_all_records", &raw.Pools); err != nil {
		return nil, fmt.Errorf("Pool: %w", err)
	}
	if len(raw.Pools) != 1 {
		return nil, errors.New("Pool: Antwort ohne genau einen Pool")
	}
	if err := s.call(ctx, "host.get_all_records", &raw.Hosts); err != nil {
		return nil, fmt.Errorf("Hosts: %w", err)
	}
	if len(raw.Hosts) == 0 {
		return nil, errors.New("Hosts: keine Hosts gemeldet")
	}
	if len(raw.Hosts) > MaxHosts {
		return nil, ErrTooMuch
	}
	// Übrige Teile: Ein Fehler lässt den Rest stehen.
	part := func(name string, err error) error {
		var pe *PinError
		var ae *APIError
		switch {
		case err == nil:
		case errors.Is(err, ErrTooMuch), errors.As(err, &pe), ctx.Err() != nil:
			return err
		case errors.As(err, &ae):
			raw.Partial = append(raw.Partial, name)
		default:
			return err
		}
		return nil
	}
	if err := part("Hosts", s.call(ctx, "host_metrics.get_all_records", &raw.Metrics)); err != nil {
		return nil, fmt.Errorf("Hosts: %w", err)
	}
	if err := part("VMs", s.call(ctx, "VM.get_all_records_where", &raw.VMs,
		`field "is_a_template"="false" and field "is_a_snapshot"="false" and field "is_control_domain"="false"`)); err != nil {
		return nil, fmt.Errorf("VMs: %w", err)
	}
	if len(raw.VMs) > MaxVMs {
		return nil, ErrTooMuch
	}
	srErr := s.call(ctx, "SR.get_all_records", &raw.SRs)
	if err := part("Speicher", srErr); err != nil {
		return nil, fmt.Errorf("Speicher: %w", err)
	}
	if len(raw.SRs) > MaxSRs {
		return nil, ErrTooMuch
	}
	if srErr == nil {
		// PBDs einzeln: Der ganze Eintrag enthält device_config (Zugangsdaten der Speicher).
		pbds := map[string]bool{}
		for _, sr := range raw.SRs {
			for _, p := range sr.PBDs {
				if refPattern.MatchString(p) {
					pbds[p] = true
				}
			}
		}
		if len(pbds) > MaxPBDs {
			return nil, ErrTooMuch
		}
		for _, p := range sortedKeys(pbds) {
			var on bool
			err := s.call(ctx, "PBD.get_currently_attached", &on, p)
			if err := part("Anbindung", err); err != nil {
				return nil, fmt.Errorf("Speicher: %w", err)
			}
			if err != nil {
				break
			}
			raw.Attached[p] = on
		}
	}
	c.metrics(ctx, s, &raw)
	snap := Build(raw, c.now())
	s.mu.Lock()
	snap.XAPI.Fingerprint = s.seen
	s.mu.Unlock()
	return snap, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// metrics holt /rrd_updates je erreichbarem Host. Den Pool-Master über die
// bestehende Verbindung, die übrigen nur mit dem Fingerabdruck, den der Pool
// für sie meldet, und nur, wenn ihre Adresse freigegeben ist (Guard).
func (c *Client) metrics(ctx context.Context, s *session, raw *Raw) {
	var master string
	for _, p := range raw.Pools {
		master = p.Master
	}
	var certs map[string]certRec
	certErr := s.call(ctx, "certificate.get_all_records_where", &certs, `field "type"="host"`)
	pins := map[string]string{}
	for _, cr := range certs {
		fp := cr.SHA256
		if fp == "" {
			fp = cr.SHA256Old
		}
		if pin, ok := NormalizePin(fp); ok && cr.Type == "host" && refPattern.MatchString(cr.Host) {
			pins[cr.Host] = pin
		}
	}
	start := c.now().Add(-RRDWindow).Unix()
	for _, ref := range sortedKeys(raw.Hosts) {
		h := raw.Hosts[ref]
		if !uuidPattern.MatchString(h.UUID) {
			continue
		}
		if m, ok := raw.Metrics[h.Metrics]; ok && !m.Live {
			raw.RRDError[h.UUID] = "Host nicht erreichbar"
			continue
		}
		if ctx.Err() != nil {
			raw.RRDError[h.UUID] = "Zeit abgelaufen"
			continue
		}
		var ep *endpoint
		if ref == master {
			ep = s.endpoint
		} else {
			pin, ok := pins[ref]
			addr := strings.TrimSpace(h.Address)
			switch {
			case certErr != nil || !ok:
				raw.RRDError[h.UUID] = "Fingerabdruck des Hosts nicht bekannt (Zertifikate des Pools nicht lesbar)"
				continue
			case addr == "" || !addrPattern.MatchString(addr):
				raw.RRDError[h.UUID] = "Adresse des Hosts unbekannt"
				continue
			}
			ep = c.endpoint(addr, s.cfg.Port, pin)
		}
		vals, err := s.rrd(ctx, ep, h.UUID, start)
		if ep != s.endpoint {
			ep.close()
		}
		if err != nil {
			raw.RRDError[h.UUID] = cleanN(err.Error(), 200)
			continue
		}
		raw.RRD[h.UUID] = vals
	}
}

// RRDValues: gemittelte Messwerte eines Hosts und seiner VMs.
type RRDValues struct {
	HostCPU  *float64 // Anteil 0–1
	MemTotal uint64   // KiB
	MemFree  uint64   // KiB
	VMCPU    map[string]float64
	VMMem    map[string]uint64 // Byte
}

// xport: Antwort von /rrd_updates (rrdtool-xport, XML).
type xport struct {
	XMLName xml.Name `xml:"xport"`
	Meta    struct {
		Columns int      `xml:"columns"`
		Legend  []string `xml:"legend>entry"`
	} `xml:"meta"`
	Rows []struct {
		T int64    `xml:"t"`
		V []string `xml:"v"`
	} `xml:"data>row"`
}

// rrd liest die Messwerte eines Hosts (mit Sitzung als Cookie).
func (s *session) rrd(ctx context.Context, ep *endpoint, hostUUID string, start int64) (RRDValues, error) {
	q := url.Values{"start": {strconv.FormatInt(start, 10)}, "cf": {"AVERAGE"}, "interval": {"60"}, "host": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.base+"/rrd_updates?"+q.Encode(), nil)
	if err != nil {
		return RRDValues{}, err
	}
	req.AddCookie(&http.Cookie{Name: "session_id", Value: s.ref})
	req.Header.Set("Accept", "application/xml")
	s.mu.Lock()
	s.calls = append(s.calls, "GET /rrd_updates")
	s.mu.Unlock()
	resp, err := ep.http.Do(req)
	if err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return RRDValues{}, errors.New("TLS: Zertifikat des Hosts passt nicht zum Fingerabdruck, den der Pool meldet")
		}
		return RRDValues{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRRD+1))
	if err != nil {
		return RRDValues{}, err
	}
	if len(b) > maxRRD {
		return RRDValues{}, ErrTooMuch
	}
	if resp.StatusCode != http.StatusOK {
		return RRDValues{}, fmt.Errorf("Messwerte: HTTP %d", resp.StatusCode)
	}
	return ParseRRD(b, hostUUID)
}

// ParseRRD wertet eine Antwort von /rrd_updates aus: Mittel der CPU über alle
// Zeilen, Speicher aus der jüngsten Zeile mit Wert.
func ParseRRD(b []byte, hostUUID string) (RRDValues, error) {
	var x xport
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	if err := d.Decode(&x); err != nil {
		return RRDValues{}, errors.New("Messwerte nicht lesbar")
	}
	if len(x.Meta.Legend) == 0 || len(x.Meta.Legend) > 50000 || len(x.Rows) > 1000 {
		return RRDValues{}, errors.New("Messwerte unplausibel")
	}
	out := RRDValues{VMCPU: map[string]float64{}, VMMem: map[string]uint64{}}
	type acc struct {
		sum  float64
		n    int
		last float64
		lt   int64
		ok   bool
	}
	cols := make([]acc, len(x.Meta.Legend))
	for _, r := range x.Rows {
		for i, v := range r.V {
			if i >= len(cols) {
				break
			}
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || f != f || f > 1e18 || f < -1e18 {
				continue // NaN, inf, leer
			}
			cols[i].sum += f
			cols[i].n++
			if !cols[i].ok || r.T >= cols[i].lt {
				cols[i].last, cols[i].lt, cols[i].ok = f, r.T, true
			}
		}
	}
	vmCPUs := map[string][]float64{}
	for i, l := range x.Meta.Legend {
		c := cols[i]
		if c.n == 0 {
			continue
		}
		parts := strings.Split(l, ":")
		if len(parts) != 4 || parts[0] != "AVERAGE" || !uuidPattern.MatchString(parts[2]) {
			continue
		}
		avg := c.sum / float64(c.n)
		switch parts[1] {
		case "host":
			if parts[2] != hostUUID {
				continue
			}
			switch parts[3] {
			case "cpu_avg":
				if avg >= 0 && avg <= 1.0001 {
					v := min(avg, 1)
					out.HostCPU = &v
				}
			case "memory_total_kib":
				if c.last > 0 {
					out.MemTotal = uint64(c.last)
				}
			case "memory_free_kib":
				if c.last >= 0 {
					out.MemFree = uint64(c.last)
				}
			}
		case "vm":
			id := parts[2]
			switch {
			case parts[3] == "cpu_usage":
				if avg >= 0 && avg <= 1.0001 {
					out.VMCPU[id] = min(avg, 1)
				}
			case cpuN.MatchString(parts[3]):
				if avg >= 0 && avg <= 1.0001 {
					vmCPUs[id] = append(vmCPUs[id], min(avg, 1))
				}
			case parts[3] == "memory":
				if c.last >= 0 && c.last < 1<<50 {
					out.VMMem[id] = uint64(c.last)
				}
			}
		}
	}
	// ältere Versionen ohne cpu_usage: Mittel der vCPUs
	for id, list := range vmCPUs {
		if _, ok := out.VMCPU[id]; ok || len(list) == 0 {
			continue
		}
		var sum float64
		for _, v := range list {
			sum += v
		}
		out.VMCPU[id] = sum / float64(len(list))
	}
	if out.MemFree > out.MemTotal {
		out.MemTotal, out.MemFree = 0, 0
	}
	return out, nil
}

var cpuN = regexp.MustCompile(`^cpu[0-9]{1,4}$`)

// Guidances: bekannte Schritte nach Updates (update_guidances).
var guidances = map[string]string{
	"reboot_host":                             "Host neu starten",
	"reboot_host_on_livepatch_failure":        "Host neu starten (Livepatch fehlgeschlagen)",
	"reboot_host_on_kernel_livepatch_failure": "Host neu starten (Kernel-Livepatch fehlgeschlagen)",
	"reboot_host_on_xen_livepatch_failure":    "Host neu starten (Xen-Livepatch fehlgeschlagen)",
	"restart_toolstack":                       "Toolstack neu starten",
	"restart_device_model":                    "Gerätemodell der VMs neu starten",
	"restart_vm":                              "VMs neu starten",
}

// GuidanceText: Text zu einem Schritt nach Updates.
func GuidanceText(g string) string {
	if t, ok := guidances[g]; ok {
		return t
	}
	return g
}

func pct(f float64) *float64 {
	v := f * 100
	return &v
}

// Build bildet die rohen Antworten auf den Snapshot ab. Ungültige Einträge
// (ohne Namen, unplausible Zahlen) fallen weg.
func Build(raw Raw, now time.Time) *snmp.Snapshot {
	x := &snmp.XAPI{Hosts: []snmp.XAPIHost{}, VMs: []snmp.XAPIVM{}, SRs: []snmp.XAPISR{}}
	snap := &snmp.Snapshot{CollectedAt: now, Disks: []snmp.Disk{}, Interfaces: []snmp.Interface{}, Supplies: []snmp.Supply{},
		Partial: raw.Partial}
	var master string
	for _, p := range raw.Pools {
		x.Pool = clean(p.Name)
		master = p.Master
		x.HA.Enabled = p.HAEnabled
		if v, ok := p.HATolerate.nonNeg(); ok && v < 1000 {
			x.HA.Tolerate = int(v)
		}
		if v, ok := p.HAPlan.nonNeg(); ok && v < 1000 {
			x.HA.Plan = int(v)
		}
		x.HA.Overcommitted = p.HAOvercommit
	}
	hostNames := map[string]string{} // Ref → Name
	seen := map[string]bool{}
	var cpuSum float64
	var cpuN int
	var memTotal, memFree uint64
	var masterUptime uint64
	for _, ref := range sortedKeys(raw.Hosts) {
		h := raw.Hosts[ref]
		name := clean(h.Name)
		if name == "" {
			name = clean(h.UUID)
		}
		if name == "" || seen["h"+name] {
			continue
		}
		seen["h"+name] = true
		hostNames[ref] = name
		xh := snmp.XAPIHost{Name: name, Master: ref == master, Enabled: h.Enabled,
			Maintenance: strings.EqualFold(strings.TrimSpace(h.OtherConfig["MAINTENANCE_MODE"]), "true")}
		xh.Live = true // ohne Messeintrag unbekannt: nicht als ausgefallen werten
		if m, ok := raw.Metrics[h.Metrics]; ok {
			xh.Live = m.Live
			if v, ok := m.MemTotal.nonNeg(); ok {
				xh.MemTotal = v
			}
		}
		if bt, err := strconv.ParseFloat(strings.TrimSpace(h.OtherConfig["boot_time"]), 64); err == nil && bt > 0 {
			if up := now.Sub(time.Unix(int64(bt), 0)); up > 0 && up < 20*365*24*time.Hour {
				xh.UptimeS = uint64(up.Seconds())
			}
		}
		switch strings.TrimSpace(h.UpdatesApplied) {
		case "yes":
			xh.Updates = "aktuell"
		case "no":
			xh.Updates = "ausstehend"
		}
		for _, g := range h.Pending {
			if _, ok := guidances[g]; ok && len(xh.Pending) < 10 && !contains(xh.Pending, g) {
				xh.Pending = append(xh.Pending, g)
			}
		}
		sort.Strings(xh.Pending)
		if r, ok := raw.RRD[h.UUID]; ok {
			if r.HostCPU != nil {
				xh.CPUPct = pct(*r.HostCPU)
				cpuSum += *xh.CPUPct
				cpuN++
			}
			if r.MemTotal > 0 {
				xh.MemTotal, xh.MemFree = r.MemTotal*1024, r.MemFree*1024
				memTotal += xh.MemTotal
				memFree += xh.MemFree
			}
		} else if e := raw.RRDError[h.UUID]; e != "" {
			xh.MetricsError = cleanN(e, 200)
		}
		if xh.Master {
			x.Master = name
			masterUptime = xh.UptimeS
			brand := clean(h.SoftwareVersion["product_brand"])
			ver := clean(h.SoftwareVersion["product_version"])
			if ver == "" {
				ver = clean(h.SoftwareVersion["platform_version"])
			}
			x.Product = cleanN(strings.TrimSpace(brand+" "+ver), 80)
		}
		x.Hosts = append(x.Hosts, xh)
	}
	vmCPU := map[string]float64{}
	vmMem := map[string]uint64{}
	for _, r := range raw.RRD {
		for k, v := range r.VMCPU {
			vmCPU[k] = v
		}
		for k, v := range r.VMMem {
			vmMem[k] = v
		}
	}
	for _, ref := range sortedKeys(raw.VMs) {
		v := raw.VMs[ref]
		if v.Template || v.Snapshot || v.ControlDomain || !uuidPattern.MatchString(v.UUID) || seen["v"+v.UUID] {
			continue
		}
		seen["v"+v.UUID] = true
		st := strings.ToLower(strings.TrimSpace(v.PowerState))
		switch st {
		case "running":
			x.VMCount.Running++
		case "halted":
			x.VMCount.Halted++
		case "paused":
			x.VMCount.Paused++
		case "suspended":
			x.VMCount.Suspended++
		default:
			st = "unknown"
		}
		if len(x.VMs) >= VMsShown {
			continue
		}
		name := clean(v.Name)
		if name == "" {
			name = v.UUID
		}
		vm := snmp.XAPIVM{UUID: v.UUID, Name: name, State: st, Host: hostNames[v.ResidentOn],
			AutoStart: v.HARestart == "restart" || strings.EqualFold(strings.TrimSpace(v.OtherConfig["auto_poweron"]), "true")}
		if n, ok := v.VCPUs.nonNeg(); ok && n < 10000 {
			vm.VCPUs = int(n)
		}
		if st == "running" {
			if c, ok := vmCPU[v.UUID]; ok {
				vm.CPUPct = pct(c)
			}
			if m, ok := vmMem[v.UUID]; ok {
				vm.MemBytes = m
			} else if m, ok := v.MemTarget.nonNeg(); ok && m < 1<<50 {
				vm.MemBytes = m
			}
		}
		x.VMs = append(x.VMs, vm)
	}
	for _, ref := range sortedKeys(raw.SRs) {
		r := raw.SRs[ref]
		name := clean(r.Name)
		if name == "" {
			name = clean(r.UUID)
		}
		typ := lower(r.Type)
		if name == "" || seen["s"+name] {
			continue
		}
		seen["s"+name] = true
		sr := snmp.XAPISR{Name: name, Type: typ, Shared: r.Shared}
		size, ok1 := r.Size.nonNeg()
		used, ok2 := r.Used.nonNeg()
		media := typ == "iso" || typ == "udev" || lower(r.ContentType) == "iso"
		if ok1 && ok2 && size > 0 && used <= size && !media {
			sr.Total, sr.Used = size, used
			snap.Disks = append(snap.Disks, snmp.Disk{Mount: "SR " + name, FSType: "sr", TotalBytes: size, FreeBytes: size - used})
		}
		if !contains(raw.Partial, "Anbindung") {
			for _, p := range r.PBDs {
				on, known := raw.Attached[p]
				if !known || on {
					continue
				}
				// Host des PBD: aus host.PBDs
				for href, h := range raw.Hosts {
					if containsRef(h.PBDs, p) && hostNames[href] != "" && !contains(sr.Detached, hostNames[href]) {
						sr.Detached = append(sr.Detached, hostNames[href])
					}
				}
			}
			sort.Strings(sr.Detached)
			if len(sr.Detached) > 20 {
				sr.Detached = sr.Detached[:20]
			}
		}
		x.SRs = append(x.SRs, sr)
		if len(x.SRs) >= MaxSRs {
			break
		}
	}
	sort.Slice(x.Hosts, func(i, j int) bool { return x.Hosts[i].Name < x.Hosts[j].Name })
	sort.Slice(x.VMs, func(i, j int) bool {
		if x.VMs[i].Name != x.VMs[j].Name {
			return x.VMs[i].Name < x.VMs[j].Name
		}
		return x.VMs[i].UUID < x.VMs[j].UUID
	})
	sort.Slice(x.SRs, func(i, j int) bool { return x.SRs[i].Name < x.SRs[j].Name })
	sort.Slice(snap.Disks, func(i, j int) bool { return snap.Disks[i].Mount < snap.Disks[j].Mount })
	if cpuN > 0 {
		snap.CPU = &snmp.CPU{Cores: cpuN, Percent: cpuSum / float64(cpuN)}
	}
	if memTotal > 0 {
		snap.Memory = &snmp.Memory{TotalBytes: memTotal, AvailableBytes: memFree}
	}
	snap.XAPI = x
	snap.System.UptimeS = masterUptime
	snap.System.Name = x.Pool
	if snap.System.Name == "" {
		snap.System.Name = x.Master
	}
	prod := x.Product
	if prod == "" {
		prod = "XenServer"
	}
	snap.System.Descr = cleanN(fmt.Sprintf("%s, Pool %s (%d Hosts, %d VMs, %d Storage-Repositories)", prod, x.Pool,
		len(x.Hosts), x.VMCount.Running+x.VMCount.Halted+x.VMCount.Paused+x.VMCount.Suspended, len(x.SRs)), 255)
	return snap
}

// lower: Typen nur aus Kleinbuchstaben, Ziffern, _ und - (sonst leer).
func lower(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 40 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
		return ""
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsRef(list []string, s string) bool { return contains(list, s) }

// Rebooted: Ein Host läuft kürzer als bei der letzten Abfrage und lief
// vorher lange genug (snmp.MinUptimeForReboot).
func Rebooted(prev, cur *snmp.XAPI) bool {
	if prev == nil || cur == nil {
		return false
	}
	before := map[string]uint64{}
	for _, h := range prev.Hosts {
		before[h.Name] = h.UptimeS
	}
	for _, h := range cur.Hosts {
		if b, ok := before[h.Name]; ok && snmp.RebootCounts(b) && h.UptimeS > 0 && h.UptimeS+60 < b {
			return true
		}
	}
	return false
}
