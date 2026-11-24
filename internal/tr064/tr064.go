// SPDX-License-Identifier: AGPL-3.0-only

// Package tr064 liest eine FRITZ!Box über TR-064 (SOAP mit Digest-Anmeldung),
// ausschließlich lesend.
//
// Die Zentrale ruft nur Aktionen aus einer festen Liste auf (allowed), alle
// ohne Argumente und alle nur lesend. Die Beschreibung der Box
// (/tr64desc.xml) liefert nur die Steuer-Adressen dieser Dienste; Dienste
// außerhalb der Liste werden nicht übernommen.
//
// TR-064 kennt kein reines Leserecht (AVM, „TR-064 First Steps“, 6.1): Fast
// alle Werte brauchen das Recht „FRITZ!Box Einstellungen“ (C). Das ist
// bewusst so entschieden (21.11.2026). Das Konto auf der Zentrale darf damit
// mehr als lesen; Schutz geben die Liste unten, die Verschlüsselung des
// Passworts und dass nur Admins es pflegen.
//
// Verbindungen laufen über den Guard der Checks (-check-netze). Über HTTPS
// (Port 49443) prüft die Zentrale das selbstsignierte Zertifikat der Box
// gegen einen festen Fingerabdruck (SHA-256), den der Admin bestätigt hat.
//
// Alles, was die Box liefert, ist nicht vertrauenswürdig: Antworten sind in
// der Größe begrenzt, Texte gekürzt, Zahlen geprüft.
package tr064

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Standard-Ports der FRITZ!Box.
const (
	PortHTTP  = 49000
	PortHTTPS = 49443
)

// Grenzen.
const (
	MaxText     = 200
	maxDesc     = 1 << 20
	maxResponse = 64 << 10
	maxValues   = 64
)

// Config beschreibt, wie eine Box abgefragt wird.
type Config struct {
	Host     string // Hostname oder IP-Adresse
	Port     uint16 // 0 = 49000 bzw. 49443 mit TLS
	User     string
	Password string
	// Pin: SHA-256 des Zertifikats der Box (hex, klein); gesetzt = HTTPS
	Pin string
}

func (cfg Config) port() uint16 {
	if cfg.Port != 0 {
		return cfg.Port
	}
	if cfg.Pin != "" {
		return PortHTTPS
	}
	return PortHTTP
}

var (
	userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)
	pinPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidUser: Benutzername eines FRITZ!Box-Kontos (Buchstaben, Ziffern, . _ @ -).
func ValidUser(s string) bool { return userPattern.MatchString(s) }

// ValidPassword: 1 bis 128 Zeichen ohne Steuerzeichen.
func ValidPassword(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= 128 && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// ValidPin: SHA-256 als 64 Hexziffern (klein).
func ValidPin(s string) bool { return pinPattern.MatchString(s) }

// NormalizePin nimmt einen Fingerabdruck mit oder ohne Doppelpunkte und in
// beliebiger Schreibweise an und gibt ihn als 64 kleine Hexziffern zurück.
func NormalizePin(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	return s, ValidPin(s)
}

// FormatPin: AB:CD:… zum Anzeigen.
func FormatPin(pin string) string {
	h := strings.ToUpper(pin)
	var sb strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// Dialer verbindet nur zu freigegebenen Adressen (checks.Guard).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Client fragt FRITZ!Boxen ab.
type Client struct {
	Guard   Dialer
	Timeout time.Duration // je Anfrage, Standard 10 s
	Budget  time.Duration // ganze Abfrage, Standard 40 s
	Now     func() time.Time
	// UserAgent, z. B. openwacht/1.2.3
	UserAgent string
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) budget() time.Duration {
	if c.Budget > 0 {
		return c.Budget
	}
	return 40 * time.Second
}

// Fehler, die die Oberfläche verständlich anzeigen soll.
var (
	ErrAuth     = errors.New("Anmeldung abgelehnt (401): Benutzer und Passwort prüfen")
	ErrNoTR064  = errors.New("keine TR-064-Beschreibung: Ist „Zugriff für Anwendungen zulassen“ (Heimnetz → Netzwerk → Netzwerkeinstellungen) an, und stimmt der Port?")
	ErrTooMuch  = errors.New("die FRITZ!Box liefert mehr Daten als erlaubt")
	ErrNoRights = errors.New("Rechte fehlen (606): Das Konto braucht das Recht „FRITZ!Box Einstellungen“")
)

// PinError: Das Zertifikat der Box passt nicht zum hinterlegten Fingerabdruck.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	return "TLS: Zertifikat der FRITZ!Box passt nicht zum hinterlegten Fingerabdruck (jetzt " + FormatPin(e.Got) + ")"
}

// ActionError: Die Box hat eine Aktion mit einem UPnP-Fehler abgelehnt.
type ActionError struct {
	Action string
	Code   int
}

func (e *ActionError) Error() string {
	switch e.Code {
	case 606:
		return e.Action + ": Recht fehlt (606)"
	case 401:
		return e.Action + ": Aktion unbekannt (401)"
	}
	return fmt.Sprintf("%s: Fehler %d", e.Action, e.Code)
}

// Unauthorized: Recht fehlt (606) oder Aktion unbekannt (401). Dann fehlt
// nur dieser Teil, die Abfrage läuft weiter.
func (e *ActionError) Unauthorized() bool { return e.Code == 606 || e.Code == 401 }

// Dienste und Aktionen, die die Zentrale aufrufen darf. Alles lesend, ohne
// Argumente. Neues hier nur nach Prüfung in der AVM-Dokumentation.
const (
	svcDeviceInfo = "urn:dslforum-org:service:DeviceInfo:1"
	svcCommon     = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"
	svcPPP        = "urn:dslforum-org:service:WANPPPConnection:1"
	svcIP         = "urn:dslforum-org:service:WANIPConnection:1"
	svcDSL        = "urn:dslforum-org:service:WANDSLInterfaceConfig:1"
)

var allowed = map[string][]string{
	svcDeviceInfo: {"GetInfo"},
	svcCommon:     {"GetCommonLinkProperties", "GetTotalBytesSent", "GetTotalBytesReceived", "GetAddonInfos"},
	svcPPP:        {"GetStatusInfo", "GetExternalIPAddress"},
	svcIP:         {"GetStatusInfo", "GetExternalIPAddress"},
	svcDSL:        {"GetInfo"},
}

// Allowed meldet, ob eine Aktion auf der Liste steht (für Tests).
func Allowed(service, action string) bool {
	for _, a := range allowed[service] {
		if a == action {
			return true
		}
	}
	return false
}

var controlPattern = regexp.MustCompile(`^/upnp/control/[A-Za-z0-9_]{1,40}$`)

type session struct {
	c      *Client
	http   *http.Client
	base   string
	cfg    Config
	closer func()
	// Steuer-Adressen aus der Beschreibung (nur erlaubte Dienste)
	control map[string]string
	// Digest-Zustand der Box (realm, nonce, …), unter mu
	mu     sync.Mutex
	chal   *challenge
	nc     int
	seenFP string // Fingerabdruck des Zertifikats (HTTPS)
}

func (c *Client) open(cfg Config) (*session, error) {
	if !ValidUser(cfg.User) || !ValidPassword(cfg.Password) {
		return nil, errors.New("Benutzer oder Passwort ungültig")
	}
	if cfg.Pin != "" && !ValidPin(cfg.Pin) {
		return nil, errors.New("Fingerabdruck ungültig")
	}
	return c.session(cfg, false)
}

// session baut die Verbindung. anyCert: nur für Fingerprint, dann wird kein
// Passwort gesendet.
func (c *Client) session(cfg Config, anyCert bool) (*session, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s := &session{c: c, cfg: cfg}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostOnly(cfg.Host)}
	// Die Box hat ein selbstsigniertes Zertifikat: Statt der Kette zählt der
	// Fingerabdruck. InsecureSkipVerify schaltet nur die Standardprüfung ab;
	// VerifyConnection ersetzt sie und bricht ab, wenn er nicht passt.
	tcfg.InsecureSkipVerify = true
	tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &PinError{}
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		got := hex.EncodeToString(sum[:])
		s.mu.Lock()
		s.seenFP = got
		s.mu.Unlock()
		if anyCert {
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.Pin)) != 1 {
			return &PinError{Got: got}
		}
		return nil
	}
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            c.Guard.DialContext,
		TLSClientConfig:        tcfg,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 32 << 10,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
	}
	s.http = &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Weiterleitungen nie folgen: Das Ziel läge womöglich außerhalb der Freigabe.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	scheme := "http"
	if cfg.Pin != "" || anyCert {
		scheme = "https"
	}
	s.base = scheme + "://" + net.JoinHostPort(hostOnly(cfg.Host), strconv.Itoa(int(cfg.port())))
	s.closer = tr.CloseIdleConnections
	return s, nil
}

func hostOnly(h string) string { return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]") }

// Fingerprint verbindet per TLS und liefert den Fingerabdruck des
// Zertifikats, ohne sich anzumelden (für „Verbindung prüfen“: Der Admin
// bestätigt ihn einmal, danach gilt nur noch dieser).
func (c *Client) Fingerprint(ctx context.Context, host string, port uint16) (string, error) {
	if port == 0 {
		port = PortHTTPS
	}
	s, err := c.session(Config{Host: host, Port: port}, true)
	if err != nil {
		return "", err
	}
	defer s.closer()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/tr64desc.xml", nil)
	if err != nil {
		return "", errors.New("Adresse ungültig")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return "", describe(err, port)
	}
	resp.Body.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenFP == "" {
		return "", errors.New("kein Zertifikat erhalten (HTTPS an diesem Port?)")
	}
	return s.seenFP, nil
}

// --- Beschreibung ---------------------------------------------------------------

type descService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// describeBox liest /tr64desc.xml und merkt sich die Steuer-Adressen der
// erlaubten Dienste.
func (s *session) describeBox(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/tr64desc.xml", nil)
	if err != nil {
		return errors.New("Adresse ungültig")
	}
	s.header(req)
	resp, err := s.http.Do(req)
	if err != nil {
		return describe(err, s.cfg.port())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrNoTR064
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDesc+1))
	if err != nil {
		return describe(err, s.cfg.port())
	}
	if len(body) > maxDesc {
		return ErrTooMuch
	}
	s.control = map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	n := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrNoTR064
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "service" {
			n++
			if n > 200 {
				return ErrTooMuch
			}
			var d descService
			if err := dec.DecodeElement(&d, &se); err != nil {
				return ErrNoTR064
			}
			st, cu := strings.TrimSpace(d.ServiceType), strings.TrimSpace(d.ControlURL)
			if _, ok := allowed[st]; ok && controlPattern.MatchString(cu) {
				if _, dup := s.control[st]; !dup {
					s.control[st] = cu
				}
			}
		}
	}
	if s.control[svcDeviceInfo] == "" {
		return ErrNoTR064
	}
	return nil
}

func (s *session) has(service string) bool { return s.control[service] != "" }

func (s *session) header(req *http.Request) {
	if s.c.UserAgent != "" {
		req.Header.Set("User-Agent", s.c.UserAgent)
	}
}

// --- SOAP -----------------------------------------------------------------------

// call ruft eine erlaubte Aktion ohne Argumente auf und liefert die Werte der
// Antwort (Name ohne „New“ → Text).
func (s *session) call(ctx context.Context, service, action string) (map[string]string, error) {
	if !Allowed(service, action) {
		return nil, fmt.Errorf("Aktion %s nicht erlaubt", action) // Programmierfehler
	}
	path := s.control[service]
	if path == "" {
		return nil, &ActionError{Action: action, Code: 401}
	}
	parts := strings.Split(service, ":")
	short := parts[len(parts)-2]
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + service + `"/></s:Body></s:Envelope>`
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+path, strings.NewReader(body))
		if err != nil {
			return nil, errors.New("Adresse ungültig")
		}
		s.header(req)
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		req.Header.Set("SoapAction", service+"#"+action)
		if auth := s.authorization(http.MethodPost, path); auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			return nil, describe(err, s.cfg.port())
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
		resp.Body.Close()
		if err != nil {
			return nil, describe(err, s.cfg.port())
		}
		if len(raw) > maxResponse {
			return nil, ErrTooMuch
		}
		if resp.StatusCode == http.StatusUnauthorized {
			ch, ok := parseChallenge(resp.Header.Values("WWW-Authenticate"))
			if !ok {
				return nil, errors.New("Anmeldung: unbekanntes Verfahren (nur Digest mit MD5 oder SHA-256)")
			}
			s.mu.Lock()
			had := s.chal != nil
			stale := ch.stale
			s.chal, s.nc = &ch, 0
			s.mu.Unlock()
			// Erster Versuch ohne Anmeldung oder neuer Nonce: noch einmal.
			// Wurde mit gültigem Nonce abgelehnt, stimmt das Passwort nicht.
			if attempt == 0 || (attempt == 1 && stale && had) {
				continue
			}
			return nil, ErrAuth
		}
		vals, fault, err := parseResponse(raw, action)
		if fault != 0 {
			return nil, &ActionError{Action: short + "." + action, Code: fault}
		}
		if err != nil {
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("HTTP %d bei %s", resp.StatusCode, action)
			}
			return nil, err
		}
		return vals, nil
	}
}

// parseResponse liest <ActionResponse> bzw. einen UPnP-Fehler.
func parseResponse(raw []byte, action string) (map[string]string, int, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	var stack []string
	vals := map[string]string{}
	inResp, inCode := false, false
	fault := 0
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fault, errors.New("Antwort ist keine TR-064-Antwort")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if len(stack) > 8 {
				return nil, 0, ErrTooMuch
			}
			switch {
			case t.Name.Local == action+"Response" && len(stack) == 3:
				inResp = true
			case t.Name.Local == "errorCode":
				inCode = true
			}
			text.Reset()
		case xml.CharData:
			if text.Len() < 4096 {
				text.Write(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, 0, errors.New("Antwort ist keine TR-064-Antwort")
			}
			name := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch {
			case inCode && name == "errorCode":
				inCode = false
				if n, err := strconv.Atoi(strings.TrimSpace(text.String())); err == nil && n > 0 && n < 10000 {
					fault = n
				} else {
					fault = 9999
				}
			case inResp && len(stack) == 3:
				if len(vals) >= maxValues {
					return nil, 0, ErrTooMuch
				}
				vals[strings.TrimPrefix(name, "New")] = text.String()
			case inResp && len(stack) == 2:
				inResp = false
			}
			text.Reset()
		}
	}
	if fault != 0 {
		return nil, fault, nil
	}
	if len(vals) == 0 && !bytes.Contains(raw, []byte(action+"Response")) {
		return nil, 0, errors.New("Antwort ist keine TR-064-Antwort")
	}
	return vals, 0, nil
}

// --- Digest (RFC 7616) ----------------------------------------------------------

type challenge struct {
	realm, nonce, opaque, algorithm string
	qopAuth, stale                  bool
}

func parseChallenge(headers []string) (challenge, bool) {
	var best challenge
	found := false
	for _, h := range headers {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
		if !strings.EqualFold(scheme, "Digest") {
			continue
		}
		p := parseParams(rest)
		ch := challenge{realm: p["realm"], nonce: p["nonce"], opaque: p["opaque"], algorithm: strings.ToUpper(p["algorithm"])}
		if ch.algorithm == "" {
			ch.algorithm = "MD5"
		}
		if ch.algorithm != "MD5" && ch.algorithm != "SHA-256" {
			continue
		}
		if ch.nonce == "" || len(ch.nonce) > 200 || len(ch.realm) > 200 || len(ch.opaque) > 200 ||
			strings.ContainsAny(ch.nonce+ch.realm+ch.opaque, "\"\\\r\n") {
			continue
		}
		for _, q := range strings.Split(p["qop"], ",") {
			if strings.TrimSpace(q) == "auth" {
				ch.qopAuth = true
			}
		}
		ch.stale = strings.EqualFold(p["stale"], "true")
		// SHA-256 vor MD5, wenn die Box beides anbietet
		if !found || ch.algorithm == "SHA-256" {
			best, found = ch, true
		}
	}
	return best, found
}

// parseParams: key=value, key="value", … (Werte ohne Anführungszeichen).
func parseParams(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 && len(out) < 20 {
		s = strings.TrimLeft(s, " ,\t")
		k, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		var v string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				break
			}
			v, s = rest[1:end+1], rest[end+2:]
		} else {
			v, s, _ = strings.Cut(rest, ",")
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

func (s *session) authorization(method, uri string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.chal
	if ch == nil {
		return ""
	}
	s.nc++
	var h func() hash.Hash = md5.New //nolint:gosec // vom Protokoll vorgegeben (TR-064, RFC 7616)
	if ch.algorithm == "SHA-256" {
		h = sha256.New
	}
	sum := func(parts ...string) string {
		x := h()
		io.WriteString(x, strings.Join(parts, ":"))
		return hex.EncodeToString(x.Sum(nil))
	}
	ha1 := sum(s.cfg.User, ch.realm, s.cfg.Password)
	ha2 := sum(method, uri)
	var b strings.Builder
	fmt.Fprintf(&b, `Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s`,
		s.cfg.User, ch.realm, ch.nonce, uri, ch.algorithm)
	if ch.qopAuth {
		cb := make([]byte, 12)
		_, _ = rand.Read(cb)
		cnonce := hex.EncodeToString(cb)
		nc := fmt.Sprintf("%08x", s.nc)
		fmt.Fprintf(&b, `, qop=auth, nc=%s, cnonce="%s", response="%s"`, nc, cnonce, sum(ha1, ch.nonce, nc, cnonce, "auth", ha2))
	} else {
		fmt.Fprintf(&b, `, response="%s"`, sum(ha1, ch.nonce, ha2))
	}
	if ch.opaque != "" {
		fmt.Fprintf(&b, `, opaque="%s"`, ch.opaque)
	}
	return b.String()
}

// --- Fehler und Texte -------------------------------------------------------------

func describe(err error, port uint16) error {
	var pe *PinError
	if errors.As(err, &pe) {
		return pe
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return errors.New("keine Antwort (Zeitüberschreitung)")
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" && strings.Contains(oe.Err.Error(), "refused") {
		return fmt.Errorf("Verbindung abgelehnt (Port %d; TR-064 an der FRITZ!Box aktiviert?)", port)
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return errors.New("TLS: Die Gegenstelle spricht kein HTTPS (Port 49000 ist HTTP, 49443 HTTPS)")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// clean: gültiges UTF-8 ohne Steuerzeichen, höchstens n Zeichen.
func clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r) || r == ' ' || r == ' ':
			return ' '
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		r := []rune(s)
		s = string(r[:n-1]) + "…"
	}
	return s
}
