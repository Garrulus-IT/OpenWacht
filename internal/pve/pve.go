// SPDX-License-Identifier: AGPL-3.0-only

// Package pve liest die API von Proxmox VE, ausschließlich lesend.
//
// Die Zentrale schickt nur GET-Anfragen mit einem API-Token, das auf dem
// Proxmox-Host die Rolle PVEAuditor hat. Hat das Token mehr Rechte, meldet
// die Abfrage das als Hinweis (zu_viele_rechte), benutzt sie aber nicht.
//
// Verbindungen laufen über den Guard der Checks (-check-netze). Das
// selbstsignierte Zertifikat von Proxmox wird gegen die hinterlegte CA des
// Hosts (/etc/pve/pve-root-ca.pem) geprüft. Den Namen im Zertifikat
// vergleicht die Zentrale dann nicht: Proxmox trägt dort oft nur interne
// Namen ein, und den Schutz gibt die CA, deren Schlüssel nur dieser Host hat.
// Ohne CA gelten die System-CAs mit vollständiger Prüfung (z. B. ACME).
//
// Alles, was der Host liefert, ist nicht vertrauenswürdig: Antworten sind in
// der Größe begrenzt, Texte gekürzt, Listen begrenzt, Zahlen geprüft.
package pve

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Grenzen.
const (
	MaxGuests    = 500
	MaxStorages  = 64
	MaxThinPools = 32
	MaxText      = 200
	maxBody      = 4 << 20
	// MaxCAPEM: Größe des eingefügten CA-Zertifikats
	MaxCAPEM = 16 << 10
	// maxLogLines: Zeilen eines vzdump-Protokolls, die gelesen werden
	maxLogLines = 5000
	// maxTasksPerPoll: so viele neue vzdump-Aufgaben wertet eine Abfrage aus,
	// der Rest folgt bei der nächsten
	maxTasksPerPoll = 30
	// maxConfigsPerPoll: so viele Gast-Konfigurationen (beim Booten starten)
	// liest eine Abfrage höchstens neu
	maxConfigsPerPoll = 40
	// TaskWindow: so weit zurück sucht die erste Abfrage nach Backups
	TaskWindow = 8 * 24 * time.Hour
	// configEvery: so oft wird „beim Booten starten“ je Gast neu gelesen
	configEvery = 10 * time.Minute
)

// Config beschreibt, wie ein Host abgefragt wird.
type Config struct {
	Host  string // Hostname oder IP-Adresse
	Port  uint16 // Standard 8006
	Token string // USER@REALM!TOKENID=UUID
	// CAPEM: CA des Hosts (PEM); leer = System-CAs mit Namensprüfung
	CAPEM string
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z][A-Za-z0-9._-]{0,31}![A-Za-z][A-Za-z0-9._-]{0,63}=` +
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidToken: Form USER@REALM!TOKENID=UUID, wie Proxmox sie ausgibt.
func ValidToken(s string) bool { return tokenPattern.MatchString(s) }

// TokenID: der öffentliche Teil (USER@REALM!TOKENID) ohne Geheimnis.
func TokenID(s string) string {
	if i := strings.IndexByte(s, '='); i > 0 {
		return s[:i]
	}
	return ""
}

// CA: geprüftes CA-Zertifikat.
type CA struct {
	Pool        *x509.CertPool
	Fingerprint string // SHA-256 des ersten Zertifikats, hex mit Doppelpunkten
	Subject     string
	NotAfter    time.Time
}

// ParseCA prüft ein eingefügtes CA-Zertifikat: 1 bis 4 Zertifikate im
// PEM-Format, alle CA-Zertifikate. Fehlermeldungen sind für Menschen.
func ParseCA(s string) (*CA, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxCAPEM {
		return nil, errors.New("CA-Zertifikat zu groß (höchstens 16 KiB)")
	}
	rest := []byte(s)
	ca := &CA{Pool: x509.NewCertPool()}
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, errors.New("Bitte nur Zertifikate einfügen (BEGIN CERTIFICATE), keinen Schlüssel")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("CA-Zertifikat nicht lesbar")
		}
		if !c.IsCA {
			return nil, errors.New("Das ist kein CA-Zertifikat. Bitte den Inhalt von /etc/pve/pve-root-ca.pem einfügen, nicht pve-ssl.pem")
		}
		if n == 0 {
			sum := sha256.Sum256(c.Raw)
			ca.Fingerprint = fingerprint(sum[:])
			ca.Subject = clean(c.Subject.String(), MaxText)
			ca.NotAfter = c.NotAfter
		}
		ca.Pool.AddCert(c)
		n++
		if n > 4 {
			return nil, errors.New("Höchstens 4 Zertifikate")
		}
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("CA-Zertifikat: bitte den vollständigen Inhalt von /etc/pve/pve-root-ca.pem einfügen (-----BEGIN CERTIFICATE----- …)")
	}
	return ca, nil
}

func fingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
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

// Client fragt Proxmox-Hosts ab.
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

// Fehler, die die Oberfläche verständlich anzeigen soll.
var (
	ErrToken     = errors.New("Token abgelehnt (401): Token-ID und Geheimnis prüfen")
	ErrForbidden = errors.New("Rechte fehlen (403): das Token braucht die Rolle PVEAuditor auf /")
	ErrTooMuch   = errors.New("der Host liefert mehr Daten als erlaubt")
)

// TLSError: Das Zertifikat des Hosts passt nicht zur hinterlegten CA.
type TLSError struct{ Msg string }

func (e *TLSError) Error() string { return "TLS: " + e.Msg }

type session struct {
	c      *Client
	http   *http.Client
	base   string
	token  string
	closer func()
}

func (c *Client) open(cfg Config) (*session, error) {
	if !ValidToken(cfg.Token) {
		return nil, errors.New("Token ungültig")
	}
	if cfg.Port == 0 {
		cfg.Port = 8006
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostOnly(cfg.Host)}
	if strings.TrimSpace(cfg.CAPEM) != "" {
		ca, err := ParseCA(cfg.CAPEM)
		if err != nil {
			return nil, err
		}
		// Kette gegen die CA des Hosts prüfen, ohne Namensvergleich (siehe
		// Paketbeschreibung). InsecureSkipVerify schaltet nur die
		// Standardprüfung ab; VerifyConnection ersetzt sie und bricht ab,
		// wenn die Kette nicht zur CA führt.
		tcfg.InsecureSkipVerify = true
		tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyChain(cs.PeerCertificates, ca.Pool, c.now())
		}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            c.Guard.DialContext,
		TLSClientConfig:        tcfg,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      true,
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Weiterleitungen nie folgen: Das Ziel läge womöglich außerhalb der
		// Freigabe, und das Token ginge mit.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	base := "https://" + net.JoinHostPort(hostOnly(cfg.Host), strconv.Itoa(int(cfg.Port))) + "/api2/json"
	return &session{c: c, http: hc, base: base, token: cfg.Token, closer: tr.CloseIdleConnections}, nil
}

func hostOnly(h string) string { return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]") }

func verifyChain(certs []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	if len(certs) == 0 {
		return &TLSError{"kein Zertifikat erhalten"}
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err == nil {
		return nil
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) && ci.Reason == x509.Expired {
		return &TLSError{"Zertifikat des Hosts abgelaufen oder noch nicht gültig"}
	}
	return &TLSError{"Zertifikat des Hosts passt nicht zur hinterlegten CA (anderer Host oder andere CA?)"}
}

// get liest /api2/json<path> und entpackt {"data": …} nach out.
func (s *session) get(ctx context.Context, path string, q url.Values, out any) error {
	u := s.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("Adresse ungültig")
	}
	req.Header.Set("Authorization", "PVEAPIToken="+s.token)
	req.Header.Set("Accept", "application/json")
	if s.c.UserAgent != "" {
		req.Header.Set("User-Agent", s.c.UserAgent)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return describe(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrToken
	case resp.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("HTTP %d bei %s", resp.StatusCode, clean(path, 80))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return describe(err)
	}
	if len(body) > maxBody {
		return ErrTooMuch
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return errors.New("Antwort ist keine Proxmox-API (Adresse und Port prüfen)")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("Antwort von %s nicht lesbar", clean(path, 80))
	}
	return nil
}

func describe(err error) error {
	var te *TLSError
	if errors.As(err, &te) {
		return te
	}
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		var ua x509.UnknownAuthorityError
		var he x509.HostnameError
		switch {
		case errors.As(cv.Err, &ua):
			return &TLSError{"Zertifikat nicht vertrauenswürdig; bitte die CA des Hosts (/etc/pve/pve-root-ca.pem) hinterlegen"}
		case errors.As(cv.Err, &he):
			// Go prüft den Namen vor der CA. Unbekannte CA ist die häufigere
			// Ursache (selbstsigniertes Proxmox-Zertifikat) und zuerst zu beheben.
			if len(cv.UnverifiedCertificates) > 0 && !systemTrusted(cv.UnverifiedCertificates) {
				return &TLSError{"Zertifikat nicht vertrauenswürdig; bitte die CA des Hosts (/etc/pve/pve-root-ca.pem) hinterlegen"}
			}
			return &TLSError{"Name passt nicht zum Zertifikat"}
		}
		return &TLSError{clean(cv.Err.Error(), 150)}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return errors.New("keine Antwort (Zeitüberschreitung)")
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		if strings.Contains(oe.Err.Error(), "refused") {
			return errors.New("Verbindung abgelehnt (Port prüfen, Standard 8006)")
		}
	}
	// Freigabefehler des Guards und Ähnliches unverändert weiterreichen.
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func systemTrusted(certs []*x509.Certificate) bool {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Intermediates: inter})
	return err == nil
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
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			return ' '
		case unicode.Is(unicode.Cf, r): // z. B. Richtungswechsel (U+202E)
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > n {
		r := []rune(s)
		s = string(r[:n-1]) + "…"
	}
	return s
}

// flexInt nimmt Zahlen und Zahlen als Text an (Proxmox liefert beides).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < -1e18 || v > 1e18 {
		return errors.New("keine Zahl")
	}
	*f = flexInt(v)
	return nil
}

func (f flexInt) u64() uint64 {
	if f < 0 {
		return 0
	}
	return uint64(f)
}
