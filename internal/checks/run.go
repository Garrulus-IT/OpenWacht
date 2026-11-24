// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // Europe/Berlin auch ohne Zeitzonendaten im System
	"unicode/utf8"

	"github.com/garrulus-it/openwacht/internal/safe"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Status eines Checks, Reihenfolge nach Schwere.
const (
	OK      = "ok"
	Warn    = "warn"
	Crit    = "crit"
	Unknown = "unknown"
)

// Result: Message ist stabil formuliert (ändert sich nur, wenn sich etwas
// ändert), Metric ist flüchtig (z. B. Antwortzeit) und für Menschen
// formatiert. Latency ist die gemessene Antwortzeit für den Verlauf,
// 0 = keine Messung.
type Result struct {
	Status  string
	Message string
	Metric  string
	Latency time.Duration
}

var berlin = func() *time.Location {
	l, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		return time.UTC
	}
	return l
}()

// Runner führt Checks aus.
type Runner struct {
	Guard *Guard
	Now   func() time.Time
	// DNSPort: Port eigener DNS-Server, leer = 53 (in Tests ersetzbar)
	DNSPort string
}

// Run führt einen Check aus. Er bricht nie ab: Jeder Fehler wird zu einem
// Ergebnis, auch ein Programmfehler.
func (r *Runner) Run(ctx context.Context, kind string, s Spec) (res Result) {
	defer func() {
		if p := recover(); safe.Handle("check", p) {
			res = Result{Unknown, "interner Fehler im Sensor", "", 0}
		}
	}()
	timeout := time.Duration(s.TimeoutSec) * time.Second
	switch kind {
	case "ping":
		return pingCheck(ctx, r.Guard, s, timeout)
	case "dns":
		return r.dns(ctx, s, timeout)
	case "http_json":
		return r.httpJSON(ctx, s, timeout)
	case "tcp_banner":
		return r.tcpBanner(ctx, s, timeout)
	case "ntp":
		return r.ntp(ctx, s, timeout)
	case "tcp":
		return r.tcp(ctx, s, timeout)
	case "http":
		return r.http(ctx, s, timeout)
	case "tls":
		return r.tls(ctx, s, timeout)
	}
	if IsAgentKind(kind) {
		return Result{Unknown, "Sensor läuft auf dem Agent, nicht auf der Zentrale", "", 0}
	}
	if IsSNMPKind(kind) {
		return Result{Unknown, "Wert kommt mit der SNMP-Abfrage des Geräts", "", 0}
	}
	return Result{Unknown, "unbekannter Typ " + clean(kind, 20), "", 0}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// clean: Fremdtext auf eine Zeile ohne Steuerzeichen und begrenzte Länge bringen.
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }), " ")
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit-1]) + "…"
	}
	return s
}

func secs(d time.Duration) string { return strings.TrimSuffix(fmt.Sprintf("%g", d.Seconds()), ".0") }

func ms(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) }

// describeNetErr übersetzt Verbindungsfehler in eine kurze Meldung. Ein
// gesperrtes Ziel ergibt „unbekannt“, kein „Fehler“: Das ist ein Problem
// der Einrichtung, nicht des Dienstes.
func describeNetErr(err error, timeout time.Duration, prefix string) Result {
	var na *NotAllowedError
	var dns *net.DNSError
	var ne net.Error
	switch {
	case errors.As(err, &na):
		return Result{Unknown, na.Error() + " (Netzfreigabe unter Einstellungen bzw. -check-netze)", "", 0}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return Result{Crit, prefix + "Zeitüberschreitung nach " + secs(timeout) + " s", "", 0}
	case errors.As(err, &dns):
		return Result{Crit, prefix + "Name " + clean(dns.Name, 100) + " nicht auflösbar", "", 0}
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		msg := op.Err.Error()
		// „connect: connection refused“ → „connection refused“
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}
		return Result{Crit, prefix + germanErrno(msg), "", 0}
	}
	return Result{Crit, prefix + "nicht erreichbar: " + clean(err.Error(), 150), "", 0}
}

func germanErrno(msg string) string {
	switch msg {
	case "connection refused":
		return "Verbindung abgelehnt"
	case "no route to host":
		return "keine Route zum Host"
	case "network is unreachable":
		return "Netz nicht erreichbar"
	case "connection reset by peer":
		return "Verbindung zurückgesetzt"
	case "host is down":
		return "Host nicht erreichbar"
	}
	return "nicht erreichbar: " + clean(msg, 150)
}

// --- TCP ---------------------------------------------------------------------

func (r *Runner) tcp(ctx context.Context, s Spec, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	c, err := r.Guard.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, fmt.Sprint(s.Port)))
	if err != nil {
		return describeNetErr(err, timeout, fmt.Sprintf("Port %d: ", s.Port))
	}
	c.Close()
	took := time.Since(start)
	return Result{OK, fmt.Sprintf("Port %d offen", s.Port), ms(took), took}
}

// --- HTTP --------------------------------------------------------------------

const maxBody = 256 << 10

// fetch holt url per GET über den Guard, ohne Proxy und ohne Weiterleitungen.
// Den Inhalt liest es nur, wenn body gesetzt ist (höchstens maxBody).
func (r *Runner) fetch(ctx context.Context, s Spec, timeout time.Duration, body bool) (int, []byte, time.Duration, *Result) {
	roots, err := s.roots()
	if err != nil {
		return 0, nil, 0, &Result{Unknown, clean(err.Error(), 150), "", 0}
	}
	tr := &http.Transport{
		Proxy:                  nil, // nie über einen Proxy aus der Umgebung
		DialContext:            r.Guard.DialContext,
		TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Weiterleitungen nicht folgen: 3xx wird selbst bewertet, und das
		// Ziel einer Weiterleitung könnte außerhalb der Freigabe liegen.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return 0, nil, 0, &Result{Unknown, "URL ungültig", "", 0}
	}
	req.Header.Set("User-Agent", "openwacht/"+version.Version)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return 0, nil, 0, &Result{Crit, "TLS: " + explainVerify(cv), "", 0}
		}
		res := describeNetErr(err, timeout, "")
		return 0, nil, 0, &res
	}
	defer resp.Body.Close()
	var data []byte
	if body {
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			res := describeNetErr(err, timeout, "Antwort unvollständig: ")
			return 0, nil, 0, &res
		}
	}
	return resp.StatusCode, data, time.Since(start), nil
}

func statusOK(s Spec, code int) bool {
	if len(s.ExpectStatus) > 0 {
		return slices.Contains(s.ExpectStatus, code)
	}
	return code >= 200 && code < 400
}

func (r *Runner) http(ctx context.Context, s Spec, timeout time.Duration) Result {
	code, body, took, fail := r.fetch(ctx, s, timeout, s.Contains != "")
	if fail != nil {
		return *fail
	}
	elapsed := ms(took)
	if !statusOK(s, code) {
		return Result{Crit, fmt.Sprintf("HTTP %d (unerwartet)", code), elapsed, took}
	}
	// Vom Inhalt wird nur gemeldet, ob der Text vorkommt, nie der Inhalt selbst.
	if s.Contains != "" && !bytes.Contains(body, []byte(s.Contains)) {
		return Result{Crit, fmt.Sprintf("HTTP %d, erwarteter Text fehlt", code), elapsed, took}
	}
	return Result{OK, fmt.Sprintf("HTTP %d", code), elapsed, took}
}

// --- TLS-Zertifikat ----------------------------------------------------------

func explainVerify(cv *tls.CertificateVerificationError) string {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(cv.Err, &he):
		if strings.Contains(he.Host, ":") || net.ParseIP(he.Host) != nil {
			return "IP passt nicht zum Zertifikat"
		}
		return "Name passt nicht zum Zertifikat"
	case errors.As(cv.Err, &ci) && ci.Reason == x509.Expired:
		return "Zertifikat abgelaufen oder noch nicht gültig"
	case errors.As(cv.Err, &ua):
		if len(cv.UnverifiedCertificates) > 0 {
			leaf := cv.UnverifiedCertificates[0]
			if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
				return "selbstsigniertes Zertifikat"
			}
		}
		return "Kette unvollständig oder unbekannte CA (fehlt das Zwischenzertifikat?)"
	}
	return clean(cv.Err.Error(), 150)
}

// remaining: bewusst grob, damit sich die Meldung nicht bei jedem Lauf ändert.
func remaining(d time.Duration) string {
	days := d.Hours() / 24
	switch {
	case days >= 2:
		return fmt.Sprintf("%d Tage", int(days))
	case days >= 1:
		return "1 Tag"
	}
	return "weniger als 1 Tag"
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return ""
}

func (r *Runner) handshake(ctx context.Context, addr string, cfg *tls.Config) (*tls.ConnectionState, error) {
	conn, err := r.Guard.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	return &st, nil
}

func (r *Runner) tls(ctx context.Context, s Spec, timeout time.Duration) Result {
	roots, err := s.roots()
	if err != nil {
		return Result{Unknown, clean(err.Error(), 150), "", 0}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := s.Host
	if s.Connect != "" {
		target = s.Connect // direkt an diese Adresse, Name per SNI (z. B. vorbei am NAT-Loopback)
	}
	addr := net.JoinHostPort(target, fmt.Sprint(s.Port))
	var leaf *x509.Certificate
	problem := ""
	st, err := r.handshake(ctx, addr, &tls.Config{ServerName: s.Host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		var cv *tls.CertificateVerificationError
		if !errors.As(err, &cv) {
			var na *NotAllowedError
			var ne net.Error
			var op *net.OpError
			if errors.As(err, &na) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() || errors.As(err, &op) {
				return describeNetErr(err, timeout, "")
			}
			return Result{Crit, "TLS-Handshake fehlgeschlagen: " + clean(err.Error(), 150), "", 0}
		}
		problem = explainVerify(cv)
		if len(cv.UnverifiedCertificates) > 0 {
			leaf = cv.UnverifiedCertificates[0]
		}
	} else if len(st.PeerCertificates) > 0 {
		leaf = st.PeerCertificates[0]
	}
	if leaf == nil {
		if problem == "" {
			problem = "Zertifikat nicht lesbar"
		}
		return Result{Crit, problem, "", 0}
	}
	left := leaf.NotAfter.Sub(r.now())
	until := leaf.NotAfter.In(berlin).Format("02.01.2006")
	by := ""
	if n := issuerName(leaf); n != "" {
		by = ", Aussteller " + clean(n, 60)
	}
	warnAt := time.Duration(s.WarnDays * float64(24*time.Hour))
	critAt := time.Duration(s.CritDays * float64(24*time.Hour))
	switch {
	case left <= 0:
		return Result{Crit, "abgelaufen am " + until + by, "", 0}
	case problem != "":
		return Result{Crit, problem + "; gültig bis " + until + by, "", 0}
	case left < critAt:
		return Result{Crit, "läuft in " + remaining(left) + " ab (" + until + ")" + by, "", 0}
	case left < warnAt:
		return Result{Warn, "läuft in " + remaining(left) + " ab (" + until + ")" + by, "", 0}
	}
	return Result{OK, "gültig bis " + until + " (noch " + remaining(left) + ")" + by, "", 0}
}
