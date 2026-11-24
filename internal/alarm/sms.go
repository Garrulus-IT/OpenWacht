// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// SMS über ein brevis.one-Gateway (0.43.0).
//
// HTTP API laut Hersteller-Doku (docs.brevis.one, „HTTP API“, gelesen am
// 23.11.2026): https://<Gateway>/api.php mit username, password, to, text und
// optional mode (number, group, user, …), ring (Anruf statt SMS) und flash.
// Fehler kommen als HTTP-Status: 400 (Fehler bzw. „Parameter miss“), 401
// (Benutzer oder Passwort falsch), 403 (kein Recht auf die HTTP API), 408
// (Zeitüberschreitung). Eine Erfolgsantwort beschreibt die Doku nicht; wie die
// Zabbix-Vorlage des Herstellers zählt jeder 2xx-Status als Erfolg. Die Werte
// „true“ für ring und flash stammen ebenfalls aus der Zabbix-Vorlage.
//
// Sicherheit:
//   - Immer POST mit Formular, nie GET: Das Passwort steht so weder in einer
//     URL noch in den Zugriffsprotokollen des Gateways.
//   - Das Gateway hat ab Werk ein selbstsigniertes Zertifikat. Geprüft wird
//     deshalb ein fester Fingerabdruck (SHA-256 des Zertifikats), bevor ein
//     Byte der Anfrage hinausgeht.
//   - Die Adresse muss als Alarmziel freigegeben sein (wie ntfy und Webhooks),
//     geprüft beim Speichern und vor jedem Versand. Keine Weiterleitungen,
//     kein Proxy, Antworten werden höchstens 4 KiB weit gelesen.
//   - Fehlertexte enthalten nie Passwort oder Telefonnummer; Text vom Gateway
//     wird nicht übernommen, nur der Status ausgewertet.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
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
	"unicode"
	"unicode/utf8"
)

// SMSConfig: Zugang zu einem Gateway.
type SMSConfig struct {
	Gateway  string // https://host[:port], normalisiert
	User     string
	Password string
	Pin      string // SHA-256 des Zertifikats, 64 kleine Hexziffern
}

// SMS-Empfänger: eine Nummer oder eine Gruppe auf dem Gateway.
const (
	SMSModeNumber = "number"
	SMSModeGroup  = "group"
)

// SMSTarget: Empfänger eines Versands.
type SMSTarget struct {
	Mode string // SMSModeNumber oder SMSModeGroup
	To   string // Nummer (international, +49…) bzw. Gruppen-ID oder -name
}

// Grenzen.
const (
	MaxSMSLen       = 160 // Zeichen im GSM-7-Alphabet, also genau eine SMS
	MaxSMSReceivers = 20  // Benutzer je Kanal (jede SMS kostet)
	smsReadLimit    = 4096
	smsTimeout      = 20 * time.Second
)

var (
	smsGroupPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)
	mobilePattern   = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	pinPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NormalizeGateway prüft die Adresse eines Gateways und liefert sie als
// https://host[:port] (ohne Pfad; /api.php hängt der Client an). Nur https,
// weil Benutzer und Passwort mitgehen.
func NormalizeGateway(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 300 {
		return "", errors.New("Adresse fehlt oder ist zu lang")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.Hostname() == "" {
		return "", errors.New("keine gültige Adresse (Form https://sms-gateway.example)")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("keine Zugangsdaten, Parameter oder Anker in der Adresse")
	}
	if p := strings.TrimRight(u.Path, "/"); p != "" && p != "/api.php" {
		return "", errors.New("nur die Adresse des Gateways, ohne Pfad")
	}
	if strings.ToLower(u.Scheme) != "https" {
		return "", errors.New("nur https (Benutzer und Passwort gehen mit)")
	}
	if strings.ContainsFunc(u.Host, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return "", errors.New("Adresse mit Leer- oder Steuerzeichen")
	}
	return "https://" + canonicalHost("https", u.Host), nil
}

// SMSEndpoint: die URL der API zu einem normalisierten Gateway.
func SMSEndpoint(gateway string) string { return gateway + "/api.php" }

// ValidSMSUser: eigener API-Benutzer, nicht admin (Empfehlung des Herstellers).
func ValidSMSUser(u string) error {
	if u == "" || utf8.RuneCountInString(u) > 64 || !utf8.ValidString(u) ||
		strings.ContainsFunc(u, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return errors.New("Benutzer: 1 bis 64 Zeichen ohne Leer- und Steuerzeichen")
	}
	if strings.EqualFold(u, "admin") {
		return errors.New("bitte nicht „admin“, sondern einen eigenen Benutzer nur mit dem Recht „Zugriff auf die HTTP API“")
	}
	return nil
}

// ValidSMSPassword: 1 bis 128 Zeichen ohne Steuerzeichen.
func ValidSMSPassword(p string) bool {
	n := utf8.RuneCountInString(p)
	return n >= 1 && n <= 128 && utf8.ValidString(p) && !strings.ContainsFunc(p, unicode.IsControl)
}

// ValidSMSGroup: ID oder Name einer Gruppe auf dem Gateway.
func ValidSMSGroup(g string) bool { return smsGroupPattern.MatchString(g) }

// ValidPin: SHA-256 als 64 kleine Hexziffern.
func ValidPin(s string) bool { return pinPattern.MatchString(s) }

// NormalizePin nimmt einen Fingerabdruck mit oder ohne Doppelpunkte an.
func NormalizePin(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	return s, ValidPin(s)
}

// NormalizeMobile bringt eine Mobilnummer in die internationale Form
// +491701234567. Erlaubt sind Leerzeichen, Bindestriche, Schrägstriche und
// Klammern; 0049… wird zu +49…, eine nationale 0170… zu +49170… (Deutschland).
func NormalizeMobile(raw string) (string, bool) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '/', '(', ')', '.':
			return -1
		}
		return r
	}, strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(s, "00"):
		s = "+" + s[2:]
	case strings.HasPrefix(s, "0"):
		s = "+49" + s[1:]
	}
	return s, mobilePattern.MatchString(s)
}

// ValidMobile: Nummer in der Form, die NormalizeMobile liefert.
func ValidMobile(s string) bool { return mobilePattern.MatchString(s) }

// MaskMobile: „+49 … 67“ für Anzeigen.
func MaskMobile(s string) string {
	if len(s) < 6 {
		return "…"
	}
	return s[:3] + " … " + s[len(s)-2:]
}

// gatewayNumber: Form für den Parameter to (00491701234567, wie in der Doku).
func gatewayNumber(s string) string { return "00" + strings.TrimPrefix(s, "+") }

// SMSError: Fehler des Gateways (für Tests und Meldungen).
type SMSError struct {
	Status int
	Text   string
}

func (e *SMSError) Error() string { return e.Text }

// PinError: Das Zertifikat passt nicht zum gespeicherten Fingerabdruck.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	return "Zertifikat des Gateways passt nicht zum gespeicherten Fingerabdruck (Zertifikat erneuert? Fingerabdruck prüfen und neu übernehmen)"
}

// smsTLS prüft statt der Kette den Fingerabdruck. pin leer = jedes
// Zertifikat annehmen (nur für SMSFingerprint, ohne Anfrage).
func smsTLS(host, pin string, seen *string, mu *sync.Mutex) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		// InsecureSkipVerify schaltet nur die Standardprüfung ab; VerifyConnection
		// ersetzt sie und bricht ab, bevor die Anfrage mit dem Passwort hinausgeht.
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

// smsDialer: Verbindungsaufbau (in Tests ersetzbar).
var smsDialer = &net.Dialer{Timeout: 10 * time.Second}

func (s *Sender) smsAllowed(gateway string) error {
	n, err := NormalizeGateway(gateway)
	if err != nil || n != gateway || !s.Targets.AllowedURL(SMSEndpoint(n)) {
		return errors.New("Gateway ist nicht (mehr) als Alarmziel freigegeben")
	}
	return nil
}

func hostPort(gateway string) (host, addr string) {
	u, _ := url.Parse(gateway)
	host = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return host, net.JoinHostPort(host, port)
}

// SMSFingerprint verbindet per TLS und liefert den Fingerabdruck des
// Zertifikats, ohne eine Anfrage und ohne Zugangsdaten zu senden.
func (s *Sender) SMSFingerprint(ctx context.Context, gateway string) (string, error) {
	return s.smsHandshake(ctx, gateway, "")
}

// SMSReachable: Gateway erreichbar und Zertifikat unverändert (TLS-Handshake,
// keine Anfrage, keine Zugangsdaten).
func (s *Sender) SMSReachable(ctx context.Context, gateway, pin string) error {
	if !ValidPin(pin) {
		return errors.New("kein Fingerabdruck hinterlegt")
	}
	_, err := s.smsHandshake(ctx, gateway, pin)
	return err
}

func (s *Sender) smsHandshake(ctx context.Context, gateway, pin string) (string, error) {
	if err := s.smsAllowed(gateway); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, addr := hostPort(gateway)
	conn, err := smsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", netError(err)
	}
	defer conn.Close()
	var seen string
	var mu sync.Mutex
	tc := tls.Client(conn, smsTLS(host, pin, &seen, &mu))
	if err := tc.HandshakeContext(ctx); err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return "", pe
		}
		return "", fmt.Errorf("TLS-Verbindung fehlgeschlagen: %s", Clean(err.Error(), 160))
	}
	_ = tc.Close()
	mu.Lock()
	defer mu.Unlock()
	if seen == "" {
		return "", errors.New("kein Zertifikat erhalten (HTTPS an diesem Port?)")
	}
	return seen, nil
}

func netError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var pe *PinError
	if errors.As(err, &pe) {
		return pe
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Gateway nicht erreichbar (Zeitüberschreitung)")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("Gateway nicht erreichbar (Zeitüberschreitung)")
	}
	return fmt.Errorf("Gateway nicht erreichbar: %s", Clean(err.Error(), 160))
}

// SendSMS schickt text an t. ring: zusätzlich zur SMS einen Anruf auslösen
// (eigene Anfrage mit ring=true; laut Doku ignoriert das Gateway dabei text).
func (s *Sender) SendSMS(ctx context.Context, c SMSConfig, t SMSTarget, text string, ring bool) error {
	if err := s.smsAllowed(c.Gateway); err != nil {
		return err
	}
	if ValidSMSUser(c.User) != nil || !ValidSMSPassword(c.Password) {
		return errors.New("Benutzer oder Passwort des Gateways ungültig")
	}
	if !ValidPin(c.Pin) {
		return errors.New("Fingerabdruck des Zertifikats fehlt")
	}
	switch t.Mode {
	case SMSModeNumber:
		if !ValidMobile(t.To) {
			return errors.New("ungültige Mobilnummer")
		}
	case SMSModeGroup:
		if !ValidSMSGroup(t.To) {
			return errors.New("ungültige Gruppe")
		}
	default:
		return errors.New("unbekannter Empfänger")
	}
	if text == "" {
		return errors.New("leere Nachricht")
	}
	if err := s.postSMS(ctx, c, t, text, false); err != nil {
		return err
	}
	if ring {
		if err := s.postSMS(ctx, c, t, text, true); err != nil {
			return fmt.Errorf("SMS gesendet, Anruf fehlgeschlagen: %w", err)
		}
	}
	return nil
}

func (s *Sender) postSMS(ctx context.Context, c SMSConfig, t SMSTarget, text string, ring bool) error {
	host, addr := hostPort(c.Gateway)
	var seen string
	var mu sync.Mutex
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return smsDialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       smsTLS(host, c.Pin, &seen, &mu),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   smsTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	form := url.Values{
		"username": {c.User},
		"password": {c.Password},
		"to":       {t.To},
		"text":     {text},
		"mode":     {t.Mode},
	}
	if t.Mode == SMSModeNumber {
		form.Set("to", gatewayNumber(t.To))
	}
	if ring {
		form.Set("ring", "true")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, SMSEndpoint(c.Gateway), strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("Anfrage nicht erstellbar")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "OpenWacht")
	resp, err := client.Do(req)
	if err != nil {
		return netError(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, smsReadLimit))
	return smsStatus(resp.StatusCode, string(body))
}

// smsStatus wertet die Antwort aus. Der Text des Gateways geht nicht in die
// Meldung (er kann Nummern enthalten), er hilft nur bei der Einordnung.
func smsStatus(code int, body string) error {
	b := strings.ToLower(body)
	switch {
	case code >= 200 && code < 300:
		// Laut Doku kommen Fehler als Status. Vorsicht für Geräte, die mit 200
		// und Fehlertext antworten (Annahme, nicht in der Doku beschrieben).
		if strings.HasPrefix(strings.TrimSpace(b), "error") || strings.HasPrefix(strings.TrimSpace(b), "failed") {
			return &SMSError{Status: code, Text: "Gateway meldet einen Fehler (Details im Protokoll des Gateways)"}
		}
		return nil
	case code >= 300 && code < 400:
		return &SMSError{Status: code, Text: fmt.Sprintf("Gateway antwortete mit Weiterleitung (HTTP %d), Weiterleitungen werden nicht verfolgt", code)}
	case code == http.StatusBadRequest && strings.Contains(b, "parameter miss"):
		return &SMSError{Status: code, Text: "Gateway: Pflichtangabe fehlt (HTTP 400)"}
	case code == http.StatusBadRequest:
		return &SMSError{Status: code, Text: "Gateway lehnt ab: Gruppe, Kontakt oder Nummer unbekannt bzw. ungültig (HTTP 400, Details im Protokoll des Gateways)"}
	case code == http.StatusUnauthorized:
		return &SMSError{Status: code, Text: "Gateway: Benutzer oder Passwort falsch (HTTP 401)"}
	case code == http.StatusForbidden:
		return &SMSError{Status: code, Text: "Gateway: Der Benutzer hat nicht das Recht „Zugriff auf die HTTP API“ (HTTP 403)"}
	case code == http.StatusRequestTimeout:
		return &SMSError{Status: code, Text: "Gateway: Zeitüberschreitung beim Versand (HTTP 408, Mobilfunk prüfen, Details im Protokoll des Gateways)"}
	}
	return &SMSError{Status: code, Text: fmt.Sprintf("Gateway antwortete mit HTTP %d", code)}
}

// --- Text ------------------------------------------------------------------------

// GSM-7: Grundzeichensatz (1 Zeichen) und Erweiterung (2 Zeichen). Wer nur
// diese Zeichen nutzt, passt mit 160 Zeichen in genau eine SMS; ein einziges
// anderes Zeichen (z. B. „…“) machte daraus UCS-2 mit nur 70 Zeichen.
const (
	gsmBasic = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
	gsmExt   = "^{}\\[~]|€"
)

var gsmReplace = map[rune]string{
	'…': "...", '–': "-", '—': "-", '‐': "-", '„': "\"", '“': "\"", '”': "\"", '‚': "'", '‘': "'", '’': "'",
	'·': "-", '•': "-", '×': "x", '°': " Grad", 'µ': "u", 'ł': "l", 'á': "a", 'â': "a", 'ê': "e", 'ë': "e",
	'í': "i", 'î': "i", 'ó': "o", 'ô': "o", 'ú': "u", 'û': "u", 'ç': "c", 'š': "s", 'ž': "z", 'č': "c", 'ř': "r",
	'Á': "A", 'À': "A", 'È': "E", 'Í': "I", 'Ó': "O", 'Ú': "U", 'Š': "S", 'Ž': "Z", 'Č': "C", '\t': " ",
}

// GSM7 ersetzt Zeichen außerhalb von GSM-7 und liefert den Text samt Länge
// in Zeichen (Erweiterungszeichen zählen doppelt).
func GSM7(s string) (string, int) {
	var sb strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r':
			sb.WriteByte(' ')
			n++
		case strings.ContainsRune(gsmBasic, r):
			sb.WriteRune(r)
			n++
		case strings.ContainsRune(gsmExt, r):
			sb.WriteRune(r)
			n += 2
		default:
			rep, ok := gsmReplace[r]
			if !ok {
				rep = "?"
			}
			sb.WriteString(rep)
			n += len(rep)
		}
	}
	return sb.String(), n
}

// FitSMS: höchstens MaxSMSLen GSM-7-Zeichen, sonst mit „...“ gekürzt.
func FitSMS(s string) string {
	s = Clean(s, 1000)
	out, n := GSM7(s)
	if n <= MaxSMSLen {
		return out
	}
	var sb strings.Builder
	m := 0
	for _, r := range out {
		w := 1
		if strings.ContainsRune(gsmExt, r) {
			w = 2
		}
		if m+w > MaxSMSLen-3 {
			break
		}
		sb.WriteRune(r)
		m += w
	}
	return strings.TrimRight(sb.String(), " ") + "..."
}

func smsLine(channelTenant string, r Report, long bool) string {
	state := stateShort[r.Status]
	if r.Event == Recovered {
		state = "OK"
	}
	dev := r.Device
	if dev == "" {
		dev, _, _ = strings.Cut(r.Check, " · ")
	}
	if r.Tenant != "" && r.Tenant != channelTenant {
		dev = r.Tenant + "/" + dev
	}
	line := state + " " + Clean(dev, 60)
	if r.Sensor != "" && r.Sensor != dev {
		line += " - " + Clean(r.Sensor, 60)
	}
	if long && r.Message != "" {
		line += ": " + Clean(r.Message, 120)
	}
	if r.Event == Reminder {
		line += " (Erinnerung)"
	}
	return line
}

// BuildSMS: eine SMS für alle Ereignisse eines Durchlaufs (Gerät, Sensor,
// Zustand; bei einem Ereignis auch die Meldung), höchstens 160 Zeichen.
func BuildSMS(channelTenant string, reports []Report) string {
	if len(reports) == 0 {
		return ""
	}
	sorted := append([]Report(nil), reports...)
	// Schlimmstes zuerst (wie ntfy), Entwarnungen zuletzt.
	weight := func(r Report) int {
		if r.Event == Recovered {
			return -1
		}
		return rank[r.Status]
	}
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && weight(sorted[j]) > weight(sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	if len(sorted) == 1 {
		return FitSMS("OpenWacht: " + smsLine(channelTenant, sorted[0], true))
	}
	head := fmt.Sprintf("OpenWacht: %d Meldungen. ", len(sorted))
	text := head
	for i, r := range sorted {
		next := text
		if i > 0 {
			next += "; "
		}
		next += smsLine(channelTenant, r, false)
		rest := len(sorted) - i - 1
		suffix := ""
		if rest > 0 {
			suffix = fmt.Sprintf(" +%d weitere", rest)
		}
		if _, n := GSM7(Clean(next+suffix, 1000)); n > MaxSMSLen && i > 0 {
			return FitSMS(text + fmt.Sprintf(" +%d weitere", len(sorted)-i))
		}
		text = next
	}
	return FitSMS(text)
}

// TestSMS: Text für „Test senden“.
func TestSMS(tenant, channel string) string {
	return FitSMS("OpenWacht " + Clean(tenant, 60) + ": Test des Alarmkanals \"" + Clean(channel, 60) + "\". Der Kanal funktioniert.")
}

// SMS: Hinweis der Selbstüberwachung als SMS.
func (n Notice) SMS() string {
	state := map[string]string{Warn: "WARN", Crit: "KRIT", OK: "OK"}[n.Status]
	return FitSMS(n.subject() + ": " + state + " " + Clean(n.Title, 80) + ". " + Clean(n.Text, 120))
}
