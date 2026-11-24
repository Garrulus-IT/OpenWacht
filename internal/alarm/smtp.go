// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// Mailversand über ein SMTP-Relay (Einstellung des Betreibers, Etappe 20a).
//
// Nur net/smtp aus der Standardbibliothek. Verschlüsselung ist Pflicht:
// STARTTLS (meist Port 587) oder TLS von Anfang an (465). Ohne
// Verschlüsselung nur zu einem Relay auf Loopback (z. B. Postfix im selben
// Container). Zertifikate werden immer geprüft, gegen die Systemwurzeln oder
// eine eigene CA (internes Relay). Anmeldung mit PLAIN oder LOGIN, nur über
// TLS bzw. Loopback.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig: Zugang zum Relay.
type SMTPConfig struct {
	Host string
	Port int
	TLS  string // starttls, tls, keine
	From string // Absenderadresse
	User string
	Pass string
	CA   string // PEM, optional
}

// MaxRecipients: so viele Empfänger hat eine Mail höchstens (wie in der DB).
const MaxRecipients = 100

// ValidateSMTP prüft die Einstellung ohne Verbindung.
func ValidateSMTP(c SMTPConfig) error {
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsFunc(c.Host, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".-:[]", r))
	}) {
		return errors.New("Server: Name oder Adresse ohne Schema, z. B. mail.example.com")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("Port: 1 bis 65535")
	}
	switch c.TLS {
	case "starttls", "tls":
	case "keine":
		if !isLoopback(strings.Trim(c.Host, "[]")) {
			return errors.New("ohne Verschlüsselung nur zu einem Relay auf Loopback (127.0.0.1, ::1, localhost)")
		}
	default:
		return errors.New("Verschlüsselung: starttls, tls oder keine")
	}
	if _, err := parseFrom(c.From); err != nil {
		return err
	}
	if c.Pass != "" && c.User == "" {
		return errors.New("Passwort ohne Benutzer")
	}
	if len(c.User) > 254 || strings.ContainsFunc(c.User, unicodeControl) {
		return errors.New("Benutzer: höchstens 254 Zeichen")
	}
	if len(c.Pass) > 512 || strings.ContainsAny(c.Pass, "\r\n\x00") {
		return errors.New("Passwort: höchstens 512 Zeichen ohne Zeilenumbruch")
	}
	if c.CA != "" {
		if len(c.CA) > 16384 {
			return errors.New("CA: höchstens 16 KiB")
		}
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CA)) {
			return errors.New("CA: kein Zertifikat im PEM-Format gefunden")
		}
	}
	return nil
}

func parseFrom(s string) (*mail.Address, error) {
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || len(a.Address) > 254 || strings.ContainsAny(a.Address, "\r\n<>") {
		return nil, errors.New("Absender: eine Adresse wie openwacht@example.com")
	}
	return a, nil
}

// ValidRecipient: Adressen aus den Benutzerkonten noch einmal prüfen, bevor
// sie in RCPT TO landen.
func ValidRecipient(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && len(s) <= 254 && !strings.ContainsAny(s, "\r\n<>")
}

// Mailer verschickt Mails. Dial ist in Tests ersetzbar.
type Mailer struct {
	Timeout time.Duration
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	// Helo: Name im EHLO (z. B. der Host der Oberfläche)
	Helo string
	now  func() time.Time
}

// NewMailer mit festen Zeitlimits.
func NewMailer(helo string) *Mailer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &Mailer{Timeout: 60 * time.Second, Dial: d.DialContext, Helo: helo}
}

// Send baut die Nachricht und gibt sie dem Relay. Empfänger stehen nur im
// Umschlag (RCPT TO), nicht im Kopf: Sie sehen sich gegenseitig nicht.
// Lehnt das Relay einzelne Empfänger ab, geht die Mail an die übrigen; erst
// wenn keiner angenommen wird, ist es ein Fehler. Fehlertexte enthalten nie
// das Passwort.
func (m *Mailer) Send(ctx context.Context, c SMTPConfig, rcpts []string, msg Mail) (rejected []string, err error) {
	if err := ValidateSMTP(c); err != nil {
		return nil, fmt.Errorf("Mail-Einstellung: %w", err)
	}
	if len(rcpts) == 0 {
		return nil, errors.New("keine Empfänger")
	}
	if len(rcpts) > MaxRecipients {
		rcpts = rcpts[:MaxRecipients]
	}
	from, _ := parseFrom(c.From)
	now := time.Now
	if m.now != nil {
		now = m.now
	}
	data, err := BuildMIME(from.Address, msg, now())
	if err != nil {
		return nil, err
	}
	host := strings.Trim(c.Host, "[]")
	addr := net.JoinHostPort(host, strconv.Itoa(c.Port))
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	conn, err := m.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Relay nicht erreichbar: %s", Clean(err.Error(), 200))
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if c.CA != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(c.CA))
		tlsCfg.RootCAs = pool
	}
	if c.TLS == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS: %s", Clean(err.Error(), 200))
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return nil, smtpErr("Begrüßung", err)
	}
	defer cl.Close()
	helo := m.Helo
	if helo == "" {
		helo = "localhost"
	}
	if err := cl.Hello(helo); err != nil {
		return nil, smtpErr("EHLO", err)
	}
	if c.TLS == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return nil, errors.New("Das Relay bietet kein STARTTLS an")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("STARTTLS: %s", Clean(err.Error(), 200))
		}
	}
	if c.User != "" {
		_, mechs := cl.Extension("AUTH")
		var a smtp.Auth
		switch {
		case hasWord(mechs, "PLAIN"):
			a = smtp.PlainAuth("", c.User, c.Pass, host)
		case hasWord(mechs, "LOGIN"):
			a = &loginAuth{user: c.User, pass: c.Pass, host: host}
		default:
			return nil, errors.New("Das Relay bietet weder AUTH PLAIN noch AUTH LOGIN an")
		}
		if err := cl.Auth(a); err != nil {
			return nil, smtpErr("Anmeldung", err)
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return nil, smtpErr("MAIL FROM", err)
	}
	accepted := 0
	for _, r := range rcpts {
		if !ValidRecipient(r) {
			rejected = append(rejected, r)
			continue
		}
		if err := cl.Rcpt(r); err != nil {
			var te *textproto.Error
			if errors.As(err, &te) && te.Code >= 400 && te.Code < 600 {
				rejected = append(rejected, r)
				continue
			}
			return rejected, smtpErr("RCPT TO", err)
		}
		accepted++
	}
	if accepted == 0 {
		return rejected, errors.New("Das Relay hat keinen Empfänger angenommen")
	}
	w, err := cl.Data()
	if err != nil {
		return rejected, smtpErr("DATA", err)
	}
	if _, err := w.Write(data); err != nil {
		return rejected, smtpErr("DATA", err)
	}
	if err := w.Close(); err != nil {
		return rejected, smtpErr("Annahme", err)
	}
	_ = cl.Quit()
	return rejected, nil
}

func hasWord(list, w string) bool {
	for _, x := range strings.Fields(strings.ToUpper(list)) {
		if x == w {
			return true
		}
	}
	return false
}

func smtpErr(step string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		return fmt.Errorf("%s: Relay antwortete %d %s", step, te.Code, Clean(te.Msg, 150))
	}
	return fmt.Errorf("%s: %s", step, Clean(err.Error(), 200))
}

// loginAuth: AUTH LOGIN (z. B. Exchange), nur über TLS oder Loopback.
type loginAuth struct {
	user, pass, host string
	step             int
}

func (a *loginAuth) Start(info *smtp.ServerInfo) (string, []byte, error) {
	if !info.TLS && !isLoopback(a.host) {
		return "", nil, errors.New("Anmeldung nur über eine verschlüsselte Verbindung")
	}
	if info.Name != a.host {
		return "", nil, errors.New("falscher Servername")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	}
	return nil, errors.New("unerwartete Rückfrage bei AUTH LOGIN")
}

// --- MIME ----------------------------------------------------------------------

// header: Wert ohne Zeilenumbrüche, Nicht-ASCII als encoded-word.
func header(s string) string {
	s = Clean(s, 200)
	return mime.QEncoding.Encode("utf-8", s)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// BuildMIME: text/plain und text/html als Alternativen, Bilder per
// multipart/related mit Content-ID. Zeilenenden CRLF.
func BuildMIME(from string, m Mail, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	domain := "openwacht"
	if _, d, ok := strings.Cut(from, "@"); ok && d != "" {
		domain = d
	}
	h := func(k, v string) { buf.WriteString(k + ": " + v + "\r\n") }
	h("From", "OpenWacht <"+from+">")
	h("To", "undisclosed-recipients:;")
	h("Subject", header(m.Subject))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", "<"+randomID()+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")

	alt := func(w *multipart.Writer) error {
		for _, part := range []struct{ typ, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
			pw, err := w.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {part.typ + "; charset=utf-8"},
				"Content-Transfer-Encoding": {"quoted-printable"}})
			if err != nil {
				return err
			}
			qp := quotedprintable.NewWriter(pw)
			if _, err := qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(part.body, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
				return err
			}
			if err := qp.Close(); err != nil {
				return err
			}
		}
		return w.Close()
	}

	if len(m.Attachments) > 0 {
		if len(m.Images) > 0 {
			return nil, errors.New("Anhänge und Bilder zusammen werden nicht unterstützt")
		}
		mixed := multipart.NewWriter(&buf)
		h("Content-Type", "multipart/mixed; boundary="+mixed.Boundary())
		buf.WriteString("\r\n")
		var inner bytes.Buffer
		aw := multipart.NewWriter(&inner)
		if err := alt(aw); err != nil {
			return nil, err
		}
		pw, err := mixed.CreatePart(textproto.MIMEHeader{"Content-Type": {"multipart/alternative; boundary=" + aw.Boundary()}})
		if err != nil {
			return nil, err
		}
		if _, err := pw.Write(inner.Bytes()); err != nil {
			return nil, err
		}
		for _, a := range m.Attachments {
			if strings.ContainsAny(a.Name, "\"\r\n\\/") || strings.ContainsAny(a.Type, "\r\n;\"") || a.Name == "" {
				return nil, errors.New("ungültiger Anhang")
			}
			pw, err := mixed.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {a.Type + `; name="` + a.Name + `"`},
				"Content-Transfer-Encoding": {"base64"},
				"Content-Disposition":       {`attachment; filename="` + a.Name + `"`}})
			if err != nil {
				return nil, err
			}
			enc := base64.StdEncoding.EncodeToString(a.Data)
			for len(enc) > 76 {
				pw.Write([]byte(enc[:76] + "\r\n"))
				enc = enc[76:]
			}
			pw.Write([]byte(enc + "\r\n"))
		}
		if err := mixed.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	if len(m.Images) == 0 {
		w := multipart.NewWriter(&buf)
		h("Content-Type", "multipart/alternative; boundary="+w.Boundary())
		buf.WriteString("\r\n")
		if err := alt(w); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	rel := multipart.NewWriter(&buf)
	h("Content-Type", `multipart/related; type="multipart/alternative"; boundary=`+rel.Boundary())
	buf.WriteString("\r\n")
	var inner bytes.Buffer
	aw := multipart.NewWriter(&inner)
	if err := alt(aw); err != nil {
		return nil, err
	}
	pw, err := rel.CreatePart(textproto.MIMEHeader{"Content-Type": {"multipart/alternative; boundary=" + aw.Boundary()}})
	if err != nil {
		return nil, err
	}
	if _, err := pw.Write(inner.Bytes()); err != nil {
		return nil, err
	}
	for _, img := range m.Images {
		if strings.ContainsAny(img.CID, "<>\r\n \"") {
			return nil, errors.New("ungültige Content-ID")
		}
		pw, err := rel.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {"image/png"},
			"Content-Transfer-Encoding": {"base64"},
			"Content-ID":                {"<" + img.CID + ">"},
			"Content-Disposition":       {`inline; filename="graph.png"`}})
		if err != nil {
			return nil, err
		}
		enc := base64.StdEncoding.EncodeToString(img.Data)
		for len(enc) > 76 {
			pw.Write([]byte(enc[:76] + "\r\n"))
			enc = enc[76:]
		}
		pw.Write([]byte(enc + "\r\n"))
	}
	if err := rel.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
