// SPDX-License-Identifier: AGPL-3.0-only

// Package smtptest ist eine kleine SMTP-Gegenstelle für Tests: EHLO,
// STARTTLS, TLS von Anfang an, AUTH PLAIN/LOGIN, MAIL, RCPT, DATA, QUIT.
// Empfänger mit „abgelehnt“ im Namen lehnt sie mit 550 ab.
package smtptest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Message: eine angenommene Mail.
type Message struct {
	From string
	To   []string
	Data string
	TLS  bool
	User string
}

// Server: die Gegenstelle.
type Server struct {
	Addr     string
	Host     string
	Port     int
	CAPEM    string // Wurzel für das Serverzertifikat
	User     string // erwarteter Benutzer ("" = keine Anmeldung nötig)
	Pass     string
	Implicit bool // TLS von Anfang an
	NoTLS    bool // kein STARTTLS anbieten
	OnlyAuth string

	mu   sync.Mutex
	msgs []Message
	ln   net.Listener
	tlsc *tls.Config
}

// Messages: bisher angenommene Mails.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// Start lauscht auf 127.0.0.1 und beendet sich mit dem Test.
func Start(t *testing.T, implicit bool, user, pass string) *Server {
	t.Helper()
	s := &Server{Implicit: implicit, User: user, Pass: pass}
	s.tlsc, s.CAPEM = testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.Addr = ln.Addr().String()
	s.Host = "127.0.0.1"
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	isTLS := false
	if s.Implicit {
		tc := tls.Server(c, s.tlsc)
		if tc.Handshake() != nil {
			return
		}
		c, isTLS = tc, true
	}
	r := bufio.NewReader(c)
	w := func(line string) { c.Write([]byte(line + "\r\n")) }
	w("220 smtptest ESMTP")
	var cur Message
	authed := s.User == ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-smtptest")
			if !isTLS && !s.NoTLS {
				w("250-STARTTLS")
			}
			auth := "PLAIN LOGIN"
			if s.OnlyAuth != "" {
				auth = s.OnlyAuth
			}
			w("250-AUTH " + auth)
			w("250 8BITMIME")
		case cmd == "STARTTLS":
			w("220 los")
			tc := tls.Server(c, s.tlsc)
			if tc.Handshake() != nil {
				return
			}
			c, isTLS = tc, true
			r = bufio.NewReader(c)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			arg := strings.TrimSpace(line[len("AUTH PLAIN"):])
			b, _ := base64.StdEncoding.DecodeString(arg)
			parts := strings.Split(string(b), "\x00")
			if len(parts) == 3 && parts[1] == s.User && parts[2] == s.Pass {
				authed, cur.User = true, parts[1]
				w("235 ok")
			} else {
				w("535 falsch")
			}
		case cmd == "AUTH LOGIN":
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := r.ReadString('\n')
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := r.ReadString('\n')
			ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
			pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			if string(ub) == s.User && string(pb) == s.Pass {
				authed, cur.User = true, string(ub)
				w("235 ok")
			} else {
				w("535 falsch")
			}
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			if !authed {
				w("530 erst anmelden")
				continue
			}
			cur.From = strings.Trim(line[len("MAIL FROM:"):], "<> ")
			if i := strings.Index(cur.From, ">"); i >= 0 {
				cur.From = cur.From[:i]
			}
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			to := strings.Trim(line[len("RCPT TO:"):], "<> ")
			if strings.Contains(to, "abgelehnt") {
				w("550 gibt es nicht")
				continue
			}
			cur.To = append(cur.To, to)
			w("250 ok")
		case cmd == "DATA":
			w("354 los")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			cur.Data, cur.TLS = b.String(), isTLS
			s.mu.Lock()
			s.msgs = append(s.msgs, cur)
			s.mu.Unlock()
			cur = Message{User: cur.User}
			w("250 angenommen")
		case cmd == "RSET":
			cur = Message{User: cur.User}
			w("250 ok")
		case cmd == "NOOP":
			w("250 ok")
		case cmd == "QUIT":
			w("221 tschüss")
			return
		default:
			w("502 unbekannt")
		}
	}
}

// testCert: selbst signiertes Zertifikat für 127.0.0.1 und localhost.
func testCert(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtptest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pemCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, pemCA
}
