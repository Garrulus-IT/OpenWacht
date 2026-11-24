// SPDX-License-Identifier: AGPL-3.0-only

// Package verzeichnis meldet Benutzer an einem LDAP-Verzeichnis (Active
// Directory) an und liest ihre Gruppen (Etappe 22a).
//
// Nur LDAPS oder LDAP mit StartTLS, das Zertifikat wird immer geprüft (System-
// wurzeln oder eigene CA). Ablauf: Bind mit dem Dienstkonto, Benutzer suchen
// (UPN oder sAMAccountName), Bind als Benutzer mit seinem Passwort, dann für
// jede abgebildete Gruppe prüfen, ob er Mitglied ist (bei AD auch verschachtelt
// über LDAP_MATCHING_RULE_IN_CHAIN).
package verzeichnis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config ist eine Anbindung.
type Config struct {
	URL          string // ldaps://dc1.firma.de oder ldap://dc1.firma.de (dann StartTLS)
	CAPEM        string // leer = Systemwurzeln
	BindDN       string
	BindPassword string
	BaseDN       string
	NestedGroups bool // AD: verschachtelte Gruppen (1.2.840.113556.1.4.1941)
	Timeout      time.Duration
	// Dial: nur für Tests (Guard der Zentrale prüft die Adresse vorher).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// User ist ein gefundener Benutzer.
type User struct {
	DN       string
	ID       string // objectGUID (hex) oder DN
	UPN      string
	Name     string
	Mail     string
	Disabled bool     // userAccountControl ACCOUNTDISABLE
	Groups   []string // DNs der Gruppen aus groups, in denen er Mitglied ist
}

// Fehler, die die Anmeldung unterscheiden muss.
var (
	ErrNotFound    = errors.New("Benutzer nicht gefunden")
	ErrBadPassword = errors.New("Passwort falsch")
	ErrAmbiguous   = errors.New("Benutzer nicht eindeutig")
)

// ValidateURL prüft die Adresse der Anbindung.
func ValidateURL(raw string) (host, port string, starttls bool, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" {
		return "", "", false, errors.New("Adresse bitte als ldaps://host[:port] oder ldap://host[:port]")
	}
	switch u.Scheme {
	case "ldaps":
		port = "636"
	case "ldap":
		port, starttls = "389", true
	default:
		return "", "", false, errors.New("nur ldaps:// oder ldap:// (dann mit StartTLS)")
	}
	host = u.Hostname()
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "", false, errors.New("ungültiger Port")
		}
		port = p
	}
	return host, port, starttls, nil
}

func (c Config) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if strings.TrimSpace(c.CAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("CA-Zertifikat ist kein gültiges PEM")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (c Config) connect(ctx context.Context) (*ldap.Conn, error) {
	host, port, starttls, err := ValidateURL(c.URL)
	if err != nil {
		return nil, err
	}
	tc, err := c.tlsConfig(host)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("Verbindung zu %s: %w", net.JoinHostPort(host, port), err)
	}
	var conn *ldap.Conn
	if starttls {
		conn = ldap.NewConn(raw, false)
		conn.Start()
		conn.SetTimeout(timeout)
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	} else {
		t := tls.Client(raw, tc)
		if err := t.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS: %w", err)
		}
		conn = ldap.NewConn(t, true)
		conn.Start()
		conn.SetTimeout(timeout)
	}
	return conn, nil
}

// serviceBind verbindet und meldet das Dienstkonto an.
func (c Config) serviceBind(ctx context.Context) (*ldap.Conn, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	if c.BindPassword == "" {
		conn.Close()
		return nil, errors.New("Passwort des Dienstkontos fehlt")
	}
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("Anmeldung des Dienstkontos: %w", err)
	}
	return conn, nil
}

// Test prüft Verbindung und Dienstkonto.
func (c Config) Test(ctx context.Context) error {
	conn, err := c.serviceBind(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
		"(objectClass=*)", []string{"dn"}, nil))
	if err != nil {
		return fmt.Errorf("Basis-DN %q: %w", c.BaseDN, err)
	}
	return nil
}

var userAttrs = []string{"objectGUID", "userPrincipalName", "sAMAccountName", "displayName", "cn", "mail", "userAccountControl"}

// SplitLogin trennt „name@domain“ bzw. „DOMAIN\name“.
func SplitLogin(login string) (name, domain, netbios string) {
	login = strings.TrimSpace(login)
	if i := strings.IndexByte(login, '\\'); i > 0 {
		return login[i+1:], "", login[:i]
	}
	if i := strings.LastIndexByte(login, '@'); i > 0 {
		return login[:i], strings.ToLower(login[i+1:]), ""
	}
	return login, "", ""
}

func (c Config) find(conn *ldap.Conn, filter string) (*ldap.Entry, error) {
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter, userAttrs, nil))
	if err != nil {
		return nil, fmt.Errorf("Suche: %w", err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return res.Entries[0], nil
	}
	return nil, ErrAmbiguous
}

// userFilter: per UPN (name@domain) oder sAMAccountName (DOMAIN\name).
func userFilter(name, domain string) string {
	if domain != "" {
		return "(&(objectClass=user)(userPrincipalName=" + ldap.EscapeFilter(name+"@"+domain) + "))"
	}
	return "(&(objectClass=user)(sAMAccountName=" + ldap.EscapeFilter(name) + "))"
}

func toUser(e *ldap.Entry) User {
	u := User{DN: e.DN, UPN: e.GetAttributeValue("userPrincipalName"), Mail: e.GetAttributeValue("mail")}
	if g := e.GetRawAttributeValue("objectGUID"); len(g) > 0 {
		u.ID = hex.EncodeToString(g)
	} else {
		u.ID = strings.ToLower(e.DN)
	}
	u.Name = e.GetAttributeValue("displayName")
	if u.Name == "" {
		u.Name = e.GetAttributeValue("cn")
	}
	if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil && uac&2 != 0 {
		u.Disabled = true
	}
	return u
}

// memberOf prüft je abgebildeter Gruppe die Mitgliedschaft.
func (c Config) memberOf(conn *ldap.Conn, userDN string, groups []string) ([]string, error) {
	var out []string
	for _, g := range groups {
		f := "(memberOf=" + ldap.EscapeFilter(g) + ")"
		if c.NestedGroups {
			f = "(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(g) + ")"
		}
		res, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
			f, []string{"dn"}, nil))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				continue
			}
			return nil, fmt.Errorf("Gruppen: %w", err)
		}
		if len(res.Entries) > 0 {
			out = append(out, g)
		}
	}
	return out, nil
}

// Authenticate meldet login (name@domain oder DOMAIN\name) mit password an und
// liefert den Benutzer samt den Gruppen aus groups, in denen er Mitglied ist.
func (c Config) Authenticate(ctx context.Context, login, password string, groups []string) (User, error) {
	if password == "" {
		return User{}, ErrBadPassword // sonst „unauthenticated bind“
	}
	name, domain, _ := SplitLogin(login)
	if name == "" || len(name) > 256 {
		return User{}, ErrNotFound
	}
	conn, err := c.serviceBind(ctx)
	if err != nil {
		return User{}, err
	}
	defer conn.Close()
	e, err := c.find(conn, userFilter(name, domain))
	if err != nil {
		return User{}, err
	}
	u := toUser(e)
	if err := conn.Bind(u.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return User{}, ErrBadPassword
		}
		return User{}, fmt.Errorf("Anmeldung: %w", err)
	}
	// Gruppen mit dem Dienstkonto lesen (der Benutzer darf das evtl. nicht).
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return User{}, fmt.Errorf("Dienstkonto: %w", err)
	}
	if u.Groups, err = c.memberOf(conn, u.DN, groups); err != nil {
		return User{}, err
	}
	return u, nil
}

// LookupByID sucht einen Benutzer für den Abgleich (nur mit dem Dienstkonto).
// id ist objectGUID (hex) oder der DN in Kleinbuchstaben.
func (c Config) LookupByID(ctx context.Context, conn *ldap.Conn, id string, groups []string) (User, error) {
	var e *ldap.Entry
	var err error
	if b, herr := hex.DecodeString(id); herr == nil && len(b) == 16 {
		var f strings.Builder
		for _, x := range b {
			fmt.Fprintf(&f, "\\%02x", x)
		}
		e, err = c.find(conn, "(objectGUID="+f.String()+")")
	} else {
		var res *ldap.SearchResult
		res, err = conn.Search(ldap.NewSearchRequest(id, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
			"(objectClass=user)", userAttrs, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return User{}, ErrNotFound
		}
		if err == nil {
			if len(res.Entries) == 0 {
				return User{}, ErrNotFound
			}
			e = res.Entries[0]
		}
	}
	if err != nil {
		return User{}, err
	}
	u := toUser(e)
	if u.Groups, err = c.memberOf(conn, u.DN, groups); err != nil {
		return User{}, err
	}
	return u, nil
}

// Session: Verbindung des Dienstkontos für den Abgleich mehrerer Benutzer.
func (c Config) Session(ctx context.Context) (*ldap.Conn, error) { return c.serviceBind(ctx) }

// Email liefert die Adresse für das OpenWacht-Konto: UPN, sonst mail.
func (u User) Email() string {
	if u.UPN != "" {
		return strings.ToLower(u.UPN)
	}
	return strings.ToLower(u.Mail)
}

// VerifyByID prüft das Passwort des Benutzers mit der ID id (Bestätigung
// einer Änderung durch ein angemeldetes Konto ohne 2FA).
func (c Config) VerifyByID(ctx context.Context, id, password string) error {
	if password == "" {
		return ErrBadPassword
	}
	conn, err := c.serviceBind(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	u, err := c.LookupByID(ctx, conn, id, nil)
	if err != nil {
		return err
	}
	if u.Disabled {
		return ErrBadPassword
	}
	if err := conn.Bind(u.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return ErrBadPassword
		}
		return fmt.Errorf("Anmeldung: %w", err)
	}
	return nil
}
