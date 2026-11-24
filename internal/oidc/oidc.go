// SPDX-License-Identifier: AGPL-3.0-only

// Package oidc meldet Benutzer per OpenID Connect an (Authorization Code mit
// PKCE, Etappe 22b). Nur Standardbibliothek: Das ID-Token kommt direkt vom
// Token-Endpunkt über eine geprüfte TLS-Verbindung; nach OpenID Connect Core
// 3.1.3.7 ersetzt diese Prüfung die Signaturprüfung. Geprüft werden Issuer,
// Audience, azp, Ablauf und Nonce.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config einer Anbindung.
type Config struct {
	Issuer       string // https://keycloak.firma.de/realms/firma
	ClientID     string
	ClientSecret string
	CAPEM        string // leer = Zertifikate des Systems
	GroupClaim   string // Standard "groups"
	// EmailClaim: der einzige Claim, aus dem die Adresse kommt (Standard
	// "email"; erlaubt "email", "upn", "preferred_username"). Kein Rückfall
	// auf andere Claims (Befund M2).
	EmailClaim string
	Timeout    time.Duration
	// Dial verbindet (Netzfreigabe der Zentrale); nil = net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
}

// Endpoints aus dem Discovery-Dokument.
type Endpoints struct {
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	Issuer        string `json:"issuer"`
}

// Claims des angemeldeten Benutzers.
type Claims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

var (
	// ErrRejected: Token oder Antwort passt nicht (Issuer, Audience, Nonce, Ablauf).
	ErrRejected = errors.New("Antwort des Identity Providers abgelehnt")
)

const maxBody = 1 << 20

// ValidEmailClaim: Claims, die als Adresse eingestellt werden dürfen.
func ValidEmailClaim(c string) bool {
	return c == "email" || c == "upn" || c == "preferred_username"
}

// ValidateIssuer prüft die Form der Issuer-Adresse.
func ValidateIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 760 {
		return errors.New("Issuer bitte als https-Adresse ohne Parameter angeben, z. B. https://sso.firma.de/realms/firma")
	}
	return nil
}

func (c Config) client() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("CA-Zertifikat nicht lesbar")
		}
		tc.RootCAs = pool
	}
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	t := c.Timeout
	if t == 0 {
		t = 10 * time.Second
	}
	return &http.Client{
		Timeout: t,
		Transport: &http.Transport{TLSClientConfig: tc, DialContext: dial, Proxy: nil, ForceAttemptHTTP2: true,
			TLSHandshakeTimeout: t, ResponseHeaderTimeout: t},
		// Keine Umleitungen: Sie könnten an andere Ziele führen.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func readJSON(resp *http.Response, v any) error {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return errors.New("Antwort zu groß")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Antwort %d", resp.StatusCode)
	}
	return json.Unmarshal(b, v)
}

// Discover lädt das Discovery-Dokument und prüft es.
func (c Config) Discover(ctx context.Context) (Endpoints, error) {
	var ep Endpoints
	if err := ValidateIssuer(c.Issuer); err != nil {
		return ep, err
	}
	hc, err := c.client()
	if err != nil {
		return ep, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return ep, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ep, err
	}
	if err := readJSON(resp, &ep); err != nil {
		return ep, fmt.Errorf("Discovery: %w", err)
	}
	if ep.Issuer != c.Issuer {
		return ep, fmt.Errorf("Discovery: Issuer %q passt nicht zur Anbindung", ep.Issuer)
	}
	for _, e := range []string{ep.Authorization, ep.Token} {
		u, err := url.Parse(e)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return ep, errors.New("Discovery: Endpunkte müssen https sein")
		}
	}
	return ep, nil
}

// Random liefert n zufällige Bytes als base64url.
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthURL baut die Adresse für den Browser (PKCE S256).
func (c Config) AuthURL(ep Endpoints, redirect, state, nonce, verifier, loginHint string) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	sep := "?"
	if strings.Contains(ep.Authorization, "?") {
		sep = "&"
	}
	return ep.Authorization + sep + q.Encode()
}

// Exchange tauscht den Code gegen das ID-Token und prüft es.
func (c Config) Exchange(ctx context.Context, ep Endpoints, code, verifier, redirect, nonce string) (Claims, error) {
	var out Claims
	if code == "" || len(code) > 4096 {
		return out, ErrRejected
	}
	hc, err := c.client()
	if err != nil {
		return out, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := hc.Do(req)
	if err != nil {
		return out, err
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := readJSON(resp, &tok); err != nil {
		return out, fmt.Errorf("Token-Endpunkt: %w", err)
	}
	return c.Verify(tok.IDToken, nonce)
}

// Verify prüft die Claims eines ID-Tokens (ohne Signatur, siehe Paketdoku).
func (c Config) Verify(idToken, nonce string) (Claims, error) {
	var out Claims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 || len(idToken) > 64<<10 {
		return out, ErrRejected
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out, ErrRejected
	}
	var cl map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cl); err != nil {
		return out, ErrRejected
	}
	str := func(k string) string {
		var s string
		if v, ok := cl[k]; ok {
			_ = json.Unmarshal(v, &s)
		}
		return s
	}
	if str("iss") != c.Issuer {
		return out, fmt.Errorf("%w: Issuer", ErrRejected)
	}
	var aud []string
	if v, ok := cl["aud"]; ok {
		var one string
		if json.Unmarshal(v, &one) == nil {
			aud = []string{one}
		} else {
			_ = json.Unmarshal(v, &aud)
		}
	}
	found := false
	for _, a := range aud {
		found = found || a == c.ClientID
	}
	if !found || (len(aud) > 1 && str("azp") != c.ClientID) || (str("azp") != "" && str("azp") != c.ClientID) {
		return out, fmt.Errorf("%w: Audience", ErrRejected)
	}
	var exp float64
	if v, ok := cl["exp"]; !ok || json.Unmarshal(v, &exp) != nil {
		return out, fmt.Errorf("%w: Ablauf fehlt", ErrRejected)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if float64(now().Add(-time.Minute).Unix()) > exp {
		return out, fmt.Errorf("%w: abgelaufen", ErrRejected)
	}
	if nonce == "" || str("nonce") != nonce {
		return out, fmt.Errorf("%w: Nonce", ErrRejected)
	}
	out.Subject = str("sub")
	if out.Subject == "" || len(out.Subject) > 200 {
		return out, fmt.Errorf("%w: sub", ErrRejected)
	}
	addr := c.EmailClaim
	if addr == "" {
		addr = "email"
	}
	if !ValidEmailClaim(addr) {
		return out, fmt.Errorf("%w: Adress-Claim %q nicht erlaubt", ErrRejected, addr)
	}
	if addr == "email" {
		// Ist die Adresse ausdrücklich unbestätigt, gilt die Anmeldung nicht.
		if v, ok := cl["email_verified"]; ok {
			var b bool
			if json.Unmarshal(v, &b) != nil || !b {
				return out, fmt.Errorf("%w: E-Mail-Adresse beim Identity Provider nicht bestätigt", ErrRejected)
			}
		}
	}
	if e := strings.ToLower(strings.TrimSpace(str(addr))); strings.Contains(e, "@") && len(e) <= 254 {
		out.Email = e
	}
	out.Name = strings.TrimSpace(str("name"))
	if out.Name == "" {
		out.Name = out.Email
	}
	claim := c.GroupClaim
	if claim == "" {
		claim = "groups"
	}
	if v, ok := cl[claim]; ok {
		var list []string
		if json.Unmarshal(v, &list) != nil {
			var one string
			if json.Unmarshal(v, &one) == nil {
				list = []string{one}
			}
		}
		for _, g := range list {
			if g != "" && len(g) <= 1000 && len(out.Groups) < 500 {
				out.Groups = append(out.Groups, g)
			}
		}
	}
	return out, nil
}
