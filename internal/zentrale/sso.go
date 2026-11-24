// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/oidc"
	"github.com/garrulus-it/openwacht/internal/verzeichnis"
)

// Anmeldung per OIDC (Etappe 22b): Authorization Code mit PKCE. Der Zustand
// der laufenden Anmeldung (state, nonce, PKCE-Verifier, Anbindung, Ablauf)
// steht HMAC-gesichert in einem HttpOnly-Cookie; die Zentrale merkt sich
// nichts. SameSite=Lax, weil die Rückkehr vom IdP eine Navigation von einer
// fremden Seite ist (Strict schickte das Cookie dann nicht mit).

const ssoCookie = "__Host-openwacht-sso"
const ssoPath = "/api/v1/sitzung/sso/rueckkehr"

type ssoState struct {
	Dir      string `json:"d"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

func (s *Server) ssoKey() []byte { return deriveKey(s.key, "openwacht sso v1") }

func (s *Server) ssoSeal(st ssoState) string {
	b, _ := json.Marshal(st)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.ssoKey())
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) ssoOpen(v string) (ssoState, bool) {
	var st ssoState
	p, sig, ok := strings.Cut(v, ".")
	if !ok || len(v) > 2048 {
		return st, false
	}
	m := hmac.New(sha256.New, s.ssoKey())
	m.Write([]byte(p))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return st, false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Expires < s.now().Unix() {
		return st, false
	}
	return st, true
}

func (s *Server) ssoRedirect() string {
	u := *s.cfg.BaseURL
	u.Path, u.RawQuery, u.Fragment = ssoPath, "", ""
	return u.String()
}

func (s *Server) oidcConfig(d dirRow) (oidc.Config, error) {
	secret, err := auth.Open(s.ldapKey(), d.PassEnc, ldapAAD(d.ID, d.Tenant, d.URL, d.BindDN))
	if err != nil {
		return oidc.Config{}, errors.New("Client-Secret nicht lesbar")
	}
	c := oidc.Config{Issuer: d.URL, ClientID: d.BindDN, ClientSecret: string(secret), GroupClaim: d.BaseDN,
		EmailClaim: d.EmailClaim, Dial: s.ldapDial(d.Tenant), Now: s.now}
	if d.CAPEM != nil {
		c.CAPEM = *d.CAPEM
	}
	return c, nil
}

// handleSSOStart: E-Mail-Adresse → Anbindung der Domäne → Adresse beim IdP.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte kurz warten.")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	_, domain, _ := verzeichnis.SplitLogin(email)
	none := func() {
		writeError(w, http.StatusNotFound, "Für diese Adresse ist keine Anmeldung über den Firmen-Login (SSO) eingerichtet.")
	}
	if domain == "" || len(email) > 254 {
		none()
		return
	}
	var d dirRow
	var kind string
	err := s.pool.QueryRow(ctx, `SELECT d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem,
		d.bind_pass_enc, d.nested_groups, d.kind FROM openwacht.directory_for_login($1, NULL) d`, domain).
		Scan(&d.ID, &d.Tenant, &d.URL, &d.BindDN, &d.BaseDN, &d.CAPEM, &d.PassEnc, &d.Nested, &kind)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "oidc") {
		none()
		return
	}
	if err != nil {
		internalError(w, "sso", err)
		return
	}
	c, err := s.oidcConfig(d)
	if err != nil {
		internalError(w, "sso", err)
		return
	}
	ep, err := c.Discover(ctx)
	if err != nil {
		slog.Warn("SSO: Identity Provider nicht erreichbar", "anbindung", d.ID, "fehler", err)
		writeError(w, http.StatusServiceUnavailable, "Der Identity Provider ist gerade nicht erreichbar. Bitte später erneut versuchen.")
		return
	}
	st := ssoState{Dir: d.ID, State: oidc.Random(24), Nonce: oidc.Random(24), Verifier: oidc.Random(48),
		Expires: s.now().Add(10 * time.Minute).Unix()}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: s.ssoSeal(st), Path: "/", MaxAge: 600,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"weiterleitung": c.AuthURL(ep, s.ssoRedirect(), st.State, st.Nonce, st.Verifier, email)})
}

// handleSSOReturn: Rückkehr vom IdP. Antwortet immer mit einer Umleitung auf
// die Oberfläche; Fehler nur als fester Code (keine Texte vom IdP).
func (s *Server) handleSSOReturn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	back := func(code string) {
		target := "/"
		if code != "" {
			target = "/?sso=" + code
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
	clear := func() {
		http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode})
	}
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		back("zu-viele")
		return
	}
	c, err := r.Cookie(ssoCookie)
	if err != nil {
		back("abgelaufen")
		return
	}
	st, ok := s.ssoOpen(c.Value)
	clear()
	q := r.URL.Query()
	if !ok || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 || st.State == "" {
		back("abgelaufen")
		return
	}
	if q.Get("error") != "" {
		back("abgebrochen")
		return
	}
	var d dirRow
	err = s.pool.QueryRow(ctx, `SELECT d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem,
		d.bind_pass_enc, d.nested_groups, d.email_claim FROM openwacht.directory_oidc($1) d`, st.Dir).
		Scan(&d.ID, &d.Tenant, &d.URL, &d.BindDN, &d.BaseDN, &d.CAPEM, &d.PassEnc, &d.Nested, &d.EmailClaim)
	if err != nil {
		back("abgelehnt")
		return
	}
	cfg, err := s.oidcConfig(d)
	if err != nil {
		back("fehler")
		return
	}
	ep, err := cfg.Discover(ctx)
	if err != nil {
		back("nicht-erreichbar")
		return
	}
	cl, err := cfg.Exchange(ctx, ep, q.Get("code"), st.Verifier, s.ssoRedirect(), st.Nonce)
	if err != nil {
		slog.Warn("SSO: Anmeldung abgelehnt", "anbindung", d.ID, "fehler", err)
		back("abgelehnt")
		return
	}
	email, err := s.accountEmail(ctx, d.ID, verzeichnis.User{UPN: cl.Email})
	if err != nil {
		back("fehler")
		return
	}
	if email == "" {
		slog.Warn("SSO: Adresse passt zu keiner Domäne der Anbindung", "anbindung", d.ID)
		back("keine-rechte")
		return
	}
	var id *string
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.directory_user_sync($1, $2, $3, $4, $5, true)::text`,
		d.ID, cl.Subject, email, cl.Name, cl.Groups).Scan(&id); err != nil {
		slog.Warn("SSO: Konto nicht abgeglichen", "anbindung", d.ID, "fehler", err)
		back("fehler")
		return
	}
	if id == nil {
		back("keine-rechte")
		return
	}
	src := s.loginSource(r)
	if s.loginBlocked(ctx, *id, src) {
		back("keine-rechte")
		return
	}
	var totp bool
	if err := s.pool.QueryRow(ctx, `SELECT totp_enabled FROM openwacht.auth_state($1)`, *id).Scan(&totp); err != nil {
		back("fehler")
		return
	}
	if totp {
		raw, th, err := newToken()
		if err != nil {
			back("fehler")
			return
		}
		lt := s.cfg.PendingLifetime
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.session_create($1, $2, 'zweiter_faktor', $3, $4)`, *id, th, lt, lt); err != nil {
			back("fehler")
			return
		}
		s.setCookie(w, pendingCookie, raw, lt)
		back("zweiter-faktor")
		return
	}
	if _, err := s.newSession(ctx, w, *id, src); err != nil {
		back("fehler")
		return
	}
	back("")
}

// newSession legt die volle Sitzung an und setzt das Cookie.
// src ist die Quelle der Anmeldung (loginSource); sie gilt danach als bekannt.
func (s *Server) newSession(ctx context.Context, w http.ResponseWriter, userID string, src []byte) (tokenHash []byte, err error) {
	if _, err := s.pool.Exec(ctx, `SELECT openwacht.auth_login_succeeded($1, $2)`, userID, src); err != nil {
		return nil, err
	}
	raw, th, err := newToken()
	if err != nil {
		return nil, err
	}
	// Höchstdauer: Standard der Zentrale, für Konten einer Anbindung
	// höchstens deren Einstellung (Etappe 30, I2).
	lifetime := s.cfg.SessionLifetime
	var max *time.Duration
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.session_max_for($1)`, userID).Scan(&max); err != nil {
		return nil, err
	}
	if max != nil && *max > 0 && *max < lifetime {
		lifetime = *max
	}
	idle := s.cfg.SessionIdle
	if idle > lifetime {
		idle = lifetime
	}
	if _, err := s.pool.Exec(ctx, `SELECT openwacht.session_create($1, $2, 'voll', $3, $4)`,
		userID, th, idle, lifetime); err != nil {
		return nil, err
	}
	s.auditAuth(ctx, userID, "anmeldung.erfolg", nil, true)
	s.setCookie(w, sessionCookie, raw, lifetime)
	return th, nil
}
