// SPDX-License-Identifier: AGPL-3.0-only

// Package oidctest ist ein kleiner Identity Provider für Tests (Discovery,
// Authorize, Token). Nur Testdaten.
package oidctest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// IdP: Anmeldungen laufen ohne Formular. Der nächste Benutzer steht in User.
type IdP struct {
	Server   *httptest.Server
	Issuer   string
	CAPEM    string
	ClientID string
	Secret   string

	mu    sync.Mutex
	User  map[string]any // Claims des nächsten Logins (ohne iss/aud/nonce/exp)
	codes map[string]grant
	// Manipulationen für Negativtests
	WrongIssuer, WrongAudience, Expired, WrongNonce bool
	Requests                                        []url.Values
}

type grant struct {
	nonce, challenge, redirect string
	claims                     map[string]any
}

// Start startet den IdP mit eigener CA.
func Start(t *testing.T) *IdP {
	t.Helper()
	p := &IdP{ClientID: "openwacht", Secret: "test-secret-123", codes: map[string]grant{}}
	mux := http.NewServeMux()
	p.Server = httptest.NewUnstartedServer(mux)
	p.Server.StartTLS()
	t.Cleanup(p.Server.Close)
	p.Issuer = p.Server.URL + "/realms/test"
	p.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Server.Certificate().Raw}))
	mux.HandleFunc("GET /realms/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.Issuer,
			"authorization_endpoint": p.Issuer + "/auth", "token_endpoint": p.Issuer + "/token"})
	})
	// Authorize: leitet sofort mit Code zurück (der Test ruft die Adresse auf).
	mux.HandleFunc("GET /realms/test/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != p.ClientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
			http.Error(w, "bad request", 400)
			return
		}
		p.mu.Lock()
		code := base64.RawURLEncoding.EncodeToString([]byte(time.Now().String() + q.Get("state")))
		p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), claims: p.User}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /realms/test/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		defer p.mu.Unlock()
		p.Requests = append(p.Requests, r.PostForm)
		id, sec, _ := r.BasicAuth()
		g, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || id != p.ClientID || sec != p.Secret || g.redirect != r.PostForm.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		claims := map[string]any{"iss": p.Issuer, "aud": p.ClientID, "nonce": g.nonce, "exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix()}
		for k, v := range g.claims {
			claims[k] = v
		}
		if p.WrongIssuer {
			claims["iss"] = "https://boese.invalid"
		}
		if p.WrongAudience {
			claims["aud"] = "anderer-client"
		}
		if p.Expired {
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
		}
		if p.WrongNonce {
			claims["nonce"] = "falsch"
		}
		b, _ := json.Marshal(claims)
		tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
		json.NewEncoder(w).Encode(map[string]string{"id_token": tok, "access_token": "x", "token_type": "Bearer"})
	})
	return p
}

// SetUser setzt die Claims der nächsten Anmeldung.
func (p *IdP) SetUser(c map[string]any) {
	p.mu.Lock()
	p.User = c
	p.mu.Unlock()
}

// Reset nimmt alle Manipulationen zurück.
func (p *IdP) Reset() {
	p.mu.Lock()
	p.WrongIssuer, p.WrongAudience, p.Expired, p.WrongNonce = false, false, false, false
	p.mu.Unlock()
}
