// SPDX-License-Identifier: AGPL-3.0-only

// Package oidctest ist ein kleiner Identity Provider für Tests (Discovery,
// Authorize, Token, JWKS). ID-Tokens sind echt signiert (RS256 oder ES256),
// die Schlüssel lassen sich rotieren. Nur Testdaten.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
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

	// Signatur: Alg ist "RS256" (Standard) oder "ES256"; zum Testen auch
	// "none", "HS256" (mit dem Client-Secret) oder "PS256" (als RS256-Kopf
	// mit falschem Namen). BadSignature kippt ein Bit der Signatur,
	// UnknownKid setzt ein kid, das der JWKS nicht kennt, NoKid lässt es weg,
	// KeyInHeader legt den Schlüssel als jwk in den Kopf.
	Alg                                          string
	BadSignature, UnknownKid, NoKid, KeyInHeader bool
	// JWKSRequests zählt die Abrufe des JWKS (Cache, Rotation).
	JWKSRequests int
	// JWKSDown: JWKS antwortet mit 503.
	JWKSDown bool
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	kid      int
	retired  []map[string]string // ältere öffentliche Schlüssel, die noch im JWKS stehen
}

var (
	rsaOnce sync.Once
	rsaPool []*rsa.PrivateKey
)

// testRSAKey: RSA-Schlüssel sind langsam zu erzeugen; ein kleiner Vorrat
// für alle Tests eines Pakets.
func testRSAKey(i int) *rsa.PrivateKey {
	rsaOnce.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaPool = append(rsaPool, k)
		}
	})
	return rsaPool[i%len(rsaPool)]
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *IdP) kidName() string { return fmt.Sprintf("schluessel-%d", p.kid) }

func (p *IdP) publicJWKs() []map[string]string {
	pad := func(b []byte, n int) []byte { return append(make([]byte, n-len(b)), b...) }
	ecx, ecy := p.ecKey.PublicKey.X.Bytes(), p.ecKey.PublicKey.Y.Bytes()
	keys := []map[string]string{
		{"kty": "RSA", "use": "sig", "kid": p.kidName() + "-rsa", "n": b64(p.rsaKey.N.Bytes()),
			"e": b64(big.NewInt(int64(p.rsaKey.E)).Bytes())},
		{"kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256", "kid": p.kidName() + "-ec",
			"x": b64(pad(ecx, 32)), "y": b64(pad(ecy, 32))},
		// Schlüssel zum Verschlüsseln: muss übergangen werden
		{"kty": "RSA", "use": "enc", "kid": "verschluesseln", "n": b64(testRSAKey(2).N.Bytes()), "e": "AQAB"},
	}
	return append(keys, p.retired...)
}

// RotateKeys erzeugt neue Signaturschlüssel (neues kid). keepOld: die alten
// bleiben im JWKS stehen (übliche Rotation); sonst sind sie sofort weg.
func (p *IdP) RotateKeys(keepOld bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if keepOld {
		p.retired = append(p.retired, p.publicJWKs()[:2]...)
	} else {
		p.retired = nil
	}
	p.kid++
	p.rsaKey = testRSAKey(p.kid)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	p.ecKey = ec
}

// sign baut das ID-Token (p.mu ist gesperrt).
func (p *IdP) sign(claims map[string]any) string {
	alg := p.Alg
	if alg == "" {
		alg = "RS256"
	}
	head := map[string]any{"alg": alg, "typ": "JWT"}
	switch alg {
	case "ES256":
		head["kid"] = p.kidName() + "-ec"
	default:
		head["kid"] = p.kidName() + "-rsa"
	}
	if p.UnknownKid {
		head["kid"] = "unbekannt"
	}
	if p.NoKid {
		delete(head, "kid")
	}
	if p.KeyInHeader {
		head["jwk"] = p.publicJWKs()[0]
	}
	hb, _ := json.Marshal(head)
	cb, _ := json.Marshal(claims)
	signed := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	switch alg {
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, p.ecKey, sum[:])
		if err != nil {
			panic(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "HS256":
		m := hmac.New(sha256.New, []byte(p.Secret))
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	case "none":
		sig = nil
	default: // RS256, PS256 (falscher Name, gleiche Bytes)
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
	}
	if p.BadSignature && len(sig) > 0 {
		sig[len(sig)/2] ^= 1
	}
	return signed + "." + b64(sig)
}

type grant struct {
	nonce, challenge, redirect string
	claims                     map[string]any
}

// Start startet den IdP mit eigener CA.
func Start(t *testing.T) *IdP {
	t.Helper()
	p := &IdP{ClientID: "openwacht", Secret: "test-secret-123", codes: map[string]grant{}, kid: -1}
	p.RotateKeys(false)
	mux := http.NewServeMux()
	p.Server = httptest.NewUnstartedServer(mux)
	p.Server.StartTLS()
	t.Cleanup(p.Server.Close)
	p.Issuer = p.Server.URL + "/realms/test"
	p.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Server.Certificate().Raw}))
	mux.HandleFunc("GET /realms/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.Issuer,
			"authorization_endpoint": p.Issuer + "/auth", "token_endpoint": p.Issuer + "/token",
			"jwks_uri": p.Issuer + "/certs"})
	})
	mux.HandleFunc("GET /realms/test/certs", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.JWKSRequests++
		if p.JWKSDown {
			http.Error(w, "nicht verfügbar", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": p.publicJWKs()})
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
		tok := p.sign(claims)
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
	p.Alg, p.BadSignature, p.UnknownKid, p.NoKid, p.KeyInHeader, p.JWKSDown = "", false, false, false, false, false
	p.mu.Unlock()
}

// Set ändert Felder unter der Sperre (für Tests mit parallelen Anfragen).
func (p *IdP) Set(f func(p *IdP)) {
	p.mu.Lock()
	f(p)
	p.mu.Unlock()
}
