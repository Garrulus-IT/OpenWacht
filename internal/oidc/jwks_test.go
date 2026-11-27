// SPDX-License-Identifier: AGPL-3.0-only

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/oidc/oidctest"
)

func jwksSetup(t *testing.T) (*oidctest.IdP, Config) {
	p := oidctest.Start(t)
	p.SetUser(map[string]any{"sub": "u-1", "email": "anna@firma.test"})
	return p, Config{Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: p.Secret, CAPEM: p.CAPEM, Keys: NewKeyCache()}
}

func TestSignaturGueltig(t *testing.T) {
	p, c := jwksSetup(t)
	for _, alg := range []string{"RS256", "ES256"} {
		p.Set(func(p *oidctest.IdP) { p.Alg = alg })
		if cl, err := login(t, c, p); err != nil || cl.Subject != "u-1" {
			t.Fatalf("%s: %+v %v", alg, cl, err)
		}
	}
	// ohne kid: es gibt je Verfahren genau einen Schlüssel
	p.Set(func(p *oidctest.IdP) { p.Alg, p.NoKid = "ES256", true })
	if _, err := login(t, c, p); err != nil {
		t.Fatalf("ohne kid: %v", err)
	}
}

func TestSignaturAbgelehnt(t *testing.T) {
	p, c := jwksSetup(t)
	for name, f := range map[string]func(p *oidctest.IdP){
		"none":               func(p *oidctest.IdP) { p.Alg = "none" },
		"HS256 mit Secret":   func(p *oidctest.IdP) { p.Alg = "HS256" },
		"PS256":              func(p *oidctest.IdP) { p.Alg = "PS256" },
		"Signatur verändert": func(p *oidctest.IdP) { p.BadSignature = true },
		"ES256 verändert":    func(p *oidctest.IdP) { p.Alg, p.BadSignature = "ES256", true },
		"kid unbekannt":      func(p *oidctest.IdP) { p.UnknownKid = true },
		"Schlüssel im Kopf":  func(p *oidctest.IdP) { p.KeyInHeader = true },
	} {
		p.Reset()
		p.Set(f)
		if cl, err := login(t, c, p); !errors.Is(err, ErrRejected) || cl.Subject != "" {
			t.Errorf("%s: angenommen: %+v %v", name, cl, err)
		}
	}
	// RS256-Kopf, aber Schlüssel nur als EC vorhanden: kein Mischen der Verfahren
	keys := []verifyKey{{kid: "a", alg: "ES256"}}
	if _, ok := pick(keys, jwsHeader{Alg: "RS256", Kid: "a"}); ok {
		t.Fatal("Verfahren gemischt")
	}
	// Nutzdaten nach dem Signieren geändert
	p.Reset()
	tok := signedToken(t, c, p)
	parts := strings.Split(tok, ".")
	var cl map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(b, &cl)
	cl["email"] = "chef@firma.test"
	b, _ = json.Marshal(cl)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
	ep, _ := c.Discover(context.Background())
	if err := c.VerifySignature(context.Background(), ep, forged); !errors.Is(err, ErrRejected) {
		t.Fatalf("veränderte Nutzdaten: %v", err)
	}
	if err := c.VerifySignature(context.Background(), ep, tok); err != nil {
		t.Fatalf("unverändert: %v", err)
	}
}

// signedToken holt ein echtes Token vom Token-Endpunkt, ohne es zu prüfen.
func signedToken(t *testing.T, c Config, p *oidctest.IdP) string {
	t.Helper()
	ctx := context.Background()
	ep, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce, ver := Random(16), Random(16), Random(32)
	hc, _ := c.client()
	resp, err := hc.Get(c.AuthURL(ep, "https://ow.test/rueckkehr", state, nonce, ver, ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://ow.test/rueckkehr"}, "code_verifier": {ver}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ep.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	r2, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := readJSON(r2, &tok); err != nil {
		t.Fatal(err)
	}
	return tok.IDToken
}

func TestSchluesselCacheUndRotation(t *testing.T) {
	p, c := jwksSetup(t)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	count := func() int {
		var n int
		p.Set(func(p *oidctest.IdP) { n = p.JWKSRequests })
		return n
	}
	for i := 0; i < 3; i++ {
		if _, err := login(t, c, p); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("JWKS %d-mal geladen, erwartet einmal (Cache)", n)
	}
	// Rotation mit Übergang: neues kid → einmal neu laden, dann wieder aus dem Cache
	p.RotateKeys(true)
	now = now.Add(2 * time.Minute)
	if _, err := login(t, c, p); err != nil {
		t.Fatalf("nach Rotation: %v", err)
	}
	if _, err := login(t, c, p); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("nach Rotation %d Abrufe, erwartet 2", n)
	}
	// Unbekanntes kid lädt höchstens einmal je Minute neu
	p.Set(func(p *oidctest.IdP) { p.UnknownKid = true })
	for i := 0; i < 3; i++ {
		if _, err := login(t, c, p); !errors.Is(err, ErrRejected) {
			t.Fatalf("unbekanntes kid: %v", err)
		}
	}
	if n := count(); n != 2 {
		t.Fatalf("unbekanntes kid: %d Abrufe (letzter Abruf ist keine Minute her)", n)
	}
	now = now.Add(2 * time.Minute)
	login(t, c, p)
	if n := count(); n != 3 {
		t.Fatalf("nach einer Minute: %d Abrufe, erwartet 3", n)
	}
	p.Reset()
	// harte Rotation (alter Schlüssel sofort weg) und JWKS kurz nicht erreichbar:
	// Mit gültigem Cache gelingt die Anmeldung mit dem bekannten Schlüssel weiter.
	p.Set(func(p *oidctest.IdP) { p.JWKSDown = true })
	if _, err := login(t, c, p); err != nil {
		t.Fatalf("JWKS aus, Schlüssel im Cache: %v", err)
	}
	// Nach Ablauf des Caches ohne JWKS: keine Anmeldung
	now = now.Add(jwksTTL + time.Minute)
	if _, err := login(t, c, p); err == nil {
		t.Fatal("ohne JWKS und ohne Cache angemeldet")
	}
	p.Set(func(p *oidctest.IdP) { p.JWKSDown = false })
	now = now.Add(2 * time.Minute)
	p.RotateKeys(false)
	if _, err := login(t, c, p); err != nil {
		t.Fatalf("nach harter Rotation: %v", err)
	}
}

func TestJWKSLesen(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	weak := map[string]string{"kty": "RSA", "kid": "klein", "n": b64(small.N.Bytes()), "e": "AQAB"}
	offCurve := map[string]string{"kty": "EC", "crv": "P-256", "kid": "daneben", "x": b64(make([]byte, 32)), "y": b64(append(make([]byte, 31), 1))}
	p384 := map[string]string{"kty": "EC", "crv": "P-384", "kid": "p384", "x": b64(make([]byte, 48)), "y": b64(make([]byte, 48))}
	evenE := map[string]string{"kty": "RSA", "kid": "gerade", "n": b64(testBig(2048).Bytes()), "e": "Ag"}
	ps := map[string]string{"kty": "RSA", "alg": "PS256", "kid": "ps", "n": b64(testBig(2048).Bytes()), "e": "AQAB"}
	b, _ := json.Marshal(map[string]any{"keys": []any{weak, offCurve, p384, evenE, ps}})
	if _, err := parseJWKS(b); err == nil {
		t.Fatal("nur unbrauchbare Schlüssel angenommen")
	}
	good := map[string]string{"kty": "RSA", "kid": "gut", "n": b64(testBig(2048).Bytes()), "e": "AQAB"}
	b, _ = json.Marshal(map[string]any{"keys": []any{weak, good}})
	keys, err := parseJWKS(b)
	if err != nil || len(keys) != 1 || keys[0].kid != "gut" {
		t.Fatalf("Auswahl: %+v %v", keys, err)
	}
	for _, bad := range []string{"", "{}", `{"keys":"x"}`, "[]"} {
		if _, err := parseJWKS([]byte(bad)); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	for _, u := range []string{"", "http://idp.example/certs", "https://", "https://a@idp.example/x", "/certs"} {
		if checkJWKSURI(u) == nil {
			t.Errorf("jwks_uri %q angenommen", u)
		}
	}
}

// testBig: ungerade Zahl mit genau n Bit (als Modulus für Formprüfungen).
func testBig(n int) *big.Int {
	x := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	return x.Add(x, big.NewInt(1))
}

func FuzzJWS(f *testing.F) {
	f.Add(`eyJhbGciOiJSUzI1NiIsImtpZCI6ImEifQ.e30.c2ln`, `{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`)
	f.Add(`eyJhbGciOiJub25lIn0.e30.`, `{"keys":[]}`)
	f.Fuzz(func(t *testing.T, tok, set string) {
		keys, _ := parseJWKS([]byte(set))
		h, signed, sig, err := splitJWS(tok)
		if err != nil {
			return
		}
		if h.Alg != "RS256" && h.Alg != "ES256" {
			t.Fatalf("Verfahren %q durchgelassen", h.Alg)
		}
		if k, ok := pick(keys, h); ok {
			k.verify(h.Alg, signed, sig)
		}
	})
}
