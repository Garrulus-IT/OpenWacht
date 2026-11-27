// SPDX-License-Identifier: AGPL-3.0-only

package oidc

// Signaturprüfung des ID-Tokens gegen die Schlüssel des Identity Providers
// (JWKS, 1.0.6) als zweite Schicht neben der geprüften TLS-Verbindung zum
// Token-Endpunkt. Nur RS256 (RSA ab 2048 Bit) und ES256 (P-256); „none“,
// HS256 und alles andere wird abgelehnt.
//
// Schlüssel werden je Issuer, JWKS-Adresse und CA zwischengespeichert
// (höchstens jwksTTL). Ein unbekanntes kid lädt die Liste neu (Rotation beim
// IdP), aber höchstens einmal je jwksRefetch, damit ein kaputter IdP die
// Zentrale nicht in eine Schleife zieht.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	jwksTTL     = time.Hour
	jwksRefetch = time.Minute
	jwksMaxKeys = 100
)

// jwk: ein Schlüssel aus dem JWKS (RFC 7517/7518), nur die Felder, die zählen.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// verifyKey: ein geprüfter öffentlicher Schlüssel für genau ein Verfahren.
type verifyKey struct {
	kid string
	alg string // RS256 oder ES256
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
}

// parseJWKS liest die Schlüsselliste. Schlüssel mit anderem Zweck, anderem
// Verfahren oder unpassenden Werten werden übergangen, nicht abgelehnt: Ein
// IdP darf daneben Schlüssel für Verschlüsselung oder PS256 führen.
func parseJWKS(b []byte) ([]verifyKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("JWKS nicht lesbar")
	}
	var out []verifyKey
	for i, raw := range set.Keys {
		if i >= jwksMaxKeys {
			break
		}
		var k jwk
		if json.Unmarshal(raw, &k) != nil || (k.Use != "" && k.Use != "sig") || len(k.Kid) > 200 {
			continue
		}
		switch k.Kty {
		case "RSA":
			if k.Alg != "" && k.Alg != "RS256" {
				continue
			}
			if pub := parseRSA(k.N, k.E); pub != nil {
				out = append(out, verifyKey{kid: k.Kid, alg: "RS256", rsa: pub})
			}
		case "EC":
			if (k.Alg != "" && k.Alg != "ES256") || k.Crv != "P-256" {
				continue
			}
			if pub := parseP256(k.X, k.Y); pub != nil {
				out = append(out, verifyKey{kid: k.Kid, alg: "ES256", ec: pub})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS ohne brauchbaren Schlüssel (RS256 oder ES256)")
	}
	return out, nil
}

func parseRSA(n64, e64 string) *rsa.PublicKey {
	nb, err1 := base64.RawURLEncoding.DecodeString(n64)
	eb, err2 := base64.RawURLEncoding.DecodeString(e64)
	if err1 != nil || err2 != nil || len(nb) > 1024 || len(eb) == 0 || len(eb) > 4 {
		return nil
	}
	n := new(big.Int).SetBytes(nb)
	e := 0
	for _, x := range eb {
		e = e<<8 | int(x)
	}
	// mindestens 2048 Bit (wie bei Passkeys), höchstens 8192; e ungerade und > 1
	if n.BitLen() < 2048 || n.BitLen() > 8192 || e < 3 || e%2 == 0 {
		return nil
	}
	return &rsa.PublicKey{N: n, E: e}
}

func parseP256(x64, y64 string) *ecdsa.PublicKey {
	xb, err1 := base64.RawURLEncoding.DecodeString(x64)
	yb, err2 := base64.RawURLEncoding.DecodeString(y64)
	if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
		return nil
	}
	// ParseUncompressedPublicKey prüft, dass der Punkt auf der Kurve liegt.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, xb...), yb...))
	if err != nil {
		return nil
	}
	return pub
}

// jwsHeader: Kopf des ID-Tokens.
type jwsHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
	Jku  string          `json:"jku"`
	Jwk  json.RawMessage `json:"jwk"`
	X5u  string          `json:"x5u"`
}

// splitJWS zerlegt das Token und liest den Kopf. Schlüssel im Token selbst
// (jwk, jku, x5u) und kritische Erweiterungen werden abgelehnt: Wer das
// Token schreibt, darf nicht bestimmen, womit es geprüft wird.
func splitJWS(tok string) (h jwsHeader, signed, sig []byte, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 64<<10 {
		return h, nil, nil, ErrRejected
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return h, nil, nil, ErrRejected
	}
	if len(h.Crit) > 0 || h.Jku != "" || len(h.Jwk) > 0 || h.X5u != "" {
		return h, nil, nil, fmt.Errorf("%w: Schlüsselangabe im Token", ErrRejected)
	}
	if h.Alg != "RS256" && h.Alg != "ES256" {
		return h, nil, nil, fmt.Errorf("%w: Verfahren %q nicht erlaubt (nur RS256, ES256)", ErrRejected, truncate(h.Alg, 20))
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return h, nil, nil, ErrRejected
	}
	return h, []byte(parts[0] + "." + parts[1]), sig, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// verify prüft die Signatur mit genau diesem Schlüssel.
func (k verifyKey) verify(alg string, signed, sig []byte) bool {
	if alg != k.alg {
		return false
	}
	sum := sha256.Sum256(signed)
	switch alg {
	case "RS256":
		return k.rsa != nil && rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, sum[:], sig) == nil
	case "ES256":
		if k.ec == nil || len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k.ec, sum[:], r, s)
	}
	return false
}

// pick: Schlüssel zum Kopf. Mit kid genau dieser; ohne kid nur, wenn es für
// das Verfahren genau einen gibt.
func pick(keys []verifyKey, h jwsHeader) (verifyKey, bool) {
	var cand []verifyKey
	for _, k := range keys {
		if k.alg != h.Alg {
			continue
		}
		if h.Kid != "" && k.kid == h.Kid {
			return k, true
		}
		if h.Kid == "" {
			cand = append(cand, k)
		}
	}
	if h.Kid == "" && len(cand) == 1 {
		return cand[0], true
	}
	return verifyKey{}, false
}

// KeyCache hält die Schlüssel je IdP. Ohne eigenen Cache nutzt Config den
// gemeinsamen der Zentrale.
type KeyCache struct {
	mu      sync.Mutex
	entries map[string]*keyEntry
}

type keyEntry struct {
	keys    []verifyKey
	fetched time.Time
	tried   time.Time // letzter Abruf, auch erfolgloser
}

// NewKeyCache legt einen leeren Cache an.
func NewKeyCache() *KeyCache { return &KeyCache{entries: map[string]*keyEntry{}} }

var defaultKeys = NewKeyCache()

func (c Config) cacheKey(jwksURI string) string {
	sum := sha256.Sum256([]byte(c.Issuer + "\x00" + jwksURI + "\x00" + c.CAPEM))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) fetchJWKS(ctx context.Context, jwksURI string) ([]verifyKey, error) {
	hc, err := c.client()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	var raw json.RawMessage
	if err := readJSON(resp, &raw); err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	return parseJWKS(raw)
}

// keysFor liefert die Schlüssel aus dem Cache oder lädt sie. refresh = kid
// unbekannt: neu laden, wenn der letzte Abruf länger als jwksRefetch her ist.
func (c Config) keysFor(ctx context.Context, jwksURI string, refresh bool) ([]verifyKey, bool, error) {
	cache := c.Keys
	if cache == nil {
		cache = defaultKeys
	}
	key := c.cacheKey(jwksURI)
	now := c.now()
	cache.mu.Lock()
	e := cache.entries[key]
	if e != nil && len(e.keys) > 0 && now.Sub(e.fetched) < jwksTTL && (!refresh || now.Sub(e.tried) < jwksRefetch) {
		keys := e.keys
		cache.mu.Unlock()
		return keys, false, nil
	}
	if e != nil && len(e.keys) == 0 && now.Sub(e.tried) < jwksRefetch {
		cache.mu.Unlock()
		return nil, false, errors.New("JWKS: letzter Abruf gescheitert, nächster Versuch in einer Minute")
	}
	cache.mu.Unlock()

	keys, err := c.fetchJWKS(ctx, jwksURI)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if e = cache.entries[key]; e == nil {
		e = &keyEntry{}
		if len(cache.entries) > 1000 { // je Anbindung einer; Schutz gegen Wachstum
			cache.entries = map[string]*keyEntry{}
		}
		cache.entries[key] = e
	}
	e.tried = now
	if err != nil {
		// Alte Schlüssel bis zum Ablauf behalten: ein kurzer Ausfall des
		// JWKS-Endpunkts sperrt niemanden aus, dessen Token sie prüfen.
		if len(e.keys) > 0 && now.Sub(e.fetched) < jwksTTL {
			return e.keys, false, nil
		}
		e.keys = nil
		return nil, false, err
	}
	e.keys, e.fetched = keys, now
	return keys, true, nil
}

// VerifySignature prüft die Signatur des ID-Tokens gegen die Schlüssel des
// IdP (jwks_uri aus dem Discovery-Dokument).
func (c Config) VerifySignature(ctx context.Context, ep Endpoints, idToken string) error {
	h, signed, sig, err := splitJWS(idToken)
	if err != nil {
		return err
	}
	if err := checkJWKSURI(ep.JWKS); err != nil {
		return err
	}
	keys, fresh, err := c.keysFor(ctx, ep.JWKS, false)
	if err != nil {
		return err
	}
	k, ok := pick(keys, h)
	if !ok && !fresh {
		// Rotation beim IdP: neuer Schlüssel, den der Cache noch nicht kennt.
		if keys, _, err = c.keysFor(ctx, ep.JWKS, true); err != nil {
			return err
		}
		k, ok = pick(keys, h)
	}
	if !ok {
		return fmt.Errorf("%w: kein passender Schlüssel des Identity Providers (kid %q)", ErrRejected, truncate(h.Kid, 40))
	}
	if !k.verify(h.Alg, signed, sig) {
		return fmt.Errorf("%w: Signatur", ErrRejected)
	}
	return nil
}

func checkJWKSURI(raw string) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 2000 {
		return errors.New("Discovery: jwks_uri fehlt oder ist nicht https")
	}
	return nil
}

// CheckKeys lädt die Schlüssel des IdP ohne Cache (Verbindung prüfen beim
// Anlegen einer Anbindung) und meldet, wie viele brauchbar sind.
func (c Config) CheckKeys(ctx context.Context, ep Endpoints) (int, error) {
	if err := checkJWKSURI(ep.JWKS); err != nil {
		return 0, err
	}
	keys, err := c.fetchJWKS(ctx, ep.JWKS)
	return len(keys), err
}
