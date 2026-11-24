// SPDX-License-Identifier: AGPL-3.0-only

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/oidc/oidctest"
)

func login(t *testing.T, c Config, p *oidctest.IdP) (Claims, error) {
	t.Helper()
	ctx := context.Background()
	ep, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce, ver := Random(16), Random(16), Random(32)
	u := c.AuthURL(ep, "https://ow.test/rueckkehr", state, nonce, ver, "anna@firma.test")
	hc, _ := c.client()
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != state {
		t.Fatal("state")
	}
	return c.Exchange(ctx, ep, loc.Query().Get("code"), ver, "https://ow.test/rueckkehr", nonce)
}

func TestAnmeldung(t *testing.T) {
	p := oidctest.Start(t)
	c := Config{Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: p.Secret, CAPEM: p.CAPEM}
	p.SetUser(map[string]any{"sub": "u-1", "email": "Anna@Firma.test", "name": "Anna", "groups": []string{"ow-admins", "andere"}})
	cl, err := login(t, c, p)
	if err != nil || cl.Subject != "u-1" || cl.Email != "anna@firma.test" || strings.Join(cl.Groups, ",") != "ow-admins,andere" {
		t.Fatalf("%+v %v", cl, err)
	}
	// eigener Gruppen-Claim, einzelner String; Adresse aus upn nur, wenn so eingestellt
	c.GroupClaim = "rollen"
	p.SetUser(map[string]any{"sub": "u-2", "upn": "otto@firma.test", "rollen": "ops"})
	if cl, err := login(t, c, p); err != nil || cl.Email != "" {
		t.Fatalf("upn ohne Einstellung als Adresse genommen: %+v %v", cl, err)
	}
	c.EmailClaim = "upn"
	if cl, err := login(t, c, p); err != nil || cl.Email != "otto@firma.test" || strings.Join(cl.Groups, ",") != "ops" {
		t.Fatalf("%+v %v", cl, err)
	}
	c.EmailClaim = ""
	// Befund M2: unbestätigte email plus fremdes preferred_username/upn → abgelehnt,
	// kein Rückfall auf die anderen Claims.
	p.SetUser(map[string]any{"sub": "u-3", "email": "chef@firma.test", "email_verified": false,
		"preferred_username": "buergermeister@firma.test", "upn": "it-leitung@firma.test"})
	if cl, err := login(t, c, p); !errors.Is(err, ErrRejected) || cl.Email != "" {
		t.Fatalf("unbestätigt: %+v %v", cl, err)
	}
	// Ohne email: auch kein Rückfall auf preferred_username.
	p.SetUser(map[string]any{"sub": "u-4", "preferred_username": "buergermeister@firma.test"})
	if cl, err := login(t, c, p); err != nil || cl.Email != "" {
		t.Fatalf("Rückfall auf preferred_username: %+v %v", cl, err)
	}
	// email_verified als Text o. Ä. gilt nicht als bestätigt.
	p.SetUser(map[string]any{"sub": "u-5", "email": "chef@firma.test", "email_verified": "true"})
	if _, err := login(t, c, p); !errors.Is(err, ErrRejected) {
		t.Fatalf("email_verified als Text: %v", err)
	}
	// Bei Claim upn spielt email_verified keine Rolle.
	c.EmailClaim = "upn"
	p.SetUser(map[string]any{"sub": "u-6", "email": "x@firma.test", "email_verified": false, "upn": "otto@firma.test"})
	if cl, err := login(t, c, p); err != nil || cl.Email != "otto@firma.test" {
		t.Fatalf("upn mit unbestätigter email: %+v %v", cl, err)
	}
	c.EmailClaim = "sub"
	p.SetUser(map[string]any{"sub": "a@firma.test"})
	if _, err := login(t, c, p); !errors.Is(err, ErrRejected) {
		t.Fatalf("unerlaubter Adress-Claim: %v", err)
	}
	c.EmailClaim = ""
	// Negativfälle
	for name, set := range map[string]*bool{"Issuer": &p.WrongIssuer, "Audience": &p.WrongAudience, "Ablauf": &p.Expired, "Nonce": &p.WrongNonce} {
		p.Reset()
		*set = true
		p.SetUser(map[string]any{"sub": "u-1"})
		if _, err := login(t, c, p); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p.Reset()
	bad := c
	bad.ClientSecret = "falsch"
	if _, err := login(t, bad, p); err == nil {
		t.Error("falsches Secret")
	}
	noCA := c
	noCA.CAPEM = ""
	if _, err := noCA.Discover(context.Background()); err == nil {
		t.Error("fremde CA angenommen")
	}
	other := c
	other.Issuer = p.Issuer + "/x"
	if _, err := other.Discover(context.Background()); err == nil {
		t.Error("Discovery mit falschem Issuer")
	}
}

func TestVerify(t *testing.T) {
	c := Config{Issuer: "https://idp.test", ClientID: "ow", Now: func() time.Time { return time.Unix(1000, 0) }}
	tok := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".x"
	}
	base := func() map[string]any {
		return map[string]any{"iss": "https://idp.test", "aud": []string{"ow"}, "exp": 2000, "nonce": "n", "sub": "s"}
	}
	if _, err := c.Verify(tok(base()), "n"); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(m map[string]any){
		"mehrere aud ohne azp": func(m map[string]any) { m["aud"] = []string{"ow", "x"} },
		"fremder azp":          func(m map[string]any) { m["azp"] = "x" },
		"ohne exp":             func(m map[string]any) { delete(m, "exp") },
		"ohne sub":             func(m map[string]any) { delete(m, "sub") },
		"aud fehlt":            func(m map[string]any) { delete(m, "aud") },
	} {
		m := base()
		mod(m)
		if _, err := c.Verify(tok(m), "n"); err == nil {
			t.Errorf("%s angenommen", name)
		}
	}
	if _, err := c.Verify(tok(base()), ""); err == nil {
		t.Error("leere Nonce angenommen")
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[]")) + ".c"} {
		if _, err := c.Verify(bad, "n"); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	if ValidateIssuer("http://idp.test") == nil || ValidateIssuer("https://idp.test?x=1") == nil || ValidateIssuer("https://idp.test/realms/a") != nil {
		t.Error("ValidateIssuer")
	}
	_ = http.StatusOK
}
