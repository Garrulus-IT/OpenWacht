// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/oidc/oidctest"
)

// raw: Anfrage ohne Umleitungen zu folgen, mit den Cookies des Clients.
func (c *client) raw(method, path string, body any, header map[string]string) (*http.Response, string) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return resp, string(b)
}

// ssoLogin: Start, IdP, Rückkehr. Liefert das Ziel der letzten Umleitung.
func ssoLogin(t *testing.T, srv *httptest.Server, p *oidctest.IdP, email string, tamper func(q url.Values)) (*client, string) {
	t.Helper()
	c := newClient(t, srv)
	r := c.do("POST", "/api/v1/sitzung/sso", map[string]string{"email": email})
	if r.status != 200 {
		t.Fatalf("SSO-Start %s: %d %s", email, r.status, r.raw)
	}
	pool := x509.NewCertPool()
	pool.AddCert(p.Server.Certificate())
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(r.body["weiterleitung"].(string))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Path != ssoPath {
		t.Fatalf("Rückkehr-Adresse: %v", resp.Header.Get("Location"))
	}
	q := loc.Query()
	if tamper != nil {
		tamper(q)
	}
	back, _ := c.raw("GET", ssoPath+"?"+q.Encode(), nil, nil)
	if back.StatusCode != http.StatusSeeOther {
		t.Fatalf("Rückkehr: %d", back.StatusCode)
	}
	return c, back.Header.Get("Location")
}

func oidcBody(p *oidctest.IdP) map[string]any {
	return map[string]any{
		"art": "oidc", "mandant": ids["Fertigung"], "name": "Keycloak", "url": p.Issuer, "client_id": p.ClientID,
		"passwort": p.Secret, "ca": p.CAPEM, "domaenen": []string{"sso.test"},
		"gruppen": []map[string]any{
			{"gruppe": "ow-admins", "mandant": ids["Lager Nord"], "rolle": "admin"},
			{"gruppe": "ow-ops", "mandant": ids["Fertigung"], "rolle": "operator"},
		},
	}
}

func TestSSOAnmeldung(t *testing.T) {
	s, srv := settingsServer(t, Config{})
	resetSettings(t)
	cleanDirectories(t)
	t.Cleanup(func() { cleanDirectories(t); resetSettings(t) })
	ctx := context.Background()
	p := oidctest.Start(t)

	fw := loginOn(t, srv, "v_fw")
	body := oidcBody(p)
	body["code"] = freshCode(t, "v_fw")
	expectStatus(t, "ohne Netzfreigabe", fw.do("POST", "/api/v1/verzeichnisse", body), 502)
	s.ldapDialOverride = (&net.Dialer{}).DialContext
	for name, mod := range map[string]func(m map[string]any){
		"http-Issuer":     func(m map[string]any) { m["url"] = strings.Replace(p.Issuer, "https", "http", 1) },
		"falscher Issuer": func(m map[string]any) { m["url"] = p.Issuer + "x" },
		"NetBIOS":         func(m map[string]any) { m["netbios"] = "FIRMA" },
		"ohne Client-ID":  func(m map[string]any) { m["client_id"] = "" },
		"Claim":           func(m map[string]any) { m["gruppen_claim"] = "a b" },
		"Art":             func(m map[string]any) { m["art"] = "saml" },
		"Adress-Claim":    func(m map[string]any) { m["adress_claim"] = "sub" },
	} {
		b := oidcBody(p)
		mod(b)
		b["code"] = freshCode(t, "v_fw")
		if r := fw.do("POST", "/api/v1/verzeichnisse", b); r.status < 400 {
			t.Errorf("%s angenommen: %s", name, r.raw)
		} else if name == "Adress-Claim" && !strings.Contains(r.raw, "Adress-Claim") {
			t.Errorf("Adress-Claim: Meldung %s", r.raw)
		}
	}
	body["code"] = freshCode(t, "v_fw")
	r := fw.do("POST", "/api/v1/verzeichnisse", body)
	expectStatus(t, "anlegen", r, 201)
	dirID, _ := r.body["id"].(string)
	approveDir(t, dirID)
	oa := loginOn(t, srv, "v_oa")
	if l := oa.do("GET", "/api/v1/verzeichnisse", nil); strings.Contains(l.raw, "Keycloak") {
		t.Error("Geschwister sieht OIDC-Anbindung")
	}
	expectStatus(t, "Test", fw.do("POST", "/api/v1/verzeichnisse/"+dirID+"/test", nil), 200)

	// Anmeldung mit Gruppen
	p.SetUser(map[string]any{"sub": "kc-anna", "email": "anna@sso.test", "name": "Anna SSO", "groups": []string{"ow-admins"}})
	c, loc := ssoLogin(t, srv, p, "anna@sso.test", nil)
	if loc != "/" {
		t.Fatalf("Ziel: %s", loc)
	}
	me := c.do("GET", "/api/v1/ich", nil)
	if me.status != 200 || me.body["quelle"] != "oidc" || me.body["email"] != "anna@sso.test" {
		t.Fatalf("ich: %s", me.raw)
	}
	c.csrf, _ = me.body["csrf"].(string)
	if _, _, roles := dirUser(t, "anna@sso.test"); roles != "Lager Nord:admin" {
		t.Errorf("Rollen: %s", roles)
	}
	// Gruppen ändern sich beim nächsten Login
	p.SetUser(map[string]any{"sub": "kc-anna", "email": "anna@sso.test", "name": "Anna SSO", "groups": []string{"ow-ops"}})
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", nil); loc != "/" {
		t.Fatalf("zweite Anmeldung: %s", loc)
	}
	if _, _, roles := dirUser(t, "anna@sso.test"); roles != "Fertigung:operator" {
		t.Errorf("Rollen nach Wechsel: %s", roles)
	}
	// Bestätigung ohne 2FA geht bei SSO nicht (kein Passwort): klare Meldung
	r = c.do("DELETE", "/api/v1/verzeichnisse/00000000-0000-4000-8000-000000000000", map[string]any{"code": "irgendwas"})
	if r.status != 403 || !strings.Contains(r.raw, "Zwei-Faktor") {
		t.Errorf("Bestätigung SSO: %d %s", r.status, r.raw)
	}

	// Negativfälle
	p.SetUser(map[string]any{"sub": "kc-x", "email": "x@sso.test", "groups": []string{"andere"}})
	if _, loc := ssoLogin(t, srv, p, "x@sso.test", nil); loc != "/?sso=keine-rechte" {
		t.Errorf("ohne Gruppe: %s", loc)
	}
	p.SetUser(map[string]any{"sub": "kc-y", "email": "chef@fremd.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "y@sso.test", nil); loc != "/?sso=keine-rechte" {
		t.Errorf("fremde Domäne: %s", loc)
	}
	// Befund M2: unbestätigte email, fremde Adresse in preferred_username/upn → abgelehnt.
	p.SetUser(map[string]any{"sub": "kc-m2", "email": "m2@fremd.test", "email_verified": false,
		"preferred_username": "anna@sso.test", "upn": "anna@sso.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", nil); loc != "/?sso=abgelehnt" {
		t.Errorf("unbestätigte email mit fremdem preferred_username: %s", loc)
	}
	p.SetUser(map[string]any{"sub": "kc-m2b", "preferred_username": "anna@sso.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", nil); loc != "/?sso=keine-rechte" {
		t.Errorf("ohne email, nur preferred_username: %s", loc)
	}
	var m2 int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.users WHERE external_id IN ('kc-m2', 'kc-m2b')`).Scan(&m2)
	if m2 != 0 {
		t.Errorf("%d Konten aus abgelehnten Anmeldungen angelegt", m2)
	}
	// Adress-Claim upn je Anbindung (z. B. Entra ID): dann zählt upn, email nicht.
	if _, err := owner.Exec(ctx, `UPDATE openwacht.directories SET email_claim = 'upn' WHERE id = $1`, dirID); err != nil {
		t.Fatal(err)
	}
	if l := fw.do("GET", "/api/v1/verzeichnisse", nil); !strings.Contains(l.raw, `"adress_claim":"upn"`) {
		t.Errorf("Adress-Claim nicht in der Liste: %s", l.raw)
	}
	p.SetUser(map[string]any{"sub": "kc-upn", "email": "falsch@fremd.test", "email_verified": false, "upn": "upn.nutzer@sso.test",
		"groups": []string{"ow-ops"}})
	if _, loc := ssoLogin(t, srv, p, "upn.nutzer@sso.test", nil); loc != "/" {
		t.Errorf("Anmeldung mit upn: %s", loc)
	}
	if _, _, roles := dirUser(t, "upn.nutzer@sso.test"); roles != "Fertigung:operator" {
		t.Errorf("Konto aus upn: Rollen %q", roles)
	}
	owner.Exec(ctx, `UPDATE openwacht.directories SET email_claim = 'email' WHERE id = $1`, dirID)
	p.SetUser(map[string]any{"sub": "kc-anna", "email": "anna@sso.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", func(q url.Values) { q.Set("state", "falsch") }); loc != "/?sso=abgelaufen" {
		t.Errorf("falscher state: %s", loc)
	}
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", func(q url.Values) { q.Set("error", "access_denied") }); loc != "/?sso=abgebrochen" {
		t.Errorf("abgebrochen: %s", loc)
	}
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", func(q url.Values) { q.Set("code", "erfunden") }); loc != "/?sso=abgelehnt" {
		t.Errorf("falscher Code: %s", loc)
	}
	for name, set := range map[string]*bool{"Nonce": &p.WrongNonce, "Issuer": &p.WrongIssuer, "Audience": &p.WrongAudience, "Ablauf": &p.Expired} {
		p.Reset()
		*set = true
		if _, loc := ssoLogin(t, srv, p, "anna@sso.test", nil); loc != "/?sso=abgelehnt" {
			t.Errorf("%s: %s", name, loc)
		}
	}
	p.Reset()
	// Rückkehr ohne Cookie (fremder Browser)
	c2 := newClient(t, srv)
	if resp, _ := c2.raw("GET", ssoPath+"?code=x&state=y", nil, nil); resp.Header.Get("Location") != "/?sso=abgelaufen" {
		t.Errorf("ohne Cookie: %s", resp.Header.Get("Location"))
	}
	// Manipuliertes Cookie
	c3 := newClient(t, srv)
	c3.cookies[ssoCookie] = &http.Cookie{Name: ssoCookie, Value: s.ssoSeal(ssoState{Dir: dirID, State: "s", Expires: time.Now().Add(time.Hour).Unix()}) + "x"}
	if resp, _ := c3.raw("GET", ssoPath+"?code=x&state=s", nil, nil); resp.Header.Get("Location") != "/?sso=abgelaufen" {
		t.Errorf("manipuliertes Cookie: %s", resp.Header.Get("Location"))
	}
	// SSO-Start für LDAP-/unbekannte Domäne, Passwort-Login für SSO-Domäne
	expectStatus(t, "unbekannte Domäne", newClient(t, srv).do("POST", "/api/v1/sitzung/sso", map[string]string{"email": "a@nirgends.test"}), 404)
	expectStatus(t, "Passwort für SSO-Konto", newClient(t, srv).do("POST", "/api/v1/sitzung",
		map[string]string{"email": "anna@sso.test", "passwort": "irgendein-passwort"}), 401)

	// Mit eingerichteter 2FA: zweiter Schritt
	annaID, _, _ := dirUser(t, "anna@sso.test")
	secret, _ := auth.GenerateTOTPSecret()
	enc, _ := auth.Seal(deriveKey(testKey, "openwacht secretbox v1"), secret, []byte(annaID))
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2, totp_enabled = true, totp_last_step = 0 WHERE id = $1`, annaID, enc)
	c, loc = ssoLogin(t, srv, p, "anna@sso.test", nil)
	if loc != "/?sso=zweiter-faktor" {
		t.Fatalf("mit 2FA: %s", loc)
	}
	expectStatus(t, "ohne Code", c.do("GET", "/api/v1/ich", nil), 401)
	r = c.do("POST", "/api/v1/sitzung/zweiter-faktor", map[string]string{"code": auth.TOTPCode(secret, auth.TOTPStep(time.Now()))})
	expectStatus(t, "Code", r, 200)
	c.csrf, _ = r.body["csrf"].(string)
	expectStatus(t, "ich nach Code", c.do("GET", "/api/v1/ich", nil), 200)

	// Anbindung gelöscht und neu angelegt: das Konto wird übernommen und wieder frei
	expectStatus(t, "löschen", fw.do("DELETE", "/api/v1/verzeichnisse/"+dirID, map[string]any{"code": freshCode(t, "v_fw")}), 200)
	expectStatus(t, "nach Löschen", newClient(t, srv).do("POST", "/api/v1/sitzung/sso", map[string]string{"email": "anna@sso.test"}), 404)
	body["code"] = freshCode(t, "v_fw")
	r = fw.do("POST", "/api/v1/verzeichnisse", body)
	expectStatus(t, "neu anlegen", r, 201)
	dirID, _ = r.body["id"].(string)
	approveDir(t, dirID)
	owner.Exec(ctx, `UPDATE openwacht.users SET totp_last_step = 0 WHERE id = $1`, annaID)
	if _, loc := ssoLogin(t, srv, p, "anna@sso.test", nil); loc != "/?sso=zweiter-faktor" {
		t.Errorf("Übernahme: %s", loc)
	}
	if id, dis, roles := dirUser(t, "anna@sso.test"); id != annaID || dis || roles != "Lager Nord:admin" {
		t.Errorf("Übernahme: %s %v %s", id, dis, roles)
	}

	// Lokale Konten mit gleicher Adresse werden nie übernommen
	hash, _ := auth.HashPassword(testPassword, testParams)
	var localID string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash, disabled)
		VALUES ($1, 'lokal@sso.test', 'Lokal', $2, true) RETURNING id::text`, ids["Fertigung"], hash).Scan(&localID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, localID) })
	owner.Exec(ctx, `UPDATE openwacht.users SET auth_source = 'oidc' WHERE id = $1`, localID) // selbst mit falscher Quelle
	p.SetUser(map[string]any{"sub": "kc-lokal", "email": "lokal@sso.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "lokal@sso.test", nil); loc != "/?sso=fehler" {
		t.Errorf("lokales Konto: %s", loc)
	}
	var adopted *string
	owner.QueryRow(ctx, `SELECT directory_id::text FROM openwacht.users WHERE id = $1`, localID).Scan(&adopted)
	if adopted != nil {
		t.Error("lokales Konto übernommen")
	}

	// Verwaiste Konten anderer Mandanten werden nicht übernommen
	var orphan string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, auth_source, disabled, directory_disabled)
		VALUES ($1, 'waise@sso.test', 'Waise', 'oidc', true, true) RETURNING id::text`, ids["Organisation"]).Scan(&orphan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.users WHERE id = $1`, orphan) })
	p.SetUser(map[string]any{"sub": "kc-waise", "email": "waise@sso.test", "groups": []string{"ow-admins"}})
	if _, loc := ssoLogin(t, srv, p, "waise@sso.test", nil); loc != "/?sso=fehler" {
		t.Errorf("Waise anderer Mandant: %s", loc)
	}

	// Anbindung aus: Start und Rückkehr gehen nicht mehr
	owner.Exec(ctx, `UPDATE openwacht.directories SET enabled = false WHERE id = $1`, dirID)
	expectStatus(t, "Anbindung aus", newClient(t, srv).do("POST", "/api/v1/sitzung/sso", map[string]string{"email": "anna@sso.test"}), 404)
}

func bearer(t *testing.T, srv *httptest.Server, token, method, path string, body any) response {
	t.Helper()
	c := newClient(t, srv)
	c.origin = ""
	resp, raw := c.raw(method, path, body, map[string]string{"Authorization": "Bearer " + token})
	r := response{status: resp.StatusCode, header: resp.Header, raw: raw}
	json.Unmarshal([]byte(raw), &r.body)
	return r
}

func TestAPITokens(t *testing.T) {
	s, srv := settingsServer(t, Config{})
	resetSettings(t)
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = NULL`)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'tok-%'`)
		resetSettings(t)
	})
	fw := loginOn(t, srv, "v_fw")
	create := func(c *client, user, tenant, role string, days int) response {
		return c.do("POST", "/api/v1/api-tokens", map[string]any{"mandant": ids[tenant], "name": "Grafana " + role, "rolle": role,
			"tage": days, "code": freshCode(t, user)})
	}
	for name, r := range map[string]response{
		"Admin-Rolle": create(fw, "v_fw", "Fertigung", "admin", 30),
		"zu lang":     create(fw, "v_fw", "Fertigung", "leser", 366),
		"Eltern":      create(fw, "v_fw", "IT", "leser", 30),
	} {
		if r.status < 400 || r.status >= 500 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	lz := loginOn(t, srv, "v_lz")
	if r := lz.do("POST", "/api/v1/api-tokens", map[string]any{"mandant": ids["Lager Nord"], "name": "x", "rolle": "leser", "tage": 3,
		"code": testPassword}); r.status != 403 {
		t.Errorf("Leser legt Token an: %d %s", r.status, r.raw)
	}
	expectStatus(t, "ohne Code", fw.do("POST", "/api/v1/api-tokens", map[string]any{"mandant": ids["Fertigung"], "name": "x",
		"rolle": "leser", "tage": 3}), 403)
	r := create(fw, "v_fw", "Fertigung", "leser", 30)
	expectStatus(t, "Leser-Token", r, 201)
	leser, _ := r.body["token"].(string)
	leserID, _ := r.body["id"].(string)
	if !strings.HasPrefix(leser, "owt1.") {
		t.Fatalf("Token: %q", leser)
	}
	var stored []byte
	owner.QueryRow(ctx, `SELECT token_hash FROM openwacht.api_tokens WHERE id = $1`, leserID).Scan(&stored)
	if len(stored) != 32 || strings.Contains(string(stored), leser[5:]) {
		t.Error("Token nicht nur als Hash gespeichert")
	}
	r = create(fw, "v_fw", "Fertigung", "operator", 30)
	expectStatus(t, "Operator-Token", r, 201)
	op, _ := r.body["token"].(string)

	// Sicht: Fertigung und darunter, nicht Eltern oder Geschwister
	r = bearer(t, srv, leser, "GET", "/api/v1/mandanten", nil)
	expectStatus(t, "Mandanten per Token", r, 200)
	if !strings.Contains(r.raw, "Lager Nord") || strings.Contains(r.raw, "Organisation") || strings.Contains(r.raw, `"IT"`) {
		t.Errorf("Sicht: %s", r.raw)
	}
	// Leser darf nicht schreiben, Operator schon (ohne CSRF, ohne Origin)
	expectStatus(t, "Leser legt Gerät an", bearer(t, srv, leser, "POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/geraete",
		map[string]any{"name": "tok-leser", "adresse": "192.0.2.10"}), 403)
	expectStatus(t, "Operator legt Gerät an", bearer(t, srv, op, "POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/geraete",
		map[string]any{"name": "tok-op", "adresse": "192.0.2.11"}), 201)
	if r := bearer(t, srv, op, "POST", "/api/v1/mandanten/"+ids["IT"]+"/geraete",
		map[string]any{"name": "tok-it", "adresse": "192.0.2.12"}); r.status != 403 && r.status != 404 {
		t.Errorf("Operator im Eltern-Mandanten: %d", r.status)
	}
	// Keine Sitzung, keine Verwaltung, kein Betrieb
	expectStatus(t, "ich per Token", bearer(t, srv, leser, "GET", "/api/v1/ich", nil), 403)
	expectStatus(t, "Einstellungen per Token", bearer(t, srv, op, "GET", "/api/v1/einstellungen", nil), 403)
	if r := bearer(t, srv, op, "POST", "/api/v1/api-tokens", map[string]any{"mandant": ids["Fertigung"], "name": "x", "rolle": "leser",
		"tage": 3, "code": "x"}); r.status != 403 {
		t.Errorf("Token legt Token an: %d", r.status)
	}
	// 2FA-Pflicht „alle“ betrifft Tokens nicht
	owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = 'alle'`)
	expectStatus(t, "Token bei 2FA-Pflicht", bearer(t, srv, leser, "GET", "/api/v1/mandanten", nil), 200)
	owner.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = NULL`)
	// Ungültige Tokens
	for _, bad := range []string{"", "owt1.", "owt1.abc", "owa1.x.y", strings.Replace(leser, "owt1.", "owt2.", 1), leser[:len(leser)-2] + "AA"} {
		expectStatus(t, "ungültig "+bad, bearer(t, srv, bad, "GET", "/api/v1/mandanten", nil), 401)
	}
	// Rolle und Passwort des Token-Kontos sind fest
	var tokUser string
	owner.QueryRow(ctx, `SELECT user_id::text FROM openwacht.api_tokens WHERE id = $1`, leserID).Scan(&tokUser)
	if r := fw.do("PUT", "/api/v1/benutzer/"+tokUser+"/rollen/"+ids["Fertigung"], map[string]any{"rolle": "admin"}); r.status < 400 {
		t.Errorf("Rolle des Tokens geändert: %s", r.raw)
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.role_assignments SET role = 'admin' WHERE user_id = $1`, tokUser); err == nil {
		t.Error("Token-Konto als Admin (Eigentümer)")
	}
	if _, err := owner.Exec(ctx, `UPDATE openwacht.users SET password_hash = 'x' WHERE id = $1`, tokUser); err == nil {
		t.Error("Token-Konto mit Passwort")
	}
	if l := fw.do("GET", "/api/v1/benutzer?mandant="+ids["Fertigung"], nil); strings.Contains(l.raw, "API-Token") {
		t.Error("Token-Konto in der Benutzerliste")
	}
	// Liste: Fertigung und Eltern sehen sie, Geschwister nicht
	if l := fw.do("GET", "/api/v1/api-tokens", nil); len(l.body["tokens"].([]any)) < 2 || strings.Contains(l.raw, leser[5:]) {
		t.Errorf("Liste: %s", l.raw)
	}
	oa := loginOn(t, srv, "v_oa")
	if l := oa.do("GET", "/api/v1/api-tokens", nil); len(l.body["tokens"].([]any)) != 0 {
		t.Errorf("Geschwister sieht Tokens: %s", l.raw)
	}
	expectStatus(t, "Geschwister widerruft", oa.do("DELETE", "/api/v1/api-tokens/"+leserID, nil), 404)
	it := loginOn(t, srv, "v_it")
	if l := it.do("GET", "/api/v1/api-tokens", nil); !strings.Contains(l.raw, leserID) {
		t.Error("Eltern sieht Token nicht")
	}
	// Rate Limit je Token
	s.apiTokenRate = newRateWindow(2)
	bearer(t, srv, op, "GET", "/api/v1/mandanten", nil)
	bearer(t, srv, op, "GET", "/api/v1/mandanten", nil)
	if r := bearer(t, srv, op, "GET", "/api/v1/mandanten", nil); r.status != 429 {
		t.Errorf("Rate Limit: %d", r.status)
	}
	expectStatus(t, "anderes Token nicht betroffen", bearer(t, srv, leser, "GET", "/api/v1/mandanten", nil), 200)
	s.apiTokenRate = newRateWindow(apiTokenLimit)
	// Widerrufen und Ablauf
	expectStatus(t, "widerrufen", fw.do("DELETE", "/api/v1/api-tokens/"+leserID, nil), 200)
	expectStatus(t, "nach Widerruf", bearer(t, srv, leser, "GET", "/api/v1/mandanten", nil), 401)
	expectStatus(t, "zweimal widerrufen", fw.do("DELETE", "/api/v1/api-tokens/"+leserID, nil), 404)
	owner.Exec(ctx, `UPDATE openwacht.api_tokens SET expires_at = now() - interval '1 second' WHERE token_hash <> $1`, stored)
	expectStatus(t, "abgelaufen", bearer(t, srv, op, "GET", "/api/v1/mandanten", nil), 401)
	var audits int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('api_token.angelegt', 'api_token.widerrufen')`).Scan(&audits)
	if audits < 3 {
		t.Errorf("Audit: %d", audits)
	}
}
