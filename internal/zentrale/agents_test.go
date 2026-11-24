// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/pki"
)

var (
	agentOnce sync.Once
	agentSrv  *httptest.Server
	agentErr  error
)

// agentServer startet den Agent-Port (TLS 1.3, mTLS) neben dem Verwaltungsserver.
func agentServer(t *testing.T) *httptest.Server {
	t.Helper()
	verwaltungSetup(t)
	agentOnce.Do(func() {
		vServer.cfg.AgentNames = []string{"127.0.0.1"}
		if agentErr = vServer.InitAgentCA(context.Background()); agentErr != nil {
			return
		}
		// Eigener TLS-Listener mit genau der Produktionskonfiguration
		// (httptest.StartTLS würde ein eigenes Zertifikat einsetzen).
		agentSrv = httptest.NewUnstartedServer(vServer.AgentHandler())
		agentSrv.Listener = tls.NewListener(agentSrv.Listener, vServer.AgentTLSConfig())
		agentSrv.Start()
		agentSrv.URL = strings.Replace(agentSrv.URL, "http://", "https://", 1)
	})
	if agentErr != nil {
		t.Fatal(agentErr)
	}
	return agentSrv
}

type testAgent struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	cert tls.Certificate
	id   string
	ca   *x509.CertPool
}

// pinnedClient prüft die Zentrale beim ersten Kontakt nur über den
// CA-Fingerabdruck aus dem Token, wie es der echte Agent tut.
func pinnedClient(fp string) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // ersetzt durch VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			var raw [][]byte
			for _, c := range cs.PeerCertificates {
				raw = append(raw, c.Raw)
			}
			_, err := pki.VerifyPinnedServer(raw, fp, "127.0.0.1", time.Now())
			return err
		},
	}}}
}

func postJSON(c *http.Client, url string, body any) (int, []byte, error) {
	b, _ := json.Marshal(body)
	resp, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

func newCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func register(t *testing.T, token, hostname string) (*testAgent, int, string) {
	t.Helper()
	srv := agentServer(t)
	_, fp, err := agentproto.ParseToken(token)
	if err != nil {
		fp = strings.Repeat("A", 43)
	}
	key, csr := newCSR(t)
	status, body, err := postJSON(pinnedClient(fp), srv.URL+agentproto.PathRegister,
		agentproto.RegisterRequest{Token: token, CSR: csr, Hostname: hostname})
	if err != nil {
		t.Fatalf("Registrierung: %v", err)
	}
	if status != 200 {
		return nil, status, string(body)
	}
	var resp agentproto.RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	a := &testAgent{t: t, key: key, id: resp.AgentID, ca: x509.NewCertPool()}
	a.setCert(resp.Certificate)
	a.ca.AppendCertsFromPEM([]byte(resp.CA))
	return a, status, string(body)
}

func (a *testAgent) setCert(certPEM string) {
	c, err := pki.ParseCertPEM([]byte(certPEM))
	if err != nil {
		a.t.Fatal(err)
	}
	a.cert = tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: a.key, Leaf: c}
}

func (a *testAgent) client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: a.ca, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{a.cert},
	}}}
}

func validSnapshot(host string) agentproto.Snapshot {
	return agentproto.Snapshot{
		CollectedAt: time.Now(), Hostname: host, OS: "Debian GNU/Linux 13", Kernel: "6.12.0", Arch: "amd64",
		AgentVersion: "test", UptimeSec: 100,
		CPU:    agentproto.CPU{Cores: 2, Percent: 7.5, Load1: 0.1},
		Memory: agentproto.Memory{TotalBytes: 4 << 30, AvailableBytes: 2 << 30},
		Disks:  []agentproto.Disk{{Mount: "/", FSType: "ext4", TotalBytes: 10 << 30, FreeBytes: 5 << 30}},
	}
}

func (a *testAgent) report(host string) (int, string) {
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathReport, validSnapshot(host))
	if err != nil {
		return -1, err.Error()
	}
	return status, string(body)
}

func newAgentToken(t *testing.T, user, tenant string, count int) (string, response) {
	t.Helper()
	r := as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/agent-tokens", map[string]any{"notiz": "Test", "anzahl": count})
	tok, _ := r.body["token"].(string)
	return tok, r
}

func agentHosts(t *testing.T, user string) string {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/agents", nil)
	expectStatus(t, "Agents "+user, r, 200)
	var hosts []string
	for _, x := range r.body["agents"].([]any) {
		hosts = append(hosts, x.(map[string]any)["hostname"].(string))
	}
	return strings.Join(hosts, ",")
}

// --- Tests ----------------------------------------------------------------------

func TestAgentRegistrierenUndMelden(t *testing.T) {
	agentServer(t)
	tok, r := newAgentToken(t, "v_fw", "Fertigung", 1)
	expectStatus(t, "Token anlegen", r, 201)
	a, status, body := register(t, tok, "srv-halle1")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	// Einmal-Token: zweite Registrierung scheitert.
	if _, status, _ := register(t, tok, "srv-halle1b"); status != 401 {
		t.Errorf("Token zweimal verwendbar: %d", status)
	}
	if s, b := a.report("srv-halle1"); s != 200 || !strings.Contains(b, "intervall_sekunden") {
		t.Fatalf("Messwerte: %d %s", s, b)
	}
	// Sichtbarkeit: Fertigung und IT ja, Organisation und Lager (Kind) nein.
	for user, want := range map[string]bool{"v_fw": true, "v_it": true, "v_oa": false, "v_lz": false} {
		if got := strings.Contains(agentHosts(t, user), "srv-halle1"); got != want {
			t.Errorf("%s sieht Agent: %v, erwartet %v", user, got, want)
		}
	}
	// Mandant und Messwerte stimmen.
	r = as(t, "v_fw").do("GET", "/api/v1/agents?mandant="+ids["Fertigung"], nil)
	found := false
	for _, x := range r.body["agents"].([]any) {
		m := x.(map[string]any)
		if m["id"] == a.id {
			found = true
			mw, _ := m["messwerte"].(map[string]any)
			if m["mandant_id"] != ids["Fertigung"] || mw == nil || mw["os"] != "Debian GNU/Linux 13" {
				t.Errorf("Agent-Daten: %v", m)
			}
		}
	}
	if !found {
		t.Error("Agent nicht in der Liste der Fertigung")
	}
	var auditTenant string
	owner.QueryRow(context.Background(), `SELECT tenant_id::text FROM openwacht.audit_log
		WHERE action = 'agent.registriert' AND details->>'agent' = $1`, a.id).Scan(&auditTenant)
	if auditTenant != ids["Fertigung"] {
		t.Errorf("Audit agent.registriert: Mandant %q", auditTenant)
	}
}

func TestAgentTokenRechte(t *testing.T) {
	agentServer(t)
	_, r := newAgentToken(t, "v_lz", "Lager Nord", 1)
	expectStatus(t, "Leser legt Token an", r, 403)
	_, r = newAgentToken(t, "v_oa", "Fertigung", 1)
	expectStatus(t, "Organisation legt Token für Fertigung an", r, 403)
	_, r = newAgentToken(t, "v_fw", "IT", 1)
	expectStatus(t, "Fertigung legt Token für IT an", r, 403)
	expectStatus(t, "zu viele", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/agent-tokens",
		map[string]any{"anzahl": 5000}), 400)
	expectStatus(t, "zu lange gültig", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/agent-tokens",
		map[string]any{"gueltig_stunden": 1000}), 400)

	tok, r := newAgentToken(t, "v_fw", "Fertigung", 2)
	expectStatus(t, "Token für 2 Agents", r, 201)
	for i, want := range []int{200, 200, 401} {
		if _, status, _ := register(t, tok, "fw-multi"); status != want {
			t.Errorf("Registrierung %d: %d, erwartet %d", i+1, status, want)
		}
	}

	// Liste ohne Geheimnis; löschen nur im eigenen Bereich.
	tok, _ = newAgentToken(t, "v_fw", "Fertigung", 1)
	list := as(t, "v_fw").do("GET", "/api/v1/mandanten/"+ids["Fertigung"]+"/agent-tokens", nil)
	if strings.Contains(list.raw, tok) || strings.Contains(list.raw, "owa1.") {
		t.Fatal("Token-Liste enthält das Geheimnis")
	}
	tokens, _ := list.body["tokens"].([]any)
	if len(tokens) == 0 {
		t.Fatal("Token nicht in der Liste")
	}
	tid := tokens[0].(map[string]any)["id"].(string)
	expectStatus(t, "Organisation löscht Token", as(t, "v_oa").do("DELETE", "/api/v1/agent-tokens/"+tid, nil), 404)
	expectStatus(t, "Fertigung löscht Token", as(t, "v_fw").do("DELETE", "/api/v1/agent-tokens/"+tid, nil), 204)
	if _, status, _ := register(t, tok, "fw-geloescht"); status != 401 {
		t.Errorf("gelöschtes Token verwendbar: %d", status)
	}
}

func TestAgentTokenAbgelaufenUndFremd(t *testing.T) {
	srv := agentServer(t)
	tok, secret, _ := agentproto.NewToken(vServer.AgentCAFingerprint())
	hash := sha256.Sum256(secret)
	if _, err := owner.Exec(context.Background(), `INSERT INTO openwacht.agent_tokens (token_hash, tenant_id, uses_left, expires_at)
		VALUES ($1, $2, 1, now() - interval '1 minute')`, hash[:], ids["Fertigung"]); err != nil {
		t.Fatal(err)
	}
	if _, status, _ := register(t, tok, "fw-alt"); status != 401 {
		t.Errorf("abgelaufenes Token: %d", status)
	}
	// Token einer anderen Zentrale: Der Agent bricht schon die TLS-Verbindung ab.
	other, _ := pki.NewCA("andere", time.Now())
	foreign, _, _ := agentproto.NewToken(pki.Fingerprint(other.Cert))
	_, csr := newCSR(t)
	if _, _, err := postJSON(pinnedClient(pki.Fingerprint(other.Cert)), srv.URL+agentproto.PathRegister,
		agentproto.RegisterRequest{Token: foreign, CSR: csr, Hostname: "x"}); err == nil {
		t.Error("Agent verbindet sich trotz falschem CA-Fingerabdruck")
	}
	// Und die Zentrale lehnt es selbst auch ab (Client vertraut hier der echten CA).
	realCA := x509.NewCertPool()
	realCA.AddCert(vServer.agent.ca.Cert)
	direct := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: realCA, ServerName: "127.0.0.1"}}}
	if status, body, err := postJSON(direct, srv.URL+agentproto.PathRegister,
		agentproto.RegisterRequest{Token: foreign, CSR: csr, Hostname: "x"}); err != nil || status != 400 ||
		!strings.Contains(string(body), "anderen Zentrale") {
		t.Errorf("fremdes Token: %d %s %v", status, body, err)
	}
}

func TestAgentOhneOderMitFremdemZertifikat(t *testing.T) {
	srv := agentServer(t)
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a, _, _ := register(t, tok, "fw-zert")

	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.ca, ServerName: "127.0.0.1"}}}
	if s, _, _ := postJSON(noCert, srv.URL+agentproto.PathReport, validSnapshot("fw-zert")); s != 401 {
		t.Errorf("ohne Client-Zertifikat: %d", s)
	}
	// Selbst ausgestelltes Zertifikat mit gleicher Agent-ID von einer fremden CA.
	other, _ := pki.NewCA("Angreifer", time.Now())
	_, csr := newCSR(t)
	fake, _ := other.SignAgentCSR(csr, a.id, time.Hour, time.Now())
	evil := &testAgent{t: t, key: a.key, ca: a.ca}
	evil.cert = tls.Certificate{Certificate: [][]byte{fake.Raw}, PrivateKey: a.key, Leaf: fake}
	if s, _ := evil.report("fw-zert"); s == 200 {
		t.Error("Zertifikat einer fremden CA akzeptiert")
	}
	// TLS 1.2 wird abgelehnt.
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.ca, ServerName: "127.0.0.1",
		MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{a.cert}}}}
	if _, _, err := postJSON(old, srv.URL+agentproto.PathReport, validSnapshot("fw-zert")); err == nil {
		t.Error("TLS 1.2 akzeptiert")
	}
	// Ungültige Messwerte.
	bad := validSnapshot("<script>")
	if s, _, _ := postJSON(a.client(), srv.URL+agentproto.PathReport, bad); s != 400 {
		t.Errorf("ungültige Messwerte: %d", s)
	}
}

func TestAgentErneuernUndSperren(t *testing.T) {
	srv := agentServer(t)
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a, _, _ := register(t, tok, "fw-erneuern")
	oldCert := a.cert

	key, csr := newCSR(t)
	s, body, err := postJSON(a.client(), srv.URL+agentproto.PathRenew, agentproto.RenewRequest{CSR: csr})
	if err != nil || s != 200 {
		t.Fatalf("Erneuern: %d %s %v", s, body, err)
	}
	var rr agentproto.RenewResponse
	json.Unmarshal(body, &rr)
	// Die Antwort könnte verloren gehen: Das alte Zertifikat gilt weiter ...
	if s, _ := a.report("fw-erneuern"); s != 200 {
		t.Errorf("altes Zertifikat direkt nach Erneuerung: %d", s)
	}
	// ... bis der Agent das neue benutzt. Danach ist das alte ungültig.
	a.key = key
	a.setCert(rr.Certificate)
	if id, _ := pki.AgentID(a.cert.Leaf); id != a.id {
		t.Errorf("neues Zertifikat mit anderer Agent-ID: %s", id)
	}
	if s, _ := a.report("fw-erneuern"); s != 200 {
		t.Errorf("neues Zertifikat: %d", s)
	}
	stale := &testAgent{t: t, cert: oldCert, ca: a.ca}
	if s, _ := stale.report("fw-erneuern"); s != 401 {
		t.Errorf("altes Zertifikat nach Benutzung des neuen: %d", s)
	}

	expectStatus(t, "Organisation sperrt Fertigung-Agent", as(t, "v_oa").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 404)
	expectStatus(t, "Leser im Lager sperrt", as(t, "v_lz").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 404)
	expectStatus(t, "Fertigung sperrt", as(t, "v_fw").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 204)
	expectStatus(t, "erneut sperren", as(t, "v_fw").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 404)
	if s, _ := a.report("fw-erneuern"); s != 401 {
		t.Errorf("gesperrter Agent meldet: %d", s)
	}
	_, csr = newCSR(t)
	if s, _, _ := postJSON(a.client(), srv.URL+agentproto.PathRenew, agentproto.RenewRequest{CSR: csr}); s != 401 {
		t.Errorf("gesperrter Agent erneuert: %d", s)
	}
	// Entsperren geht auch für den Eigentümer nicht.
	if _, err := owner.Exec(context.Background(), `UPDATE openwacht.agents SET revoked_at = NULL WHERE id = $1`, a.id); err == nil {
		t.Error("Sperre ließ sich aufheben")
	}
}

func TestAgentCABleibtUndBrauchtDenSchluessel(t *testing.T) {
	agentServer(t)
	fp := vServer.AgentCAFingerprint()
	// Zweiter Start mit demselben Schlüssel: dieselbe CA.
	s2, err := New(vServer.cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.InitAgentCA(context.Background()); err != nil || s2.AgentCAFingerprint() != fp {
		t.Fatalf("zweiter Start: %v", err)
	}
	// Mit einem anderen Hauptschlüssel lässt sich die CA nicht öffnen.
	s3, _ := New(vServer.cfg, pool, bytes.Repeat([]byte{7}, 32))
	if err := s3.InitAgentCA(context.Background()); err == nil {
		t.Error("CA mit falschem Hauptschlüssel geöffnet")
	}
}

// Jede Schicht für sich: die Middleware (für künftige Endpunkte ohne eigene
// Prüfung) und die Datenbankfunktion agent_check.
func TestAgentPruefungJeSchicht(t *testing.T) {
	agentServer(t)
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	a, _, _ := register(t, tok, "fw-spaet")
	ctx := context.Background()
	serial := pki.SerialHex(a.cert.Leaf)

	check := func(id, s string) bool {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT openwacht.agent_check($1, $2)`, id, s).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !check(a.id, serial) {
		t.Fatal("agent_check: gültiges Zertifikat abgelehnt")
	}
	if check(a.id, "abc123") {
		t.Error("agent_check: fremde Seriennummer akzeptiert")
	}

	called := false
	h := vServer.requireAgent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	call := func() int {
		called = false
		req := httptest.NewRequest("POST", "/agent/v1/irgendwas", nil)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{a.cert.Leaf}}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if call(); !called {
		t.Fatal("Middleware: gültiger Agent abgewiesen")
	}
	expectStatus(t, "sperren", as(t, "v_fw").do("POST", "/api/v1/agents/"+a.id+"/sperren", nil), 204)
	if code := call(); called || code != 401 {
		t.Errorf("Middleware lässt gesperrten Agent durch: %d", code)
	}
	if check(a.id, serial) {
		t.Error("agent_check: gesperrter Agent gültig")
	}
	req := httptest.NewRequest("POST", "/agent/v1/irgendwas", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("Middleware ohne TLS: %d", rec.Code)
	}
}
