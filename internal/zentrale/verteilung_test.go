// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
)

// insecure: Download-Client wie im Befehl (ohne Zertifikatsprüfung).
var insecure = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: nil}}

func download(t *testing.T, path, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", agentSrv.URL+PathDownload+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// downloadSetup: zwei Schlüssel (aktiv, Reserve), Pakete für Linux und Windows.
func downloadSetup(t *testing.T) (privA, privB ed25519.PrivateKey, pubA, pubB ed25519.PublicKey) {
	t.Helper()
	agentServer(t)
	resetSettings(t)
	ctx := context.Background()
	pubA, privA, _ = ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ = ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys, vServer.cfg.Authenticode, vServer.cfg.AgentURL = "", "", ""
		vServer.agent.download = newIPLimiter(60, time.Minute)
		owner.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
		owner.Exec(ctx, `DELETE FROM openwacht.update_key_revocations`)
		owner.Exec(ctx, `DELETE FROM openwacht.agent_tokens WHERE note = 'Download'`)
		resetSettings(t)
	})
	vServer.cfg.UpdateKeys = keyLine(pubA, "aktiv") + keyLine(pubB, "reserve")
	setOperator(t, "v_it", true)
	return
}

func dlToken(t *testing.T, tenant string) string {
	t.Helper()
	r := as(t, "v_it").do("POST", "/api/v1/mandanten/"+ids[tenant]+"/agent-tokens", map[string]any{"notiz": "Download", "anzahl": 2})
	expectStatus(t, "Token", r, 201)
	return r.body["token"].(string)
}

func TestAgentDownload(t *testing.T) {
	privA, _, pubA, _ := downloadSetup(t)
	ctx := context.Background()
	it := as(t, "v_it")
	tok := dlToken(t, "Fertigung")

	// Ohne Paket: 404, ohne oder mit falschem Token: 401
	if st, _ := download(t, "linux/amd64/signatur", tok); st != 404 {
		t.Errorf("ohne Paket: %d", st)
	}
	bin := []byte("agent-linux-0.40.0")
	expectStatus(t, "Paket", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "linux/amd64", bin), bin), 201)
	winBin := []byte("agent-windows-0.40.0")
	expectStatus(t, "Windows", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "windows/amd64", winBin), winBin), 201)

	foreign, _, _ := agentproto.NewToken(strings.Repeat("ab", 32))
	for name, tk := range map[string]string{"ohne": "", "kaputt": "owa1.xx", "andere Zentrale": foreign,
		"unbekannt": strings.Replace(tok, tok[5:15], "AAAAAAAAAA", 1)} {
		if st, _ := download(t, "linux/amd64", tk); st != 401 {
			t.Errorf("Token %s: %d", name, st)
		}
	}
	// Ohne gültiges Token erfährt niemand, welche Plattformen es gibt.
	if st, _ := download(t, "linux/386", strings.Replace(tok, tok[5:15], "AAAAAAAAAA", 1)); st != 401 {
		t.Errorf("unbekannte Plattform mit falschem Token: %d", st)
	}
	for _, p := range []string{"linux/386", "darwin/arm64", "windows/arm64"} {
		if st, _ := download(t, p, tok); st != 404 {
			t.Errorf("Plattform %s: %d", p, st)
		}
	}

	st, sigText := download(t, "linux/amd64/signatur", tok)
	if st != 200 || !strings.HasPrefix(sigText, update.DownloadHeader+"\nversion 0.40.0\nos linux\narch amd64\n") ||
		!strings.Contains(sigText, "schluessel "+update.KeyID(pubA)+"\n") {
		t.Fatalf("Signatur: %d %q", st, sigText)
	}
	if st, got := download(t, "linux/amd64", tok); st != 200 || got != string(bin) {
		t.Fatalf("Binary: %d", st)
	}
	// Das Token wird nicht verbraucht.
	var left int
	owner.QueryRow(ctx, `SELECT uses_left FROM openwacht.agent_tokens WHERE note = 'Download' AND tenant_id = $1`, ids["Fertigung"]).Scan(&left)
	if left != 2 {
		t.Errorf("Token verbraucht: %d", left)
	}

	// Windows nur mit Authenticode-Fingerabdruck (eigene Liste, unabhängig
	// vom Inhalt von internal/update/authenticode.txt)
	vServer.cfg.Authenticode = "# kein Fingerabdruck\n"
	if st, body := download(t, "windows/amd64", tok); st != 404 || !strings.Contains(body, "Authenticode") {
		t.Errorf("Windows ohne Fingerabdruck: %d %s", st, body)
	}
	vServer.cfg.Authenticode = strings.Repeat("AB", 20) + "\n"
	if st, got := download(t, "windows/amd64", tok); st != 200 || got != string(winBin) {
		t.Errorf("Windows mit Fingerabdruck: %d", st)
	}

	// Neueres Paket mit beschädigtem Inhalt in der DB: nicht ausgeliefert.
	bin2 := []byte("agent-linux-0.41.0")
	expectStatus(t, "Paket 2", uploadUpdate(t, it, signedPackage(t, privA, "0.41.0", "linux/amd64", bin2), bin2), 201)
	if _, err := owner.Exec(ctx, `UPDATE openwacht.agent_updates SET data = convert_to('agent-linux-0.41.X', 'UTF8') WHERE version = '0.41.0'`); err != nil {
		t.Fatal(err)
	}
	if st, _ := download(t, "linux/amd64", tok); st != 500 {
		t.Errorf("beschädigtes Paket ausgeliefert: %d", st)
	}
	// Signatur passt nicht mehr zur Zeile (anderer Hash): fällt auf das ältere zurück.
	owner.Exec(ctx, `UPDATE openwacht.agent_updates SET sha256 = repeat('0', 64) WHERE version = '0.41.0'`)
	if st, s := download(t, "linux/amd64/signatur", tok); st != 200 || !strings.Contains(s, "version 0.40.0\n") {
		t.Errorf("Rückfall auf gültiges Paket: %d %s", st, s)
	}

	// Abgelaufenes Token
	owner.Exec(ctx, `UPDATE openwacht.agent_tokens SET expires_at = now() - interval '1 minute' WHERE note = 'Download'`)
	if st, _ := download(t, "linux/amd64", tok); st != 401 {
		t.Errorf("abgelaufenes Token: %d", st)
	}

	// Ohne Schlüssel im Build: aus
	vServer.cfg.UpdateKeys = noUpdateKeys
	tok2 := dlToken(t, "IT")
	if st, body := download(t, "linux/amd64", tok2); st != 404 || !strings.Contains(body, "Update-Schlüssel") {
		t.Errorf("ohne Schlüssel: %d %s", st, body)
	}
}

func TestAgentDownloadWiderruf(t *testing.T) {
	privA, privB, pubA, pubB := downloadSetup(t)
	it := as(t, "v_it")
	tok := dlToken(t, "Organisation")
	binA := []byte("agent-a-0.40.0")
	expectStatus(t, "A", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "linux/amd64", binA), binA), 201)
	// Reserve B widerruft A; danach gilt nur noch das Paket von B.
	s, _ := update.Sign(privB, update.ManifestFor("0.39.0", "linux", "amd64", []byte("agent-b-0.39.0")), update.KeyID(pubA))
	sig, _ := json.Marshal(s)
	expectStatus(t, "Widerruf", uploadUpdate(t, it, sig, []byte("agent-b-0.39.0")), 201)
	st, text := download(t, "linux/amd64/signatur", tok)
	if st != 200 || !strings.Contains(text, "version 0.39.0\n") || !strings.Contains(text, "widerrufen "+update.KeyID(pubA)+"\n") {
		t.Fatalf("nach Widerruf: %d %s", st, text)
	}
	_ = pubB
}

func TestAgentDownloadBefehle(t *testing.T) {
	privA, _, pubA, pubB := downloadSetup(t)
	it := as(t, "v_it")
	bin := []byte("agent-linux-0.40.0")
	expectStatus(t, "Paket", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "linux/amd64", bin), bin), 201)
	vServer.cfg.AgentURL = agentSrv.URL
	// Admin eines Untermandanten bekommt die Befehle mit dem Token.
	r := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/agent-tokens", map[string]any{"notiz": "Download"})
	expectStatus(t, "Token", r, 201)
	dl, _ := r.body["download"].(map[string]any)
	linux, _ := dl["linux/amd64"].(map[string]any)
	cmd, _ := linux["befehl"].(string)
	tok := r.body["token"].(string)
	if !strings.Contains(cmd, tok) || !strings.Contains(cmd, update.KeyID(pubA)+")") || !strings.Contains(cmd, update.KeyID(pubB)+")") ||
		!strings.Contains(cmd, "--cacert ca.pem") || strings.Contains(cmd, " -k ") {
		t.Fatalf("Befehl: %v", r.body)
	}
	if _, ok := dl["windows/amd64"]; ok {
		t.Error("Windows-Befehl ohne Authenticode")
	}
	// Gerätegebundenes Token liefert dieselben Befehle.
	dev := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/geraete", map[string]any{"name": "dl-geraet"})
	expectStatus(t, "Gerät", dev, 201)
	t.Cleanup(func() { owner.Exec(context.Background(), `DELETE FROM openwacht.devices WHERE name = 'dl-geraet'`) })
	r2 := as(t, "v_fw").do("POST", "/api/v1/geraete/"+dev.body["id"].(string)+"/agent-token", map[string]any{})
	expectStatus(t, "Gerätetoken", r2, 201)
	if d, _ := r2.body["download"].(map[string]any); d["linux/amd64"] == nil {
		t.Errorf("Gerätetoken ohne Befehl: %v", r2.body)
	}
	vServer.cfg.Authenticode = strings.Repeat("CD", 20)
	winBin := []byte("agent-windows")
	expectStatus(t, "Windows", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "windows/amd64", winBin), winBin), 201)
	r3 := as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/agent-tokens", map[string]any{"notiz": "Download"})
	w, _ := r3.body["download"].(map[string]any)["windows/amd64"].(map[string]any)
	if wc, _ := w["befehl"].(string); !strings.Contains(wc, "'"+strings.Repeat("CD", 20)+"'") || !strings.Contains(wc, "Get-AuthenticodeSignature") ||
		!strings.Contains(wc, "--cacert") || strings.Contains(wc, " -k ") {
		t.Errorf("Windows-Befehl: %v", w)
	}
}

// TestDownloadSkriptMitOpenSSL führt den Prüfteil des Linux-Befehls mit sh,
// curl und openssl aus: gegen die echte Zentrale und gegen eine Zentrale, die
// fälscht (anderes Binary, andere Version, unbekannter Schlüssel).
func TestDownloadSkriptMitOpenSSL(t *testing.T) {
	for _, tool := range []string{"sh", "curl", "openssl", "sha256sum", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " fehlt")
		}
	}
	if out, _ := exec.Command("openssl", "version").Output(); !strings.HasPrefix(string(out), "OpenSSL 3") {
		t.Skip("braucht OpenSSL 3 (pkeyutl -rawin)")
	}
	privA, _, pubA, _ := downloadSetup(t)
	it := as(t, "v_it")
	bin := []byte("#!/bin/sh\necho agent 0.40.0\n")
	expectStatus(t, "Paket", uploadUpdate(t, it, signedPackage(t, privA, "0.40.0", "linux/amd64", bin), bin), 201)
	tok := dlToken(t, "IT")
	info := downloadInfo{Version: "0.40.0", Keys: []downloadKey{{update.KeyID(pubA), update.PublicKeyPEM(pubA)}}}

	run := func(base, ca string, info downloadInfo) (string, error) {
		dir := t.TempDir()
		out := filepath.Join(dir, "agent")
		script := linuxVerifyScript(base, tok, ca, "amd64", info) + `cp b "$OUT"` + "\n"
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "OUT="+out, "NO_PROXY=*", "no_proxy=*", "HTTPS_PROXY=", "https_proxy=")
		b, err := cmd.CombinedOutput()
		got, _ := os.ReadFile(out)
		if err == nil && string(got) != string(bin) {
			t.Fatalf("geprüftes Binary weicht ab: %q", got)
		}
		return string(b), err
	}
	realCA := vServer.caBundle()
	if out, err := run(agentSrv.URL, realCA, info); err != nil {
		t.Fatalf("echte Zentrale: %v\n%s", err, out)
	}

	// Fälschende Zentrale: liefert die echte Signaturdatei mit Änderungen.
	_, real := download(t, "linux/amd64/signatur", tok)
	var (
		mu       sync.Mutex
		forge    func(w http.ResponseWriter, r *http.Request)
		sawToken atomic.Bool
	)
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), tok) {
			sawToken.Store(true)
		}
		mu.Lock()
		f := forge
		mu.Unlock()
		f(w, r)
	}))
	defer fake.Close()
	fakeCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fake.Certificate().Raw}))
	serve := func(sigText string, binary []byte) {
		mu.Lock()
		defer mu.Unlock()
		forge = func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/signatur") {
				io.WriteString(w, sigText)
				return
			}
			w.Write(binary)
		}
	}
	other := []byte("#!/bin/sh\necho boese 0.40.0\n")
	sumOther := update.ManifestFor("0.40.0", "linux", "amd64", other)
	cases := map[string]struct {
		sig  string
		bin  []byte
		info downloadInfo
		want string
	}{
		"anderes Binary":          {real, other, info, "passt nicht zur Signatur"},
		"Binary mit neuem Hash":   {strings.Replace(real, "sha256 "+update.ManifestFor("0.40.0", "linux", "amd64", bin).SHA256, "sha256 "+sumOther.SHA256, 1), other, info, "Signatur ungültig"},
		"andere Version":          {strings.Replace(real, "version 0.40.0", "version 0.39.0", 1), bin, downloadInfo{Version: "0.39.0", Keys: info.Keys}, "Signatur ungültig"},
		"unbekannter Schlüssel":   {strings.Replace(real, "schluessel "+update.KeyID(pubA), "schluessel 0123456789abcdef", 1), bin, info, "unbekanntem Schlüssel"},
		"fremde Plattform":        {strings.Replace(real, "arch amd64", "arch arm64", 1), bin, info, "Signaturdatei passt nicht"},
		"kein Download-Format":    {"openwacht-agent-update v1\n" + real, bin, info, "Signaturdatei passt nicht"},
		"Widerruf untergeschoben": {real + "widerrufen 0123456789abcdef\n", bin, info, "Signatur ungültig"},
	}
	// Mit der CA der echten Zentrale lehnt curl die fälschende ab, bevor das Token hinausgeht.
	serve(real, bin)
	if out, err := run(fake.URL, realCA, info); err == nil || sawToken.Load() {
		t.Errorf("fremde Zentrale mit echter CA angenommen oder Token gesendet (%v): %s", err, out)
	}
	// Die Prüfung der Signatur greift auch, wenn TLS passt (z. B. übernommene Zentrale).
	for name, c := range cases {
		serve(c.sig, c.bin)
		out, err := run(fake.URL, fakeCA, c.info)
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: angenommen oder falscher Grund (%v): %s", name, err, out)
		}
	}
}
