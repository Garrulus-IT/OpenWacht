// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
)

func signedPackage(t *testing.T, priv ed25519.PrivateKey, ver, platform string, bin []byte) []byte {
	t.Helper()
	goos, arch, _ := strings.Cut(platform, "/")
	s, err := update.Sign(priv, update.ManifestFor(ver, goos, arch, bin))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	return b
}

// keyLine: Zeile für schluessel.pub.
func keyLine(pub ed25519.PublicKey, state string) string {
	return strings.TrimSpace("ed25519:"+base64.StdEncoding.EncodeToString(pub)+" "+state) + "\n"
}

func uploadUpdate(t *testing.T, c *client, sig, bin []byte) response {
	t.Helper()
	req, _ := http.NewRequest("POST", c.base+"/api/v1/agent-updates", bytes.NewReader(bin))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-OpenWacht-Signatur", base64.StdEncoding.EncodeToString(sig))
	req.Header.Set("X-CSRF-Token", c.csrf)
	req.Header.Set("Origin", c.origin)
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := response{status: resp.StatusCode, raw: string(raw)}
	json.Unmarshal(raw, &r.body)
	return r
}

func (a *testAgent) reportAs(host, ver, platform string) agentproto.ReportResponse {
	a.t.Helper()
	snap := validSnapshot(host)
	snap.AgentVersion, snap.Platform = ver, platform
	status, body, err := postJSON(a.client(), agentSrv.URL+agentproto.PathReport, snap)
	if err != nil || status != 200 {
		a.t.Fatalf("Meldung: %d %v %s", status, err, body)
	}
	var resp agentproto.ReportResponse
	json.Unmarshal(body, &resp)
	return resp
}

func TestAgentUpdates(t *testing.T) {
	agentServer(t)
	resetSettings(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys = ""
		owner.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
		// Die Test-Agents stören sonst Dashboard- und Prognose-Tests.
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'upd-%'`)
		owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE hostname LIKE 'upd-%' AND revoked_at IS NULL`)
		resetSettings(t)
	})
	bin := []byte("neues-agent-binary-0.23.0")
	sig := signedPackage(t, priv, "0.23.0", "linux/amd64", bin)

	it := as(t, "v_it")
	// Ohne Schlüssel im Build: Updates aus (seit 24.11.2026 hat der Build einen,
	// deshalb hier ausdrücklich leer)
	vServer.cfg.UpdateKeys = noUpdateKeys
	expectStatus(t, "ohne Schlüssel", uploadUpdate(t, it, sig, bin), 409)
	vServer.cfg.UpdateKeys = keyLine(pub, "")
	expectStatus(t, "Nicht-Betreiber", uploadUpdate(t, it, sig, bin), 403)
	setOperator(t, "v_it", true)
	for name, c := range map[string]struct{ sig, bin []byte }{
		"fremder Schlüssel": {signedPackage(t, otherPriv, "0.23.0", "linux/amd64", bin), bin},
		"anderes Binary":    {sig, bytes.Repeat([]byte("x"), len(bin))},
		"ohne Signatur":     {nil, bin},
		"kaputte Signatur":  {[]byte(`{"version":"0.23.0"}`), bin},
	} {
		if r := uploadUpdate(t, it, c.sig, c.bin); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	r := uploadUpdate(t, it, sig, bin)
	expectStatus(t, "hochladen", r, 201)
	expectStatus(t, "doppelt", uploadUpdate(t, it, sig, bin), 409)
	winBin := []byte("windows-binary")
	expectStatus(t, "Windows-Paket", uploadUpdate(t, it, signedPackage(t, priv, "0.23.0", "windows/amd64", winBin), winBin), 201)

	// Agents in Fertigung und Organisation
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	fwAgent, st, body := register(t, tok, "upd-fw")
	if st != 200 {
		t.Fatalf("Registrierung: %d %s", st, body)
	}
	tok, _ = newAgentToken(t, "v_oa", "Organisation", 1)
	oaAgent, _, _ := register(t, tok, "upd-oa")

	// Ohne Freigabe kein Angebot, keine Daten
	if resp := fwAgent.reportAs("upd-fw", "0.22.1", "linux/amd64"); resp.Update != nil {
		t.Fatal("Angebot ohne Freigabe")
	}
	if st, _, _ := postJSON(fwAgent.client(), agentSrv.URL+agentproto.PathUpdateBinary, map[string]string{"version": "0.23.0", "plattform": "linux/amd64"}); st != 404 {
		t.Errorf("Binary ohne Freigabe: %d", st)
	}
	// Freigabe: Admin des Mandanten, nicht Geschwister, nicht Leser
	release := func(user, agent, ver string) response {
		return as(t, user).do("PUT", "/api/v1/agents/"+agent+"/update", map[string]any{"version": ver})
	}
	expectStatus(t, "Geschwister gibt frei", release("v_oa", fwAgent.id, "0.23.0"), 404)
	expectStatus(t, "Leser gibt frei", release("v_lz", fwAgent.id, "0.23.0"), 404)
	expectStatus(t, "Version ohne Paket", release("v_fw", fwAgent.id, "0.24.0"), 400)
	expectStatus(t, "Freigabe", release("v_fw", fwAgent.id, "0.23.0"), 200)
	expectStatus(t, "Eltern gibt frei", release("v_it", oaAgent.id, "0.23.0"), 200)

	// Angebot nur, wenn neuer und Plattform passt
	resp := fwAgent.reportAs("upd-fw", "0.22.1", "linux/amd64")
	if resp.Update == nil || resp.Update.Version != "0.23.0" {
		t.Fatalf("kein Angebot: %+v", resp)
	}
	if resp := fwAgent.reportAs("upd-fw", "0.23.0", "linux/amd64"); resp.Update != nil {
		t.Error("Angebot für gleiche Version")
	}
	if resp := fwAgent.reportAs("upd-fw", "0.24.0", "linux/amd64"); resp.Update != nil {
		t.Error("Angebot zur Rückstufung")
	}
	if resp := fwAgent.reportAs("upd-fw", "0.22.1", "linux/arm64"); resp.Update != nil {
		t.Error("Angebot für fehlende Plattform")
	}
	// Signatur und Binary
	req := map[string]string{"version": "0.23.0", "plattform": "linux/amd64"}
	st, got, _ := postJSON(fwAgent.client(), agentSrv.URL+agentproto.PathUpdateSignature, req)
	if st != 200 || !bytes.Equal(got, sig) {
		t.Errorf("Signatur: %d %s", st, got)
	}
	st, got, _ = postJSON(fwAgent.client(), agentSrv.URL+agentproto.PathUpdateBinary, req)
	if st != 200 || !bytes.Equal(got, bin) {
		t.Errorf("Binary: %d", st)
	}
	if st, got, _ = postJSON(fwAgent.client(), agentSrv.URL+agentproto.PathUpdateBinary,
		map[string]string{"version": "0.23.0", "plattform": "windows/amd64"}); st != 200 || !bytes.Equal(got, winBin) {
		t.Errorf("Windows-Binary: %d", st)
	}
	if st, _, _ = postJSON(fwAgent.client(), agentSrv.URL+agentproto.PathUpdateBinary,
		map[string]string{"version": "0.22.0", "plattform": "linux/amd64"}); st != 404 {
		t.Errorf("andere Version: %d", st)
	}
	// Ohne Client-Zertifikat nichts
	if st, _, _ = postJSON(pinnedClient(strings.Repeat("A", 43)), agentSrv.URL+agentproto.PathUpdateBinary, req); st == 200 {
		t.Error("Binary ohne Zertifikat")
	}
	// Liste: Fertigung sieht eigene Agents samt Freigabe, nicht Organisation
	l := as(t, "v_fw").do("GET", "/api/v1/agent-updates", nil)
	expectStatus(t, "Liste", l, 200)
	if !strings.Contains(l.raw, "upd-fw") || strings.Contains(l.raw, "upd-oa") || l.body["schluessel"] != update.KeyID(pub) || !strings.Contains(l.raw, `"zustand":"aktiv"`) {
		t.Errorf("Liste: %s", l.raw)
	}
	// Zurücknehmen
	expectStatus(t, "Geschwister nimmt zurück", as(t, "v_oa").do("DELETE", "/api/v1/agents/"+fwAgent.id+"/update", nil), 404)
	expectStatus(t, "zurücknehmen", as(t, "v_fw").do("DELETE", "/api/v1/agents/"+fwAgent.id+"/update", nil), 200)
	if resp := fwAgent.reportAs("upd-fw", "0.22.1", "linux/amd64"); resp.Update != nil {
		t.Error("Angebot nach Zurücknehmen")
	}
	// Mandant der Freigabe kommt aus dem Agent, nicht aus der Anfrage (RLS-Schicht direkt)
	var tenant string
	owner.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.agent_update_releases WHERE agent_id = $1`, oaAgent.id).Scan(&tenant)
	if tenant != ids["Organisation"] {
		t.Errorf("Mandant der Freigabe: %s", tenant)
	}
	// Datenbank allein (zweite Schicht): Mandant aus dem Agent, RLS für Admins
	try := func(user, agent, tenant string) error {
		return vServer.withUser(ctx, ids[user], func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_update_releases (agent_id, tenant_id, version) VALUES ($1, $2, '0.23.0')
				ON CONFLICT (agent_id) DO UPDATE SET version = EXCLUDED.version`, agent, ids[tenant])
			return err
		})
	}
	if err := try("v_fw", fwAgent.id, "Organisation"); err != nil {
		t.Errorf("Fertigung mit falschem Mandanten: %v", err)
	}
	owner.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.agent_update_releases WHERE agent_id = $1`, fwAgent.id).Scan(&tenant)
	if tenant != ids["Fertigung"] {
		t.Errorf("Mandant aus der Anfrage übernommen: %s", tenant)
	}
	if err := try("v_fw", oaAgent.id, "Fertigung"); err == nil {
		t.Error("Fertigung gibt Agent des Organisations frei (DB)")
	}
	if err := try("v_lz", fwAgent.id, "Fertigung"); err == nil {
		t.Error("Leser gibt frei (DB)")
	}
	if err := vServer.withUser(ctx, ids["v_fw"], func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
		if err == nil && tag.RowsAffected() > 0 {
			return errors.New("gelöscht")
		}
		return nil
	}); err != nil {
		t.Error("Admin löscht Pakete (DB)")
	}

	// Pakete löschen nur der Betreiber
	pid, _ := r.body["id"].(string)
	expectStatus(t, "Admin löscht Paket", as(t, "v_fw").do("DELETE", "/api/v1/agent-updates/"+pid, nil), 403)
	expectStatus(t, "Betreiber löscht", it.do("DELETE", "/api/v1/agent-updates/"+pid, nil), 200)
	if resp := oaAgent.reportAs("upd-oa", "0.22.1", "linux/amd64"); resp.Update != nil {
		t.Error("Angebot ohne Paket")
	}
}

// Etappe 32: zwei Schlüssel; die Reserve widerruft den aktiven über ein
// signiertes Update. Danach bietet die Zentrale nichts mehr an, was mit dem
// widerrufenen Schlüssel signiert ist, und nimmt nichts mehr an.
func TestAgentUpdateWiderruf(t *testing.T) {
	agentServer(t)
	resetSettings(t)
	ctx := context.Background()
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() {
		vServer.cfg.UpdateKeys = ""
		owner.Exec(ctx, `DELETE FROM openwacht.agent_updates`)
		owner.Exec(ctx, `DELETE FROM openwacht.update_key_revocations`)
		owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE name LIKE 'wdr-%'`)
		owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE hostname LIKE 'wdr-%' AND revoked_at IS NULL`)
		resetSettings(t)
	})
	vServer.cfg.UpdateKeys = keyLine(pubA, "aktiv") + keyLine(pubB, "reserve")
	setOperator(t, "v_it", true)
	it := as(t, "v_it")
	signed := func(priv ed25519.PrivateKey, ver string, bin []byte, revoke ...string) []byte {
		s, err := update.Sign(priv, update.ManifestFor(ver, "linux", "amd64", bin), revoke...)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(s)
		return b
	}
	binA := []byte("agent-0.23.0-a")
	expectStatus(t, "Paket A", uploadUpdate(t, it, signed(privA, "0.23.0", binA), binA), 201)
	tok, _ := newAgentToken(t, "v_fw", "Fertigung", 1)
	ag, st, body := register(t, tok, "wdr-fw")
	if st != 200 {
		t.Fatalf("Registrierung: %d %s", st, body)
	}
	expectStatus(t, "Freigabe", as(t, "v_fw").do("PUT", "/api/v1/agents/"+ag.id+"/update", map[string]any{"version": "0.23.0"}), 200)
	if resp := ag.reportAs("wdr-fw", "0.22.1", "linux/amd64"); resp.Update == nil {
		t.Fatal("kein Angebot vor dem Widerruf")
	}
	// Der aktive Schlüssel darf die Reserve nicht widerrufen.
	binX := []byte("agent-0.24.0-x")
	expectStatus(t, "aktiv widerruft Reserve", uploadUpdate(t, it, signed(privA, "0.24.0", binX, update.KeyID(pubB)), binX), 400)
	// Nicht-Betreiber dürfen keinen Widerruf hochladen.
	binB := []byte("agent-0.24.0-b")
	sigB := signed(privB, "0.24.0", binB, update.KeyID(pubA))
	expectStatus(t, "Widerruf durch Admin ohne Betreiber", uploadUpdate(t, as(t, "v_fw"), sigB, binB), 403)
	expectStatus(t, "Widerrufs-Update", uploadUpdate(t, it, sigB, binB), 201)
	var by, ver string
	if err := owner.QueryRow(ctx, `SELECT revoked_by, version FROM openwacht.update_key_revocations WHERE key_id = $1`, update.KeyID(pubA)).Scan(&by, &ver); err != nil ||
		by != update.KeyID(pubB) || ver != "0.24.0" {
		t.Fatalf("Widerruf gespeichert: %q %q %v", by, ver, err)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'update_schluessel.widerrufen' AND details->>'schluessel' = $1`, update.KeyID(pubA)).Scan(&n)
	if n != 1 {
		t.Errorf("Audit: %d", n)
	}
	// Paket A wird nicht mehr angeboten und nicht mehr ausgeliefert.
	if resp := ag.reportAs("wdr-fw", "0.22.1", "linux/amd64"); resp.Update != nil {
		t.Errorf("Angebot mit widerrufenem Schlüssel: %+v", resp.Update)
	}
	req := map[string]string{"version": "0.23.0", "plattform": "linux/amd64"}
	for _, p := range []string{agentproto.PathUpdateSignature, agentproto.PathUpdateBinary} {
		if st, _, _ := postJSON(ag.client(), agentSrv.URL+p, req); st != 404 {
			t.Errorf("%s nach Widerruf: %d", p, st)
		}
	}
	// Neue Pakete mit A: abgelehnt. Mit B: weiter möglich und angeboten.
	binA2 := []byte("agent-0.25.0-a")
	if r := uploadUpdate(t, it, signed(privA, "0.25.0", binA2), binA2); r.status != 400 || !strings.Contains(r.raw, "widerrufen") {
		t.Errorf("Paket mit widerrufenem Schlüssel: %d %s", r.status, r.raw)
	}
	expectStatus(t, "Freigabe B", as(t, "v_fw").do("PUT", "/api/v1/agents/"+ag.id+"/update", map[string]any{"version": "0.24.0"}), 200)
	if resp := ag.reportAs("wdr-fw", "0.22.1", "linux/amd64"); resp.Update == nil || resp.Update.Version != "0.24.0" {
		t.Errorf("Angebot B: %+v", resp.Update)
	}
	l := it.do("GET", "/api/v1/agent-updates", nil)
	if l.body["schluessel"] != "" || !strings.Contains(l.raw, `"zustand":"widerrufen"`) || !strings.Contains(l.raw, `"durch":"`+update.KeyID(pubB)+`"`) {
		t.Errorf("Liste: %s", l.raw)
	}
	// Zweite Schicht: Widerruf direkt in der Datenbank nur für Betreiber.
	err := vServer.withUser(ctx, ids["v_fw"], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.update_key_revocations (key_id, revoked_by, version, created_by)
			VALUES ($1, $2, '0.1.0', openwacht.current_user_id())`, update.KeyID(pubB), update.KeyID(pubA))
		return err
	})
	if !isDenied(err) {
		t.Errorf("Widerruf durch Nicht-Betreiber in der DB: %v", err)
	}
}

// noUpdateKeys: wie eine schluessel.pub ohne Schlüssel (nur Kommentar), damit
// Tests „Updates aus“ prüfen können, obwohl der Build Schlüssel enthält.
const noUpdateKeys = "# keine Schlüssel (Test)\n"
