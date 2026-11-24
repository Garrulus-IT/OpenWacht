// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agent"
	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// caServer: eine zweite Zentrale auf derselben Datenbank, die die CAs beim
// Start lädt (wie nach „systemctl restart“).
func caServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := New(vServer.cfg, pool, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitAgentCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s.AgentHandler())
	srv.Listener = tls.NewListener(srv.Listener, s.AgentTLSConfig())
	srv.Start()
	t.Cleanup(srv.Close)
	return s, strings.Replace(srv.URL, "http://", "https://", 1)
}

// pointAgent: Agent-Verzeichnis auf eine andere Zentrale zeigen lassen.
func pointAgent(t *testing.T, dir, url string) *agent.Runner {
	t.Helper()
	p := filepath.Join(dir, "agent.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	cfg["zentrale"] = url
	b, _ = json.Marshal(cfg)
	os.WriteFile(p, b, 0o644)
	r, err := agent.NewRunner(dir, func() (agentproto.Snapshot, error) { return validSnapshot("ca-e2e"), nil })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func snapCAs(t *testing.T, agentID string) (cas []string, certCA string) {
	t.Helper()
	var raw []byte
	if err := owner.QueryRow(context.Background(), `SELECT coalesce(snapshot->'cas', '[]'), coalesce(snapshot->>'zert_ca', '')
		FROM openwacht.agents WHERE id = $1`, agentID).Scan(&raw, &certCA); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &cas)
	return cas, certCA
}

func caFile(t *testing.T, dir string) []string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	cas, err := pki.ParseCABundle(b)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(cas))
	for i, c := range cas {
		out[i] = pki.Fingerprint(c)
	}
	return out
}

func TestAgentCAWechsel(t *testing.T) {
	agentServer(t)
	resetLimits(t)
	ctx := context.Background()
	// Ursprüngliche CA sichern und am Ende wiederherstellen (gemeinsame Test-DB).
	var origID int16
	var origCert string
	var origKey []byte
	if err := owner.QueryRow(ctx, `SELECT id, cert_pem, key_enc FROM openwacht.agent_ca WHERE state = 'aktiv'`).Scan(&origID, &origCert, &origKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.agent_ca`)
		owner.Exec(ctx, `INSERT INTO openwacht.agent_ca (id, cert_pem, key_enc, state) VALUES ($1, $2, $3, 'aktiv')`, origID, origCert, origKey)
	})
	fpA := vServer.AgentCAFingerprint()

	dir := t.TempDir()
	tok, r := newAgentToken(t, "v_fw", "Fertigung", 2)
	expectStatus(t, "Token", r, 201)
	vServer.agent.limiter = newIPLimiter(vServer.cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
	id, err := agent.Register(ctx, dir, agentSrv.URL, tok, "ca-e2e", false)
	if err != nil {
		t.Fatal(err)
	}
	// Zweiter Agent, der nie aktualisiert wird (behält nur die alte CA).
	dirOld := t.TempDir()
	if _, err := agent.Register(ctx, dirOld, agentSrv.URL, tok, "ca-e2e-alt", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pointAgent(t, dirOld, agentSrv.URL).Report(ctx); err != nil {
		t.Fatal(err)
	}
	run := pointAgent(t, dir, agentSrv.URL)
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if cas, certCA := snapCAs(t, id); strings.Join(cas, ",") != fpA || certCA != fpA {
		t.Fatalf("vor dem Wechsel: %v %s", cas, certCA)
	}

	// Schritt 1: neue CA. Mit falschem Hauptschlüssel abgelehnt.
	tx, _ := owner.Begin(ctx)
	if _, err := AgentCANew(ctx, tx, make([]byte, 32), time.Now()); err == nil || !strings.Contains(err.Error(), "Hauptschlüssel") {
		t.Errorf("falscher Schlüssel: %v", err)
	}
	tx.Rollback(ctx)
	tx, _ = owner.Begin(ctx)
	infoB, err := AgentCANew(ctx, tx, testKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	fpB := infoB.Fingerprint
	tx, _ = owner.Begin(ctx)
	if _, err := AgentCANew(ctx, tx, testKey, time.Now()); err == nil {
		t.Error("zweite neue CA")
	}
	tx.Rollback(ctx)
	s2, url2 := caServer(t)
	if strings.Join(s2.agent.fps, ",") != fpA+","+fpB || s2.AgentCAFingerprint() != fpA {
		t.Fatalf("Zentrale nach Schritt 1: %v", s2.agent.fps)
	}
	run = pointAgent(t, dir, url2)
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caFile(t, dir); strings.Join(got, ",") != fpA+","+fpB {
		t.Fatalf("ca.pem nach Schritt 1: %v", got)
	}
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if cas, _ := snapCAs(t, id); strings.Join(cas, ",") != fpA+","+fpB {
		t.Fatalf("gemeldete CAs: %v", cas)
	}
	// Schritt 2: Andere Agents kennen die neue CA noch nicht.
	tx, _ = owner.Begin(ctx)
	if err := AgentCASwitch(ctx, tx, false); err == nil || !strings.Contains(err.Error(), "kennen die neue CA") {
		t.Errorf("Umstellen ohne alle Agents: %v", err)
	}
	tx.Rollback(ctx)
	tx, _ = owner.Begin(ctx)
	if err := AgentCARemoveOld(ctx, tx, true); err == nil {
		t.Error("Entfernen ohne alte CA")
	}
	tx.Rollback(ctx)
	tx, _ = owner.Begin(ctx)
	if err := AgentCASwitch(ctx, tx, true); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	s3, url3 := caServer(t)
	if s3.AgentCAFingerprint() != fpB || strings.Join(s3.agent.fps, ",") != fpB+","+fpA {
		t.Fatalf("Zentrale nach Schritt 2: %v", s3.agent.fps)
	}
	// Der Agent erreicht die umgestellte Zentrale (Server-Zertifikat von B),
	// bekommt die neue Reihenfolge und erneuert sein Zertifikat bei B.
	run = pointAgent(t, dir, url3)
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caFile(t, dir); strings.Join(got, ",") != fpB+","+fpA {
		t.Fatalf("ca.pem nach Schritt 2: %v", got)
	}
	if _, certCA := snapCAs(t, id); certCA != fpA {
		t.Fatalf("Zertifikat vor der Erneuerung: %s", certCA)
	}
	if err := run.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if _, certCA := snapCAs(t, id); certCA != fpB {
		t.Fatalf("Zertifikat nach der Erneuerung: %s", certCA)
	}
	// Der nicht aktualisierte Agent (nur A in ca.pem) erreicht B nicht.
	old := pointAgent(t, dirOld, url3)
	if _, _, err := old.Report(ctx); err == nil {
		t.Error("Agent ohne neue CA erreicht die umgestellte Zentrale")
	}
	// Neue Registrierungen brauchen ein Token mit dem Fingerabdruck von B.
	if !strings.HasSuffix(tok, "."+fpA) {
		t.Fatalf("Token: %s", tok)
	}

	// Schritt 3: Noch hat ein Agent (der alte) ein Zertifikat von A.
	tx, _ = owner.Begin(ctx)
	if err := AgentCARemoveOld(ctx, tx, false); err == nil || !strings.Contains(err.Error(), "Zertifikat der alten CA") {
		t.Errorf("Entfernen mit Zertifikaten von A: %v", err)
	}
	tx.Rollback(ctx)
	owner.Exec(ctx, `UPDATE openwacht.agents SET last_seen = now() - interval '40 days' WHERE snapshot->>'zert_ca' = $1`, fpA)
	tx, _ = owner.Begin(ctx)
	if err := AgentCARemoveOld(ctx, tx, false); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	_, url4 := caServer(t)
	run = pointAgent(t, dir, url4)
	if _, _, err := run.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if got := caFile(t, dir); strings.Join(got, ",") != fpB {
		t.Fatalf("ca.pem nach Schritt 3: %v", got)
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action IN ('agent_ca.neu', 'agent_ca.umgestellt', 'agent_ca.alte_entfernt')
		AND details->>'fingerabdruck' IN ($1, $2) OR details->>'aktiv' = $2`, fpA, fpB).Scan(&n)
	if n != 3 {
		t.Errorf("Audit: %d", n)
	}
}

func TestAgentCAOberflaeche(t *testing.T) {
	agentServer(t)
	resetSettings(t)
	setOperator(t, "v_it", true)
	expectStatus(t, "Admin ohne Betreiber", as(t, "v_fw").do("GET", "/api/v1/einstellungen/agent-ca", nil), 403)
	r := as(t, "v_it").do("GET", "/api/v1/einstellungen/agent-ca", nil)
	expectStatus(t, "Betreiber", r, 200)
	if !strings.Contains(r.raw, `"zustand":"aktiv"`) || !strings.Contains(r.raw, vServer.AgentCAFingerprint()) || !strings.Contains(r.raw, `"gueltig_bis"`) {
		t.Errorf("Antwort: %s", r.raw)
	}
}

// Rücksicherung: maßgeblich ist der Schlüssel der aktiven CA, auch wenn sie
// nach einem Wechsel nicht mehr id 1 hat; alte Sicherungen haben nur id 1.
func TestBackupCAKey(t *testing.T) {
	o, _ := freshInstall(t)
	ctx := context.Background()
	if k, err := BackupCAKey(ctx, o); err != nil || k != nil {
		t.Fatalf("ohne CA: %x %v", k, err)
	}
	o.Exec(ctx, `INSERT INTO openwacht.agent_ca (id, cert_pem, key_enc, state) VALUES (1, 'a', '\x01aa', 'alt'), (2, 'b', '\x02bb', 'aktiv')`)
	if k, err := BackupCAKey(ctx, o); err != nil || string(k) != "\x02\xbb" {
		t.Fatalf("nach Wechsel: %x %v", k, err)
	}
	// Schema von vor 0039 (nur id 1, keine Spalte state)
	o.Exec(ctx, `ALTER TABLE openwacht.agent_ca DROP COLUMN state CASCADE`)
	if k, err := BackupCAKey(ctx, o); err != nil || string(k) != "\x01\xaa" {
		t.Fatalf("altes Schema: %x %v", k, err)
	}
	// Meldung bei Sicherung mit anderem Hauptschlüssel nennt das Kennzeichen.
	box, _ := auth.Seal(deriveKey(testKey, "openwacht agent-ca v1"), []byte("x"), []byte("agent-ca"))
	if err := CheckAgentCAKey(make([]byte, 32), box); err == nil || !strings.Contains(err.Error(), "anderen Hauptschlüssel") {
		t.Errorf("anderer Schlüssel: %v", err)
	}
	if err := CheckAgentCAKey(testKey, box); err != nil {
		t.Error(err)
	}
}
