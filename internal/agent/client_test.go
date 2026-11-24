// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// zentraleEnv: echte Zentrale mit Agent-Port und PostgreSQL.
type zentraleEnv struct {
	url    string
	owner  *pgx.Conn
	tenant string
	srv    *zentrale.Server
}

func startZentrale(t *testing.T, lifetime time.Duration) *zentraleEnv {
	t.Helper()
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tdb.Close)
	owner, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close(ctx) })
	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	var tenant string
	if err := owner.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	pcfg, _ := pgxpool.ParseConfig("")
	pcfg.ConnConfig = tdb.AppCfg.Copy()
	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("http://127.0.0.1")
	s, err := zentrale.New(zentrale.Config{BaseURL: base, AgentNames: []string{"127.0.0.1"},
		AgentCertLifetime: lifetime, PasswordParams: &auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}},
		pool, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitAgentCA(ctx); err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: s.AgentHandler()}
	go hs.Serve(tls.NewListener(ln, s.AgentTLSConfig()))
	t.Cleanup(func() { hs.Close() })
	return &zentraleEnv{url: "https://" + ln.Addr().String(), owner: owner, tenant: tenant, srv: s}
}

// token legt ein Registrierungs-Token direkt in der Datenbank an.
func (z *zentraleEnv) token(t *testing.T, uses int) string {
	t.Helper()
	tok, secret, err := agentproto.NewToken(z.srv.AgentCAFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(secret)
	if _, err := z.owner.Exec(context.Background(), `INSERT INTO openwacht.agent_tokens (token_hash, tenant_id, uses_left, expires_at)
		VALUES ($1, $2, $3, now() + interval '1 hour')`, h[:], z.tenant, uses); err != nil {
		t.Fatal(err)
	}
	return tok
}

func fakeCollect() (agentproto.Snapshot, error) {
	return agentproto.Snapshot{
		CollectedAt: time.Now(), Hostname: "testhost", OS: "Test", Kernel: "1", Arch: "amd64", AgentVersion: "test",
		CPU:    agentproto.CPU{Cores: 1, Percent: 5},
		Memory: agentproto.Memory{TotalBytes: 1 << 30, AvailableBytes: 1 << 29},
	}, nil
}

func TestRegistrierenMeldenErneuern(t *testing.T) {
	z := startZentrale(t, 30*24*time.Hour)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "agent")
	id, err := Register(ctx, dir, z.url, z.token(t, 1), "testhost", false)
	if err != nil {
		t.Fatal(err)
	}
	// Dateirechte: Verzeichnis und Schlüssel nur für den Besitzer.
	for name, want := range map[string]os.FileMode{".": 0o700, fileKey: 0o600} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: Rechte %v, erwartet %v (%v)", name, fi.Mode().Perm(), want, err)
		}
	}
	// Zweite Registrierung ohne -neu wird abgelehnt.
	if _, err := Register(ctx, dir, z.url, z.token(t, 1), "testhost", false); !errors.Is(err, ErrAlreadyRegistered) {
		t.Errorf("doppelte Registrierung: %v", err)
	}

	r, err := NewRunner(dir, fakeCollect)
	if err != nil {
		t.Fatal(err)
	}
	if r.AgentID() != id {
		t.Errorf("Agent-ID %s, erwartet %s", r.AgentID(), id)
	}
	if _, _, err := r.Report(ctx); err != nil {
		t.Fatalf("Meldung: %v", err)
	}
	var host, tenant string
	if err := z.owner.QueryRow(ctx, `SELECT snapshot->>'hostname', tenant_id::text FROM openwacht.agents WHERE id = $1`, id).
		Scan(&host, &tenant); err != nil || host != "testhost" || tenant != z.tenant {
		t.Fatalf("in der Datenbank: %q %q %v", host, tenant, err)
	}

	// Erneuern: neuer Schlüssel, neue Seriennummer, Meldung klappt weiter.
	oldKey, _ := os.ReadFile(filepath.Join(dir, fileKey))
	var oldSerial string
	z.owner.QueryRow(ctx, `SELECT cert_serial FROM openwacht.agents WHERE id = $1`, id).Scan(&oldSerial)
	if err := r.Renew(ctx); err != nil {
		t.Fatalf("Erneuern: %v", err)
	}
	newKey, _ := os.ReadFile(filepath.Join(dir, fileKey))
	if bytes.Equal(oldKey, newKey) {
		t.Error("Schlüssel bei Erneuerung nicht gewechselt")
	}
	if _, _, err := r.Report(ctx); err != nil {
		t.Fatalf("Meldung nach Erneuerung: %v", err)
	}
	var serial string
	var prev *string
	z.owner.QueryRow(ctx, `SELECT cert_serial, cert_serial_prev FROM openwacht.agents WHERE id = $1`, id).Scan(&serial, &prev)
	if serial == oldSerial || prev != nil {
		t.Errorf("nach Erneuerung und Meldung: Seriennummer %s (alt %s), vorige %v", serial, oldSerial, prev)
	}
	// Nach Neustart lädt der Agent das neue Zertifikat von der Platte.
	r2, err := NewRunner(dir, fakeCollect)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r2.Report(ctx); err != nil {
		t.Errorf("nach Neustart: %v", err)
	}

	// Gesperrt: Die Zentrale lehnt ab, der Agent bekommt 401.
	z.owner.Exec(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1`, id)
	if _, status, err := r2.Report(ctx); err == nil || status != http.StatusUnauthorized {
		t.Errorf("gesperrter Agent: %d %v", status, err)
	}
}

func TestErneuerungsZeitpunkt(t *testing.T) {
	// Zertifikat mit 3 Stunden Laufzeit: nach 2 Stunden soll erneuert werden.
	z := startZentrale(t, 3*time.Hour)
	dir := filepath.Join(t.TempDir(), "agent")
	if _, err := Register(context.Background(), dir, z.url, z.token(t, 1), "testhost", false); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRunner(dir, fakeCollect)
	if r.needsRenewal() {
		t.Error("frisches Zertifikat soll nicht erneuert werden")
	}
	r.now = func() time.Time { return time.Now().Add(2*time.Hour + time.Minute) }
	if !r.needsRenewal() {
		t.Error("nach zwei Dritteln der Laufzeit muss erneuert werden")
	}
}

func TestRegistrierungNegativ(t *testing.T) {
	z := startZentrale(t, time.Hour)
	ctx := context.Background()
	dir := t.TempDir()
	// Token einer anderen Zentrale: Der Agent bricht beim ersten Kontakt ab.
	other, _ := pki.NewCA("andere", time.Now())
	foreign, _, _ := agentproto.NewToken(pki.Fingerprint(other.Cert))
	if _, err := Register(ctx, filepath.Join(dir, "a"), z.url, foreign, "h", false); err == nil {
		t.Error("Registrierung bei falscher Zentrale")
	}
	if _, err := os.Stat(filepath.Join(dir, "a", fileKey)); err == nil {
		t.Error("nach fehlgeschlagener Registrierung liegt ein Schlüssel auf der Platte")
	}
	for name, zentrale := range map[string]string{
		"http statt https": "http://127.0.0.1:1", "mit Pfad": z.url + "/x", "ohne Host": "https://",
	} {
		if _, err := Register(ctx, filepath.Join(dir, "b"), zentrale, z.token(t, 1), "h", false); err == nil {
			t.Errorf("%s akzeptiert", name)
		}
	}
	if _, err := Register(ctx, filepath.Join(dir, "c"), z.url, z.token(t, 1), "<boese>", false); err == nil {
		t.Error("ungültiger Hostname akzeptiert")
	}
	if _, err := Register(ctx, filepath.Join(dir, "d"), z.url, "kein-token", "h", false); err == nil {
		t.Error("kaputtes Token akzeptiert")
	}
	// Verbrauchtes Token.
	tok := z.token(t, 1)
	if _, err := Register(ctx, filepath.Join(dir, "e"), z.url, tok, "h", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(ctx, filepath.Join(dir, "f"), z.url, tok, "h", false); err == nil {
		t.Error("verbrauchtes Token akzeptiert")
	}
}

func TestBackoff(t *testing.T) {
	prev := time.Duration(0)
	for n := 1; n <= 20; n++ {
		d := backoff(n)
		if d < prev || d > 15*time.Minute {
			t.Fatalf("backoff(%d) = %v", n, d)
		}
		prev = d
	}
}

// TestKeineUmleitungen (Befund H1): Eine übernommene Zentrale darf den Agent
// nicht per Umleitung an andere Adressen schicken, weder bei der
// Registrierung noch im Betrieb. Am Ziel darf keine Anfrage ankommen.
func TestKeineUmleitungen(t *testing.T) {
	z := startZentrale(t, 30*24*time.Hour)
	ctx := context.Background()

	// „Internes“ Ziel: einfacher HTTP-Server, der jede Anfrage zählt.
	hits := make(chan string, 100)
	target := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.Method + " " + r.URL.Path
		w.Write([]byte(`{}`))
	})}
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go target.Serve(tln)
	t.Cleanup(func() { target.Close() })
	targetURL := "http://" + tln.Addr().String() + "/admin/reboot?jetzt=1"

	// Bösartige Zentrale: gleiche CA und gleiches Serverzertifikat wie die
	// echte, antwortet aber auf alles mit einer Umleitung zum Ziel.
	var code atomic.Int32
	evil := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL, int(code.Load()))
	})}
	eln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go evil.Serve(tls.NewListener(eln, z.srv.AgentTLSConfig()))
	t.Cleanup(func() { evil.Close() })
	evilURL := "https://" + eln.Addr().String()

	dir := filepath.Join(t.TempDir(), "agent")
	if _, err := Register(ctx, dir, z.url, z.token(t, 1), "testhost", false); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(dir, fakeCollect)
	if err != nil {
		t.Fatal(err)
	}
	r.zentrale, _ = url.Parse(evilURL)

	for _, c := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound, http.StatusSeeOther, http.StatusMovedPermanently} {
		code.Store(int32(c))
		// Registrierung (Client mit Fingerabdruck)
		if _, err := Register(ctx, filepath.Join(t.TempDir(), "neu"), evilURL, z.token(t, 1), "testhost", false); err == nil {
			t.Errorf("Registrierung mit Umleitung %d: kein Fehler", c)
		}
		// Betrieb: Meldung, Erneuerung, Sensor- und Sammler-Abfragen
		if _, status, err := r.Report(ctx); err == nil || status != c {
			t.Errorf("Meldung mit Umleitung %d: Status %d, Fehler %v", c, status, err)
		}
		if err := r.Renew(ctx); err == nil {
			t.Errorf("Erneuerung mit Umleitung %d: kein Fehler", c)
		}
		if _, err := postJSON(ctx, r.client, r.zentrale.String()+agentproto.PathCollectorResult, struct{}{}, nil); err == nil {
			t.Errorf("Sammler-Ergebnis mit Umleitung %d: kein Fehler", c)
		}
		if _, err := postRaw(ctx, r.client, r.zentrale.String()+agentproto.PathReport, struct{}{}, 1<<10); err == nil {
			t.Errorf("Update-Abfrage mit Umleitung %d: kein Fehler", c)
		}
	}
	select {
	case h := <-hits:
		t.Fatalf("Anfrage kam am Umleitungsziel an: %s", h)
	case <-time.After(200 * time.Millisecond):
	}
}

// Etappe 32: CA-Bündel nur übernehmen, wenn es eine bisherige CA enthält;
// Zertifikat erneuern, sobald es nicht von der ersten CA stammt.
func TestCABuendel(t *testing.T) {
	now := time.Now()
	a, _ := pki.NewCA("A", now)
	b, _ := pki.NewCA("B", now)
	c, _ := pki.NewCA("C", now)
	_, csr, err := newKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.SignAgentCSR(csr, "6f1d2c1e-1b6e-4a43-9a51-0d3f6f1a2b3c", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &Runner{dir: dir, cas: []*x509.Certificate{a.Cert}, client: &http.Client{},
		cert: &tls.Certificate{Leaf: leaf}}
	if r.issuerOutdated() {
		t.Error("Zertifikat von A gilt als veraltet")
	}
	if err := r.updateCA(pki.CABundlePEM([]*x509.Certificate{b.Cert, c.Cert})); err == nil {
		t.Fatal("Bündel ohne bisherige CA übernommen")
	}
	if _, err := os.Stat(filepath.Join(dir, fileCA)); err == nil {
		t.Fatal("ca.pem trotz Ablehnung geschrieben")
	}
	if err := r.updateCA(pki.CABundlePEM([]*x509.Certificate{b.Cert, a.Cert})); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, fileCA))
	if cas, err := pki.ParseCABundle(got); err != nil || len(cas) != 2 || pki.Fingerprint(cas[0]) != pki.Fingerprint(b.Cert) {
		t.Fatalf("ca.pem: %v", err)
	}
	if fps := r.caFingerprints(); len(fps) != 2 || fps[0] != pki.Fingerprint(b.Cert) {
		t.Errorf("Fingerabdrücke: %v", fps)
	}
	if !r.issuerOutdated() {
		t.Error("Zertifikat von A nach Umstellung auf B nicht veraltet")
	}
	for name, bad := range map[string][]byte{
		"leer":      nil,
		"kein PEM":  []byte("x"),
		"Schlüssel": []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"keine CA":  pki.CertToPEM(leaf),
		"doppelt":   pki.CABundlePEM([]*x509.Certificate{a.Cert, a.Cert}),
		"Rest":      append(pki.CertToPEM(a.Cert), []byte("Müll")...),
		"zu viele":  pki.CABundlePEM([]*x509.Certificate{a.Cert, b.Cert, c.Cert, mustCA(t)}),
	} {
		if err := r.updateCA(bad); err == nil {
			t.Errorf("%s übernommen", name)
		}
	}
}

func mustCA(t *testing.T) *x509.Certificate {
	ca, err := pki.NewCA("D", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca.Cert
}
