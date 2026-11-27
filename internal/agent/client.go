// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// Dateien im Zustandsverzeichnis (Verzeichnis 0700, Schlüssel 0600).
const (
	fileConfig = "agent.json"
	fileKey    = "schluessel.pem"
	fileCert   = "zertifikat.pem"
	fileCA     = "ca.pem"
)

// Grenzen für das von der Zentrale gewünschte Intervall.
const (
	minInterval = 15 * time.Second
	maxInterval = time.Hour
)

type config struct {
	Zentrale string `json:"zentrale"`
	AgentID  string `json:"agent_id"`
}

var ErrAlreadyRegistered = errors.New("dieser Rechner ist bereits registriert (Verzeichnis enthält agent.json); mit -neu ersetzen")

func checkZentrale(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return nil, fmt.Errorf("Adresse der Zentrale muss die Form https://host:port haben, nicht %q", raw)
	}
	u.Path = ""
	return u, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func newKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return key, csr, err
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// noRedirect: Der Agent folgt nie einer Umleitung. Eine übernommene
// Zentrale könnte ihn sonst mit 307/302 an beliebige Adressen im internen
// Netz schicken, auch über http (Leitprinzip 1, Befund H1). Die
// Umleitungsantwort selbst gilt danach als Fehler (alles außer 200 bzw. 204).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func postJSON(ctx context.Context, c *http.Client, url string, in, out any) (int, error) {
	return postJSONLimit(ctx, c, url, in, out, 64<<10)
}

// postJSONLimit: wie postJSON mit eigener Obergrenze für die Antwort.
func postJSONLimit(ctx context.Context, c *http.Client, url string, in, out any, limit int64) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if int64(len(data)) > limit {
		return resp.StatusCode, errors.New("Antwort der Zentrale zu groß")
	}
	if resp.StatusCode == http.StatusNoContent && out == nil {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Fehler string `json:"fehler"`
		}
		json.Unmarshal(data, &e)
		if e.Fehler == "" {
			e.Fehler = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("Zentrale: %s (HTTP %d)", e.Fehler, resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("Antwort der Zentrale unlesbar: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Register meldet den Rechner mit einem Token bei der Zentrale an und legt
// Schlüssel und Zertifikat im Verzeichnis dir ab. Beim ersten Kontakt
// vertraut der Agent nur der CA, deren Fingerabdruck im Token steht.
func Register(ctx context.Context, dir, zentrale, token, hostname string, replace bool) (string, error) {
	u, err := checkZentrale(zentrale)
	if err != nil {
		return "", err
	}
	_, fp, err := agentproto.ParseToken(token)
	if err != nil {
		return "", err
	}
	if err := agentproto.ValidHostname(hostname); err != nil {
		return "", fmt.Errorf("Hostname %q ist ungültig (Option -hostname): %w", hostname, err)
	}
	if err := prepareDir(dir); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, fileConfig)); err == nil && !replace {
		return "", ErrAlreadyRegistered
	}
	key, csr, err := newKeyAndCSR()
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	// Je Schritt eine eigene Frist, damit ein Fehler sagt, woran es lag
	// (Verbindung, TLS, Antwort), statt nach 30 s nur „Timeout“ zu melden.
	pinned := &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Die normale Prüfung entfällt nur, weil VerifyConnection sie durch
			// die strengere Prüfung gegen den Fingerabdruck ersetzt.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				raw := make([][]byte, 0, len(cs.PeerCertificates))
				for _, c := range cs.PeerCertificates {
					raw = append(raw, c.Raw)
				}
				_, err := pki.VerifyPinnedServer(raw, fp, host, time.Now())
				return err
			},
		}}, CheckRedirect: noRedirect}
	var resp agentproto.RegisterResponse
	if _, err := postJSON(ctx, pinned, u.String()+agentproto.PathRegister,
		agentproto.RegisterRequest{Token: token, CSR: csr, Hostname: hostname}, &resp); err != nil {
		return "", registerError(u.Host, err)
	}
	// Antwort prüfen, bevor etwas gespeichert wird.
	ca, err := pki.ParseCertPEM([]byte(resp.CA))
	if err != nil || pki.Fingerprint(ca) != fp {
		return "", errors.New("die Zentrale hat eine andere CA geliefert als im Token angegeben")
	}
	cert, err := pki.ParseCertPEM([]byte(resp.Certificate))
	if err != nil {
		return "", err
	}
	if id, err := pki.AgentID(cert); err != nil || id != resp.AgentID || !key.PublicKey.Equal(cert.PublicKey) {
		return "", errors.New("das gelieferte Zertifikat passt nicht zu dieser Anmeldung")
	}
	kp, err := keyPEM(key)
	if err != nil {
		return "", err
	}
	cfg, _ := json.MarshalIndent(config{Zentrale: u.String(), AgentID: resp.AgentID}, "", "  ")
	for _, f := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{fileKey, kp, 0o600}, {fileCert, []byte(resp.Certificate), 0o644},
		{fileCA, []byte(resp.CA), 0o644}, {fileConfig, cfg, 0o644},
	} {
		if err := writeFileAtomic(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return "", err
		}
	}
	return resp.AgentID, nil
}

// Runner meldet regelmäßig Messwerte und erneuert das Zertifikat.
type Runner struct {
	dir      string
	cfg      config
	zentrale *url.URL
	client   *http.Client
	collect  func() (agentproto.Snapshot, error)
	now      func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
	// cas: Agent-CAs aus ca.pem, die ausstellende zuerst (Etappe 32); unter mu
	cas []*x509.Certificate
	// tlsBase: TLS-Einstellungen ohne RootCAs, für einen neuen Transport nach einem CA-Wechsel
	tlsBase *tls.Config

	// coll: Sammler für SNMP-Geräte (nur nach lokaler Freigabe aktiv)
	coll *snmpCollector
	// sens: Sensoren auf dem Agent (misst nur lokal Freigegebenes)
	sens *sensorRunner
	// upd: signierte Updates (Etappe 23)
	upd updateState
}

// NewRunner lädt den Zustand aus dir.
func NewRunner(dir string, collect func() (agentproto.Snapshot, error)) (*Runner, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileConfig))
	if err != nil {
		return nil, fmt.Errorf("nicht registriert (%v); zuerst „openwacht-agent registrieren“ ausführen", err)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	u, err := checkZentrale(cfg.Zentrale)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, fileCA))
	if err != nil {
		return nil, err
	}
	cas, err := pki.ParseCABundle(caPEM)
	if err != nil {
		return nil, fmt.Errorf("ca.pem ist unlesbar: %w", err)
	}
	r := &Runner{dir: dir, cfg: cfg, zentrale: u, collect: collect, now: time.Now, cas: cas,
		upd: updateState{key: defaultUpdateKey(), tried: map[string]time.Time{}}}
	r.coll = newSNMPCollector(r)
	r.sens = newSensorRunner(r)
	if err := r.loadCert(); err != nil {
		return nil, err
	}
	r.tlsBase = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: u.Hostname(),
		// Liefert immer das aktuelle Zertifikat, auch nach einer Erneuerung.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			r.mu.RLock()
			defer r.mu.RUnlock()
			return r.cert, nil
		},
	}
	st := &swapTransport{}
	st.p.Store(r.newTransport(cas))
	r.client = &http.Client{Timeout: 30 * time.Second, Transport: st, CheckRedirect: noRedirect}
	return r, nil
}

// swapTransport: Transport, der sich nach einem CA-Wechsel austauschen lässt,
// während Sammler und Sensoren denselben Client benutzen.
type swapTransport struct {
	p atomic.Pointer[http.Transport]
}

func (t *swapTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.p.Load().RoundTrip(r)
}

func (t *swapTransport) CloseIdleConnections() { t.p.Load().CloseIdleConnections() }

func (r *Runner) newTransport(cas []*x509.Certificate) *http.Transport {
	pool := x509.NewCertPool()
	for _, c := range cas {
		pool.AddCert(c)
	}
	cfg := r.tlsBase.Clone()
	cfg.RootCAs = pool
	return &http.Transport{TLSClientConfig: cfg}
}

// caFingerprints: Fingerabdrücke aus ca.pem in Dateireihenfolge.
func (r *Runner) caFingerprints() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.cas))
	for i, c := range r.cas {
		out[i] = pki.Fingerprint(c)
	}
	return out
}

// updateCA übernimmt ein neues Bündel der Agent-CAs (Etappe 32). Es kam über
// eine gegen die bisherigen CAs geprüfte Verbindung und muss mindestens eine
// davon enthalten: So kann auch eine fehlerhafte Antwort den Agent nicht von
// der Zentrale aussperren.
func (r *Runner) updateCA(bundle []byte) error {
	cas, err := pki.ParseCABundle(bundle)
	if err != nil {
		return err
	}
	old := map[string]bool{}
	for _, fp := range r.caFingerprints() {
		old[fp] = true
	}
	keep := false
	for _, c := range cas {
		keep = keep || old[pki.Fingerprint(c)]
	}
	if !keep {
		return errors.New("neues CA-Bündel enthält keine der bisherigen CAs")
	}
	if err := writeFileAtomic(filepath.Join(r.dir, fileCA), pki.CABundlePEM(cas), 0o644); err != nil {
		return err
	}
	r.mu.Lock()
	r.cas = cas
	r.mu.Unlock()
	if st, ok := r.client.Transport.(*swapTransport); ok {
		prev := st.p.Swap(r.newTransport(cas))
		prev.CloseIdleConnections()
	}
	return nil
}

// issuerOutdated: Stammt das Client-Zertifikat nicht von der ausstellenden
// CA (der ersten in ca.pem)? Dann nach einem CA-Wechsel neu ausstellen lassen.
func (r *Runner) issuerOutdated() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.cas) == 0 || r.cert == nil || r.cert.Leaf == nil {
		return false
	}
	return r.cert.Leaf.CheckSignatureFrom(r.cas[0]) != nil
}

func (r *Runner) loadCert() error {
	c, err := tls.LoadX509KeyPair(filepath.Join(r.dir, fileCert), filepath.Join(r.dir, fileKey))
	if err != nil {
		return fmt.Errorf("Zertifikat oder Schlüssel unlesbar: %w", err)
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.cert = &c
	r.mu.Unlock()
	return nil
}

// CertNotAfter: Ablauf des aktuellen Zertifikats.
func (r *Runner) CertNotAfter() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert.Leaf.NotAfter
}

// AgentID ist die Kennung dieses Agents.
func (r *Runner) AgentID() string { return r.cfg.AgentID }

// needsRenewal: erneuern, wenn weniger als ein Drittel der Laufzeit übrig ist.
func (r *Runner) needsRenewal() bool {
	r.mu.RLock()
	leaf := r.cert.Leaf
	r.mu.RUnlock()
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Sub(r.now()) < life/3
}

// Renew holt ein neues Zertifikat mit neuem Schlüssel. Erst nach der
// Antwort werden die Dateien ersetzt; geht die Antwort verloren, gilt das
// alte Zertifikat bei der Zentrale weiter.
func (r *Runner) Renew(ctx context.Context) error {
	key, csr, err := newKeyAndCSR()
	if err != nil {
		return err
	}
	var resp agentproto.RenewResponse
	if _, err := postJSON(ctx, r.client, r.zentrale.String()+agentproto.PathRenew, agentproto.RenewRequest{CSR: csr}, &resp); err != nil {
		return err
	}
	cert, err := pki.ParseCertPEM([]byte(resp.Certificate))
	if err != nil {
		return err
	}
	if id, err := pki.AgentID(cert); err != nil || id != r.cfg.AgentID || !key.PublicKey.Equal(cert.PublicKey) {
		return errors.New("erneuertes Zertifikat passt nicht zu diesem Agent")
	}
	kp, err := keyPEM(key)
	if err != nil {
		return err
	}
	// Schlüssel zuerst, dann Zertifikat; ein Absturz dazwischen wird beim
	// Laden bemerkt (Paar passt nicht) und das alte Zertifikat bleibt im Speicher.
	if err := writeFileAtomic(filepath.Join(r.dir, fileKey), kp, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(r.dir, fileCert), []byte(resp.Certificate), 0o644); err != nil {
		return err
	}
	if err := r.loadCert(); err != nil {
		return err
	}
	if resp.CA != "" {
		if err := r.updateCA([]byte(resp.CA)); err != nil {
			slog.Warn("CA-Bündel aus der Erneuerung nicht übernommen", "fehler", err)
		}
	}
	// Das Client-Zertifikat wird nur beim TLS-Handshake vorgezeigt. Offene
	// Keep-Alive-Verbindungen würden sonst weiter mit dem alten Zertifikat laufen.
	r.client.CloseIdleConnections()
	return nil
}

// Report sammelt und sendet einmal. Liefert das gewünschte Intervall.
func (r *Runner) Report(ctx context.Context) (time.Duration, int, error) {
	snap, err := r.collect()
	if err != nil {
		return 0, 0, fmt.Errorf("Messwerte: %w", err)
	}
	// Die Freigabe als Sammler meldet der Agent mit, damit die Zentrale ihn
	// zur Auswahl anbietet; ohne Freigabe holt er keine Geräteliste ab.
	if nets, err := ReadCollectorConfig(r.dir); err != nil {
		slog.Warn("Sammler: lokale Freigabe unlesbar, Sammler bleibt aus", "fehler", err)
	} else if nets != nil {
		snap.Collector = &agentproto.Collector{Nets: netStrings(nets)}
	}
	// Ebenso die Freigabe für Sensoren, damit die Oberfläche sie anzeigt.
	if rel, err := ReadSensorConfig(r.dir); err != nil {
		slog.Warn("Sensoren: lokale Freigabe unlesbar", "fehler", err)
	} else {
		snap.Sensors = rel
	}
	snap.Platform = Platform()
	snap.UpdateError = readUpdateError(r.dir)
	snap.CAs = r.caFingerprints()
	var resp agentproto.ReportResponse
	status, err := postJSON(ctx, r.client, r.zentrale.String()+agentproto.PathReport, snap, &resp)
	if err != nil {
		return 0, status, err
	}
	r.upd.offer = resp.Update
	if resp.CA != "" {
		if err := r.updateCA([]byte(resp.CA)); err != nil {
			slog.Warn("CA-Bündel der Zentrale nicht übernommen", "fehler", err)
		} else {
			slog.Info("Agent-CAs aktualisiert", "anzahl", len(r.caFingerprints()))
		}
	}
	d := time.Duration(resp.IntervalSeconds) * time.Second
	return min(max(d, minInterval), maxInterval), status, nil
}

// Run meldet, bis ctx endet. Fehler führen zu wachsenden Pausen (bis 15 Min.),
// nie zum Abbruch: Ein Agent soll eine Störung der Zentrale überstehen.
func (r *Runner) Run(ctx context.Context) {
	failures := 0
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() { defer wg.Done(); r.coll.run(ctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); r.sens.run(ctx) }()
	for {
		if r.needsRenewal() || r.issuerOutdated() {
			if err := r.Renew(ctx); err != nil {
				slog.Warn("Zertifikat erneuern fehlgeschlagen", "fehler", err)
			} else {
				slog.Info("Zertifikat erneuert", "gueltig_bis", r.CertNotAfter())
			}
		}
		next, status, err := r.Report(ctx)
		var wait time.Duration
		switch {
		case err == nil:
			failures, wait = 0, next
			r.coll.trigger()
			r.sens.trigger()
			r.maybeUpdate(ctx)
		default:
			failures++
			wait = backoff(failures)
			if status == http.StatusUnauthorized {
				slog.Error("Zentrale lehnt diesen Agent ab (gesperrt oder Zertifikat ersetzt)", "fehler", err)
				wait = max(wait, 15*time.Minute)
			} else {
				slog.Warn("Meldung fehlgeschlagen", "fehler", err, "naechster_versuch", wait)
			}
		}
		// ±10 % Streuung, damit nicht alle Agents gleichzeitig melden.
		wait = time.Duration(float64(wait) * (0.9 + 0.2*mrand.Float64()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func backoff(n int) time.Duration {
	d := time.Duration(math.Pow(2, float64(min(n, 10)))) * 5 * time.Second
	return min(d, 15*time.Minute)
}

// registerError benennt, an welchem Schritt die Registrierung scheiterte.
func registerError(host string, err error) error {
	var dns *net.DNSError
	var op *net.OpError
	l := err.Error()
	switch {
	case errors.As(err, &dns):
		return fmt.Errorf("Name der Zentrale nicht gefunden (%s): %w", host, err)
	case strings.Contains(l, "TLS handshake timeout"):
		return fmt.Errorf("Zentrale %s antwortet nicht auf TLS (richtiger Port für Agents? Standard 8444): %w", host, err)
	case strings.Contains(l, "timeout awaiting response headers"):
		return fmt.Errorf("Zentrale %s hat nicht rechtzeitig geantwortet: %w", host, err)
	case errors.As(err, &op) && op.Op == "dial":
		return fmt.Errorf("keine Verbindung zur Zentrale %s (Firewall, Port, Adresse): %w", host, err)
	case strings.Contains(l, "Fingerabdruck") || strings.Contains(l, "Zertifikat") || strings.Contains(l, "keine CA") ||
		strings.Contains(l, "certificate") || strings.Contains(l, "x509"):
		return fmt.Errorf("Zertifikat der Zentrale %s passt nicht zum Token (Adresse und Port für Agents prüfen): %w", host, err)
	}
	return fmt.Errorf("Registrierung bei %s: %w", host, err)
}
