// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Agent-Port der Zentrale: Registrierung, Messwerte, Zertifikatserneuerung.
//
// Eigener Listener mit TLS 1.3 und Client-Zertifikaten (mTLS), getrennt von
// der Oberfläche. Die Zentrale antwortet Agents nur mit Daten, nie mit
// Befehlen (Leitprinzip 1). Den Mandanten leitet die Datenbank aus Token bzw.
// Agent-Tabelle ab (Leitprinzip 2).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/version"
)

// agentState hält CA und Server-Zertifikat des Agent-Ports.
type agentState struct {
	mu         sync.Mutex
	ca         *pki.CA // aktive CA: stellt Client- und Server-Zertifikate aus
	serverCert *tls.Certificate
	limiter    *ipLimiter
	download   *ipLimiter // Downloads je Adresse (Etappe 34)
	// Agent-CA-Wechsel (Etappe 32): alle vertrauenswürdigen CAs, die aktive
	// zuerst, danach neu und alt; als PEM-Bündel und als Fingerabdrücke.
	trusted []*x509.Certificate
	bundle  string
	fps     []string
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // Version 4
	b[8] = b[8]&0x3f | 0x80 // Variante RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// InitAgentCA lädt die Agent-CA aus der Datenbank oder legt sie beim ersten
// Start an. Der private Schlüssel liegt mit dem Hauptschlüssel verschlüsselt.
func (s *Server) InitAgentCA(ctx context.Context) error {
	caKey := deriveKey(s.key, "openwacht agent-ca v1")
	fresh, err := pki.NewCA("OpenWacht Agent-CA", s.now())
	if err != nil {
		return err
	}
	der, err := fresh.KeyDER()
	if err != nil {
		return err
	}
	enc, err := auth.Seal(caKey, der, []byte("agent-ca"))
	if err != nil {
		return err
	}
	var certPEM string
	var keyEnc []byte
	if err := s.pool.QueryRow(ctx, `SELECT cert_pem, key_enc FROM openwacht.agent_ca_init($1, $2)`,
		string(fresh.CertPEM()), enc).Scan(&certPEM, &keyEnc); err != nil {
		return fmt.Errorf("Agent-CA laden: %w", err)
	}
	keyDER, err := auth.Open(caKey, keyEnc, []byte("agent-ca"))
	if err != nil {
		return errors.New("Agent-CA lässt sich nicht entschlüsseln: Ist es derselbe Hauptschlüssel wie bei der Einrichtung?")
	}
	ca, err := pki.LoadCA([]byte(certPEM), keyDER)
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `SELECT state, cert_pem FROM openwacht.agent_ca_list()`)
	if err != nil {
		return fmt.Errorf("Agent-CAs laden: %w", err)
	}
	trusted := []*x509.Certificate{ca.Cert}
	for rows.Next() {
		var state, pemText string
		if err := rows.Scan(&state, &pemText); err != nil {
			rows.Close()
			return err
		}
		if state == "aktiv" {
			continue
		}
		c, err := pki.ParseCertPEM([]byte(pemText))
		if err != nil || !c.IsCA {
			rows.Close()
			return fmt.Errorf("Agent-CA (%s) unlesbar", state)
		}
		trusted = append(trusted, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	s.agent.ca = ca
	s.agent.trusted = trusted
	s.agent.bundle = string(pki.CABundlePEM(trusted))
	s.agent.fps = make([]string, len(trusted))
	for i, c := range trusted {
		s.agent.fps[i] = pki.Fingerprint(c)
	}
	return nil
}

// AgentCAFingerprint ist der Fingerabdruck, der in Registrierungs-Token steht.
func (s *Server) AgentCAFingerprint() string { return pki.Fingerprint(s.agent.ca.Cert) }

// AgentTLSConfig liefert die TLS-Konfiguration des Agent-Ports: nur TLS 1.3,
// Client-Zertifikat optional (für die Registrierung), aber falls vorhanden
// gegen die Agent-CA geprüft. Das Server-Zertifikat wird erneuert, wenn es
// weniger als 7 Tage gilt.
func (s *Server) AgentTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	for _, c := range s.agent.trusted {
		pool.AddCert(c)
	}
	if len(s.agent.trusted) == 0 {
		pool.AddCert(s.agent.ca.Cert)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.agent.mu.Lock()
			defer s.agent.mu.Unlock()
			if c := s.agent.serverCert; c != nil && c.Leaf.NotAfter.Sub(s.now()) > 7*24*time.Hour {
				return c, nil
			}
			c, err := s.agent.ca.ServerCert(s.cfg.AgentNames, 30*24*time.Hour, s.now())
			if err != nil {
				return nil, err
			}
			s.agent.serverCert = &c
			return &c, nil
		},
	}
}

// AgentHandler liefert die Routen des Agent-Ports.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+agentproto.PathRegister, s.handleAgentRegister)
	mux.Handle("POST "+agentproto.PathReport, s.requireAgent(http.HandlerFunc(s.handleAgentReport)))
	mux.Handle("POST "+agentproto.PathRenew, s.requireAgent(http.HandlerFunc(s.handleAgentRenew)))
	mux.Handle("POST "+agentproto.PathUpdateSignature, s.requireAgent(http.HandlerFunc(s.handleAgentUpdateSignature)))
	mux.Handle("POST "+agentproto.PathUpdateBinary, s.requireAgent(http.HandlerFunc(s.handleAgentUpdateBinary)))
	mux.Handle("POST "+agentproto.PathCollectorDevices, s.requireAgent(http.HandlerFunc(s.handleCollectorDevices)))
	mux.Handle("POST "+agentproto.PathCollectorResult, s.requireAgent(http.HandlerFunc(s.handleCollectorResult)))
	mux.Handle("POST "+agentproto.PathSensorJobs, s.requireAgent(http.HandlerFunc(s.handleSensorJobs)))
	mux.Handle("POST "+agentproto.PathSensorResults, s.requireAgent(http.HandlerFunc(s.handleSensorResults)))
	mux.HandleFunc("GET "+PathDownload+"{os}/{arch}", s.handleDownloadBinary)
	mux.HandleFunc("GET "+PathDownload+"{os}/{arch}/signatur", s.handleDownloadSignature)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Unbekannter Endpunkt.")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// Grenzen je Agent und Minute. Ein Agent meldet höchstens alle 15 Sekunden
// (agent.minInterval) und erneuert sein Zertifikat alle paar Wochen; die
// Grenzen lassen Neustarts und Wiederholungen zu, aber keine Flut.
const (
	agentReportsPerMinute       = 12
	agentRenewalsPerMinute      = 4
	agentUpdateFetchesPerMinute = 6
)

// agentRate prüft eine Grenze je Agent; false: Die Antwort 429 ist geschrieben.
func (s *Server) agentRate(w http.ResponseWriter, l *rateWindow, agentID string) bool {
	if l.allow(agentID, s.now()) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, "Zu viele Anfragen dieses Agents. Bitte kurz warten.")
	return false
}

type agentIdentity struct {
	ID     string
	Serial string
	Issuer string // Fingerabdruck der CA aus der geprüften Kette
}

const agentKey ctxKey = 2

// requireAgent prüft das Client-Zertifikat (Kette hat TLS schon geprüft) und
// gleicht Agent-ID und Seriennummer mit der Datenbank ab: Gesperrte Agents und
// ersetzte Zertifikate werden abgewiesen.
func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "Client-Zertifikat erforderlich.")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id, err := pki.AgentID(leaf)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Kein gültiges Agent-Zertifikat.")
			return
		}
		ident := agentIdentity{ID: id, Serial: pki.SerialHex(leaf)}
		if ch := r.TLS.VerifiedChains[0]; len(ch) > 1 {
			ident.Issuer = pki.Fingerprint(ch[1])
		}
		var ok bool
		if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_check($1, $2)`, ident.ID, ident.Serial).Scan(&ok); err != nil {
			internalError(w, "agent_check", err)
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "Agent gesperrt oder Zertifikat ersetzt.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentKey, ident)))
	})
}

func readAgentJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrage.")
		return false
	}
	return true
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	if !s.agent.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Registrierungsversuche. Bitte kurz warten.")
		return
	}
	var req agentproto.RegisterRequest
	if !readAgentJSON(w, r, 16<<10, &req) {
		return
	}
	secret, fp, err := agentproto.ParseToken(req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if fp != s.AgentCAFingerprint() {
		writeError(w, http.StatusBadRequest, "Das Token gehört zu einer anderen Zentrale.")
		return
	}
	if err := agentproto.ValidHostname(req.Hostname); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := newUUID()
	if err != nil {
		internalError(w, "uuid", err)
		return
	}
	cert, err := s.agent.ca.SignAgentCSR(req.CSR, id, s.cfg.AgentCertLifetime, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash := sha256.Sum256(secret)
	var tenant string
	err = s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_enroll($1, $2, $3, $4, $5)::text`,
		hash[:], id, req.Hostname, pki.SerialHex(cert), cert.NotAfter).Scan(&tenant)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "28000" {
		writeError(w, http.StatusUnauthorized, "Das Token ist ungültig, abgelaufen oder schon verbraucht.")
		return
	}
	if err != nil {
		internalError(w, "agent_enroll", err)
		return
	}
	slog.Info("Agent registriert", "agent", id, "hostname", req.Hostname, "mandant", tenant)
	writeJSON(w, http.StatusOK, agentproto.RegisterResponse{
		AgentID:     id,
		Certificate: string(pki.CertToPEM(cert)),
		CA:          s.caBundle(),
	})
}

// caBundle: vertrauenswürdige Agent-CAs (die aktive zuerst) als PEM.
func (s *Server) caBundle() string {
	if s.agent.bundle != "" {
		return s.agent.bundle
	}
	return string(s.agent.ca.CertPEM())
}

// caUpdateFor: neues Bündel, wenn der Agent ein anderes meldet (nil = keins).
func (s *Server) caUpdateFor(reported []string) string {
	if len(s.agent.fps) == 0 || slices.Equal(reported, s.agent.fps) {
		return ""
	}
	return s.agent.bundle
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	if !s.agentRate(w, s.agentReportRate, ident.ID) {
		return
	}
	var snap agentproto.Snapshot
	if !readAgentJSON(w, r, agentproto.MaxReportBytes, &snap) {
		return
	}
	if err := snap.Validate(s.now()); err != nil {
		writeError(w, http.StatusBadRequest, "Messwerte abgelehnt: "+err.Error())
		return
	}
	// Die ausstellende CA kommt aus der geprüften Kette, nicht vom Agent.
	snap.CertCA = ident.Issuer
	// Gespeichert wird die geprüfte Struktur, nicht der rohe Text des Agents.
	clean, err := json.Marshal(snap)
	if err != nil {
		internalError(w, "marshal", err)
		return
	}
	names, values := hostSeries(&snap)
	// Absenderadresse der Verbindung (der Agent-Port läuft ohne Proxy), nur
	// für den Vorschlag, Geräte zusammenzuführen. Nie aus den Daten des Agents.
	var addr *string
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		a := ap.Addr().Unmap().WithZone("").String()
		addr = &a
	}
	var ok bool
	if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_report($1, $2, $3, $4, $5, $6, $7::inet)`,
		ident.ID, ident.Serial, snap.Hostname, clean, names, values, addr).Scan(&ok); err != nil {
		internalError(w, "agent_report", err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "Agent gesperrt oder Zertifikat ersetzt.")
		return
	}
	writeJSON(w, http.StatusOK, agentproto.ReportResponse{IntervalSeconds: int(s.cfg.AgentInterval.Seconds()),
		Update: s.updateOffer(r.Context(), ident.ID, &snap), CA: s.caUpdateFor(snap.CAs)})
}

func (s *Server) handleAgentRenew(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	if !s.agentRate(w, s.agentRenewRate, ident.ID) {
		return
	}
	var req agentproto.RenewRequest
	if !readAgentJSON(w, r, 16<<10, &req) {
		return
	}
	cert, err := s.agent.ca.SignAgentCSR(req.CSR, ident.ID, s.cfg.AgentCertLifetime, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ok bool
	if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_renew($1, $2, $3, $4)`,
		ident.ID, ident.Serial, pki.SerialHex(cert), cert.NotAfter).Scan(&ok); err != nil {
		internalError(w, "agent_renew", err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "Agent gesperrt oder Zertifikat ersetzt.")
		return
	}
	writeJSON(w, http.StatusOK, agentproto.RenewResponse{Certificate: string(pki.CertToPEM(cert)), CA: s.caBundle()})
}

// --- Verwaltung über die Oberfläche --------------------------------------------

type tokenOut struct {
	ID         string    `json:"id"`
	Notiz      string    `json:"notiz"`
	Restanzahl int       `json:"restanzahl"`
	LaeuftAb   time.Time `json:"laeuft_ab"`
	Erstellt   time.Time `json:"erstellt"`
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Notiz         string `json:"notiz"`
		Anzahl        int    `json:"anzahl"`
		GueltigStunde int    `json:"gueltig_stunden"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Anzahl == 0 {
		in.Anzahl = 1
	}
	if in.GueltigStunde == 0 {
		in.GueltigStunde = 24
	}
	if in.Anzahl < 1 || in.Anzahl > 1000 || in.GueltigStunde < 1 || in.GueltigStunde > 168 {
		writeError(w, http.StatusBadRequest, "Anzahl 1 bis 1000, Gültigkeit 1 bis 168 Stunden.")
		return
	}
	if len([]rune(in.Notiz)) > 100 {
		writeError(w, http.StatusBadRequest, "Die Notiz darf höchstens 100 Zeichen lang sein.")
		return
	}
	token, secret, err := agentproto.NewToken(s.AgentCAFingerprint())
	if err != nil {
		internalError(w, "token", err)
		return
	}
	hash := sha256.Sum256(secret)
	expires := s.now().Add(time.Duration(in.GueltigStunde) * time.Hour)
	s.handle(w, r, "agent-token", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_tokens (token_hash, tenant_id, note, uses_left, expires_at)
			VALUES ($1, $2, $3, $4, $5)`, hash[:], tid, in.Notiz, in.Anzahl, expires); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "agent.token_erstellt", map[string]any{"anzahl": in.Anzahl, "notiz": in.Notiz,
			"gueltig_stunden": in.GueltigStunde}); err != nil {
			return 0, nil, err
		}
		offers, err := s.downloadOffers(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		// Das Token gibt es nur in dieser Antwort; gespeichert ist nur sein Hash.
		return http.StatusCreated, map[string]any{"token": token, "laeuft_ab": expires, "anzahl": in.Anzahl,
			"zentrale": s.cfg.AgentURL, "version": version.Version, "download": withCommands(offers, s.cfg.AgentURL, token, s.caBundle())}, nil
	})
}

func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "agent-tokens", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, note, uses_left, expires_at, created_at FROM openwacht.agent_tokens
			WHERE tenant_id = $1 AND expires_at > now() ORDER BY created_at DESC`, tid)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tokenOut, error) {
			var t tokenOut
			err := row.Scan(&t.ID, &t.Notiz, &t.Restanzahl, &t.LaeuftAb, &t.Erstellt)
			return t, err
		})
		if list == nil {
			list = []tokenOut{}
		}
		return http.StatusOK, map[string]any{"tokens": list}, err
	})
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "agent-token löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.agent_tokens WHERE id = $1 RETURNING tenant_id::text`, id).Scan(&tenant); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "agent.token_geloescht", map[string]any{"token": id}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

type agentOut struct {
	ID        string `json:"id"`
	MandantID string `json:"mandant_id"`
	GeraetID  string `json:"geraet_id"`
	Hostname  string `json:"hostname"`
	// Adresse, von der sich der Agent zuletzt gemeldet hat
	Adresse       *string          `json:"adresse"`
	Registriert   time.Time        `json:"registriert"`
	ZuletztDa     *time.Time       `json:"zuletzt_gesehen"`
	Gesperrt      *time.Time       `json:"gesperrt"`
	ZertifikatBis time.Time        `json:"zertifikat_bis"`
	Messwerte     *json.RawMessage `json:"messwerte"`
	Wartung       *wartungOut      `json:"wartung"`
}

func (s *Server) handleAgentList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "agents", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		maint, err := visibleMaintenance(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT a.id::text, a.tenant_id::text, a.device_id::text, a.hostname, host(a.last_addr),
				a.created_at, a.last_seen, a.revoked_at, a.cert_not_after, a.snapshot
			FROM openwacht.agents a
			WHERE ($1 = '' OR a.tenant_id = $1::uuid) ORDER BY a.hostname`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (agentOut, error) {
			var a agentOut
			var snap []byte
			err := row.Scan(&a.ID, &a.MandantID, &a.GeraetID, &a.Hostname, &a.Adresse, &a.Registriert, &a.ZuletztDa, &a.Gesperrt,
				&a.ZertifikatBis, &snap)
			if a.Gesperrt == nil {
				a.Wartung = maint["a:"+a.ID]
			}
			if snap != nil {
				raw := json.RawMessage(snap)
				a.Messwerte = &raw
			}
			return a, err
		})
		if list == nil {
			list = []agentOut{}
		}
		return http.StatusOK, map[string]any{"agents": list, "intervall_sekunden": int(s.cfg.AgentInterval.Seconds()),
			"zentrale": s.cfg.AgentURL}, err
	})
}

func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "agent sperren", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, host string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.agents SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
			RETURNING tenant_id::text, hostname`, id).Scan(&tenant, &host); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "agent.gesperrt", map[string]any{"agent": id, "hostname": host}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleAgentDelete löscht einen gesperrten Agent samt Verlauf. Wer ihn nicht
// sieht, bekommt 404; ist er nicht gesperrt, 409; fehlt das Recht, 403. Bleibt
// sein Gerät danach leer (keine Checks, kein anderer Agent), geht es mit.
func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "agent löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, host, device string
		var revoked bool
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, hostname, revoked_at IS NOT NULL, device_id::text
			FROM openwacht.agents WHERE id = $1`, id).Scan(&tenant, &host, &revoked, &device); err != nil {
			return 0, nil, err
		}
		if !revoked {
			return 0, nil, &apiError{http.StatusConflict, "Nur gesperrte Agents lassen sich löschen. Bitte zuerst sperren."}
		}
		if n, err := collectorRefs(ctx, tx, id); err != nil {
			return 0, nil, err
		} else if n > 0 {
			return 0, nil, &apiError{http.StatusConflict, fmt.Sprintf("Der Agent ist Sammler für %s. Bitte dort zuerst unter „Abgefragt von“ einen anderen Sammler oder die Zentrale wählen.", devicesText(n))}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Löschen dürfen nur Admins und Operatoren."}
		}
		if err := audit(ctx, tx, &tenant, "agent.geloescht", map[string]any{"agent": id, "hostname": host}); err != nil {
			return 0, nil, err
		}
		var name string
		err = tx.QueryRow(ctx, `DELETE FROM openwacht.devices d WHERE d.id = $1
			AND NOT EXISTS (SELECT 1 FROM openwacht.checks c WHERE c.device_id = d.id)
			AND NOT EXISTS (SELECT 1 FROM openwacht.agents a WHERE a.device_id = d.id)
			RETURNING d.name`, device).Scan(&name)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return 0, nil, err
		default:
			if err := audit(ctx, tx, &tenant, "geraet.geloescht", map[string]any{"id": device, "name": name,
				"grund": "letzter Agent gelöscht"}); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusNoContent, nil, nil
	})
}
