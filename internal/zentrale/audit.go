// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Audit-Log (Etappe 31, Befund M6): täglicher Prüflauf der Hash-Kette,
// fortlaufender Export (JSON-Zeilen in eine Datei und/oder Syslog über TLS),
// Aufbewahrung mit Anker und Export für Admins über die API.
//
// Entscheidungen (Datei und Syslog; im Übrigen die sicherere Variante):
//   - Ziele des Exports sind Startoptionen (-audit-datei, -audit-syslog), keine
//     Einstellung in der Oberfläche: Eine übernommene Sitzung des Betreibers
//     kann den Strom so nicht umleiten oder abschalten. Syslog geht nur an
//     Adressen in der Netzfreigabe (wie alle Ziele der Zentrale), mit
//     geprüftem Zertifikat (RFC 5425, Rahmen nach Oktettzahl).
//   - Jede Zeile trägt Folgenummer, Hash und Hash des Vorgängers. Wer den
//     Export aufbewahrt, hat damit einen Anker außerhalb der Datenbank:
//     `openwacht-zentrale audit-pruefen -datei …` vergleicht ihn mit der Kette.
//   - Aufbewahrung: Löschen nur am Anfang der Kette, nach erfolgreicher
//     Prüfung und nur, was alle eingestellten Ziele schon haben.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditLine: ein exportierter Eintrag (eine JSON-Zeile).
type AuditLine struct {
	Seq        int64           `json:"seq"`
	Time       time.Time       `json:"zeit"`
	Tenant     *string         `json:"mandant"`
	TenantName *string         `json:"mandant_name"`
	Actor      *string         `json:"akteur"`
	ActorEmail *string         `json:"akteur_email"`
	Action     string          `json:"aktion"`
	Details    json.RawMessage `json:"details"`
	Prev       *string         `json:"vorher"`
	Hash       string          `json:"hash"`
}

func scanAuditLine(row pgx.CollectableRow) (AuditLine, error) {
	var l AuditLine
	var details []byte
	var prev, hash []byte
	err := row.Scan(&l.Seq, &l.Time, &l.Tenant, &l.TenantName, &l.Actor, &l.ActorEmail, &l.Action, &details, &prev, &hash)
	l.Time = l.Time.UTC()
	l.Details = details
	if prev != nil {
		p := hex.EncodeToString(prev)
		l.Prev = &p
	}
	l.Hash = hex.EncodeToString(hash)
	return l, err
}

// --- Export ----------------------------------------------------------------------

// AuditSyslog: Ziel für Syslog über TLS.
type AuditSyslog struct {
	Addr   string // host:port
	CAPEM  []byte // leer = Zertifikate des Systems
	Source string // HOSTNAME im Syslog-Kopf
}

type auditExporter struct {
	mu   sync.Mutex
	conn net.Conn // offene Syslog-Verbindung
	// Fehler seit (für die Selbstüberwachung); Null = kein Fehler
	failSince map[string]time.Time
	failMsg   map[string]string
}

const (
	auditTargetFile   = "datei"
	auditTargetSyslog = "syslog"
	auditBatch        = 500
)

// auditTargets: eingestellte Ziele.
func (s *Server) auditTargets() []string {
	var t []string
	if s.cfg.AuditFile != "" {
		t = append(t, auditTargetFile)
	}
	if s.cfg.AuditSyslog != nil {
		t = append(t, auditTargetSyslog)
	}
	return t
}

// ExportAudit schreibt alle neuen Einträge an jedes Ziel.
func (s *Server) ExportAudit(ctx context.Context) error {
	var errs []error
	for _, target := range s.auditTargets() {
		err := s.exportAuditTo(ctx, target)
		s.audit.mu.Lock()
		if err != nil {
			if s.audit.failSince[target].IsZero() {
				s.audit.failSince[target] = s.now()
			}
			s.audit.failMsg[target] = err.Error()
		} else {
			delete(s.audit.failSince, target)
			delete(s.audit.failMsg, target)
		}
		s.audit.mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target, err))
			if _, e := s.pool.Exec(context.WithoutCancel(ctx), `SELECT openwacht.audit_export_done($1, NULL, $2)`, target,
				clipRunes(err.Error(), 300)); e != nil {
				slog.Warn("Audit-Export: Fehler nicht gespeichert", "fehler", e)
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Server) exportAuditTo(ctx context.Context, target string) error {
	var after int64
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.audit_export_cursor($1)`, target).Scan(&after); err != nil {
		return err
	}
	for {
		rows, err := s.pool.Query(ctx, `SELECT * FROM openwacht.audit_export_rows($1, $2)`, after, auditBatch)
		if err != nil {
			return err
		}
		lines, err := pgx.CollectRows(rows, scanAuditLine)
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			return nil
		}
		switch target {
		case auditTargetFile:
			err = writeAuditFile(s.cfg.AuditFile, lines)
		case auditTargetSyslog:
			err = s.writeAuditSyslog(ctx, lines)
		}
		if err != nil {
			return err
		}
		after = lines[len(lines)-1].Seq
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.audit_export_done($1, $2, NULL)`, target, after); err != nil {
			return err
		}
		if len(lines) < auditBatch {
			return nil
		}
	}
}

// writeAuditFile hängt Zeilen an (Datei 0640, nach dem Schreiben auf die
// Platte gebracht). Logrotate mit copytruncate oder Umbenennen geht: Die
// Datei wird bei jedem Durchlauf neu geöffnet.
func writeAuditFile(path string, lines []AuditLine) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, l := range lines {
		j, err := json.Marshal(l)
		if err != nil {
			f.Close()
			return err
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syslogFrame: RFC 5424 mit Facility „log audit“ (13), Schwere notice (5),
// gerahmt nach RFC 5425 (Länge, Leerzeichen, Nachricht).
func syslogFrame(source string, l AuditLine) ([]byte, error) {
	j, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("<109>1 %s %s openwacht - audit - %s", l.Time.UTC().Format("2006-01-02T15:04:05.000000Z"),
		syslogName(source), j)
	return []byte(strconv.Itoa(len(msg)) + " " + msg), nil
}

// syslogName: HOSTNAME nach RFC 5424 (druckbares ASCII, höchstens 255 Zeichen).
func syslogName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 && b.Len() < 255 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func (s *Server) syslogConn(ctx context.Context) (net.Conn, error) {
	if s.audit.conn != nil {
		return s.audit.conn, nil
	}
	cfg := s.cfg.AuditSyslog
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if len(cfg.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CAPEM) {
			return nil, errors.New("CA für Syslog nicht lesbar")
		}
		tc.RootCAs = pool
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Nur Ziele in der Netzfreigabe, wie alle Verbindungen der Zentrale.
	raw, err := s.guard.DialContext(dctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, tc)
	if err := c.HandshakeContext(dctx); err != nil {
		raw.Close()
		return nil, err
	}
	s.audit.conn = c
	return c, nil
}

func (s *Server) writeAuditSyslog(ctx context.Context, lines []AuditLine) error {
	s.audit.mu.Lock()
	defer s.audit.mu.Unlock()
	c, err := s.syslogConn(ctx)
	if err != nil {
		return err
	}
	var buf []byte
	for _, l := range lines {
		f, err := syslogFrame(s.cfg.AuditSyslog.Source, l)
		if err != nil {
			return err
		}
		buf = append(buf, f...)
	}
	c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write(buf); err != nil {
		c.Close()
		s.audit.conn = nil
		return err
	}
	return nil
}

// --- Prüfung und Aufbewahrung ------------------------------------------------------

// AuditCheck: Ergebnis eines Prüflaufs.
type AuditCheck struct {
	At        time.Time
	OK        bool
	BrokenSeq *int64
	Entries   int64
	FirstSeq  *int64
	LastSeq   *int64
	LastHash  []byte
}

func (c *AuditCheck) dest() []any {
	return []any{&c.OK, &c.BrokenSeq, &c.Entries, &c.FirstSeq, &c.LastSeq, &c.LastHash}
}

// CheckAudit führt einen Prüflauf aus (auch Befehl audit-pruefen).
func CheckAudit(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (AuditCheck, error) {
	var c AuditCheck
	err := q.QueryRow(ctx, `SELECT ok, broken_seq, entries, first_seq, last_seq, last_hash FROM openwacht.audit_check_run()`).
		Scan(c.dest()...)
	c.At = time.Now()
	return c, err
}

func (s *Server) lastAuditCheck(ctx context.Context) (*AuditCheck, error) {
	var c AuditCheck
	err := s.pool.QueryRow(ctx, `SELECT at, ok, broken_seq, entries, first_seq, last_seq, last_hash FROM openwacht.audit_check_last()`).
		Scan(append([]any{&c.At}, c.dest()...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

// auditDaily: Prüflauf, wenn der letzte älter als 24 Stunden ist, danach die
// Aufbewahrung. Liefert das neue Ergebnis (nil = nicht fällig).
func (s *Server) auditDaily(ctx context.Context) (*AuditCheck, error) {
	last, err := s.lastAuditCheck(ctx)
	if err != nil {
		return nil, err
	}
	if last != nil && s.now().Sub(last.At) < 24*time.Hour {
		return nil, nil
	}
	c, err := CheckAudit(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	if !c.OK {
		slog.Error("Audit-Log: Hash-Kette gebrochen", "stelle", *c.BrokenSeq, "eintraege", c.Entries)
		return &c, nil
	}
	slog.Info("Audit-Log geprüft", "eintraege", c.Entries)
	if err := s.pruneAudit(ctx); err != nil {
		slog.Warn("Audit-Log: Aufbewahrung fehlgeschlagen", "fehler", err)
	}
	return &c, nil
}

func (s *Server) pruneAudit(ctx context.Context) error {
	var days *int32
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.runtime_audit_days()`).Scan(&days); err != nil || days == nil {
		return err
	}
	// Nur löschen, was jedes Ziel schon hat.
	var max *int64
	for _, t := range s.auditTargets() {
		var cur int64
		if err := s.pool.QueryRow(ctx, `SELECT openwacht.audit_export_cursor($1)`, t).Scan(&cur); err != nil {
			return err
		}
		if max == nil || cur < *max {
			max = &cur
		}
	}
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.audit_prune($1, $2)`, *days, max).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		slog.Info("Audit-Log: alte Einträge gelöscht (Anker gesetzt)", "anzahl", n, "aufbewahrung_tage", *days)
	}
	return nil
}

// RunAudit: Export alle 10 Sekunden, Prüfung täglich, bis ctx endet.
func (s *Server) RunAudit(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	lastDaily := time.Time{}
	for {
		if len(s.auditTargets()) > 0 {
			if err := s.ExportAudit(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("Audit-Export fehlgeschlagen", "fehler", err)
			}
		}
		if s.now().Sub(lastDaily) >= time.Hour {
			if _, err := s.auditDaily(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("Audit-Log: Prüfung fehlgeschlagen", "fehler", err)
			} else {
				lastDaily = s.now()
			}
		}
		select {
		case <-ctx.Done():
			s.audit.mu.Lock()
			if s.audit.conn != nil {
				s.audit.conn.Close()
				s.audit.conn = nil
			}
			s.audit.mu.Unlock()
			return
		case <-tick.C:
		}
	}
}

// auditExportFailure: ältester Fehler eines Ziels (für die Selbstüberwachung).
func (s *Server) auditExportFailure() (since time.Time, msg string) {
	s.audit.mu.Lock()
	defer s.audit.mu.Unlock()
	for t, at := range s.audit.failSince {
		if since.IsZero() || at.Before(since) {
			since, msg = at, t+": "+s.audit.failMsg[t]
		}
	}
	return since, msg
}

// --- API -----------------------------------------------------------------------------

// handleAuditExport: GET /api/v1/audit/export?ab=<Folgenummer>&anzahl=<n>&mandant=<ID>
// liefert JSON-Zeilen für Admins, nur aus Mandanten, die sie verwalten (und
// Einträge ohne Mandant nur für Admins des Hauptmandanten, ohne Filter).
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var after int64
	if v := q.Get("ab"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "ab: Folgenummer ab 0.")
			return
		}
		after = n
	}
	limit := 1000
	if v := q.Get("anzahl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "anzahl: 1 bis 5000.")
			return
		}
		limit = n
	}
	tenant := q.Get("mandant")
	if tenant != "" && !uuidPattern.MatchString(tenant) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	var lines []AuditLine
	sess := sessionFrom(r.Context())
	err := s.withUser(r.Context(), sess.UserID, func(tx pgx.Tx) error {
		ctx := r.Context()
		var admin, root bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.admin_tenants()), openwacht.is_root_admin()`).
			Scan(&admin, &root); err != nil {
			return err
		}
		if !admin {
			return &apiError{http.StatusForbidden, "Nur Admins können das Audit-Log exportieren."}
		}
		if tenant != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, tenant).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return &apiError{http.StatusForbidden, "Diesen Mandanten verwaltest du nicht."}
			}
		}
		rows, err := tx.Query(ctx, `
			WITH RECURSIVE sub AS (
				SELECT id FROM openwacht.tenants WHERE $3 <> '' AND id = nullif($3, '')::uuid
				UNION SELECT t.id FROM openwacht.tenants t JOIN sub ON t.parent_id = sub.id)
			SELECT a.chain_seq, a.at, a.tenant_id::text, t.name, a.actor_user_id::text, u.email, a.action, a.details,
			       a.prev_hash, a.hash
			  FROM openwacht.audit_log a
			  LEFT JOIN openwacht.tenants t ON t.id = a.tenant_id
			  LEFT JOIN openwacht.users u ON u.id = a.actor_user_id
			 WHERE a.chain_seq > $1
			   AND (a.tenant_id IN (SELECT openwacht.admin_tenants()) OR (a.tenant_id IS NULL AND openwacht.is_root_admin()))
			   AND ($3 = '' OR a.tenant_id IN (SELECT id FROM sub))
			 ORDER BY a.chain_seq LIMIT $2`, after, limit, tenant)
		if err != nil {
			return err
		}
		if lines, err = pgx.CollectRows(rows, scanAuditLine); err != nil {
			return err
		}
		// Vermerk: beim gefilterten Mandanten, ohne Filter beim Hauptmandanten
		// (Eintrag ohne Mandant) bzw. beim ersten verwalteten Mandanten.
		note := nullIfEmpty(tenant)
		if note == nil && !root {
			var first string
			if err := tx.QueryRow(ctx, `SELECT min(t::text) FROM openwacht.admin_tenants() t`).Scan(&first); err != nil {
				return err
			}
			note = &first
		}
		return audit(ctx, tx, note, "audit.exportiert", map[string]any{"ab": after, "anzahl": len(lines), "mandant": tenant})
	})
	if err != nil {
		writeDBError(w, "audit export", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="openwacht-audit.jsonl"`)
	if len(lines) > 0 {
		w.Header().Set("X-OpenWacht-Letzte", strconv.FormatInt(lines[len(lines)-1].Seq, 10))
	}
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for _, l := range lines {
		enc.Encode(l)
	}
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// handleAuditStatus: GET /api/v1/einstellungen/audit (nur Betreiber).
func (s *Server) handleAuditStatus(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen audit", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var (
			at                         *time.Time
			ok                         *bool
			broken, entries, first, la *int64
			hash                       []byte
			days                       *int32
			prunedAt                   *time.Time
			prunedTotal                *int64
			fileSeq, sysSeq            *int64
			fileErr, sysErr            *string
			fileErrAt, sysErrAt        *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT * FROM openwacht.audit_status()`).Scan(&at, &ok, &broken, &entries, &first, &la, &hash,
			&days, &prunedAt, &prunedTotal, &fileSeq, &fileErr, &fileErrAt, &sysSeq, &sysErr, &sysErrAt)
		if err != nil {
			return 0, nil, err
		}
		out := map[string]any{"aufbewahrung_tage": days, "geprueft": nil, "gekuerzt": nil}
		if at != nil {
			p := map[string]any{"zeit": at, "ok": ok, "bruch": broken, "eintraege": entries, "erste": first, "letzte": la}
			if hash != nil {
				p["letzter_hash"] = hex.EncodeToString(hash)
			}
			out["geprueft"] = p
		}
		if prunedAt != nil {
			out["gekuerzt"] = map[string]any{"zeit": prunedAt, "anzahl": prunedTotal}
		}
		export := []map[string]any{}
		if s.cfg.AuditFile != "" {
			export = append(export, map[string]any{"ziel": auditTargetFile, "ort": s.cfg.AuditFile, "stand": fileSeq,
				"fehler": fileErr, "fehler_seit": fileErrAt})
		}
		if s.cfg.AuditSyslog != nil {
			export = append(export, map[string]any{"ziel": auditTargetSyslog, "ort": s.cfg.AuditSyslog.Addr, "stand": sysSeq,
				"fehler": sysErr, "fehler_seit": sysErrAt})
		}
		out["export"] = export
		return http.StatusOK, out, nil
	})
}
