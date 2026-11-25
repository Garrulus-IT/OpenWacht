// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// API-Tokens (Etappe 22b): je Mandant, Rolle Leser oder Operator, Ablauf
// höchstens ein Jahr. Format owt1.<32 Byte base64url>; gespeichert ist nur
// SHA-256. Jedes Token hat ein technisches Konto, damit RLS und Rollen
// unverändert gelten. Rate Limit je Token.

const apiTokenPrefix = "owt1."

func parseAPIToken(header string) ([]byte, bool) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return nil, false
	}
	raw, ok = strings.CutPrefix(strings.TrimSpace(raw), apiTokenPrefix)
	if !ok {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return nil, false
	}
	h := sha256.Sum256(b)
	return h[:], true
}

// apiTokenLimit: Anfragen je Token und Minute.
const apiTokenLimit = 300

func (s *Server) apiTokenSession(w http.ResponseWriter, r *http.Request, header string, next http.Handler) {
	deny := func() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="OpenWacht"`)
		writeError(w, http.StatusUnauthorized, "API-Token ungültig, abgelaufen oder widerrufen.")
	}
	h, ok := parseAPIToken(header)
	if !ok {
		deny()
		return
	}
	var uid *string
	if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.api_token_auth($1)::text`, h).Scan(&uid); err != nil {
		writeError(w, http.StatusInternalServerError, "Interner Fehler.")
		return
	}
	if uid == nil {
		deny()
		return
	}
	if !s.apiTokenRate.allow(*uid, s.now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "Zu viele Anfragen mit diesem API-Token. Bitte kurz warten.")
		return
	}
	sess := &session{APIToken: true, UserID: *uid}
	s.gated(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)), *uid, next)
}

// rateWindow: höchstens n Anfragen je Schlüssel und Minute.
type rateWindow struct {
	n     int
	mu    chan struct{}
	start map[string]time.Time
	count map[string]int
}

func newRateWindow(n int) *rateWindow {
	return &rateWindow{n: n, mu: make(chan struct{}, 1), start: map[string]time.Time{}, count: map[string]int{}}
}

func (l *rateWindow) allow(key string, now time.Time) bool {
	l.mu <- struct{}{}
	defer func() { <-l.mu }()
	if len(l.start) > 10000 {
		for k, t := range l.start {
			if now.Sub(t) >= time.Minute {
				delete(l.start, k)
				delete(l.count, k)
			}
		}
	}
	if t, ok := l.start[key]; !ok || now.Sub(t) >= time.Minute {
		l.start[key], l.count[key] = now, 0
	}
	l.count[key]++
	return l.count[key] <= l.n
}

// --- Verwaltung -------------------------------------------------------------------

func (s *Server) handleAPITokenList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "api-tokens", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT a.id::text, a.tenant_id::text, t.name, a.name, a.role, a.expires_at, a.created_at,
			a.last_used_at, a.revoked_at, coalesce(u.display_name, '')
			FROM openwacht.api_tokens a JOIN openwacht.tenants t ON t.id = a.tenant_id
			LEFT JOIN openwacht.users u ON u.id = a.created_by
			ORDER BY (a.revoked_at IS NULL AND a.expires_at > now()) DESC, a.created_at DESC`)
		if err != nil {
			return 0, nil, err
		}
		list := []map[string]any{}
		for rows.Next() {
			var id, tid, tname, name, role, by string
			var exp, created time.Time
			var used, revoked *time.Time
			if err := rows.Scan(&id, &tid, &tname, &name, &role, &exp, &created, &used, &revoked, &by); err != nil {
				return 0, nil, err
			}
			list = append(list, map[string]any{"id": id, "mandant": tid, "mandant_name": tname, "name": name, "rolle": role,
				"ablauf": exp, "angelegt": created, "zuletzt": used, "widerrufen": revoked, "von": by,
				"gueltig": revoked == nil && exp.After(s.now())})
		}
		return http.StatusOK, map[string]any{"tokens": list}, rows.Err()
	})
}

func (s *Server) handleAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mandant string `json:"mandant"`
		Name    string `json:"name"`
		Rolle   string `json:"rolle"`
		Tage    int    `json:"tage"`
		Code    string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "api-token", err) }
	var err error
	if in.Name, err = cleanName(in.Name); err != nil {
		fail(err)
		return
	}
	if !uuidPattern.MatchString(in.Mandant) {
		fail(badRequest("Mandant fehlt."))
		return
	}
	if in.Rolle != "leser" && in.Rolle != "operator" {
		fail(badRequest("Rolle: Leser oder Operator."))
		return
	}
	if in.Tage < 1 || in.Tage > 365 {
		fail(badRequest("Gültigkeit: 1 bis 365 Tage."))
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	raw, h, err := newToken()
	if err != nil {
		fail(err)
		return
	}
	exp := s.now().Add(time.Duration(in.Tage) * 24 * time.Hour)
	s.handle(w, r, "api-token", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var id string
		if err := tx.QueryRow(ctx, `SELECT openwacht.api_token_create($1, $2, $3, $4, $5)::text`, in.Mandant, in.Name, in.Rolle, h, exp).
			Scan(&id); err != nil {
			return 0, nil, err
		}
		// Das Token steht nur in dieser Antwort, nie wieder.
		return http.StatusCreated, map[string]any{"id": id, "token": apiTokenPrefix + raw, "ablauf": exp}, nil
	})
}

func (s *Server) handleAPITokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "api-token", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var done bool
		if err := tx.QueryRow(ctx, `SELECT openwacht.api_token_revoke($1)`, id).Scan(&done); err != nil {
			return 0, nil, err
		}
		if !done {
			return 0, nil, errNotFound
		}
		return http.StatusOK, map[string]any{"widerrufen": true}, nil
	})
}
