// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "__Host-openwacht"
const pendingCookie = "__Host-openwacht-2fa"

// --- Antworten --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"fehler": msg})
}

// readJSON liest höchstens 16 KiB JSON mit dem erwarteten Content-Type und
// ohne unbekannte Felder.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSONMax(w, r, v, 16<<10)
}

// readJSONMax wie readJSON, mit eigener Größengrenze (z. B. CSV-Import).
func readJSONMax(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Erwartet wird JSON (Content-Type: application/json).")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrage.")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrage.")
		return false
	}
	return true
}

// --- Sicherheits-Header -----------------------------------------------------

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.cfg.BaseURL.Scheme == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// checkOrigin lehnt verändernde Anfragen von fremden Ursprüngen ab
// (zusätzlich zu SameSite=Strict und dem CSRF-Token).
func (s *Server) checkOrigin(next http.Handler) http.Handler {
	want := map[string]bool{s.cfg.BaseURL.Scheme + "://" + s.cfg.BaseURL.Host: true}
	for _, o := range s.cfg.Origins {
		want[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if o := r.Header.Get("Origin"); o != "" && !want[o] {
				writeError(w, http.StatusForbidden, "Anfrage von fremdem Ursprung abgelehnt.")
				return
			}
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
				writeError(w, http.StatusForbidden, "Anfrage von fremdem Ursprung abgelehnt.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Sitzung ----------------------------------------------------------------

type ctxKey int

const sessionKey ctxKey = 1

type session struct {
	APIToken    bool // Anfrage mit API-Token statt Sitzung
	UserID      string
	TokenHash   []byte
	TOTPEnabled bool
	MFARequired bool // 2FA Pflicht (Einstellung), aber nicht eingerichtet
}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(sessionKey).(*session)
	return s
}

func hashToken(raw string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return nil, false
	}
	h := sha256.Sum256(b)
	return h[:], true
}

// requireSession prüft Sitzungscookie und bei verändernden Anfragen das
// CSRF-Token. allowWithoutMFA erlaubt Admins ohne 2FA den Zugriff (nur für
// Einrichten, Abmelden und "ich"); alles andere verlangt eingerichtetes 2FA.
func (s *Server) requireSession(allowWithoutMFA bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			// API-Token (Etappe 22b): kein Cookie, also auch kein CSRF; nur
			// für die normalen Endpunkte, nicht für Sitzung und 2FA.
			if allowWithoutMFA {
				writeError(w, http.StatusForbidden, "Mit einem API-Token nicht möglich.")
				return
			}
			s.apiTokenSession(w, r, a, next)
			return
		}
		c, err := r.Cookie(s.ck(sessionCookie))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Nicht angemeldet.")
			return
		}
		th, ok := hashToken(c.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Nicht angemeldet.")
			return
		}
		var sess session
		var kind string
		// Fehlversuche beenden keine Sitzungen mehr (Etappe 30): Die Sperre
		// gilt nur für Konto + Quelle der Anmeldung.
		err = s.pool.QueryRow(r.Context(),
			`SELECT user_id::text, kind, totp_enabled FROM openwacht.session_get($1)`, th).
			Scan(&sess.UserID, &kind, &sess.TOTPEnabled)
		if err != nil || kind != "voll" {
			s.clearCookie(w, sessionCookie)
			writeError(w, http.StatusUnauthorized, "Nicht angemeldet.")
			return
		}
		sess.TokenHash = th
		if !isSafeMethod(r.Method) {
			got := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.csrfToken(th))) != 1 {
				writeError(w, http.StatusForbidden, "CSRF-Token fehlt oder ist ungültig.")
				return
			}
		}
		if !sess.TOTPEnabled {
			req, err := s.mfaPolicyFor(r.Context(), sess.UserID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Interner Fehler.")
				return
			}
			sess.MFARequired = req
		}
		if sess.MFARequired && !allowWithoutMFA {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"fehler":                 "Die Zwei-Faktor-Anmeldung ist für dieses Konto Pflicht. Bitte zuerst einrichten.",
				"zwei_faktor_einrichten": true,
			})
			return
		}
		s.gated(w, r.WithContext(context.WithValue(r.Context(), sessionKey, &sess)), sess.UserID, next)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.ck(name),
		Value:    value,
		Path:     s.cookiePath(),
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: s.ck(name), Value: "", Path: s.cookiePath(), MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// --- Rate Limit je Client-Adresse --------------------------------------------

type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[netip.Addr]*ipWindow
	sweep  time.Time
}

type ipWindow struct {
	start time.Time
	n     int
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, hits: map[netip.Addr]*ipWindow{}}
}

func (l *ipLimiter) allow(ip netip.Addr, now time.Time) bool {
	ip = limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.sweep) > l.window {
		for k, v := range l.hits {
			if now.Sub(v.start) > l.window {
				delete(l.hits, k)
			}
		}
		l.sweep = now
	}
	w := l.hits[ip]
	if w == nil || now.Sub(w.start) > l.window {
		l.hits[ip] = &ipWindow{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}

// clientIP ermittelt die Client-Adresse. X-Forwarded-For wird nur übernommen,
// wenn die Verbindung von einem vertrauenswürdigen Proxy kommt; dann zählt der
// letzte Eintrag, den dieser Proxy angehängt hat.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	remote = remote.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(remote) {
			xff := r.Header.Values("X-Forwarded-For")
			if len(xff) > 0 {
				parts := strings.Split(xff[len(xff)-1], ",")
				if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
					return a.Unmap()
				}
			}
			break
		}
	}
	return remote
}
