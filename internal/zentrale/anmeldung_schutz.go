// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Etappe 30: Härtung der Anmeldung.
//
//   - M4: Sperre je Konto und Quelle (IPv4-Adresse bzw. IPv6-/64), für andere
//     Quellen nur eine wachsende Wartezeit; Rate Limit je /64.
//   - N5: Wiederherstellungscodes für die Zwei-Faktor-Anmeldung.
//   - M1: Freigabe von Anmelde-Domänen und NetBIOS-Namen durch den Betreiber.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// limitKey fasst IPv6-Adressen auf ihr /64 zusammen: Ein Anschluss bekommt
// meist ein ganzes /64, darin kann ein Angreifer die Adresse beliebig wechseln.
func limitKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// loginSource ist die Quelle einer Anmeldung als HMAC: Die Datenbank kann
// Quellen vergleichen, kennt aber die Adressen nicht (Leitprinzip 5).
func (s *Server) loginSource(r *http.Request) []byte {
	m := hmac.New(sha256.New, s.sourceKey)
	m.Write([]byte(limitKey(s.clientIP(r)).String()))
	return m.Sum(nil)
}

// loginGate prüft vor der Passwortprüfung, ob die Quelle gesperrt ist, und
// wartet bei vielen Fehlversuchen aus unbekannten Quellen. false: Die
// Antwort ist geschrieben (immer dieselbe Meldung wie bei falschem Passwort).
func (s *Server) loginGate(w http.ResponseWriter, r *http.Request, userID string, src []byte) bool {
	ctx := r.Context()
	var wait int
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.auth_login_gate($1, $2)`, userID, src).Scan(&wait); err != nil {
		internalError(w, "auth_login_gate", err)
		return false
	}
	switch {
	case wait == -1:
		s.auditAuth(ctx, userID, "anmeldung.gesperrt", nil, false)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return false
	case wait == -2:
		s.auditAuth(ctx, userID, "anmeldung.gesperrt", map[string]any{"grund": "warteschlange"}, false)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return false
	case wait > 0:
		if err := s.loginWait(ctx, time.Duration(wait)*time.Millisecond); err != nil {
			return false
		}
	}
	return true
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loginFailed zählt einen Fehlversuch für Konto und Quelle.
func (s *Server) loginFailed(ctx context.Context, userID string, src []byte) {
	if _, err := s.pool.Exec(ctx, `SELECT openwacht.auth_login_failed($1, $2)`, userID, src); err != nil {
		slog.Error("Fehlversuch nicht gezählt", "fehler", err)
	}
}

// sourceLocked: Quelle für dieses Konto gesperrt (im Zweifel ja).
func (s *Server) sourceLocked(ctx context.Context, userID string, src []byte) bool {
	var locked bool
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.auth_source_locked($1, $2)`, userID, src).Scan(&locked); err != nil {
		slog.Error("Sperre nicht prüfbar", "fehler", err)
		return true
	}
	return locked
}

// --- Wiederherstellungscodes (N5) --------------------------------------------

const recoveryCodeCount = 10

// recoveryAlphabet: Kleinbuchstaben und Ziffern ohne Verwechsler (0/o, 1/l/i),
// 31 Zeichen; zehn davon ergeben knapp 50 Bit Zufall.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// newRecoveryCodes erzeugt zehn verschiedene Codes der Form xxxxx-xxxxx.
func newRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	seen := map[string]bool{}
	buf := make([]byte, 1)
	for len(codes) < recoveryCodeCount {
		var b strings.Builder
		for b.Len() < 10 {
			if _, err := rand.Read(buf); err != nil {
				return nil, err
			}
			if buf[0] >= 248 { // 8 × 31: ohne Verzerrung
				continue
			}
			b.WriteByte(recoveryAlphabet[buf[0]%31])
		}
		raw := b.String()
		if seen[raw] {
			continue
		}
		seen[raw] = true
		codes = append(codes, raw[:5]+"-"+raw[5:])
	}
	return codes, nil
}

// normalizeRecoveryCode: Groß/klein, Leerzeichen und Bindestriche egal.
// Liefert "" bei falscher Form.
func normalizeRecoveryCode(c string) string {
	if len(c) > 40 {
		return ""
	}
	c = strings.ToLower(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, c))
	if len(c) != 10 {
		return ""
	}
	for _, r := range c {
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return ""
		}
	}
	return c
}

// recoveryHash: HMAC mit einem Schlüssel der Zentrale, an das Konto gebunden.
// Ein reiner Hash ließe sich bei 50 Bit aus einer Datenbankkopie erraten.
func (s *Server) recoveryHash(userID, normalized string) []byte {
	m := hmac.New(sha256.New, s.recoveryKey)
	m.Write([]byte(userID))
	m.Write([]byte{0})
	m.Write([]byte(normalized))
	return m.Sum(nil)
}

// setRecoveryCodes legt im Kontext des Benutzers zehn neue Codes an.
func (s *Server) setRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	codes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = s.recoveryHash(userID, normalizeRecoveryCode(c))
	}
	if _, err := tx.Exec(ctx, `SELECT openwacht.auth_recovery_set($1, $2)`, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// useRecoveryCode verbraucht einen Code. Rückgabe: noch offene Codes, -1 wenn
// der Code nicht passt.
func (s *Server) useRecoveryCode(ctx context.Context, userID, code string) (int, error) {
	n := normalizeRecoveryCode(code)
	if n == "" {
		return -1, nil
	}
	left := -1
	err := s.withUser(ctx, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT openwacht.auth_recovery_use($1, $2)`, userID, s.recoveryHash(userID, n)).Scan(&left)
	})
	return left, err
}

// handleRecoveryCodes erzeugt neue Codes (die alten verfallen). Nur mit
// eingerichteter Zwei-Faktor-Anmeldung und frischem Code aus der App.
func (s *Server) handleRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if !sess.TOTPEnabled {
		writeError(w, http.StatusConflict, "Erst die Zwei-Faktor-Anmeldung einrichten.")
		return
	}
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.confirmCode(r, req.Code); err != nil {
		writeDBError(w, "wiederherstellungscodes", err)
		return
	}
	var codes []string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		var err error
		codes, err = s.setRecoveryCodes(ctx, tx, sess.UserID)
		return err
	})
	if err != nil {
		internalError(w, "wiederherstellungscodes", err)
		return
	}
	s.auditAuth(ctx, sess.UserID, "zweifaktor.codes_erzeugt", nil, true)
	writeJSON(w, http.StatusOK, map[string]any{"wiederherstellungscodes": codes})
}

// --- Anmelde-Domänen (M1) -----------------------------------------------------

func (s *Server) handleLoginClaims(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "anmeldedomaenen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT directory_id::text, directory_name, tenant_name, kind, value, status, requested_at, conflict
			FROM openwacht.login_claims()`)
		if err != nil {
			return 0, nil, err
		}
		list := []map[string]any{}
		for rows.Next() {
			var dir, dname, tname, kind, value, status string
			var at time.Time
			var conflict bool
			if err := rows.Scan(&dir, &dname, &tname, &kind, &value, &status, &at, &conflict); err != nil {
				return 0, nil, err
			}
			list = append(list, map[string]any{"verzeichnis": dir, "verzeichnis_name": dname, "mandant": tname, "art": kind,
				"wert": value, "status": status, "beantragt": at, "konflikt": conflict})
		}
		return http.StatusOK, map[string]any{"antraege": list}, rows.Err()
	})
}

func (s *Server) handleLoginClaimDecide(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Verzeichnis string `json:"verzeichnis"`
		Art         string `json:"art"`
		Wert        string `json:"wert"`
		Freigeben   bool   `json:"freigeben"`
		Code        string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "anmeldedomaenen", err) }
	if !uuidPattern.MatchString(in.Verzeichnis) || (in.Art != "domaene" && in.Art != "netbios") || in.Wert == "" || len(in.Wert) > 253 {
		fail(badRequest("Antrag unvollständig."))
		return
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	s.handle(w, r, "anmeldedomaenen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		_, err := tx.Exec(ctx, `SELECT openwacht.login_claim_decide($1, $2, $3, $4)`, in.Verzeichnis, in.Art, in.Wert, in.Freigeben)
		if err != nil {
			var pe interface{ SQLState() string }
			if errors.As(err, &pe) {
				switch pe.SQLState() {
				case "23505":
					return 0, nil, &apiError{http.StatusConflict, "Diese Domäne bzw. dieser Name ist schon für eine andere Anbindung freigegeben."}
				case "P0002":
					return 0, nil, errNotFound
				}
			}
			return 0, nil, err
		}
		status := "abgelehnt"
		if in.Freigeben {
			status = "freigegeben"
		}
		return http.StatusOK, map[string]any{"status": status}, nil
	})
}
