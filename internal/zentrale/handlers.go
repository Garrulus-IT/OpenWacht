// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Einheitliche Meldung: verrät nicht, ob es die E-Mail gibt, ob das Konto
// gesperrt ist oder nur das Passwort falsch war.
const msgLoginFailed = "Anmeldung fehlgeschlagen. Prüfe E-Mail und Passwort. Nach mehreren Fehlversuchen wird das Konto kurz gesperrt."

func internalError(w http.ResponseWriter, where string, err error) {
	slog.Error("interner Fehler", "ort", where, "fehler", err)
	writeError(w, http.StatusInternalServerError, "Interner Fehler.")
}

func newToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(b), h[:], nil
}

func (s *Server) acquireHash(ctx context.Context) bool {
	select {
	case s.hashSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseHash() { <-s.hashSem }

func (s *Server) auditAuth(ctx context.Context, userID, action string, details map[string]any, withActor bool) {
	if details == nil {
		details = map[string]any{}
	}
	var err error
	if withActor {
		err = s.withUser(ctx, userID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT openwacht.audit_auth($1, $2, $3)`, userID, action, details)
			return err
		})
	} else {
		_, err = s.pool.Exec(ctx, `SELECT openwacht.audit_auth($1, $2, $3)`, userID, action, details)
	}
	if err != nil {
		slog.Error("Audit-Eintrag fehlgeschlagen", "aktion", action, "fehler", err)
	}
}

// --- Anmeldung --------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Passwort string `json:"passwort"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte kurz warten.")
		return
	}
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Email) > 254 || auth.CheckPasswordInput(req.Passwort) != nil {
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	}

	var (
		userID, hash          *string
		disabled, totpEnabled bool
	)
	err := s.pool.QueryRow(ctx, `SELECT user_id::text, password_hash, disabled, totp_enabled
		FROM openwacht.auth_lookup($1)`, req.Email).Scan(&userID, &hash, &disabled, &totpEnabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		internalError(w, "auth_lookup", err)
		return
	}
	src := s.loginSource(r)
	if hash == nil && s.loginDirectory(w, r, req, userID, src) {
		return
	}
	// Sperre der Quelle und Wartezeit vor dem teuren Hash (Etappe 30).
	if userID != nil && hash != nil && !disabled && !s.loginGate(w, r, *userID, src) {
		return
	}
	if !s.acquireHash(ctx) {
		return
	}
	defer s.releaseHash()
	if userID == nil || hash == nil {
		// Gleiche Arbeit wie bei einem echten Konto.
		auth.VerifyPassword(req.Passwort, s.dummyHash, *s.cfg.PasswordParams)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	}
	ok, rehash, verr := auth.VerifyPassword(req.Passwort, *hash, *s.cfg.PasswordParams)
	if verr != nil {
		slog.Error("Passwort-Hash nicht lesbar", "benutzer", *userID, "fehler", verr)
	}
	switch {
	case disabled:
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	case !ok:
		s.loginFailed(ctx, *userID, src)
		s.auditAuth(ctx, *userID, "anmeldung.fehlgeschlagen", map[string]any{"grund": "passwort"}, false)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	}

	if rehash {
		if nh, err := auth.HashPassword(req.Passwort, *s.cfg.PasswordParams); err == nil {
			err = s.withUser(ctx, *userID, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, *userID, nh)
				return err
			})
			if err != nil {
				slog.Error("Neu-Hashen fehlgeschlagen", "fehler", err)
			}
		}
	}

	s.continueLogin(w, r, *userID, totpEnabled)
}

// continueLogin: Passwort stimmt; mit 2FA folgt der Code, sonst die Sitzung.
func (s *Server) continueLogin(w http.ResponseWriter, r *http.Request, userID string, totpEnabled bool) {
	ctx := r.Context()
	if totpEnabled {
		raw, th, err := newToken()
		if err != nil {
			internalError(w, "token", err)
			return
		}
		lt := s.cfg.PendingLifetime
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.session_create($1, $2, 'zweiter_faktor', $3, $4)`,
			userID, th, lt, lt); err != nil {
			internalError(w, "session_create", err)
			return
		}
		s.setCookie(w, pendingCookie, raw, lt)
		// Passkey anbieten, wenn das Konto einen hat und die Adresse passt.
		var passkey bool
		if _, ok := s.relyingParty(); ok {
			s.pool.QueryRow(ctx, `SELECT openwacht.webauthn_pending_has($1)`, th).Scan(&passkey)
		}
		writeJSON(w, http.StatusOK, map[string]any{"zweiter_faktor": true, "passkey": passkey})
		return
	}
	s.finishLogin(w, r, userID, nil)
}

// finishLogin legt nach vollständiger Prüfung eine neue Sitzung an (immer ein
// neues Token, damit keine vorher bekannte Sitzung übernommen werden kann).
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, userID string, extra map[string]any) {
	ctx := r.Context()
	th, err := s.newSession(ctx, w, userID, s.loginSource(r))
	if err != nil {
		internalError(w, "sitzung", err)
		return
	}
	mfaRequired, err := s.mfaRequired(ctx, userID)
	if err != nil {
		internalError(w, "mfa", err)
		return
	}
	body := map[string]any{
		"csrf":                   s.csrfToken(th),
		"zwei_faktor_einrichten": mfaRequired,
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) mfaRequired(ctx context.Context, userID string) (bool, error) {
	var enabled bool
	err := s.withUser(ctx, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT totp_enabled FROM openwacht.users WHERE id = $1`, userID).Scan(&enabled)
	})
	if err != nil || enabled {
		return false, err
	}
	return s.mfaPolicyFor(ctx, userID)
}

// mfaPolicyFor: Verlangt die Einstellung (Pflicht für Admins, alle oder
// freiwillig; bei AD-Konten die Anbindung) 2FA für dieses Konto?
func (s *Server) mfaPolicyFor(ctx context.Context, userID string) (bool, error) {
	var req *bool
	err := s.pool.QueryRow(ctx, `SELECT openwacht.mfa_required_for($1)`, userID).Scan(&req)
	return req != nil && *req, err
}

type codeRequest struct {
	Code string `json:"code"`
}

// verifyTOTP prüft den Code des Benutzers und verbraucht den Zeitschritt.
func (s *Server) verifyTOTP(ctx context.Context, userID, code string, mustBeEnabled bool) (bool, error) {
	ok := false
	err := s.withUser(ctx, userID, func(tx pgx.Tx) error {
		var enc []byte
		var enabled bool
		var last int64
		if err := tx.QueryRow(ctx, `SELECT secret_enc, enabled, last_step FROM openwacht.auth_totp_get($1)`, userID).
			Scan(&enc, &enabled, &last); err != nil {
			return err
		}
		if enc == nil || enabled != mustBeEnabled {
			return nil
		}
		secret, err := auth.Open(s.boxKey, enc, []byte(userID))
		if err != nil {
			return err
		}
		step, valid := auth.VerifyTOTP(secret, code, s.now(), last)
		if !valid {
			return nil
		}
		return tx.QueryRow(ctx, `SELECT openwacht.auth_totp_use_step($1, $2)`, userID, step).Scan(&ok)
	})
	return ok, err
}

func (s *Server) handleSecondFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte kurz warten.")
		return
	}
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	expired := func() {
		s.clearCookie(w, pendingCookie)
		writeError(w, http.StatusUnauthorized, "Die Anmeldung ist abgelaufen. Bitte erneut anmelden.")
	}
	c, err := r.Cookie(s.ck(pendingCookie))
	if err != nil {
		expired()
		return
	}
	th, ok := hashToken(c.Value)
	if !ok {
		expired()
		return
	}
	var userID, kind string
	var totpEnabled bool
	if err := s.pool.QueryRow(ctx, `SELECT user_id::text, kind, totp_enabled FROM openwacht.session_get($1)`, th).
		Scan(&userID, &kind, &totpEnabled); err != nil || kind != "zweiter_faktor" {
		expired()
		return
	}
	src := s.loginSource(r)
	locked, why := s.sourceLocked(ctx, userID, src), map[string]any(nil)
	if !locked && s.mfaLocked(ctx, userID) {
		// H5: zu viele falsche Codes aus allen Quellen
		locked, why = true, map[string]any{"grund": "zweiter_faktor_konto"}
	}
	if locked {
		s.pool.Exec(ctx, `SELECT openwacht.session_delete($1)`, th)
		s.auditAuth(ctx, userID, "anmeldung.gesperrt", why, false)
		s.clearCookie(w, pendingCookie)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	}
	code := strings.TrimSpace(req.Code)
	var extra map[string]any
	if len(code) == 6 && strings.Trim(code, "0123456789") == "" {
		valid, err := s.verifyTOTP(ctx, userID, code, true)
		if err != nil {
			internalError(w, "totp", err)
			return
		}
		if !valid {
			s.loginFailed(ctx, userID, src)
			s.mfaFailed(ctx, userID)
			s.auditAuth(ctx, userID, "anmeldung.fehlgeschlagen", map[string]any{"grund": "zweiter_faktor"}, false)
			writeError(w, http.StatusUnauthorized, "Der Code ist ungültig oder wurde schon verwendet.")
			return
		}
	} else {
		// Wiederherstellungscode (Etappe 30, N5)
		left, err := s.useRecoveryCode(ctx, userID, code)
		if err != nil {
			internalError(w, "wiederherstellungscode", err)
			return
		}
		if left < 0 {
			s.loginFailed(ctx, userID, src)
			s.mfaFailed(ctx, userID)
			s.auditAuth(ctx, userID, "anmeldung.fehlgeschlagen", map[string]any{"grund": "wiederherstellungscode"}, false)
			writeError(w, http.StatusUnauthorized, "Der Code ist ungültig oder wurde schon verwendet.")
			return
		}
		s.auditAuth(ctx, userID, "zweifaktor.code_verwendet", map[string]any{"offen": left}, false)
		extra = map[string]any{"wiederherstellungscodes_offen": left}
	}
	s.pool.Exec(ctx, `SELECT openwacht.session_delete($1)`, th)
	s.clearCookie(w, pendingCookie)
	s.finishLogin(w, r, userID, extra)
}

// --- Angemeldet -------------------------------------------------------------

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if _, err := s.pool.Exec(r.Context(), `SELECT openwacht.session_delete($1)`, sess.TokenHash); err != nil {
		internalError(w, "session_delete", err)
		return
	}
	s.auditAuth(r.Context(), sess.UserID, "abmeldung", nil, true)
	s.clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

type roleInfo struct {
	MandantID string `json:"mandant_id"`
	Mandant   string `json:"mandant"`
	Rolle     string `json:"rolle"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var email, name string
	var operator, alertMail bool
	var source string
	var uiRaw []byte
	codesLeft := 0
	roles := []roleInfo{}
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT email, display_name, openwacht.is_platform_operator(), alert_mail, auth_source, alarm_ui
			FROM openwacht.users WHERE id = $1`, sess.UserID).
			Scan(&email, &name, &operator, &alertMail, &source, &uiRaw); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT openwacht.auth_recovery_left($1)`, sess.UserID).Scan(&codesLeft); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT r.tenant_id::text, t.name, r.role
			FROM openwacht.role_assignments r JOIN openwacht.tenants t ON t.id = r.tenant_id
			WHERE r.user_id = $1 ORDER BY t.name`, sess.UserID)
		if err != nil {
			return err
		}
		roles, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (roleInfo, error) {
			var ri roleInfo
			err := row.Scan(&ri.MandantID, &ri.Mandant, &ri.Rolle)
			return ri, err
		})
		return err
	})
	if err != nil {
		internalError(w, "ich", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                     sess.UserID,
		"email":                  email,
		"anzeigename":            name,
		"rollen":                 roles,
		"betreiber":              operator,
		"alarm_mails":            alertMail,
		"hinweise_ton":           scanAlarmUI(uiRaw, true), // 1.0.2
		"zwei_faktor_aktiv":      sess.TOTPEnabled,
		"zwei_faktor_einrichten": sess.MFARequired,
		"quelle":                 source, // lokal, ldap oder oidc
		// noch offene Wiederherstellungscodes (Etappe 30)
		"wiederherstellungscodes_offen": codesLeft,
		"csrf":                          s.csrfToken(sess.TokenHash),
		// Nur nach der Anmeldung: Wer die Version kennt, kennt die Lücken.
		"version": version.Version,
		"commit":  version.Commit,
	})
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if sess.TOTPEnabled {
		writeError(w, http.StatusConflict, "Die Zwei-Faktor-Anmeldung ist bereits eingerichtet.")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		internalError(w, "totp secret", err)
		return
	}
	box, err := auth.Seal(s.boxKey, secret, []byte(sess.UserID))
	if err != nil {
		internalError(w, "seal", err)
		return
	}
	var email string
	err = s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_begin($1, $2)`, sess.UserID, box); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT email FROM openwacht.users WHERE id = $1`, sess.UserID).Scan(&email)
	})
	if err != nil {
		internalError(w, "totp begin", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"geheimnis": auth.TOTPSecretText(secret),
		"uri":       auth.TOTPURI(s.cfg.Issuer, email, secret),
	})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if sess.TOTPEnabled {
		writeError(w, http.StatusConflict, "Die Zwei-Faktor-Anmeldung ist bereits eingerichtet.")
		return
	}
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	valid, err := s.verifyTOTP(ctx, sess.UserID, req.Code, false)
	if err != nil {
		internalError(w, "totp confirm", err)
		return
	}
	if !valid {
		writeError(w, http.StatusBadRequest, "Der Code ist ungültig. Bitte den aktuellen Code aus der App eingeben.")
		return
	}
	var codes []string
	err = s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_totp_enable($1)`, sess.UserID); err != nil {
			return err
		}
		// Zehn Wiederherstellungscodes, nur dieses eine Mal sichtbar (N5).
		var err error
		if codes, err = s.setRecoveryCodes(ctx, tx, sess.UserID); err != nil {
			return err
		}
		// Alle bisherigen Sitzungen beenden: Sie wurden ohne zweiten Faktor eröffnet.
		_, err = tx.Exec(ctx, `SELECT openwacht.session_delete_user($1)`, sess.UserID)
		return err
	})
	if err != nil {
		internalError(w, "totp enable", err)
		return
	}
	s.auditAuth(ctx, sess.UserID, "zweifaktor.eingerichtet", nil, true)
	s.finishLogin(w, r, sess.UserID, map[string]any{"wiederherstellungscodes": codes})
}
