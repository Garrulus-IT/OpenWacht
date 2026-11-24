// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/webauthn"
)

// Passkeys (WebAuthn) als zweiter Faktor neben der Authenticator-App
// (Etappe 36). Nur für Konten mit eingerichteter App; die App bleibt
// Rückfallweg und bestätigt heikle Änderungen. Die Zentrale speichert nur
// öffentliche Schlüssel; Challenges liegen in der Datenbank, gelten fünf
// Minuten und nur einmal.

var b64 = base64.RawURLEncoding

// relyingParty: Passkeys hängen am Namen der Basisadresse. Eine IP-Adresse
// ist als RP-ID nicht erlaubt (WebAuthn), dann gibt es keine Passkeys.
func (s *Server) relyingParty() (webauthn.RP, bool) {
	u := s.cfg.BaseURL
	host := u.Hostname()
	if host == "" {
		return webauthn.RP{}, false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return webauthn.RP{}, false
	}
	return webauthn.RP{ID: host, Origin: u.Scheme + "://" + u.Host}, true
}

var errNoPasskeyHost = &apiError{http.StatusConflict,
	"Passkeys brauchen einen DNS-Namen als Adresse der Oberfläche (keine IP-Adresse). Bitte die Adresse unter Einstellungen → Installation prüfen."}

func credList(ids [][]byte) []map[string]string {
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, map[string]string{"type": "public-key", "id": b64.EncodeToString(id)})
	}
	return out
}

type passkeyOut struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Verfahren  string     `json:"verfahren"`
	Angelegt   time.Time  `json:"angelegt"`
	ZuletztBei *time.Time `json:"zuletzt"`
}

func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	_, ok := s.relyingParty()
	s.handle(w, r, "passkeys", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, name, alg, created_at, last_used_at FROM openwacht.webauthn_credentials
			WHERE user_id = openwacht.current_user_id() ORDER BY created_at`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (passkeyOut, error) {
			var p passkeyOut
			var alg int
			err := row.Scan(&p.ID, &p.Name, &alg, &p.Angelegt, &p.ZuletztBei)
			p.Verfahren = webauthn.AlgName(alg)
			return p, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []passkeyOut{}
		}
		return http.StatusOK, map[string]any{"passkeys": list, "moeglich": ok}, nil
	})
}

func (s *Server) handlePasskeyOptions(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.relyingParty()
	if !ok {
		writeDBError(w, "passkey", errNoPasskeyHost)
		return
	}
	sess := sessionFrom(r.Context())
	if !sess.TOTPEnabled {
		writeError(w, http.StatusConflict, "Passkeys gibt es nur zusätzlich zur Authenticator-App. Bitte zuerst die App einrichten.")
		return
	}
	ch, err := webauthn.NewChallenge()
	if err != nil {
		internalError(w, "challenge", err)
		return
	}
	s.handle(w, r, "passkey optionen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT credential_id FROM openwacht.webauthn_register_begin($1, $2)`, sess.UserID, ch)
		if err != nil {
			return 0, nil, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			return 0, nil, err
		}
		var email, name string
		if err := tx.QueryRow(ctx, `SELECT email, display_name FROM openwacht.users WHERE id = $1`, sess.UserID).Scan(&email, &name); err != nil {
			return 0, nil, err
		}
		uid, err := uuidBytes(sess.UserID)
		if err != nil {
			return 0, nil, err
		}
		params := []map[string]any{}
		for _, a := range webauthn.Algs {
			params = append(params, map[string]any{"type": "public-key", "alg": a})
		}
		return http.StatusOK, map[string]any{
			"challenge":          b64.EncodeToString(ch),
			"rp":                 map[string]string{"id": rp.ID, "name": "OpenWacht"},
			"user":               map[string]string{"id": b64.EncodeToString(uid), "name": email, "displayName": name},
			"pubKeyCredParams":   params,
			"timeout":            120000,
			"attestation":        "none",
			"excludeCredentials": credList(ids),
			"authenticatorSelection": map[string]string{
				"residentKey": "discouraged", "userVerification": "preferred",
			},
		}, nil
	})
}

func uuidBytes(s string) ([]byte, error) {
	h := strings.ReplaceAll(s, "-", "")
	b := make([]byte, 16)
	if len(h) != 32 {
		return nil, errors.New("keine UUID")
	}
	for i := range b {
		var v byte
		for _, c := range h[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			default:
				return nil, errors.New("keine UUID")
			}
		}
		b[i] = v
	}
	return b, nil
}

type passkeyNew struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	ClientData  string `json:"client_data"`
	Attestation string `json:"attestation"`
}

func (s *Server) handlePasskeyCreate(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.relyingParty()
	if !ok {
		writeDBError(w, "passkey", errNoPasskeyHost)
		return
	}
	var in passkeyNew
	if !readJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > 60 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		writeError(w, http.StatusBadRequest, "Bitte einen Namen mit 1 bis 60 Zeichen angeben (z. B. „Laptop“ oder „Sicherheitsschlüssel“).")
		return
	}
	cd, err1 := b64.DecodeString(in.ClientData)
	att, err2 := b64.DecodeString(in.Attestation)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Antwort des Browsers.")
		return
	}
	// Ein neuer Anmeldefaktor ist eine heikle Änderung: frischer App-Code.
	if err := s.confirmCode(r, in.Code); err != nil {
		writeDBError(w, "passkey", err)
		return
	}
	ch, err := webauthn.ClientChallenge(cd)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Der Passkey konnte nicht geprüft werden. Bitte erneut versuchen.")
		return
	}
	cred, err := rp.VerifyRegistration(ch, cd, att)
	if err != nil {
		s.auditAuth(r.Context(), sessionFrom(r.Context()).UserID, "passkey.abgelehnt", map[string]any{"grund": err.Error()}, true)
		writeError(w, http.StatusBadRequest, "Der Passkey konnte nicht geprüft werden: "+err.Error()+".")
		return
	}
	sess := sessionFrom(r.Context())
	var id string
	err = s.withUser(r.Context(), sess.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT openwacht.webauthn_register_finish($1, $2, $3, $4, $5, $6, $7)::text`,
			sess.UserID, ch, cred.ID, cred.PublicKey, cred.Alg, int64(cred.SignCount), name).Scan(&id)
	})
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe) && pe.Code == "28000":
		writeError(w, http.StatusBadRequest, "Die Anfrage ist abgelaufen. Bitte erneut „Passkey hinzufügen“ wählen.")
		return
	case errors.As(err, &pe) && pe.Code == "54000":
		writeError(w, http.StatusConflict, "Es sind höchstens zehn Passkeys je Konto möglich.")
		return
	case errors.As(err, &pe) && pe.Code == "23505":
		writeError(w, http.StatusConflict, "Dieser Passkey ist schon registriert.")
		return
	case errors.As(err, &pe) && pe.Code == "55000":
		writeError(w, http.StatusConflict, "Passkeys gibt es nur zusätzlich zur Authenticator-App.")
		return
	case err != nil:
		writeDBError(w, "passkey speichern", err)
		return
	}
	s.auditAuth(r.Context(), sess.UserID, "passkey.angelegt", map[string]any{"name": name, "verfahren": webauthn.AlgName(cred.Alg)}, true)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var name string
	s.handle(w, r, "passkey löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.webauthn_credentials WHERE id = $1 AND user_id = openwacht.current_user_id()
			RETURNING name`, id).Scan(&name); err != nil {
			return 0, nil, err
		}
		_, err := tx.Exec(ctx, `SELECT openwacht.audit_auth(openwacht.current_user_id(), 'passkey.geloescht', $1)`, map[string]any{"name": name})
		return http.StatusNoContent, nil, err
	})
}

// --- Anmeldung mit Passkey (zweiter Schritt) -------------------------------------

func (s *Server) pendingSession(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	c, err := r.Cookie(pendingCookie)
	if err == nil {
		if th, ok := hashToken(c.Value); ok {
			return th, true
		}
	}
	clearCookie(w, pendingCookie)
	writeError(w, http.StatusUnauthorized, "Die Anmeldung ist abgelaufen. Bitte erneut anmelden.")
	return nil, false
}

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte kurz warten.")
		return
	}
	rp, ok := s.relyingParty()
	if !ok {
		writeDBError(w, "passkey", errNoPasskeyHost)
		return
	}
	th, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	ch, err := webauthn.NewChallenge()
	if err != nil {
		internalError(w, "challenge", err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT credential_id FROM openwacht.webauthn_login_begin($1, $2)`, th, ch)
	var ids [][]byte
	if err == nil {
		ids, err = pgx.CollectRows(rows, pgx.RowTo[[]byte])
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "28000" {
		clearCookie(w, pendingCookie)
		writeError(w, http.StatusUnauthorized, "Die Anmeldung ist abgelaufen. Bitte erneut anmelden.")
		return
	}
	if err != nil {
		internalError(w, "passkey anmelden", err)
		return
	}
	if len(ids) == 0 {
		writeError(w, http.StatusConflict, "Für dieses Konto ist kein Passkey eingerichtet.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        b64.EncodeToString(ch),
		"rpId":             rp.ID,
		"timeout":          120000,
		"userVerification": "preferred",
		"allowCredentials": credList(ids),
	})
}

type passkeyAssertion struct {
	ID                string `json:"id"`
	ClientData        string `json:"client_data"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

func (s *Server) handlePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte kurz warten.")
		return
	}
	rp, ok := s.relyingParty()
	if !ok {
		writeDBError(w, "passkey", errNoPasskeyHost)
		return
	}
	var in passkeyAssertion
	if !readJSON(w, r, &in) {
		return
	}
	th, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	var userID string
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.webauthn_pending_user($1)::text`, th).Scan(&userID); err != nil || userID == "" {
		clearCookie(w, pendingCookie)
		writeError(w, http.StatusUnauthorized, "Die Anmeldung ist abgelaufen. Bitte erneut anmelden.")
		return
	}
	src := s.loginSource(r)
	if s.sourceLocked(ctx, userID, src) {
		s.pool.Exec(ctx, `SELECT openwacht.session_delete($1)`, th)
		s.auditAuth(ctx, userID, "anmeldung.gesperrt", nil, false)
		clearCookie(w, pendingCookie)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return
	}
	fail := func(grund string) {
		s.loginFailed(ctx, userID, src)
		s.auditAuth(ctx, userID, "anmeldung.fehlgeschlagen", map[string]any{"grund": grund}, false)
		writeError(w, http.StatusUnauthorized, "Der Passkey wurde nicht angenommen. Bitte erneut versuchen oder den Code aus der App nehmen.")
	}
	credID, e1 := b64.DecodeString(in.ID)
	cd, e2 := b64.DecodeString(in.ClientData)
	ad, e3 := b64.DecodeString(in.AuthenticatorData)
	sig, e4 := b64.DecodeString(in.Signature)
	ch, e5 := webauthn.ClientChallenge(cd)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(credID) == 0 || len(credID) > 1023 {
		fail("passkey")
		return
	}
	var (
		owner, id string
		cred      webauthn.Credential
		count     int64
	)
	err := s.pool.QueryRow(ctx, `SELECT user_id::text, id::text, public_key, alg, sign_count FROM openwacht.webauthn_login_take($1, $2, $3)`,
		th, ch, credID).Scan(&owner, &id, &cred.PublicKey, &cred.Alg, &count)
	if errors.Is(err, pgx.ErrNoRows) {
		fail("passkey") // Challenge abgelaufen, schon benutzt oder fremder Passkey
		return
	}
	if err != nil {
		internalError(w, "passkey anmelden", err)
		return
	}
	cred.ID, cred.SignCount = credID, uint32(count)
	n, err := rp.VerifyAssertion(ch, cred, cd, ad, sig)
	if err != nil || owner != userID {
		fail("passkey")
		return
	}
	var counted bool
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.webauthn_login_used($1, $2, $3)`, th, id, int64(n)).Scan(&counted); err != nil {
		internalError(w, "passkey zähler", err)
		return
	}
	if !counted {
		// Zähler gesunken: Der Schlüssel wurde womöglich kopiert.
		fail("passkey_zaehler")
		return
	}
	s.pool.Exec(ctx, `SELECT openwacht.session_delete($1)`, th)
	clearCookie(w, pendingCookie)
	s.auditAuth(ctx, userID, "anmeldung.passkey", nil, false)
	s.finishLogin(w, r, userID, nil)
}
