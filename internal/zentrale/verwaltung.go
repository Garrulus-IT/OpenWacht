// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Verwaltung von Mandanten, Benutzern und Rollen.
//
// Jeder Zugriff läuft in einer Transaktion mit Benutzerkontext (withUser).
// Was jemand sehen und ändern darf, entscheidet die Datenbank per Row-Level
// Security; hier werden nur Eingaben geprüft und Fehler übersetzt. Ändert eine
// Anfrage keine Zeile, antwortet die API mit 404 – ob es den Datensatz nicht
// gibt oder er nur nicht sichtbar ist, wird bewusst nicht unterschieden.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/auth"
)

var (
	errNotFound = errors.New("nicht gefunden")
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	validRoles  = map[string]bool{"admin": true, "operator": true, "leser": true}
)

// apiError ist ein Fehler mit fester Meldung für die Antwort.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(msg string) error { return &apiError{http.StatusBadRequest, msg} }

// errForeignRoles: Das Konto hat Rollen auf Mandanten, die der Aufrufer nicht
// administriert. Passwort, Sperre und Name darf dann nur ein Admin ändern,
// der alle diese Mandanten verwaltet (Befund H2).
var errForeignRoles = &apiError{http.StatusForbidden,
	"Dieses Konto hat Rollen auf Mandanten, die du nicht verwaltest. Passwort, Sperre und Anzeigename kann nur ein Admin ändern, der alle diese Mandanten verwaltet."}

// errEmailUnusable: Adresse vergeben (H3). Dieselbe Meldung, egal ob das
// Konto im eigenen oder einem fremden Mandanten liegt.
var errEmailUnusable = &apiError{http.StatusConflict, "Diese E-Mail-Adresse kann nicht verwendet werden."}

// maxUserCreateRejects: abgelehnte Anlagen je Admin und Stunde (H3).
const maxUserCreateRejects = 20

// rejectCounter zählt Ereignisse je Schlüssel in der letzten Stunde.
type rejectCounter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (c *rejectCounter) prune(key string, now time.Time) []time.Time {
	keep := c.hits[key][:0]
	for _, t := range c.hits[key] {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(c.hits, key)
		return nil
	}
	c.hits[key] = keep
	return keep
}

func (c *rejectCounter) count(key string, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hits == nil {
		return 0
	}
	return len(c.prune(key, now))
}

func (c *rejectCounter) add(key string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hits == nil {
		c.hits = map[string][]time.Time{}
	}
	c.hits[key] = append(c.prune(key, now), now)
}

// writeDBError übersetzt Datenbankfehler in verständliche Antworten, ohne
// interne Details preiszugeben.
func writeDBError(w http.ResponseWriter, where string, err error) {
	var ae *apiError
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &ae):
		writeError(w, ae.status, ae.msg)
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows):
		writeError(w, http.StatusNotFound, "Nicht gefunden.")
	case errors.As(err, &pe) && pe.Code == "42501":
		writeError(w, http.StatusForbidden, "Keine Berechtigung.")
	case errors.As(err, &pe) && pe.Code == "23505":
		writeError(w, http.StatusConflict, "Ein Eintrag mit diesem Namen oder dieser E-Mail-Adresse existiert bereits.")
	case errors.As(err, &pe) && pe.Code == "23503":
		writeError(w, http.StatusConflict, "Wird noch verwendet (Untermandanten, Benutzer, Geräte oder Einträge im Audit-Log).")
	case errors.As(err, &pe) && pe.Code == "23514" && pe.ConstraintName == "" && pe.Message != "":
		// eigene Meldung aus RAISE in einer Funktion oder einem Trigger
		writeError(w, http.StatusBadRequest, pe.Message)
	case errors.As(err, &pe) && (pe.Code == "23514" || pe.Code == "22P02" || pe.Code == "22001"):
		writeError(w, http.StatusBadRequest, "Ungültige Eingabe.")
	default:
		internalError(w, where, err)
	}
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	id := r.PathValue(name)
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return "", false
	}
	return id, true
}

func cleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > 100 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", badRequest("Der Name muss 1 bis 100 Zeichen lang sein und darf keine Steuerzeichen enthalten.")
	}
	return s, nil
}

func audit(ctx context.Context, tx pgx.Tx, tenantID *string, action string, details map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details) VALUES ($1, $2, $3)`,
		tenantID, action, details)
	return err
}

// handle bündelt die Routine: Benutzerkontext, Transaktion, Fehlerabbildung.
func (s *Server) handle(w http.ResponseWriter, r *http.Request, where string, fn func(ctx context.Context, tx pgx.Tx) (int, any, error)) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var status int
	var body any
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		var err error
		status, body, err = fn(ctx, tx)
		return err
	})
	if err != nil {
		writeDBError(w, where, err)
		return
	}
	if body == nil {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, body)
}

// --- Mandanten --------------------------------------------------------------

type tenantOut struct {
	ID              string  `json:"id"`
	UebergeordnetID *string `json:"uebergeordnet_id"`
	Name            string  `json:"name"`
	Rolle           string  `json:"rolle"`
}

func (s *Server) handleTenantList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "mandanten", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT t.id::text, t.parent_id::text, t.name, coalesce(m.role, '')
			FROM openwacht.tenants t LEFT JOIN openwacht.my_tenant_roles() m ON m.tenant_id = t.id
			ORDER BY t.name`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantOut, error) {
			var t tenantOut
			err := row.Scan(&t.ID, &t.UebergeordnetID, &t.Name, &t.Rolle)
			return t, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []tenantOut{}
		}
		return http.StatusOK, map[string]any{"mandanten": list}, nil
	})
}

type tenantIn struct {
	UebergeordnetID string `json:"uebergeordnet_id"`
	Name            string `json:"name"`
}

func (s *Server) handleTenantCreate(w http.ResponseWriter, r *http.Request) {
	var in tenantIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "mandant anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if !uuidPattern.MatchString(in.UebergeordnetID) {
			return 0, nil, badRequest("Übergeordneter Mandant fehlt oder ist ungültig.")
		}
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		// Kein RETURNING: Die Lese-Policy prüft die neue Zeile, bevor der Trigger
		// sie in den Mandantenbaum eingetragen hat. Danach ist sie sichtbar.
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2)`,
			in.UebergeordnetID, name); err != nil {
			return 0, nil, err
		}
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.tenants WHERE parent_id = $1 AND lower(name) = lower($2)`,
			in.UebergeordnetID, name).Scan(&id); err != nil {
			return 0, nil, err
		}
		// Am Elternknoten protokollieren, damit der neue Mandant löschbar bleibt.
		if err := audit(ctx, tx, &in.UebergeordnetID, "mandant.angelegt", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, tenantOut{ID: id, UebergeordnetID: &in.UebergeordnetID, Name: name, Rolle: "admin"}, nil
	})
}

func (s *Server) handleTenantRename(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "mandant umbenennen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		var parent *string
		var old string
		// Alter Name für das Audit-Log; FOR UPDATE nur auf Zeilen, die die Policy erlaubt.
		if err := tx.QueryRow(ctx, `SELECT parent_id::text, name FROM openwacht.tenants
			WHERE id = $1 AND id IN (SELECT openwacht.admin_tenants())`, id).Scan(&parent, &old); err != nil {
			return 0, nil, err
		}
		ct, err := tx.Exec(ctx, `UPDATE openwacht.tenants SET name = $2 WHERE id = $1`, id, name)
		if err != nil {
			return 0, nil, err
		}
		if ct.RowsAffected() != 1 {
			return 0, nil, errNotFound
		}
		// Am Elternknoten protokollieren, wenn der Handelnde ihn sieht, sonst am Knoten selbst.
		logAt := &id
		if parent != nil {
			var visible bool
			if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.visible_tenants())`, *parent).Scan(&visible); err != nil {
				return 0, nil, err
			}
			if visible {
				logAt = parent
			}
		}
		if err := audit(ctx, tx, logAt, "mandant.umbenannt", map[string]any{"id": id, "alt": old, "neu": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleTenantDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "mandant löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var parent *string
		var name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.tenants WHERE id = $1 RETURNING parent_id::text, name`, id).
			Scan(&parent, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, parent, "mandant.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// --- Benutzer ---------------------------------------------------------------

type roleOut struct {
	MandantID string `json:"mandant_id"`
	Rolle     string `json:"rolle"`
}

type userOut struct {
	ID              string    `json:"id"`
	MandantID       string    `json:"mandant_id"`
	Email           string    `json:"email"`
	Anzeigename     string    `json:"anzeigename"`
	Deaktiviert     bool      `json:"deaktiviert"`
	ZweiFaktorAktiv bool      `json:"zwei_faktor_aktiv"`
	Verzeichnis     bool      `json:"verzeichnis"` // Konto aus dem AD: Rechte und Passwort kommen von dort
	Rollen          []roleOut `json:"rollen"`
}

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "benutzer", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT u.id::text, u.tenant_id::text, u.email, u.display_name, u.disabled, u.totp_enabled, u.directory_id IS NOT NULL
			FROM openwacht.users u
			WHERE u.tenant_id IN (SELECT openwacht.visible_tenants())
			  AND u.auth_source <> 'token' -- API-Tokens stehen unter Verwaltung › API-Tokens
			  AND ($1 = '' OR u.tenant_id = $1::uuid)
			ORDER BY u.display_name`, filter)
		if err != nil {
			return 0, nil, err
		}
		users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (userOut, error) {
			var u userOut
			err := row.Scan(&u.ID, &u.MandantID, &u.Email, &u.Anzeigename, &u.Deaktiviert, &u.ZweiFaktorAktiv, &u.Verzeichnis)
			u.Rollen = []roleOut{}
			return u, err
		})
		if err != nil {
			return 0, nil, err
		}
		byID := map[string]*userOut{}
		for i := range users {
			byID[users[i].ID] = &users[i]
		}
		// Nur Rollen auf sichtbaren Mandanten (RLS), also keine fremden Zuweisungen.
		rrows, err := tx.Query(ctx, `SELECT user_id::text, tenant_id::text, role FROM openwacht.role_assignments
			WHERE tenant_id IN (SELECT openwacht.visible_tenants())`)
		if err != nil {
			return 0, nil, err
		}
		defer rrows.Close()
		for rrows.Next() {
			var uid string
			var ro roleOut
			if err := rrows.Scan(&uid, &ro.MandantID, &ro.Rolle); err != nil {
				return 0, nil, err
			}
			if u := byID[uid]; u != nil {
				u.Rollen = append(u.Rollen, ro)
			}
		}
		if err := rrows.Err(); err != nil {
			return 0, nil, err
		}
		if users == nil {
			users = []userOut{}
		}
		return http.StatusOK, map[string]any{"benutzer": users}, nil
	})
}

type userIn struct {
	MandantID   string `json:"mandant_id"`
	Email       string `json:"email"`
	Anzeigename string `json:"anzeigename"`
	Passwort    string `json:"passwort"`
}

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+$`)

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var in userIn
	if !readJSON(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !uuidPattern.MatchString(in.MandantID) {
		writeError(w, http.StatusBadRequest, "Mandant fehlt oder ist ungültig.")
		return
	}
	if len(email) < 3 || len(email) > 254 || !emailPattern.MatchString(email) {
		writeError(w, http.StatusBadRequest, "Ungültige E-Mail-Adresse.")
		return
	}
	name, err := cleanName(in.Anzeigename)
	if err != nil {
		writeDBError(w, "", err)
		return
	}
	if err := auth.ValidateNewPassword(in.Passwort, email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// H3: Eine vergebene Adresse lässt sich am Fehlschlag erkennen (sie ist
	// installationsweit eindeutig, weil die Anmeldung über sie läuft). Gegen
	// das Durchprobieren: höchstens 20 abgelehnte Anlagen je Admin und Stunde.
	sess := sessionFrom(r.Context())
	if s.userCreateRejects.count(sess.UserID, s.now()) >= maxUserCreateRejects {
		writeError(w, http.StatusTooManyRequests, "Zu viele abgelehnte Anlagen in der letzten Stunde. Bitte später erneut versuchen.")
		return
	}
	if !s.acquireHash(r.Context()) {
		return
	}
	hash, err := auth.HashPassword(in.Passwort, *s.cfg.PasswordParams)
	s.releaseHash()
	if err != nil {
		internalError(w, "hash", err)
		return
	}
	rejected := false
	defer func() {
		if !rejected {
			return
		}
		s.userCreateRejects.add(sess.UserID, s.now())
		if err := s.withUser(context.WithoutCancel(r.Context()), sess.UserID, func(tx pgx.Tx) error {
			return audit(r.Context(), tx, &in.MandantID, "benutzer.anlegen_abgelehnt", map[string]any{"email": email, "grund": "adresse"})
		}); err != nil {
			slog.Warn("Audit benutzer.anlegen_abgelehnt fehlgeschlagen", "fehler", err)
		}
	}()
	s.handle(w, r, "benutzer anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name)
			VALUES ($1, $2, $3) RETURNING id::text`, in.MandantID, email, name).Scan(&id); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" {
				rejected = true
				return 0, nil, errEmailUnusable
			}
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, id, hash); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &in.MandantID, "benutzer.angelegt", map[string]any{"id": id, "email": email}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, userOut{ID: id, MandantID: in.MandantID, Email: email, Anzeigename: name, Rollen: []roleOut{}}, nil
	})
}

type userPatch struct {
	Anzeigename *string `json:"anzeigename"`
	Deaktiviert *bool   `json:"deaktiviert"`
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in userPatch
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if in.Deaktiviert != nil && *in.Deaktiviert && id == sess.UserID {
		writeError(w, http.StatusBadRequest, "Du kannst dich nicht selbst deaktivieren.")
		return
	}
	s.handle(w, r, "benutzer ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant string
		var manageable bool
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, id = openwacht.current_user_id() OR openwacht.user_manageable(id)
			FROM openwacht.users
			WHERE id = $1 AND tenant_id IN (SELECT openwacht.admin_tenants())`, id).Scan(&tenant, &manageable); err != nil {
			return 0, nil, err
		}
		if !manageable {
			return 0, nil, errForeignRoles
		}
		details := map[string]any{"id": id}
		if in.Anzeigename != nil {
			name, err := cleanName(*in.Anzeigename)
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE openwacht.users SET display_name = $2 WHERE id = $1`, id, name); err != nil {
				return 0, nil, err
			}
			details["anzeigename"] = name
		}
		if in.Deaktiviert != nil {
			if _, err := tx.Exec(ctx, `UPDATE openwacht.users SET disabled = $2 WHERE id = $1`, id, *in.Deaktiviert); err != nil {
				return 0, nil, err
			}
			if *in.Deaktiviert {
				if _, err := tx.Exec(ctx, `SELECT openwacht.session_delete_user($1)`, id); err != nil {
					return 0, nil, err
				}
			}
			details["deaktiviert"] = *in.Deaktiviert
		}
		if err := audit(ctx, tx, &tenant, "benutzer.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handlePasswordSet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Passwort      string `json:"passwort"`
		AltesPasswort string `json:"altes_passwort"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	self := id == sess.UserID
	var email string
	var isAdmin, manageable bool
	err := s.withUser(r.Context(), sess.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT email, tenant_id IN (SELECT openwacht.admin_tenants()), openwacht.user_manageable(id)
			FROM openwacht.users WHERE id = $1`, id).Scan(&email, &isAdmin, &manageable)
	})
	switch {
	case err != nil, self:
	case !isAdmin:
		err = errNotFound // vor dem teuren Hashen ablehnen
	case !manageable:
		err = errForeignRoles
	}
	if err != nil {
		writeDBError(w, "passwort", err)
		return
	}
	if err := auth.ValidateNewPassword(in.Passwort, email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.acquireHash(r.Context()) {
		return
	}
	defer s.releaseHash()
	if self {
		// Eigenes Passwort nur mit dem bisherigen ändern. Fehlversuche zählen
		// wie bei der Anmeldung auf Konto und Quelle: Sonst ließe sich das
		// Passwort mit einer gekaperten Sitzung beliebig oft raten.
		src := s.loginSource(r)
		if s.sourceLocked(r.Context(), id, src) {
			writeDBError(w, "passwort", errConfirmLocked)
			return
		}
		var hash *string
		if err := s.pool.QueryRow(r.Context(), `SELECT password_hash FROM openwacht.auth_lookup($1)`, email).Scan(&hash); err != nil || hash == nil {
			writeError(w, http.StatusBadRequest, "Das bisherige Passwort ist falsch.")
			return
		}
		if ok, _, _ := auth.VerifyPassword(in.AltesPasswort, *hash, *s.cfg.PasswordParams); !ok {
			s.loginFailed(r.Context(), id, src)
			s.auditAuth(r.Context(), id, "bestaetigung.fehlgeschlagen", map[string]any{"grund": "passwort_aendern"}, true)
			writeError(w, http.StatusBadRequest, "Das bisherige Passwort ist falsch.")
			return
		}
	}
	hash, err := auth.HashPassword(in.Passwort, *s.cfg.PasswordParams)
	if err != nil {
		internalError(w, "hash", err)
		return
	}
	s.handle(w, r, "passwort setzen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `SELECT openwacht.auth_set_password($1, $2)`, id, hash); err != nil {
			return 0, nil, err
		}
		// Bestehende Sitzungen beenden: Wer das alte Passwort kannte, fliegt raus.
		if _, err := tx.Exec(ctx, `SELECT openwacht.session_delete_user($1)`, id); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT openwacht.audit_auth($1, 'passwort.geaendert', $2)`,
			id, map[string]any{"durch_admin": !self}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// --- Rollen -----------------------------------------------------------------

func (s *Server) handleRoleSet(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	tid, ok := pathID(w, r, "mandant")
	if !ok {
		return
	}
	var in struct {
		Rolle string `json:"rolle"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !validRoles[in.Rolle] {
		writeError(w, http.StatusBadRequest, "Unbekannte Rolle (erlaubt: admin, operator, leser).")
		return
	}
	if uid == sessionFrom(r.Context()).UserID {
		writeError(w, http.StatusBadRequest, "Du kannst deine eigenen Rollen nicht ändern.")
		return
	}
	s.handle(w, r, "rolle setzen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		// Ersetzen statt Ändern: Für beides verlangt die Datenbank Admin-Rechte am Zielknoten.
		if _, err := tx.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1 AND tenant_id = $2`, uid, tid); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			uid, tid, in.Rolle); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "rolle.vergeben", map[string]any{"benutzer": uid, "rolle": in.Rolle}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	tid, ok := pathID(w, r, "mandant")
	if !ok {
		return
	}
	if uid == sessionFrom(r.Context()).UserID {
		writeError(w, http.StatusBadRequest, "Du kannst deine eigenen Rollen nicht ändern.")
		return
	}
	s.handle(w, r, "rolle entziehen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		ct, err := tx.Exec(ctx, `DELETE FROM openwacht.role_assignments WHERE user_id = $1 AND tenant_id = $2`, uid, tid)
		if err != nil {
			return 0, nil, err
		}
		if ct.RowsAffected() != 1 {
			return 0, nil, errNotFound
		}
		if err := audit(ctx, tx, &tid, "rolle.entzogen", map[string]any{"benutzer": uid}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}
