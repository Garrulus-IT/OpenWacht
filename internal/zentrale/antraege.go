// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Anträge auf neue Untermandanten (Etappe 36, Konzept vom 18.11.2026): Admins
// eines Untermandanten beantragen in ihrem Teilbaum, Admins des
// Hauptmandanten geben frei oder lehnen ab. Sichtbar sind Anträge für die
// Admins des Elternknotens und darüber (RLS), nie für Geschwister oder Kinder.

type tenantRequestOut struct {
	ID              string     `json:"id"`
	MandantID       string     `json:"mandant_id"`
	Mandant         string     `json:"mandant"`
	Name            string     `json:"name"`
	Begruendung     string     `json:"begruendung"`
	Zustand         string     `json:"zustand"`
	BeantragtVon    string     `json:"beantragt_von"`
	BeantragtAm     time.Time  `json:"beantragt_am"`
	EntschiedenVon  string     `json:"entschieden_von"`
	EntschiedenAm   *time.Time `json:"entschieden_am"`
	Notiz           string     `json:"notiz"`
	NeuerMandantID  *string    `json:"neuer_mandant_id"`
	DarfEntscheiden bool       `json:"darf_entscheiden"`
}

func cleanText(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", badRequest("Der Text darf höchstens 500 Zeichen lang sein und keine Zeilenumbrüche oder Steuerzeichen enthalten.")
	}
	return s, nil
}

func (s *Server) handleTenantRequestList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "anträge", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var root bool
		if err := tx.QueryRow(ctx, `SELECT openwacht.is_root_admin()`).Scan(&root); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT r.id::text, r.tenant_id::text, t.name, r.name, r.reason, r.state, p.requested,
				r.created_at, p.decided, r.decided_at, r.note, r.new_tenant::text
			FROM openwacht.tenant_requests r
			JOIN openwacht.tenants t ON t.id = r.tenant_id
			CROSS JOIN LATERAL openwacht.tenant_request_people(r.id) p
			-- offene zuerst, Entschiedenes nur 90 Tage
			WHERE r.state = 'beantragt' OR r.decided_at > now() - interval '90 days'
			ORDER BY r.state <> 'beantragt', r.created_at DESC LIMIT 200`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantRequestOut, error) {
			var o tenantRequestOut
			err := row.Scan(&o.ID, &o.MandantID, &o.Mandant, &o.Name, &o.Begruendung, &o.Zustand, &o.BeantragtVon,
				&o.BeantragtAm, &o.EntschiedenVon, &o.EntschiedenAm, &o.Notiz, &o.NeuerMandantID)
			o.DarfEntscheiden = root && o.Zustand == "beantragt"
			return o, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []tenantRequestOut{}
		}
		return http.StatusOK, map[string]any{"antraege": list, "hauptmandant": root}, nil
	})
}

func (s *Server) handleTenantRequestCreate(w http.ResponseWriter, r *http.Request) {
	parent, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Name        string `json:"name"`
		Begruendung string `json:"begruendung"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "antrag stellen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		reason, err := cleanText(in.Begruendung, 500)
		if err != nil {
			return 0, nil, err
		}
		var admin, root, exists bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants()), openwacht.is_root_admin(),
				EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id = $1 AND lower(name) = lower($2))`, parent, name).
			Scan(&admin, &root, &exists); err != nil {
			return 0, nil, err
		}
		switch {
		case !admin:
			return 0, nil, &apiError{http.StatusForbidden, "Anträge stellen nur Admins dieses Mandanten."}
		case root:
			return 0, nil, badRequest("Admins des Hauptmandanten legen Untermandanten direkt an.")
		case exists:
			return 0, nil, &apiError{http.StatusConflict, "Einen Untermandanten mit diesem Namen gibt es hier schon."}
		}
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO openwacht.tenant_requests (tenant_id, name, reason) VALUES ($1, $2, $3) RETURNING id::text`,
			parent, name, reason).Scan(&id)
		var pe *pgconn.PgError
		switch {
		case errors.As(err, &pe) && pe.Code == "23505":
			return 0, nil, &apiError{http.StatusConflict, "Für diesen Namen gibt es schon einen offenen Antrag."}
		case errors.As(err, &pe) && pe.Code == "54000":
			return 0, nil, &apiError{http.StatusConflict, "Es sind schon 20 Anträge offen. Bitte warten, bis der Hauptmandant entschieden hat."}
		case err != nil:
			return 0, nil, err
		}
		if err := audit(ctx, tx, &parent, "mandant.beantragt", map[string]any{"antrag": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]string{"id": id}, nil
	})
}

func (s *Server) handleTenantRequestDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		var in struct {
			Notiz string `json:"notiz"`
		}
		if r.ContentLength != 0 && !readJSON(w, r, &in) {
			return
		}
		s.handle(w, r, "antrag entscheiden", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
			note, err := cleanText(in.Notiz, 500)
			if err != nil {
				return 0, nil, err
			}
			var root bool
			if err := tx.QueryRow(ctx, `SELECT openwacht.is_root_admin()`).Scan(&root); err != nil {
				return 0, nil, err
			}
			if !root {
				// Kein Hinweis, ob es den Antrag gibt.
				return 0, nil, &apiError{http.StatusForbidden, "Über Anträge entscheiden nur Admins des Hauptmandanten."}
			}
			var parent, name, state string
			if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name, state FROM openwacht.tenant_requests WHERE id = $1 FOR UPDATE`, id).
				Scan(&parent, &name, &state); err != nil {
				return 0, nil, err
			}
			if state != "beantragt" {
				return 0, nil, &apiError{http.StatusConflict, "Über diesen Antrag ist schon entschieden."}
			}
			if !approve {
				if _, err := tx.Exec(ctx, `UPDATE openwacht.tenant_requests SET state = 'abgelehnt', note = $2 WHERE id = $1`, id, note); err != nil {
					return 0, nil, err
				}
				if err := audit(ctx, tx, &parent, "mandant.antrag_abgelehnt", map[string]any{"antrag": id, "name": name}); err != nil {
					return 0, nil, err
				}
				return http.StatusNoContent, nil, nil
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.tenants (parent_id, name) VALUES ($1, $2)`, parent, name); err != nil {
				var pe *pgconn.PgError
				if errors.As(err, &pe) && pe.Code == "23505" {
					return 0, nil, &apiError{http.StatusConflict, "Einen Untermandanten mit diesem Namen gibt es dort inzwischen. Bitte den Antrag ablehnen."}
				}
				return 0, nil, err
			}
			var newID string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.tenants WHERE parent_id = $1 AND lower(name) = lower($2)`, parent, name).
				Scan(&newID); err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE openwacht.tenant_requests SET state = 'freigegeben', note = $2, new_tenant = $3 WHERE id = $1`,
				id, note, newID); err != nil {
				return 0, nil, err
			}
			if err := audit(ctx, tx, &parent, "mandant.antrag_freigegeben", map[string]any{"antrag": id, "name": name}); err != nil {
				return 0, nil, err
			}
			if err := audit(ctx, tx, &parent, "mandant.angelegt", map[string]any{"id": newID, "name": name, "antrag": id}); err != nil {
				return 0, nil, err
			}
			return http.StatusOK, map[string]string{"mandant_id": newID}, nil
		})
	}
}
