// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Gruppenbaum (Etappe 13): Gruppen sind eigene Einträge je Mandant und bilden
// einen Baum mit höchstens 4 Ebenen (Migration 0016). Ein Gerät hängt an
// höchstens einer Gruppe seines Mandanten. Gruppen ordnen nur die Darstellung
// (Hosts-Baum, Wandanzeige); Rechte hängen weiterhin am Mandanten.
//
// Pflegen dürfen Operatoren und Admins (RLS wie bei Geräten), lesen alle mit
// Sicht auf den Mandanten. Zyklen, Tiefe und Mandantengrenzen prüft die
// Datenbank selbst; die Anwendung prüft vorher, um verständliche Meldungen zu
// geben.

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

// Höchstens so viele Geräte je Zuordnung (passt in die 16-KiB-Grenze für JSON).
const maxAssign = 300

type gruppeOut struct {
	ID        string    `json:"id"`
	MandantID string    `json:"mandant_id"`
	ElternID  *string   `json:"eltern_id"`
	Name      string    `json:"name"`
	Position  int       `json:"position"`
	Erstellt  time.Time `json:"erstellt"`
}

type gruppeIn struct {
	Name     string `json:"name"`
	ElternID string `json:"eltern_id"` // leer = oberste Ebene
}

// cleanGroupName prüft den Namen einer Gruppe: 1 bis 50 Zeichen, keine
// Steuerzeichen und kein „/“ (das trennt Ebenen in der Anzeige des Pfads).
func cleanGroupName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > 50 || strings.Contains(s, "/") ||
		strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", badRequest("Gruppe: 1 bis 50 Zeichen, ohne „/“ und ohne Steuerzeichen.")
	}
	return s, nil
}

// optionalID prüft eine optionale ID aus dem Request (leer = keine).
func optionalID(s, field string) (*string, error) {
	if s == "" {
		return nil, nil
	}
	if !uuidPattern.MatchString(s) {
		return nil, badRequest(field + ": ungültige ID.")
	}
	return &s, nil
}

// groupError übersetzt die Prüfungen der Datenbank in verständliche Meldungen.
func groupError(err error) error {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err
	}
	switch {
	case pe.Code == "23503" && strings.HasPrefix(pe.ConstraintName, "snmp_trap_rules_"):
		return trapRuleRef(err)
	case pe.ConstraintName == "device_groups_cycle":
		return badRequest("Eine Gruppe kann nicht in sich selbst oder in eine ihrer Untergruppen verschoben werden.")
	case pe.ConstraintName == "device_groups_depth":
		return badRequest("Höchstens 4 Ebenen (auch mit allen Untergruppen der verschobenen Gruppe).")
	case pe.ConstraintName == "device_groups_limit":
		return badRequest("Höchstens 1000 Gruppen je Mandant.")
	case pe.Code == "23505" && pe.ConstraintName == "device_groups_sibling_name":
		return &apiError{http.StatusConflict, "Auf dieser Ebene gibt es schon eine Gruppe mit diesem Namen."}
	case pe.Code == "23503":
		return badRequest("Gruppe und Gerät bzw. Eltern-Gruppe müssen zum selben Mandanten gehören.")
	}
	return err
}

// groupTenant liefert den Mandanten einer sichtbaren Gruppe.
func groupTenant(ctx context.Context, tx pgx.Tx, id string) (string, error) {
	var tenant string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.device_groups WHERE id = $1`, id).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", &apiError{http.StatusNotFound, "Gruppe nicht gefunden."}
	}
	return tenant, err
}

// lockGroups serialisiert Änderungen am Baum eines Mandanten (dieselbe Sperre
// wie im Trigger der Migration 0016).
func lockGroups(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('openwacht.device_groups:' || $1, 0))`, tenant)
	return err
}

func (s *Server) handleGroupList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "gruppen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, parent_id::text, name, position, created_at
			FROM openwacht.device_groups
			WHERE ($1 = '' OR tenant_id = $1::uuid)
			ORDER BY tenant_id, position, lower(name), id`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gruppeOut, error) {
			var g gruppeOut
			err := row.Scan(&g.ID, &g.MandantID, &g.ElternID, &g.Name, &g.Position, &g.Erstellt)
			return g, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []gruppeOut{}
		}
		return http.StatusOK, map[string]any{"gruppen": list}, nil
	})
}

func (s *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in gruppeIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gruppe anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanGroupName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		parent, err := optionalID(in.ElternID, "Eltern-Gruppe")
		if err != nil {
			return 0, nil, err
		}
		if parent != nil {
			pt, err := groupTenant(ctx, tx, *parent)
			if err != nil {
				return 0, nil, err
			}
			if pt != tid {
				return 0, nil, badRequest("Die Eltern-Gruppe gehört zu einem anderen Mandanten.")
			}
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, parent_id, name) VALUES ($1, $2, $3) RETURNING id::text`,
			tid, parent, name).Scan(&id); err != nil {
			return 0, nil, groupError(err) // ohne Recht: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "gruppe.angelegt", map[string]any{"id": id, "name": name, "eltern_id": parent}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

// handleGroupUpdate benennt um und verschiebt (eltern_id leer = oberste Ebene).
// Eine verschobene Gruppe kommt ans Ende ihrer neuen Geschwister.
func (s *Server) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in gruppeIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gruppe ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanGroupName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		parent, err := optionalID(in.ElternID, "Eltern-Gruppe")
		if err != nil {
			return 0, nil, err
		}
		tenant, err := groupTenant(ctx, tx, id)
		if err != nil {
			return 0, nil, err
		}
		if parent != nil {
			pt, err := groupTenant(ctx, tx, *parent)
			if err != nil {
				return 0, nil, err
			}
			if pt != tenant {
				return 0, nil, badRequest("Gruppen lassen sich nicht in einen anderen Mandanten verschieben.")
			}
		}
		var oldName string
		var oldParent *string
		if err := tx.QueryRow(ctx, `SELECT name, parent_id::text FROM openwacht.device_groups WHERE id = $1`, id).Scan(&oldName, &oldParent); err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.device_groups SET name = $2, parent_id = $3 WHERE id = $1`, id, name, parent)
		if err != nil {
			return 0, nil, groupError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound // nur Leser
		}
		details := map[string]any{"id": id, "name": name, "eltern_id": parent}
		if oldName != name {
			details["alter_name"] = oldName
		}
		if !sameID(oldParent, parent) {
			details["alte_eltern_id"] = oldParent
		}
		if err := audit(ctx, tx, &tenant, "gruppe.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func sameID(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type positionIn struct {
	VorID string `json:"vor_id"` // Geschwister, vor das die Gruppe kommt; leer = ans Ende
}

// handleGroupPosition setzt eine Gruppe unter ihren Geschwistern vor eine
// andere (oder ans Ende) und nummeriert die Geschwister neu.
func (s *Server) handleGroupPosition(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in positionIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gruppe sortieren", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		before, err := optionalID(in.VorID, "Vor")
		if err != nil {
			return 0, nil, err
		}
		if before != nil && *before == id {
			return http.StatusNoContent, nil, nil
		}
		tenant, err := groupTenant(ctx, tx, id)
		if err != nil {
			return 0, nil, err
		}
		if err := lockGroups(ctx, tx, tenant); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT g.id::text, g.position FROM openwacht.device_groups g
			JOIN openwacht.device_groups me ON me.id = $1
			WHERE g.tenant_id = me.tenant_id AND g.parent_id IS NOT DISTINCT FROM me.parent_id AND g.id <> me.id
			ORDER BY g.position, lower(g.name), g.id`, id)
		if err != nil {
			return 0, nil, err
		}
		type sib struct {
			id  string
			pos int
		}
		sibs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (sib, error) {
			var x sib
			err := row.Scan(&x.id, &x.pos)
			return x, err
		})
		if err != nil {
			return 0, nil, err
		}
		order := make([]string, 0, len(sibs)+1)
		placed := false
		for _, x := range sibs {
			if before != nil && x.id == *before {
				order = append(order, id)
				placed = true
			}
			order = append(order, x.id)
		}
		if before != nil && !placed {
			return 0, nil, badRequest("Vor: keine Gruppe auf derselben Ebene.")
		}
		if !placed {
			order = append(order, id)
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.device_groups g SET position = o.pos - 1
			FROM unnest($1::uuid[]) WITH ORDINALITY AS o(id, pos)
			WHERE g.id = o.id AND g.position <> o.pos - 1`, order)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			// Nichts zu ändern oder nur Leser: Leser dürfen nicht schreiben.
			var can bool
			if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.operator_tenants())`, tenant).Scan(&can); err != nil {
				return 0, nil, err
			}
			if !can {
				return 0, nil, errNotFound
			}
			return http.StatusNoContent, nil, nil
		}
		if err := audit(ctx, tx, &tenant, "gruppe.sortiert", map[string]any{"id": id, "vor_id": before}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleGroupDelete löscht eine Gruppe. Ihre Geräte und Untergruppen wandern
// eine Ebene höher (Entscheidung, 20.11.2026); es geht nichts verloren.
func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "gruppe löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		var parent *string
		err := tx.QueryRow(ctx, `SELECT tenant_id::text, parent_id::text, name FROM openwacht.device_groups WHERE id = $1`, id).
			Scan(&tenant, &parent, &name)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, &apiError{http.StatusNotFound, "Gruppe nicht gefunden."}
		}
		if err != nil {
			return 0, nil, err
		}
		// Leser sehen die Gruppe, dürfen aber nichts umhängen. RLS würde das
		// Umhängen still mit 0 Zeilen beenden; deshalb vorher fragen. Danach
		// erst Geräte und Untergruppen umhängen, dann löschen, alles in einer
		// Transaktion (die Fremdschlüssel verhindern Waisen).
		var can bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.operator_tenants())`, tenant).Scan(&can); err != nil {
			return 0, nil, err
		}
		if !can {
			return 0, nil, errNotFound
		}
		devs, err := tx.Exec(ctx, `UPDATE openwacht.devices SET group_id = $2 WHERE group_id = $1`, id, parent)
		if err != nil {
			return 0, nil, groupError(err)
		}
		var conflict string
		err = tx.QueryRow(ctx, `SELECT c.name FROM openwacht.device_groups c
			JOIN openwacht.device_groups o ON o.tenant_id = c.tenant_id AND o.parent_id IS NOT DISTINCT FROM $2::uuid
			     AND o.id <> $1 AND lower(o.name) = lower(c.name)
			WHERE c.parent_id = $1 ORDER BY lower(c.name) LIMIT 1`, id, parent).Scan(&conflict)
		if err == nil {
			return 0, nil, &apiError{http.StatusConflict,
				"Die Untergruppe „" + conflict + "“ gibt es eine Ebene höher schon. Bitte erst umbenennen oder verschieben."}
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, err
		}
		subs, err := tx.Exec(ctx, `UPDATE openwacht.device_groups SET parent_id = $2 WHERE parent_id = $1`, id, parent)
		if err != nil {
			return 0, nil, groupError(err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.device_groups WHERE id = $1`, id)
		if err != nil {
			return 0, nil, groupError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		if err := audit(ctx, tx, &tenant, "gruppe.geloescht", map[string]any{
			"id": id, "name": name, "eltern_id": parent, "geraete": devs.RowsAffected(), "untergruppen": subs.RowsAffected(),
		}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"geraete": devs.RowsAffected(), "untergruppen": subs.RowsAffected()}, nil
	})
}

type zuordnungIn struct {
	Geraete  []string `json:"geraete"`
	GruppeID string   `json:"gruppe_id"` // leer = ohne Gruppe
}

// handleDeviceGroupAssign ordnet mehrere Geräte auf einmal einer Gruppe zu
// (oder nimmt sie aus ihrer Gruppe). Ganz oder gar nicht: Ist ein Gerät nicht
// sichtbar, nicht änderbar oder in einem anderen Mandanten als die Gruppe,
// ändert sich nichts.
func (s *Server) handleDeviceGroupAssign(w http.ResponseWriter, r *http.Request) {
	var in zuordnungIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "geräte zuordnen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if len(in.Geraete) == 0 || len(in.Geraete) > maxAssign {
			return 0, nil, badRequest("Geräte: 1 bis 300 auf einmal.")
		}
		seen := map[string]bool{}
		for _, id := range in.Geraete {
			if !uuidPattern.MatchString(id) {
				return 0, nil, badRequest("Geräte: ungültige ID.")
			}
			if seen[id] {
				return 0, nil, badRequest("Geräte: jede ID nur einmal.")
			}
			seen[id] = true
		}
		group, err := optionalID(in.GruppeID, "Gruppe")
		if err != nil {
			return 0, nil, err
		}
		var gt string
		if group != nil {
			if gt, err = groupTenant(ctx, tx, *group); err != nil {
				return 0, nil, err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text FROM openwacht.devices WHERE id = ANY($1::uuid[])`, in.Geraete)
		if err != nil {
			return 0, nil, err
		}
		byTenant := map[string][]string{}
		n := 0
		for rows.Next() {
			var id, tenant string
			if err := rows.Scan(&id, &tenant); err != nil {
				rows.Close()
				return 0, nil, err
			}
			if group != nil && tenant != gt {
				rows.Close()
				return 0, nil, badRequest("Geräte lassen sich nur Gruppen ihres eigenen Mandanten zuordnen.")
			}
			byTenant[tenant] = append(byTenant[tenant], id)
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, nil, err
		}
		if n != len(in.Geraete) {
			return 0, nil, &apiError{http.StatusNotFound, "Mindestens ein Gerät wurde nicht gefunden."}
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.devices SET group_id = $2 WHERE id = ANY($1::uuid[])`, in.Geraete, group)
		if err != nil {
			return 0, nil, groupError(err)
		}
		if int(tag.RowsAffected()) != n {
			// Leser oder Gerät in einem Mandanten ohne Operator-Recht: alles zurück.
			return 0, nil, &apiError{http.StatusForbidden, "Keine Berechtigung für mindestens eines der Geräte."}
		}
		// Ein Eintrag im Audit-Log darf höchstens 8 KiB groß sein: höchstens
		// 150 IDs je Eintrag.
		for tenant, ids := range byTenant {
			for len(ids) > 0 {
				part := ids[:min(len(ids), 150)]
				ids = ids[len(part):]
				if err := audit(ctx, tx, &tenant, "geraete.gruppe", map[string]any{"geraete": part, "gruppe_id": group}); err != nil {
					return 0, nil, err
				}
			}
		}
		return http.StatusNoContent, nil, nil
	})
}

// deviceGroupForTenant prüft die Gruppe für ein Gerät eines Mandanten.
func deviceGroupForTenant(ctx context.Context, tx pgx.Tx, raw, tenant string) (*string, error) {
	group, err := optionalID(raw, "Gruppe")
	if err != nil || group == nil {
		return group, err
	}
	gt, err := groupTenant(ctx, tx, *group)
	if err != nil {
		return nil, err
	}
	if gt != tenant {
		return nil, badRequest("Geräte lassen sich nur Gruppen ihres eigenen Mandanten zuordnen.")
	}
	return group, nil
}
