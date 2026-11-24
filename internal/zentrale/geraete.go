// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Geräte (Hosts): das, was überwacht wird. Ein Gerät hat höchstens einen
// aktiven Agent und beliebig viele Checks; beides gehört zum Mandanten des
// Geräts (Migration 0012). Die Adresse eines Geräts ist nur ein Vorschlag für
// neue Checks: Die Zentrale verbindet sich nie mit ihr.
//
// Geräte werden nie automatisch verknüpft. Passen Name oder Adresse eines
// Geräts ohne Agent zu einem Agent im selben Mandanten, schlägt die Liste das
// Zusammenführen vor; ausführen muss es ein Admin oder Operator. Die Adresse
// zählt nur, wenn genau ein aktiver Agent des Mandanten sich von ihr meldet
// (hinter einem NAT teilen sich viele Agents eine Adresse).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/version"
)

type geraetIn struct {
	Name    string `json:"name"`
	Adresse string `json:"adresse"`
	// Gruppe im Gruppenbaum (Etappe 13): "" = keine; fehlt das Feld beim
	// Ändern, bleibt die Gruppe, wie sie ist.
	GruppeID *string `json:"gruppe_id"`
	// Abhängigkeit (Etappe 24): Elterngerät im selben Mandanten; "" = keins,
	// fehlt das Feld, bleibt sie, wie sie ist.
	AbhaengigVon *string `json:"abhaengig_von"`
}

type vorschlagOut struct {
	GeraetID string `json:"geraet_id"`
	Name     string `json:"name"`
	Grund    string `json:"grund"` // name | adresse
}

type geraetOut struct {
	ID          string         `json:"id"`
	MandantID   string         `json:"mandant_id"`
	Name        string         `json:"name"`
	Adresse     *string        `json:"adresse"`
	GruppeID    *string        `json:"gruppe_id"`
	Erstellt    time.Time      `json:"erstellt"`
	AgentID     *string        `json:"agent_id"` // aktiver Agent
	SNMPID      *string        `json:"snmp_id"`
	Checks      int            `json:"checks"`
	Wartung     *wartungOut    `json:"wartung"`
	Vorschlaege []vorschlagOut `json:"vorschlaege"`
	// Etappe 24: Elterngerät und, falls ein Gerät darüber ausgefallen ist, dessen Name
	AbhaengigVon *string `json:"abhaengig_von"`
	Wegen        *string `json:"nicht_erreichbar_wegen"`
}

// cleanAddress prüft die Adresse eines Geräts: leer, Hostname oder IP-Adresse
// (IP-Adressen in kanonischer Schreibweise, damit der Vergleich mit der
// Absenderadresse eines Agents stimmt).
func cleanAddress(s string) (*string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		c := a.Unmap().String()
		return &c, nil
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if !checks.ValidHost(s) {
		return nil, badRequest("Adresse: Hostname oder IP-Adresse angeben, ohne Protokoll und Port.")
	}
	return &s, nil
}

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "geraete", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		maint, err := visibleMaintenance(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT d.id::text, d.tenant_id::text, d.name, d.address, d.group_id::text, d.created_at,
				(SELECT a.id::text FROM openwacht.agents a WHERE a.device_id = d.id AND a.revoked_at IS NULL),
				(SELECT count(*) FROM openwacht.checks c WHERE c.device_id = d.id)::int,
				(SELECT s.id::text FROM openwacht.snmp_sources s WHERE s.device_id = d.id),
				d.parent_id::text, bd.name
			FROM openwacht.devices d
			LEFT JOIN openwacht.devices_blocked() b ON b.device_id = d.id
			LEFT JOIN openwacht.devices bd ON bd.id = b.blocker_id
			WHERE ($1 = '' OR d.tenant_id = $1::uuid) ORDER BY lower(d.name), d.id`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (geraetOut, error) {
			var d geraetOut
			err := row.Scan(&d.ID, &d.MandantID, &d.Name, &d.Adresse, &d.GruppeID, &d.Erstellt, &d.AgentID, &d.Checks, &d.SNMPID,
				&d.AbhaengigVon, &d.Wegen)
			d.Wartung = maint["d:"+d.ID]
			d.Vorschlaege = []vorschlagOut{}
			return d, err
		})
		if err != nil {
			return 0, nil, err
		}
		idx := map[string]int{}
		for i := range list {
			idx[list[i].ID] = i
		}
		sugg, err := deviceSuggestions(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		for _, sg := range sugg {
			if i, ok := idx[sg.from]; ok && len(list[i].Vorschlaege) < 3 {
				list[i].Vorschlaege = append(list[i].Vorschlaege, sg.vorschlagOut)
			}
		}
		if list == nil {
			list = []geraetOut{}
		}
		return http.StatusOK, map[string]any{"geraete": list}, nil
	})
}

type suggestion struct {
	from string
	vorschlagOut
}

// deviceSuggestions: Geräte ohne Agent, die wohl zu einem Agent-Gerät im
// selben Mandanten gehören. Läuft mit den Rechten des Aufrufers.
func deviceSuggestions(ctx context.Context, tx pgx.Tx) ([]suggestion, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT ON (d.id, o.id) d.id::text, o.id::text, o.name,
		       CASE WHEN d.address IS NOT NULL AND d.address = host(a.last_addr) AND
		                 (SELECT count(*) FROM openwacht.agents y
		                   WHERE y.tenant_id = a.tenant_id AND y.revoked_at IS NULL AND y.last_addr = a.last_addr) = 1
		            THEN 'adresse' ELSE 'name' END AS grund
		  FROM openwacht.devices d
		  JOIN openwacht.devices o ON o.tenant_id = d.tenant_id AND o.id <> d.id
		  JOIN openwacht.agents a ON a.device_id = o.id AND a.revoked_at IS NULL
		 WHERE NOT EXISTS (SELECT 1 FROM openwacht.agents x WHERE x.device_id = d.id)
		   AND (lower(d.name) IN (lower(o.name), lower(a.hostname))
		        OR (d.name !~ '^[0-9.]+$' AND d.name !~ ':' AND split_part(lower(d.name), '.', 1) = lower(a.hostname))
		        OR lower(d.address) = lower(a.hostname)
		        OR (d.address !~ '^[0-9.]+$' AND d.address !~ ':' AND split_part(d.address, '.', 1) = lower(a.hostname))
		        OR (d.address = host(a.last_addr) AND
		            (SELECT count(*) FROM openwacht.agents y
		              WHERE y.tenant_id = a.tenant_id AND y.revoked_at IS NULL AND y.last_addr = a.last_addr) = 1))
		 ORDER BY d.id, o.id
		 LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (suggestion, error) {
		var sg suggestion
		err := row.Scan(&sg.from, &sg.GeraetID, &sg.Name, &sg.Grund)
		return sg, err
	})
}

func (s *Server) handleDeviceCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in geraetIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gerät anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		addr, err := cleanAddress(in.Adresse)
		if err != nil {
			return 0, nil, err
		}
		var group *string
		if in.GruppeID != nil {
			if group, err = deviceGroupForTenant(ctx, tx, *in.GruppeID, tid); err != nil {
				return 0, nil, err
			}
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, address, group_id) VALUES ($1, $2, $3, $4)
			RETURNING id::text`, tid, name, addr, group).Scan(&id); err != nil {
			return 0, nil, groupError(err) // ohne Recht: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "geraet.angelegt", map[string]any{"id": id, "name": name, "adresse": addr, "gruppe_id": group}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in geraetIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gerät ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		addr, err := cleanAddress(in.Adresse)
		if err != nil {
			return 0, nil, err
		}
		var tenant string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.devices WHERE id = $1`, id).Scan(&tenant); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		details := map[string]any{"id": id, "name": name, "adresse": addr}
		if in.AbhaengigVon != nil {
			var parent *string
			if *in.AbhaengigVon != "" {
				if !uuidPattern.MatchString(*in.AbhaengigVon) {
					return 0, nil, badRequest("Ungültiges Elterngerät.")
				}
				var ok bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.devices WHERE id = $1 AND tenant_id = $2)`,
					*in.AbhaengigVon, tenant).Scan(&ok); err != nil {
					return 0, nil, err
				}
				if !ok {
					return 0, nil, badRequest("Das Elterngerät muss im selben Mandanten liegen.")
				}
				parent = in.AbhaengigVon
			}
			if _, err := tx.Exec(ctx, `UPDATE openwacht.devices SET parent_id = $2 WHERE id = $1`, id, parent); err != nil {
				return 0, nil, err
			}
			details["abhaengig_von"] = parent
		}
		var tag pgconn.CommandTag
		if in.GruppeID == nil {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.devices SET name = $2, address = $3 WHERE id = $1`, id, name, addr)
		} else {
			var group *string
			if group, err = deviceGroupForTenant(ctx, tx, *in.GruppeID, tenant); err != nil {
				return 0, nil, err
			}
			details["gruppe_id"] = group
			tag, err = tx.Exec(ctx, `UPDATE openwacht.devices SET name = $2, address = $3, group_id = $4 WHERE id = $1`, id, name, addr, group)
		}
		if err != nil {
			return 0, nil, groupError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound // nur Leser
		}
		if err := audit(ctx, tx, &tenant, "geraet.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleDeviceDelete löscht ein Gerät. Ohne Inhalt reicht der Aufruf; hat es
// noch Sensoren, einen Agent, eine Abfragequelle oder Trap-Regeln, muss der
// Name im Feld „bestaetigung“ stehen (Etappe 19). Dann sperrt und löscht die
// Datenbank den Agent, löscht Sensoren, Quellen, Trap-Regeln und Verlauf;
// das Alarmprotokoll bleibt. Ist der Agent Sammler anderer Geräte: 409.
func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Bestaetigung string `json:"bestaetigung"`
	}
	withContent := r.ContentLength != 0 || r.Header.Get("Content-Type") != ""
	if withContent && !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "gerät löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if withContent {
			var out []byte
			err := tx.QueryRow(ctx, `SELECT openwacht.device_delete_all($1, $2, true)`, id, in.Bestaetigung).Scan(&out)
			if err := deleteAllError(err); err != nil {
				return 0, nil, err
			}
			return http.StatusNoContent, nil, nil
		}
		var tenant, name string
		var nChecks, nAgents, nSNMP, nRules int
		if err := tx.QueryRow(ctx, `SELECT d.tenant_id::text, d.name,
				(SELECT count(*) FROM openwacht.checks c WHERE c.device_id = d.id)::int,
				(SELECT count(*) FROM openwacht.agents a WHERE a.device_id = d.id)::int,
				(SELECT count(*) FROM openwacht.snmp_sources s WHERE s.device_id = d.id)::int,
				(SELECT count(*) FROM openwacht.snmp_trap_rules t WHERE t.device_id = d.id)::int
			FROM openwacht.devices d WHERE d.id = $1`, id).Scan(&tenant, &name, &nChecks, &nAgents, &nSNMP, &nRules); err != nil {
			return 0, nil, err
		}
		if nChecks > 0 || nAgents > 0 || nSNMP > 0 || nRules > 0 {
			return 0, nil, &apiError{http.StatusConflict,
				"Das Gerät hat noch Sensoren, einen Agent, eine Abfragequelle oder Trap-Regeln. Zum Löschen mit Inhalt bitte den Namen des Geräts bestätigen."}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, id)
		if err != nil {
			return 0, nil, trapRuleRef(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Löschen dürfen nur Admins und Operatoren."}
		}
		if err := audit(ctx, tx, &tenant, "geraet.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// deleteAllError übersetzt die Fehler von device_delete_all. Die Meldungen
// stammen aus der eigenen Funktion und sind für Menschen geschrieben.
func deleteAllError(err error) error {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err
	}
	switch pe.Code {
	case "P0002":
		return errNotFound
	case "42501":
		return &apiError{http.StatusForbidden, "Löschen dürfen nur Admins und Operatoren."}
	case "22023":
		return &apiError{http.StatusBadRequest, pe.Message}
	case "55006":
		return &apiError{http.StatusConflict, pe.Message}
	}
	return err
}

// handleDeviceDeletePreview: was beim Löschen mitginge (für den Dialog).
func (s *Server) handleDeviceDeletePreview(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "gerät löschen vorschau", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var out json.RawMessage
		err := tx.QueryRow(ctx, `SELECT openwacht.device_delete_all($1, '', false)`, id).Scan(&out)
		if err := deleteAllError(err); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

type deviceRow struct {
	id, tenant, name string
	address          *string
	agents           int // auch gesperrte
}

func loadDevice(ctx context.Context, tx pgx.Tx, id string) (deviceRow, error) {
	d := deviceRow{id: id}
	err := tx.QueryRow(ctx, `SELECT d.tenant_id::text, d.name, d.address,
			(SELECT count(*) FROM openwacht.agents a WHERE a.device_id = d.id)::int
		FROM openwacht.devices d WHERE d.id = $1`, id).Scan(&d.tenant, &d.name, &d.address, &d.agents)
	return d, err
}

// handleDeviceMerge führt zwei Geräte desselben Mandanten zusammen. Es bleibt
// das Gerät mit Agent (sonst das in der Adresse); das andere gibt seine Checks
// und, falls dem bleibenden eine fehlt, seine Adresse ab und wird gelöscht.
// Agents wechseln nie das Gerät. Haben beide einen Agent (auch gesperrt),
// antwortet die API mit 409.
func (s *Server) handleDeviceMerge(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Mit string `json:"mit"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !uuidPattern.MatchString(in.Mit) || in.Mit == id {
		writeError(w, http.StatusBadRequest, "Bitte ein anderes Gerät angeben.")
		return
	}
	s.handle(w, r, "geräte zusammenführen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		keep, err := loadDevice(ctx, tx, id)
		if err != nil {
			return 0, nil, err
		}
		drop, err := loadDevice(ctx, tx, in.Mit)
		if err != nil {
			return 0, nil, err
		}
		if keep.tenant != drop.tenant {
			return 0, nil, &apiError{http.StatusConflict, "Nur Geräte desselben Mandanten lassen sich zusammenführen."}
		}
		if keep.agents > 0 && drop.agents > 0 {
			return 0, nil, &apiError{http.StatusConflict,
				"Beide Geräte haben einen Agent. Einen davon zuerst sperren und löschen."}
		}
		if drop.agents > 0 {
			keep, drop = drop, keep
		}
		var may bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.operator_tenants())`, keep.tenant).Scan(&may); err != nil {
			return 0, nil, err
		}
		if !may {
			return 0, nil, &apiError{http.StatusForbidden, "Zusammenführen dürfen nur Admins und Operatoren."}
		}
		moved, err := tx.Exec(ctx, `UPDATE openwacht.checks SET device_id = $1 WHERE device_id = $2`, keep.id, drop.id)
		if err != nil {
			return 0, nil, err
		}
		if keep.address == nil && drop.address != nil {
			if _, err := tx.Exec(ctx, `UPDATE openwacht.devices SET address = $2 WHERE id = $1`, keep.id, drop.address); err != nil {
				return 0, nil, err
			}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, drop.id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() != 1 {
			return 0, nil, errors.New("zusammenführen: Gerät nicht gelöscht")
		}
		if err := audit(ctx, tx, &keep.tenant, "geraet.zusammengefuehrt", map[string]any{"id": keep.id, "name": keep.name,
			"entfernt": drop.id, "entfernt_name": drop.name, "checks": moved.RowsAffected()}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": keep.id}, nil
	})
}

// handleDeviceToken erzeugt ein Token für genau einen Agent, der sich diesem
// Gerät zuordnet. Den Mandanten setzt die Datenbank aus dem Gerät.
func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		GueltigStunde int `json:"gueltig_stunden"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.GueltigStunde == 0 {
		in.GueltigStunde = 24
	}
	if in.GueltigStunde < 1 || in.GueltigStunde > 168 {
		writeError(w, http.StatusBadRequest, "Gültigkeit 1 bis 168 Stunden.")
		return
	}
	token, secret, err := agentproto.NewToken(s.AgentCAFingerprint())
	if err != nil {
		internalError(w, "token", err)
		return
	}
	hash := sha256.Sum256(secret)
	expires := s.now().Add(time.Duration(in.GueltigStunde) * time.Hour)
	s.handle(w, r, "agent-token für gerät", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		d, err := loadDevice(ctx, tx, id)
		if err != nil {
			return 0, nil, err
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.agents WHERE device_id = $1 AND revoked_at IS NULL)`,
			id).Scan(&active); err != nil {
			return 0, nil, err
		}
		if active {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon einen Agent."}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_tokens (token_hash, device_id, note, uses_left, expires_at)
			VALUES ($1, $2, $3, 1, $4)`, hash[:], id, clipRunes(d.name, 100), expires); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &d.tenant, "agent.token_erstellt", map[string]any{"anzahl": 1, "geraet": id,
			"gueltig_stunden": in.GueltigStunde}); err != nil {
			return 0, nil, err
		}
		offers, err := s.downloadOffers(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"token": token, "laeuft_ab": expires, "anzahl": 1,
			"zentrale": s.cfg.AgentURL, "version": version.Version, "download": withCommands(offers, s.cfg.AgentURL, token, s.caBundle())}, nil
	})
}
