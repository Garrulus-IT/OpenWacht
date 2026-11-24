// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
)

// Signierte Agent-Updates (Etappe 23). Die Zentrale speichert nur Pakete mit
// gültiger Offline-Signatur und bietet sie freigegebenen Agents an. Sie kann
// keine Signatur erzeugen; der Agent prüft selbst noch einmal.

// updateKey: eingebettete Schlüssel (in Tests cfg.UpdateKeys) ohne Widerrufe
// aus der Datenbank; nil = Updates aus.
func (s *Server) updateKey() *update.Keyring {
	if s.cfg.UpdateKeys != "" {
		k, err := update.ParseKeyring(s.cfg.UpdateKeys)
		if err != nil {
			return nil
		}
		return k
	}
	k, err := update.Keys()
	if err != nil {
		return nil
	}
	return k
}

// updateKeys: Schlüsselbund mit den Widerrufen aus der Datenbank.
func (s *Server) updateKeys(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (*update.Keyring, error) {
	k := s.updateKey()
	if k == nil {
		return nil, nil
	}
	var ids []string
	if err := q.QueryRow(ctx, `SELECT openwacht.update_revoked_keys()`).Scan(&ids); err != nil {
		return nil, err
	}
	k.Revoke(ids...)
	return k, nil
}

func splitPlatform(p string) (goos, arch string, ok bool) {
	goos, arch, ok = strings.Cut(p, "/")
	return goos, arch, ok && goos != "" && arch != ""
}

// updateOffer: Angebot für die Antwort auf eine Meldung (nil = keins).
func (s *Server) updateOffer(ctx context.Context, agentID string, snap *agentproto.Snapshot) *agentproto.UpdateOffer {
	goos, arch, ok := splitPlatform(snap.Platform)
	if !ok || !s.updateKey().Usable() {
		return nil
	}
	var ver, sum, sig string
	var size int64
	err := s.pool.QueryRow(ctx, `SELECT version, sha256, signature, size FROM openwacht.agent_update_offer($1, $2, $3)`,
		agentID, goos, arch).Scan(&ver, &sum, &sig, &size)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("Agent-Update: Angebot nicht lesbar", "fehler", err)
		}
		return nil
	}
	if !update.Newer(ver, snap.AgentVersion) {
		return nil
	}
	return &agentproto.UpdateOffer{Version: ver, SHA256: sum}
}

type updateRequest struct {
	Version  string `json:"version"`
	Platform string `json:"plattform"`
}

func (s *Server) handleAgentUpdateSignature(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	if !s.agentRate(w, s.agentUpdateRate, ident.ID) {
		return
	}
	var req updateRequest
	if !readAgentJSON(w, r, 1024, &req) {
		return
	}
	goos, arch, ok := splitPlatform(req.Platform)
	if !ok {
		writeError(w, http.StatusBadRequest, "Plattform fehlt.")
		return
	}
	var ver, sig string
	err := s.pool.QueryRow(r.Context(), `SELECT version, signature FROM openwacht.agent_update_offer($1, $2, $3)`, ident.ID, goos, arch).
		Scan(&ver, &sig)
	if err != nil || ver != req.Version {
		writeError(w, http.StatusNotFound, "Kein Update für diesen Agent freigegeben.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, sig)
}

func (s *Server) handleAgentUpdateBinary(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	if !s.agentRate(w, s.agentUpdateRate, ident.ID) {
		return
	}
	var req updateRequest
	if !readAgentJSON(w, r, 1024, &req) {
		return
	}
	goos, arch, ok := splitPlatform(req.Platform)
	if !ok {
		writeError(w, http.StatusBadRequest, "Plattform fehlt.")
		return
	}
	var data []byte
	err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_update_data($1, $2, $3, $4)`, ident.ID, goos, arch, req.Version).Scan(&data)
	if err != nil || data == nil {
		writeError(w, http.StatusNotFound, "Kein Update für diesen Agent freigegeben.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// --- Oberfläche ---------------------------------------------------------------

func (s *Server) handleAgentUpdatesGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "agent-updates", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, version, os, arch, sha256, size, uploaded_at FROM openwacht.agent_updates
			ORDER BY string_to_array(version, '.')::int[] DESC, os, arch`)
		if err != nil {
			return 0, nil, err
		}
		pakete := []map[string]any{}
		for rows.Next() {
			var id, ver, goos, arch, sum string
			var size int64
			var at time.Time
			if err := rows.Scan(&id, &ver, &goos, &arch, &sum, &size, &at); err != nil {
				return 0, nil, err
			}
			pakete = append(pakete, map[string]any{"id": id, "version": ver, "plattform": goos + "/" + arch, "sha256": sum,
				"groesse": size, "hochgeladen": at})
		}
		if err := rows.Err(); err != nil {
			return 0, nil, err
		}
		key := ""
		schluessel := []map[string]any{}
		if k, err := s.updateKeys(ctx, tx); err != nil {
			return 0, nil, err
		} else if k != nil {
			key = k.Active()
			for _, x := range k.Keys {
				st := x.State
				if k.IsRevoked(x.ID) {
					st = update.StateRevoked
				}
				schluessel = append(schluessel, map[string]any{"kennung": x.ID, "zustand": st})
			}
		}
		widerrufen := []map[string]any{}
		wrows, err := tx.Query(ctx, `SELECT key_id, revoked_by, version, created_at FROM openwacht.update_key_revocations ORDER BY created_at`)
		if err != nil {
			return 0, nil, err
		}
		for wrows.Next() {
			var id, by, ver string
			var at time.Time
			if err := wrows.Scan(&id, &by, &ver, &at); err != nil {
				return 0, nil, err
			}
			widerrufen = append(widerrufen, map[string]any{"kennung": id, "durch": by, "version": ver, "am": at})
		}
		if err := wrows.Err(); err != nil {
			return 0, nil, err
		}
		arows, err := tx.Query(ctx, `SELECT a.id::text, a.tenant_id::text, a.hostname, coalesce(a.snapshot->>'agent', ''),
			coalesce(a.snapshot->>'plattform', ''), coalesce(a.snapshot->>'update_fehler', ''), a.last_seen,
			r.version, r.released_at
			FROM openwacht.agents a LEFT JOIN openwacht.agent_update_releases r ON r.agent_id = a.id
			WHERE a.revoked_at IS NULL ORDER BY a.hostname`)
		if err != nil {
			return 0, nil, err
		}
		agents := []map[string]any{}
		for arows.Next() {
			var id, tid, host, ver, plat, ferr string
			var seen, relAt *time.Time
			var rel *string
			if err := arows.Scan(&id, &tid, &host, &ver, &plat, &ferr, &seen, &rel, &relAt); err != nil {
				return 0, nil, err
			}
			agents = append(agents, map[string]any{"id": id, "mandant": tid, "hostname": host, "version": ver, "plattform": plat,
				"fehler": ferr, "zuletzt": seen, "freigegeben": rel, "freigegeben_am": relAt})
		}
		return http.StatusOK, map[string]any{"schluessel": key, "schluesselbund": schluessel, "widerrufen": widerrufen,
			"pakete": pakete, "agents": agents}, arows.Err()
	})
}

// handleAgentUpdateUpload: Rumpf = Binary, Kopf X-OpenWacht-Signatur = Signaturdatei (base64).
func (s *Server) handleAgentUpdateUpload(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) { writeDBError(w, "agent-update", err) }
	var keys *update.Keyring
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		var err error
		keys, err = s.updateKeys(r.Context(), tx)
		return err
	}); err != nil {
		fail(err)
		return
	}
	if !keys.Usable() {
		fail(&apiError{http.StatusConflict, "In diesem Build ist kein Update-Schlüssel eingetragen; Agent-Updates sind aus."})
		return
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	rawSig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-OpenWacht-Signatur"))
	if err != nil || len(rawSig) == 0 {
		fail(badRequest("Signaturdatei (.sig) fehlt."))
		return
	}
	signed, err := update.ParseSigned(rawSig)
	if err != nil {
		fail(badRequest(err.Error() + "."))
		return
	}
	if err := keys.VerifySigned(signed); err != nil {
		fail(badRequest("Signatur abgelehnt: " + err.Error() + "."))
		return
	}
	bin, err := io.ReadAll(http.MaxBytesReader(w, r.Body, update.MaxSize+1))
	if err != nil {
		fail(badRequest("Binary zu groß oder unvollständig."))
		return
	}
	if err := keys.Verify(signed, bin); err != nil {
		fail(badRequest(err.Error() + "."))
		return
	}
	s.handle(w, r, "agent-update", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.agent_updates (version, os, arch, sha256, size, signature, data, uploaded_by, key_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, openwacht.current_user_id(), $8) RETURNING id::text`,
			signed.Version, signed.OS, signed.Arch, signed.SHA256, signed.Size, string(rawSig), bin, signed.KeyID).Scan(&id); err != nil {
			return 0, nil, err
		}
		// Widerrufe aus dem Update gelten ab jetzt auch für die Zentrale:
		// Pakete dieser Schlüssel werden nicht mehr angeboten.
		for _, k := range signed.Revoked {
			tag, err := tx.Exec(ctx, `INSERT INTO openwacht.update_key_revocations (key_id, revoked_by, version, created_by)
				VALUES ($1, $2, $3, openwacht.current_user_id()) ON CONFLICT (key_id) DO NOTHING`, k, signed.KeyID, signed.Version)
			if err != nil {
				return 0, nil, err
			}
			if tag.RowsAffected() == 1 {
				if err := audit(ctx, tx, nil, "update_schluessel.widerrufen", map[string]any{"schluessel": k, "durch": signed.KeyID,
					"version": signed.Version}); err != nil {
					return 0, nil, err
				}
			}
		}
		return http.StatusCreated, map[string]any{"id": id, "version": signed.Version, "plattform": signed.OS + "/" + signed.Arch},
			audit(ctx, tx, nil, "agent_update.hochgeladen", map[string]any{"version": signed.Version, "plattform": signed.OS + "/" + signed.Arch,
				"sha256": signed.SHA256})
	})
}

func (s *Server) handleAgentUpdateDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "agent-update", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		var ver string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.agent_updates WHERE id = $1 RETURNING version`, id).Scan(&ver); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, errNotFound
			}
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"geloescht": true}, audit(ctx, tx, nil, "agent_update.geloescht", map[string]any{"version": ver})
	})
}

// handleAgentUpdateRelease: Admin gibt einem Agent eine Version frei (oder nimmt sie zurück).
func (s *Server) handleAgentUpdateRelease(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if r.Method == http.MethodPut {
		if !readJSON(w, r, &in) {
			return
		}
		if !update.Newer(in.Version, "0.0.0") {
			writeDBError(w, "agent-update", badRequest("Version: erwartet x.y.z."))
			return
		}
	}
	s.handle(w, r, "agent-update", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant *string
		var host string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, hostname FROM openwacht.agents WHERE id = $1 AND revoked_at IS NULL
			AND tenant_id IN (SELECT openwacht.admin_tenants())`, id).Scan(&tenant, &host); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, errNotFound
			}
			return 0, nil, err
		}
		if r.Method == http.MethodDelete {
			if _, err := tx.Exec(ctx, `DELETE FROM openwacht.agent_update_releases WHERE agent_id = $1`, id); err != nil {
				return 0, nil, err
			}
			return http.StatusOK, map[string]any{"freigegeben": nil},
				audit(ctx, tx, tenant, "agent_update.zurueckgenommen", map[string]any{"agent": host})
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.agent_updates WHERE version = $1)`, in.Version).Scan(&exists); err != nil {
			return 0, nil, err
		}
		if !exists {
			return 0, nil, badRequest("Für diese Version ist kein Paket hochgeladen.")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_update_releases (agent_id, tenant_id, version) VALUES ($1, $2, $3)
			ON CONFLICT (agent_id) DO UPDATE SET version = EXCLUDED.version`, id, *tenant, in.Version); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"freigegeben": in.Version},
			audit(ctx, tx, tenant, "agent_update.freigegeben", map[string]any{"agent": host, "version": in.Version})
	})
}
