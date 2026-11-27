// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6: Gerät in einen anderen Mandanten verschieben (Migration 0058).
// Die Zugangsdaten der Abfragen hängen über die Zusatzdaten (AAD) am
// Mandanten; sie werden hier mit dem neuen Mandanten neu verschlüsselt,
// in derselben Transaktion, in der device_move die Zeilen umsetzt.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/traps"
)

type moveSource struct {
	id, tenant, version, host, ca string
	port                          int
	secret, trap                  []byte
}

// resealSource verschlüsselt die Zugangsdaten einer Abfrage für den neuen
// Mandanten. Ist ein Kasten nicht lesbar, bricht das Verschieben ab.
func (s *Server) resealSource(src moveSource, target string) (secret, trap []byte, err error) {
	oldF := []string{src.id, src.tenant, src.version, src.host, strconv.Itoa(src.port), src.ca}
	newF := []string{src.id, target, src.version, src.host, strconv.Itoa(src.port), src.ca}
	if src.secret != nil {
		pt, err := auth.Open(s.boxKey, src.secret, snmpSourceAAD(oldF))
		if err != nil {
			return nil, nil, fmt.Errorf("Zugangsdaten der Abfrage %s nicht lesbar: %w", src.host, err)
		}
		secret, err = auth.Seal(s.boxKey, pt, snmpSourceAAD(newF))
		clear(pt)
		if err != nil {
			return nil, nil, err
		}
	}
	if src.trap != nil {
		sec, err := traps.Open(s.trapKey, src.trap, src.id, src.tenant, src.host, src.port, src.version)
		if err != nil {
			return nil, nil, fmt.Errorf("Trap-Zugangsdaten der Abfrage %s nicht lesbar: %w", src.host, err)
		}
		if trap, err = traps.Seal(s.trapKey, sec, src.id, target, src.host, src.port, src.version); err != nil {
			return nil, nil, err
		}
	}
	return secret, trap, nil
}

func (s *Server) handleDeviceMove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		MandantID string `json:"mandant_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !uuidPattern.MatchString(in.MandantID) {
		writeError(w, http.StatusBadRequest, "Ziel-Mandant fehlt oder ist ungültig.")
		return
	}
	s.handle(w, r, "gerät verschieben", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, version, host, port, coalesce(ca_pem, ''),
			secret_enc, trap_secret_enc FROM openwacht.device_move_sources($1, $2)`, id, in.MandantID)
		if err != nil {
			return 0, nil, moveError(err)
		}
		var list []moveSource
		for rows.Next() {
			var m moveSource
			if err := rows.Scan(&m.id, &m.tenant, &m.version, &m.host, &m.port, &m.ca, &m.secret, &m.trap); err != nil {
				rows.Close()
				return 0, nil, moveError(err)
			}
			list = append(list, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, nil, moveError(err)
		}
		ids := make([]string, len(list))
		secrets := make([][]byte, len(list))
		trapSecrets := make([][]byte, len(list))
		for i, m := range list {
			ids[i] = m.id
			if secrets[i], trapSecrets[i], err = s.resealSource(m, in.MandantID); err != nil {
				return 0, nil, &apiError{http.StatusConflict, err.Error()}
			}
		}
		var res map[string]any
		err = tx.QueryRow(ctx, `SELECT openwacht.device_move($1, $2, $3::uuid[], $4::bytea[], $5::bytea[])`,
			id, in.MandantID, ids, secrets, trapSecrets).Scan(&res)
		if err != nil {
			return 0, nil, moveError(err)
		}
		return http.StatusOK, res, nil
	})
}

// moveError: nicht gefunden (P0002) und geänderte Abfragen (40001) lesbar.
func moveError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "P0002":
			return errNotFound
		case "40001":
			return &apiError{http.StatusConflict, pe.Message}
		}
	}
	return err
}
