// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// SNMP-Zugangsprofile (Etappe 27): Community oder v3-Zugang je Mandant, an
// beliebig vielen Geräten wiederverwendbar (Migration 0034).
//
// Das Profil liegt verschlüsselt mit eigenen Zusatzdaten (Profil, Mandant,
// Version). Eine Quelle mit Profil bekommt eine eigene Kopie, verschlüsselt
// mit ihren Zusatzdaten (Quelle, Mandant, Adresse, Port); Abfrage, Sammler
// und Trap-Dienst bleiben dadurch unverändert. Ändern sich die
// Zugangsdaten eines Profils, verschlüsselt die Zentrale in derselben
// Transaktion alle Quellen mit diesem Profil neu.
//
// Profile pflegen und sehen nur Admins (RLS). Zuordnen darf ein Admin des
// Gerätemandanten, der zugleich Admin des Profilmandanten ist; das Profil
// muss im selben Mandanten oder darüber liegen (Datenbank prüft beides).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

func snmpProfileAAD(id, tenant, version string) []byte {
	return []byte("openwacht snmp-profile v1|" + id + "|" + tenant + "|" + version)
}

type snmpProfileIn struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Community *string   `json:"community"` // leer/fehlt beim Ändern = bleibt
	V3        *snmpV3In `json:"v3"`
}

type snmpProfileOut struct {
	ID        string    `json:"id"`
	MandantID string    `json:"mandant_id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	V3Auth    *string   `json:"v3_auth"`
	V3Priv    *string   `json:"v3_priv"`
	Geraete   int       `json:"geraete"` // Quellen mit diesem Profil (sichtbare)
	Erstellt  time.Time `json:"erstellt"`
	Geaendert time.Time `json:"geaendert"`
}

type snmpProfileParsed struct {
	name, version string
	sec           snmpSecret
	hasSecret     bool
}

func parseSNMPProfile(in snmpProfileIn) (snmpProfileParsed, error) {
	var p snmpProfileParsed
	p.name = strings.TrimSpace(in.Name)
	if p.name == "" || utf8.RuneCountInString(p.name) > 60 || strings.ContainsFunc(p.name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return p, badRequest("Name: 1 bis 60 Zeichen, keine Steuerzeichen.")
	}
	var err error
	if p.version, err = parseSNMPVersion(in.Version); err != nil {
		return p, err
	}
	community, v3, err := parseSNMPCreds(p.version, in.Community, in.V3)
	if err != nil {
		return p, err
	}
	if v3 != nil {
		p.sec, p.hasSecret = snmpSecret{V3: v3}, true
	} else if community != "" {
		p.sec, p.hasSecret = snmpSecret{Community: community}, true
	}
	return p, nil
}

func (p snmpProfileParsed) v3Columns() (*string, *string) {
	if p.sec.V3 == nil {
		return nil, nil
	}
	return &p.sec.V3.Auth, &p.sec.V3.Priv
}

func (s *Server) sealProfile(id, tenant, version string, sec snmpSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, snmpProfileAAD(id, tenant, version))
}

func (s *Server) openProfile(id, tenant, version string, enc []byte) (snmpSecret, error) {
	var sec snmpSecret
	pt, err := auth.Open(s.boxKey, enc, snmpProfileAAD(id, tenant, version))
	if err != nil {
		return sec, errors.New("Zugangsdaten des Profils nicht entschlüsselbar, bitte im Profil neu eingeben")
	}
	if json.Unmarshal(pt, &sec) != nil || sec.Check(version) != nil {
		return snmpSecret{}, errors.New("Zugangsdaten des Profils ungültig, bitte im Profil neu eingeben")
	}
	return sec, nil
}

// profileForDevice liest die Zugangsdaten eines Profils für ein Gerät (nur
// Admins beider Mandanten, Profil im selben Mandanten oder darüber).
func (s *Server) profileForDevice(ctx context.Context, tx pgx.Tx, profile, device string) (string, snmpSecret, error) {
	var id, tenant, version string
	var a, p *string
	var enc []byte
	err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, version, v3_auth, v3_priv, secret_enc
		FROM openwacht.snmp_profile_secret($1, $2)`, profile, device).Scan(&id, &tenant, &version, &a, &p, &enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", snmpSecret{}, badRequest("Profil nicht verfügbar: Es muss zum Mandanten des Geräts oder einem darüber gehören, " +
			"und zuordnen dürfen es nur dessen Admins.")
	}
	if err != nil {
		return "", snmpSecret{}, err
	}
	sec, err := s.openProfile(id, tenant, version, enc)
	if err != nil {
		return "", snmpSecret{}, badRequest(err.Error() + ".")
	}
	return version, sec, nil
}

func profileError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "snmp_profiles_tenant_name" {
		return &apiError{http.StatusConflict, "In diesem Mandanten gibt es schon ein Profil mit diesem Namen."}
	}
	return err
}

func (s *Server) handleSNMPProfileList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "snmp-profile", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT p.id::text, p.tenant_id::text, p.name, p.version, p.v3_auth, p.v3_priv,
				(SELECT count(*) FROM openwacht.snmp_sources s WHERE s.profile_id = p.id)::int, p.created_at, p.updated_at
			FROM openwacht.snmp_profiles p ORDER BY lower(p.name), p.id`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (snmpProfileOut, error) {
			var o snmpProfileOut
			err := row.Scan(&o.ID, &o.MandantID, &o.Name, &o.Version, &o.V3Auth, &o.V3Priv, &o.Geraete, &o.Erstellt, &o.Geaendert)
			return o, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []snmpProfileOut{}
		}
		return http.StatusOK, map[string]any{"profile": list}, nil
	})
}

func (s *Server) handleSNMPProfileCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in snmpProfileIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "snmp-profil anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := parseSNMPProfile(in)
		if err != nil {
			return 0, nil, err
		}
		if !p.hasSecret {
			if p.version == snmp.V3 {
				return 0, nil, badRequest("Bitte Benutzer, Verfahren und beide Passwörter für SNMPv3 angeben.")
			}
			return 0, nil, badRequest("Bitte die Community angeben.")
		}
		id, err := newUUID()
		if err != nil {
			return 0, nil, err
		}
		enc, err := s.sealProfile(id, tid, p.version, p.sec)
		if err != nil {
			return 0, nil, err
		}
		a, pr := p.v3Columns()
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_profiles (id, tenant_id, name, version, v3_auth, v3_priv, secret_enc)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tid, p.name, p.version, a, pr, enc); err != nil {
			return 0, nil, profileError(err) // kein Admin: 42501 → 403
		}
		details := map[string]any{"id": id, "name": p.name, "version": p.version}
		if a != nil {
			details["v3_verfahren"] = *a + "/" + *pr // nie Benutzer oder Passwörter
		}
		if err := audit(ctx, tx, &tid, "snmp_profil.angelegt", details); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

// handleSNMPProfileUpdate ändert Name oder Zugangsdaten. Neue Zugangsdaten
// gehen in derselben Transaktion an alle Quellen mit diesem Profil; erreicht
// die Zentrale nicht alle, wird nichts geändert.
func (s *Server) handleSNMPProfileUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in snmpProfileIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "snmp-profil ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := parseSNMPProfile(in)
		if err != nil {
			return 0, nil, err
		}
		var tenant, oldVersion string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, version FROM openwacht.snmp_profiles WHERE id = $1 FOR UPDATE`, id).
			Scan(&tenant, &oldVersion); err != nil {
			return 0, nil, err // nicht sichtbar (kein Admin): 404
		}
		if p.version != oldVersion && !p.hasSecret {
			if p.version == snmp.V3 {
				return 0, nil, badRequest("Beim Wechsel der Version bitte Benutzer, Verfahren und beide Passwörter angeben.")
			}
			return 0, nil, badRequest("Beim Wechsel der Version bitte die Community neu eingeben.")
		}
		details := map[string]any{"id": id, "name": p.name, "version": p.version, "zugang_neu": p.hasSecret}
		if !p.hasSecret {
			tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_profiles SET name = $2 WHERE id = $1`, id, p.name)
			if err != nil {
				return 0, nil, profileError(err)
			}
			if tag.RowsAffected() == 0 {
				return 0, nil, errNotFound
			}
			if err := audit(ctx, tx, &tenant, "snmp_profil.geaendert", details); err != nil {
				return 0, nil, err
			}
			return http.StatusOK, map[string]any{"id": id, "neu_verschluesselt": 0}, nil
		}
		enc, err := s.sealProfile(id, tenant, p.version, p.sec)
		if err != nil {
			return 0, nil, err
		}
		a, pr := p.v3Columns()
		if a != nil {
			details["v3_verfahren"] = *a + "/" + *pr
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_profiles SET name = $2, version = $3, v3_auth = $4, v3_priv = $5, secret_enc = $6
			WHERE id = $1`, id, p.name, p.version, a, pr, enc)
		if err != nil {
			return 0, nil, profileError(err)
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		n, err := s.resealProfileSources(ctx, tx, id, p.version, p.sec)
		if err != nil {
			return 0, nil, err
		}
		details["neu_verschluesselt"] = n
		if err := audit(ctx, tx, &tenant, "snmp_profil.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id, "neu_verschluesselt": n}, nil
	})
}

// resealProfileSources gibt allen Quellen eines Profils die neuen
// Zugangsdaten, je Quelle mit ihren eigenen Zusatzdaten (auch für Traps).
func (s *Server) resealProfileSources(ctx context.Context, tx pgx.Tx, profile, version string, sec snmpSecret) (int, error) {
	var total *int
	if err := tx.QueryRow(ctx, `SELECT openwacht.snmp_profile_use_count($1)`, profile).Scan(&total); err != nil {
		return 0, err
	}
	if total == nil {
		return 0, errNotFound
	}
	rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, host, port, traps FROM openwacht.snmp_sources
		WHERE profile_id = $1 ORDER BY id FOR UPDATE`, profile)
	if err != nil {
		return 0, err
	}
	type src struct {
		id, tenant, host string
		port             int
		traps            bool
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (src, error) {
		var x src
		err := row.Scan(&x.id, &x.tenant, &x.host, &x.port, &x.traps)
		return x, err
	})
	if err != nil {
		return 0, err
	}
	if len(list) != *total {
		return 0, &apiError{http.StatusConflict, "Das Profil wird auch von Geräten genutzt, die Sie nicht ändern dürfen; nichts geändert."}
	}
	var a, p *string
	if sec.V3 != nil {
		a, p = &sec.V3.Auth, &sec.V3.Priv
	}
	n := 0
	for _, x := range list {
		enc, err := s.sealSNMP(x.id, x.tenant, x.host, x.port, sec)
		if err != nil {
			return 0, err
		}
		var trapEnc []byte
		if x.traps {
			if trapEnc, err = s.sealTrap(x.id, x.tenant, x.host, x.port, version, sec); err != nil {
				return 0, err
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = $2, v3_auth = $3, v3_priv = $4, secret_enc = $5,
			trap_secret_enc = $6 WHERE id = $1 AND profile_id = $7`, x.id, version, a, p, enc, trapEnc, profile)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() != 1 {
			return 0, &apiError{http.StatusConflict, "Das Profil wird auch von Geräten genutzt, die Sie nicht ändern dürfen; nichts geändert."}
		}
		n++
	}
	return n, nil
}

// handleSNMPProfileDelete löscht ein Profil. Die Geräte behalten ihre Kopie
// der Zugangsdaten und fragen weiter ab, nur ohne Bezug zum Profil.
func (s *Server) handleSNMPProfileDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "snmp-profil löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		var used *int
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name, openwacht.snmp_profile_use_count(id)
			FROM openwacht.snmp_profiles WHERE id = $1`, id).Scan(&tenant, &name, &used); err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.snmp_profiles WHERE id = $1`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		n := 0
		if used != nil {
			n = *used
		}
		if err := audit(ctx, tx, &tenant, "snmp_profil.geloescht", map[string]any{"id": id, "name": name, "geraete": n}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}
