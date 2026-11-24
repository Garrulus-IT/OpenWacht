// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// vCenter-Abfragen (Etappe 26): eine Abfragequelle mit version = 'vcenter',
// aufgebaut wie die Proxmox-Abfrage. Benutzer und Passwort (Rolle
// „Read-only“) sind verschlüsselt und an Quelle, Mandant, Adresse, Port und
// CA gebunden. Nur Admins pflegen sie; erreichbar ist nur, was die
// Netzfreigabe erlaubt. Die Zentrale meldet sich an und liest nur.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/vcenter"
)

const versionVCenter = "vcenter"

func vcAAD(id, tenant, host string, port int, caPEM string) []byte {
	sum := sha256.Sum256([]byte(caPEM))
	return []byte("openwacht vcenter v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port) + "|" + hex.EncodeToString(sum[:]))
}

type vcSecret struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) sealVC(id, tenant, host string, port int, caPEM string, sec vcSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, vcAAD(id, tenant, host, port, caPEM))
}

func (s *Server) openVC(id, tenant, host string, port int, caPEM string, enc []byte) (vcSecret, error) {
	var sec vcSecret
	pt, err := auth.Open(s.boxKey, enc, vcAAD(id, tenant, host, port, caPEM))
	if err != nil {
		return sec, errors.New("Zugangsdaten nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !vcenter.ValidUser(sec.User) || sec.Password == "" {
		return sec, errors.New("Zugangsdaten ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type vcIn struct {
	Adresse   string  `json:"adresse"`
	Port      int     `json:"port"`
	Benutzer  string  `json:"benutzer"`
	Passwort  *string `json:"passwort"` // leer/fehlt beim Ändern = bleibt
	CA        *string `json:"ca"`       // PEM; fehlt = bleibt, leer = System-CAs
	Intervall int     `json:"intervall_sekunden"`
	Aktiv     *bool   `json:"aktiv"`
}

type vcParsed struct {
	host, user, pass, ca string
	port, every          int
	enabled              bool
	caSet                bool // CA angegeben (auch leer); sonst bleibt die gespeicherte
	caInfo               *pve.CA
}

func (s *Server) parseVC(in vcIn) (vcParsed, error) {
	var p vcParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse des vCenter angeben.")
	}
	p.host = *host
	if a, err := parseLiteral(p.host); err == nil && !s.guard.Allowed(a) {
		return p, badRequest(fmt.Sprintf("Die Adresse %s ist nicht freigegeben. Freigegebene Netze: %s.", a, s.networksText()))
	}
	p.port = in.Port
	if p.port == 0 {
		p.port = 443
	}
	if p.port < 1 || p.port > 65535 {
		return p, badRequest("Port: 1 bis 65535.")
	}
	p.every = in.Intervall
	if p.every == 0 {
		p.every = 60
	}
	if p.every < 30 || p.every > 3600 {
		return p, badRequest("Intervall: 30 Sekunden bis 1 Stunde.")
	}
	p.enabled = in.Aktiv == nil || *in.Aktiv
	p.user = strings.TrimSpace(in.Benutzer)
	if !vcenter.ValidUser(p.user) {
		return p, badRequest("Benutzer: z. B. svc-openwacht@vsphere.local (Rolle „Read-only“).")
	}
	if in.Passwort != nil && *in.Passwort != "" {
		if len(*in.Passwort) > 256 {
			return p, badRequest("Passwort zu lang.")
		}
		if strings.ContainsFunc(*in.Passwort, unicode.IsControl) {
			return p, badRequest("Passwort: keine Steuerzeichen (Zeilenumbrüche, Tabulatoren).")
		}
		p.pass = *in.Passwort
	}
	p.caSet = in.CA != nil
	if in.CA != nil && strings.TrimSpace(*in.CA) != "" {
		ca, err := pve.ParseCA(*in.CA)
		if err != nil {
			return p, badRequest(err.Error() + ".")
		}
		p.ca = strings.TrimSpace(*in.CA) + "\n"
		p.caInfo = ca
	}
	return p, nil
}

// handleVCSet legt die vCenter-Abfrage eines Geräts an oder ändert sie (nur
// Admins). Ohne neues Passwort bleibt das alte, aber nur bei gleicher Adresse,
// gleichem Port, gleicher CA und gleichem Benutzer.
func (s *Server) handleVCSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in vcIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vcenter speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseVC(in)
		if err != nil {
			return 0, nil, err
		}
		var tenant, deviceName string
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name, tenant_id IN (SELECT openwacht.admin_tenants())
			FROM openwacht.devices WHERE id = $1`, deviceID).Scan(&tenant, &deviceName, &admin); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		if !admin { // die Datenbank prüft das ebenfalls (RLS); hier nur für eine klare Antwort
			return 0, nil, &apiError{http.StatusForbidden, "vCenter einrichten und ändern dürfen nur Admins."}
		}
		var id, oldHost, oldVersion string
		var oldPort int
		var oldCA *string
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version, ca_pem FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion, &oldCA)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "passwort_neu": p.pass != "", "benutzer": p.user, "ca": nil}
		if p.caInfo != nil {
			details["ca"] = p.caInfo.Fingerprint
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if p.pass == "" {
				return 0, nil, badRequest("Bitte das Passwort angeben.")
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealVC(id, tenant, p.host, p.port, p.ca, vcSecret{User: p.user, Password: p.pass})
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched, ca_pem)
				VALUES ($1, $2, 'vcenter', $3, $4, $5, $6, $7, '{}', $8)`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled, nullable(p.ca)); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "vcenter.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion != versionVCenter {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) + "). Bitte diese zuerst entfernen."}
		}
		oldCAText := ""
		if oldCA != nil {
			oldCAText = *oldCA
		}
		if !p.caSet {
			p.ca = oldCAText
		}
		if p.pass == "" {
			// Ohne neues Passwort nur bei gleicher Adresse, gleichem Port, gleicher CA und gleichem Benutzer.
			var oldEnc []byte
			if err := tx.QueryRow(ctx, `SELECT secret_enc FROM openwacht.snmp_secret_for_probe($1, $2, $3)`, deviceID, oldHost, oldPort).
				Scan(&oldEnc); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, err
			}
			old, err := s.openVC(id, tenant, oldHost, oldPort, oldCAText, oldEnc)
			if p.host != oldHost || p.port != oldPort || p.ca != oldCAText || err != nil || old.User != p.user {
				return 0, nil, badRequest("Bei neuer Adresse, neuem Port, neuer CA oder neuem Benutzer bitte das Passwort neu eingeben.")
			}
		}
		var tag interface{ RowsAffected() int64 }
		if p.pass != "" {
			enc, serr := s.sealVC(id, tenant, p.host, p.port, p.ca, vcSecret{User: p.user, Password: p.pass})
			if serr != nil {
				return 0, nil, serr
			}
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4, ca_pem = $5,
				interval_s = $6, enabled = $7 WHERE id = $1 AND version = 'vcenter'`,
				id, p.host, p.port, enc, nullable(p.ca), p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'vcenter'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "vCenter einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "vcenter.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// handleVCProbe: „Verbindung prüfen“ meldet sich an und zählt Hosts, VMs und
// Datastores. Ohne neues Passwort nimmt die Zentrale das gespeicherte, aber
// nur für dieselbe Adresse, denselben Port, dieselbe CA und denselben
// Benutzer. Nur Admins; höchstens alle 3 Sekunden je Person.
func (s *Server) handleVCProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in vcIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg vcenter.Config
	ctx := r.Context()
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseVC(in)
		if err != nil {
			return err
		}
		var tenant string
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT d.tenant_id::text, d.tenant_id IN (SELECT openwacht.admin_tenants())
			FROM openwacht.devices d WHERE d.id = $1`, deviceID).Scan(&tenant, &admin); err != nil {
			return err
		}
		if !admin {
			return &apiError{http.StatusForbidden, "Verbindung prüfen dürfen nur Admins."}
		}
		if !p.caSet {
			var stored *string
			err := tx.QueryRow(ctx, `SELECT ca_pem FROM openwacht.snmp_sources WHERE device_id = $1 AND version = 'vcenter'`,
				deviceID).Scan(&stored)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if stored != nil {
				p.ca = *stored
			}
		}
		cfg = vcenter.Config{Host: p.host, Port: uint16(p.port), User: p.user, Password: p.pass, CAPEM: p.ca}
		if cfg.Password == "" {
			var id string
			var enc []byte
			err := tx.QueryRow(ctx, `SELECT id::text, secret_enc FROM openwacht.snmp_secret_for_probe($1, $2, $3)`,
				deviceID, p.host, p.port).Scan(&id, &enc)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && enc == nil {
				return badRequest("Bitte das Passwort angeben (gespeichert ist keines für diese Adresse und diesen Port).")
			}
			if err != nil {
				return err
			}
			sec, err := s.openVC(id, tenant, p.host, p.port, p.ca, enc)
			if err != nil || sec.User != p.user {
				return badRequest("Bitte das Passwort angeben (das gespeicherte gilt nur für die bisherige Adresse, den Port, die CA und den Benutzer).")
			}
			cfg.Password = sec.Password
		}
		probeTenant = tenant
		return audit(ctx, tx, &tenant, "vcenter.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "benutzer": p.user, "passwort_neu": p.pass != ""})
	})
	if err != nil {
		writeDBError(w, "vcenter prüfen", err)
		return
	}
	info, err := s.vcFor(probeTenant).Probe(ctx, cfg)
	if err != nil {
		var na *checks.NotAllowedError
		if errors.As(err, &na) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Die Adresse %s ist nicht freigegeben. Freigegebene Netze: %s.",
				na.Addr, s.networksText()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "vcenter": info})
}

func (s *Server) vcFor(tenant string) *vcenter.Client {
	return &vcenter.Client{Guard: s.guardFor(tenant), Now: s.now}
}

// pollVC fragt ein vCenter ab (aus pollSNMP).
func (s *Server) pollVC(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, bool, error) {
	ca := ""
	if c.caPEM != nil {
		ca = *c.caPEM
	}
	sec, err := s.openVC(c.id, c.tenant, c.host, c.port, ca, c.secret)
	if err != nil {
		return nil, false, err
	}
	snap, err := s.vcFor(c.tenant).Poll(ctx, vcenter.Config{Host: c.host, Port: uint16(c.port), User: sec.User, Password: sec.Password, CAPEM: ca})
	return snap, false, err
}
