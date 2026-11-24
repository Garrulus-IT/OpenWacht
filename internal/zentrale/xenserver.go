// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// XenServer-Abfragen (0.42.0): eine Abfragequelle mit version = 'xapi',
// aufgebaut wie NetApp (Fingerabdruck des Zertifikats in den Zugangsdaten).
// Gilt auch für XCP-ng. Benutzer, Passwort und Fingerabdruck sind
// verschlüsselt und an Quelle, Mandant, Adresse und Port gebunden; ein neuer
// Fingerabdruck gilt nur mit dem Passwort zusammen. Nur Admins pflegen sie;
// erreichbar ist nur, was die Netzfreigabe erlaubt (auch die übrigen Hosts
// des Pools für Messwerte). Die Zentrale liest nur (feste Liste in xapi),
// lehnt root schon beim Speichern ab und nach der Anmeldung jede Sitzung mit
// mehr Rechten als „read-only“.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/xapi"
)

const versionXAPI = "xapi"

var errNeedXAPIPin = badRequest("Bitte zuerst „Verbindung prüfen“ und den Fingerabdruck des Zertifikats übernehmen.")

func xapiAAD(id, tenant, host string, port int) []byte {
	return []byte("openwacht xapi v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port))
}

// xapiSecret: alles, was die Anmeldung braucht. Pin gehört dazu, damit ein
// geänderter Fingerabdruck nur mit dem Passwort zusammen gilt.
type xapiSecret struct {
	User     string `json:"benutzer"`
	Password string `json:"passwort"`
	Pin      string `json:"pin"`
}

func (s *Server) sealXAPI(id, tenant, host string, port int, sec xapiSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, xapiAAD(id, tenant, host, port))
}

func (s *Server) openXAPI(id, tenant, host string, port int, enc []byte) (xapiSecret, error) {
	var sec xapiSecret
	pt, err := auth.Open(s.boxKey, enc, xapiAAD(id, tenant, host, port))
	if err != nil {
		return sec, errors.New("Zugangsdaten nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !xapi.ValidUser(sec.User) || !xapi.ValidPassword(sec.Password) || !xapi.ValidPin(sec.Pin) {
		return xapiSecret{}, errors.New("Zugangsdaten ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type xenIn struct {
	Adresse  string  `json:"adresse"`
	Port     int     `json:"port"`
	Benutzer string  `json:"benutzer"`
	Passwort *string `json:"passwort"` // leer/fehlt beim Ändern = bleibt
	// Fingerabdruck des Zertifikats (SHA-256, mit oder ohne Doppelpunkte); leer = bleibt
	Fingerabdruck string `json:"fingerabdruck"`
	Intervall     int    `json:"intervall_sekunden"`
	Aktiv         *bool  `json:"aktiv"`
}

type xenParsed struct {
	host, user, pass, pin string
	port, every           int
	enabled               bool
}

func (s *Server) parseXen(in xenIn) (xenParsed, error) {
	var p xenParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse des Pool-Masters angeben.")
	}
	p.host = *host
	if err := s.checkZentraleAddr(p.host); err != nil {
		return p, err
	}
	p.port = in.Port
	if p.port == 0 {
		p.port = 443
	}
	if p.port < 1 || p.port > 65535 {
		return p, badRequest("Port: 1 bis 65535 (Standard 443).")
	}
	p.every = in.Intervall
	if p.every == 0 {
		p.every = 120
	}
	if p.every < 60 || p.every > 3600 {
		return p, badRequest("Intervall: 1 Minute bis 1 Stunde.")
	}
	p.enabled = in.Aktiv == nil || *in.Aktiv
	p.user = strings.TrimSpace(in.Benutzer)
	if xapi.IsRoot(p.user) {
		return p, badRequest("Benutzer: root wird abgelehnt (alle Rechte). Bitte ein AD-Konto mit der Rolle „read-only“ nehmen.")
	}
	if !xapi.ValidUser(p.user) {
		return p, badRequest("Benutzer: AD-Konto wie name@domäne oder DOMÄNE\\name (Buchstaben, Ziffern, . _ @ - und \\), höchstens 128 Zeichen.")
	}
	if in.Passwort != nil && *in.Passwort != "" {
		if !xapi.ValidPassword(*in.Passwort) {
			return p, badRequest("Passwort: 1 bis 256 Zeichen, ohne Steuerzeichen.")
		}
		p.pass = *in.Passwort
	}
	if strings.TrimSpace(in.Fingerabdruck) != "" {
		pin, ok := xapi.NormalizePin(in.Fingerabdruck)
		if !ok {
			return p, badRequest("Fingerabdruck: SHA-256 als 64 Hexziffern (mit oder ohne Doppelpunkte).")
		}
		p.pin = pin
	}
	return p, nil
}

// storedXAPI: gespeicherte Zugangsdaten, nur für dieselbe Adresse und
// denselben Port und nur für Admins (snmp_secret_for_admin).
func (s *Server) storedXAPI(ctx context.Context, tx pgx.Tx, deviceID, tenant, host string, port int) (*xapiSecret, bool, error) {
	var id string
	var enc []byte
	err := tx.QueryRow(ctx, `SELECT id::text, secret_enc FROM openwacht.snmp_secret_for_admin($1, $2, $3)`, deviceID, host, port).
		Scan(&id, &enc)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && enc == nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	sec, err := s.openXAPI(id, tenant, host, port, enc)
	if err != nil {
		return nil, true, nil
	}
	return &sec, true, nil
}

// handleXenSet legt die XenServer-Abfrage eines Geräts an oder ändert sie
// (nur Admins). Ohne neues Passwort bleibt das alte, aber nur bei gleicher
// Adresse, gleichem Port, gleichem Benutzer und gleichem Fingerabdruck.
func (s *Server) handleXenSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in xenIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "xenserver speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseXen(in)
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
			return 0, nil, &apiError{http.StatusForbidden, "XenServer einrichten und ändern dürfen nur Admins."}
		}
		var id, oldHost, oldVersion string
		var oldPort int
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "benutzer": p.user, "passwort_neu": p.pass != ""}
		if p.pin != "" {
			details["fingerabdruck"] = xapi.FormatPin(p.pin)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if p.pass == "" {
				return 0, nil, badRequest("Bitte das Passwort angeben.")
			}
			if p.pin == "" {
				return 0, nil, errNeedXAPIPin
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealXAPI(id, tenant, p.host, p.port, xapiSecret{User: p.user, Password: p.pass, Pin: p.pin})
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched)
				VALUES ($1, $2, 'xapi', $3, $4, $5, $6, $7, '{}')`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "xenserver.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion != versionXAPI {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) +
				"). Bitte diese zuerst entfernen."}
		}
		var stored *xapiSecret
		if p.host == oldHost && p.port == oldPort {
			if stored, _, err = s.storedXAPI(ctx, tx, deviceID, tenant, p.host, p.port); err != nil {
				return 0, nil, err
			}
		}
		if p.pin == "" {
			if stored == nil {
				return 0, nil, errNeedXAPIPin
			}
			p.pin = stored.Pin
		}
		var enc []byte
		switch {
		case p.pass != "":
			if enc, err = s.sealXAPI(id, tenant, p.host, p.port, xapiSecret{User: p.user, Password: p.pass, Pin: p.pin}); err != nil {
				return 0, nil, err
			}
		case stored == nil || stored.User != p.user || stored.Pin != p.pin:
			return 0, nil, badRequest("Bei neuer Adresse, neuem Port, neuem Benutzer oder neuem Fingerabdruck bitte das Passwort neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if enc != nil {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4,
				interval_s = $5, enabled = $6 WHERE id = $1 AND version = 'xapi'`,
				id, p.host, p.port, enc, p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'xapi'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "XenServer einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "xenserver.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// handleXenProbe: „Verbindung prüfen“. Ohne Fingerabdruck holt sie nur den
// Fingerabdruck des Zertifikats (ohne Anmeldung, ohne Anfrage), damit der
// Admin ihn bestätigt. Ohne neues Passwort nimmt die Zentrale das
// gespeicherte, aber nur für dieselbe Adresse, denselben Port, denselben
// Benutzer und denselben Fingerabdruck. Nur Admins; höchstens alle 3 Sekunden
// je Person.
func (s *Server) handleXenProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in xenIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg xapi.Config
	ctx := r.Context()
	fingerprintOnly := false
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseXen(in)
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
		stored, _, err := s.storedXAPI(ctx, tx, deviceID, tenant, p.host, p.port)
		if err != nil {
			return err
		}
		cfg = xapi.Config{Host: p.host, Port: uint16(p.port), User: p.user, Password: p.pass, Pin: p.pin}
		if cfg.Pin == "" {
			if stored != nil {
				cfg.Pin = stored.Pin
			} else {
				fingerprintOnly = true
			}
		}
		if !fingerprintOnly && cfg.Password == "" {
			if stored == nil || stored.User != p.user || stored.Pin != cfg.Pin {
				return badRequest("Bitte das Passwort angeben (das gespeicherte gilt nur für die bisherige Adresse, den Port, den Benutzer und den Fingerabdruck).")
			}
			cfg.Password = stored.Password
		}
		probeTenant = tenant
		return audit(ctx, tx, &tenant, "xenserver.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "benutzer": p.user, "passwort_neu": p.pass != "", "nur_fingerabdruck": fingerprintOnly})
	})
	if err != nil {
		writeDBError(w, "xenserver prüfen", err)
		return
	}
	notAllowed := func(err error) bool {
		var na *checks.NotAllowedError
		if errors.As(err, &na) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Die Adresse %s ist nicht freigegeben. Freigegebene Netze: %s.",
				na.Addr, s.networksText()))
			return true
		}
		return false
	}
	client := s.xapiFor(probeTenant)
	if fingerprintOnly {
		fp, err := client.Fingerprint(ctx, cfg.Host, cfg.Port)
		if err != nil {
			if !notAllowed(err) {
				writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fingerabdruck_neu": xapi.FormatPin(fp),
			"fehler": "Bitte den Fingerabdruck des Zertifikats prüfen und übernehmen."})
		return
	}
	info, err := client.Probe(ctx, cfg)
	if err != nil {
		if notAllowed(err) {
			return
		}
		out := map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)}
		var pe *xapi.PinError
		if errors.As(err, &pe) && pe.Got != "" {
			out["fingerabdruck_neu"] = xapi.FormatPin(pe.Got)
		}
		var we *xapi.WritableError
		if errors.As(err, &we) || errors.Is(err, xapi.ErrSuperuser) || errors.Is(err, xapi.ErrRoot) {
			out["schreibrecht"] = true
		}
		var ne *xapi.NotMasterError
		if errors.As(err, &ne) && ne.Master != "" {
			out["neuer_master"] = ne.Master
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	info.Fingerprint = xapi.FormatPin(info.Fingerprint)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "xenserver": info})
}

func (s *Server) xapiFor(tenant string) *xapi.Client {
	return &xapi.Client{Guard: s.guardFor(tenant), Now: s.now}
}

// pollXAPI fragt einen XenServer-Pool ab (aus pollSNMP).
func (s *Server) pollXAPI(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, bool, error) {
	sec, err := s.openXAPI(c.id, c.tenant, c.host, c.port, c.secret)
	if err != nil {
		return nil, false, err
	}
	snap, err := s.xapiFor(c.tenant).Poll(ctx, xapi.Config{Host: c.host, Port: uint16(c.port), User: sec.User, Password: sec.Password, Pin: sec.Pin})
	if err != nil {
		return nil, false, err
	}
	var prev snmp.Snapshot
	rebooted := c.snapshot != nil && json.Unmarshal(c.snapshot, &prev) == nil && xapi.Rebooted(prev.XAPI, snap.XAPI)
	return snap, rebooted, nil
}
