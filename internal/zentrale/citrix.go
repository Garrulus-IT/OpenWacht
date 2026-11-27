// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Citrix-Abfragen (1.0.6): eine Abfragequelle mit version = 'citrix' für den
// Monitor Service (OData v4) eines Delivery Controllers, aufgebaut wie
// XenServer (Fingerabdruck des Zertifikats in den Zugangsdaten). Benutzer,
// Passwort und Fingerabdruck sind verschlüsselt und an Quelle, Mandant,
// Adresse und Port gebunden; ein neuer Fingerabdruck gilt nur mit dem
// Passwort zusammen. Nur Admins pflegen sie; erreichbar ist nur, was die
// Netzfreigabe erlaubt. Die Zentrale liest nur (GET auf zwei Entitäten), die
// Anmeldung läuft per NTLM.

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
	"github.com/garrulus-it/openwacht/internal/citrix"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const versionCitrix = "citrix"

var errNeedCitrixPin = badRequest("Bitte zuerst „Verbindung prüfen“ und den Fingerabdruck des Zertifikats übernehmen.")

func citrixAAD(id, tenant, host string, port int) []byte {
	return []byte("openwacht citrix v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port))
}

// citrixSecret: alles, was die Anmeldung braucht. Pin gehört dazu, damit ein
// geänderter Fingerabdruck nur mit dem Passwort zusammen gilt.
type citrixSecret struct {
	User     string `json:"benutzer"`
	Password string `json:"passwort"`
	Pin      string `json:"pin"`
}

func (s *Server) sealCitrix(id, tenant, host string, port int, sec citrixSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, citrixAAD(id, tenant, host, port))
}

func (s *Server) openCitrix(id, tenant, host string, port int, enc []byte) (citrixSecret, error) {
	var sec citrixSecret
	pt, err := auth.Open(s.boxKey, enc, citrixAAD(id, tenant, host, port))
	if err != nil {
		return sec, errors.New("Zugangsdaten nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !citrix.ValidUser(sec.User) || !citrix.ValidPassword(sec.Password) || !citrix.ValidPin(sec.Pin) {
		return citrixSecret{}, errors.New("Zugangsdaten ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type citrixIn struct {
	Adresse  string  `json:"adresse"`
	Port     int     `json:"port"`
	Benutzer string  `json:"benutzer"`
	Passwort *string `json:"passwort"` // leer/fehlt beim Ändern = bleibt
	// Fingerabdruck des Zertifikats (SHA-256, mit oder ohne Doppelpunkte); leer = bleibt
	Fingerabdruck string `json:"fingerabdruck"`
	Intervall     int    `json:"intervall_sekunden"`
	Aktiv         *bool  `json:"aktiv"`
}

type citrixParsed struct {
	host, user, pass, pin string
	port, every           int
	enabled               bool
}

func (s *Server) parseCitrix(in citrixIn) (citrixParsed, error) {
	var p citrixParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse eines Delivery Controllers angeben.")
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
	if !citrix.ValidUser(p.user) {
		return p, badRequest("Benutzer: AD-Konto wie DOMÄNE\\name oder name@domäne.")
	}
	if in.Passwort != nil && *in.Passwort != "" {
		if !citrix.ValidPassword(*in.Passwort) {
			return p, badRequest("Passwort: 1 bis 256 Zeichen, ohne Steuerzeichen.")
		}
		p.pass = *in.Passwort
	}
	if strings.TrimSpace(in.Fingerabdruck) != "" {
		pin, ok := citrix.NormalizePin(in.Fingerabdruck)
		if !ok {
			return p, badRequest("Fingerabdruck: SHA-256 als 64 Hexziffern (mit oder ohne Doppelpunkte).")
		}
		p.pin = pin
	}
	return p, nil
}

// storedCitrix: gespeicherte Zugangsdaten, nur für dieselbe Adresse und
// denselben Port und nur für Admins (snmp_secret_for_admin).
func (s *Server) storedCitrix(ctx context.Context, tx pgx.Tx, deviceID, tenant, host string, port int) (*citrixSecret, bool, error) {
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
	sec, err := s.openCitrix(id, tenant, host, port, enc)
	if err != nil {
		return nil, true, nil
	}
	return &sec, true, nil
}

// handleCitrixSet legt die Citrix-Abfrage eines Geräts an oder ändert sie
// (nur Admins). Ohne neues Passwort bleibt das alte, aber nur bei gleicher
// Adresse, gleichem Port, gleichem Benutzer und gleichem Fingerabdruck.
func (s *Server) handleCitrixSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in citrixIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "citrix speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseCitrix(in)
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
			return 0, nil, &apiError{http.StatusForbidden, "Citrix einrichten und ändern dürfen nur Admins."}
		}
		var id, oldHost, oldVersion string
		var oldPort int
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "benutzer": p.user, "passwort_neu": p.pass != ""}
		if p.pin != "" {
			details["fingerabdruck"] = citrix.FormatPin(p.pin)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if p.pass == "" {
				return 0, nil, badRequest("Bitte das Passwort angeben.")
			}
			if p.pin == "" {
				return 0, nil, errNeedCitrixPin
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealCitrix(id, tenant, p.host, p.port, citrixSecret{User: p.user, Password: p.pass, Pin: p.pin})
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched)
				VALUES ($1, $2, 'citrix', $3, $4, $5, $6, $7, '{}')`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "citrix.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion != versionCitrix {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) +
				"). Bitte diese zuerst entfernen."}
		}
		var stored *citrixSecret
		if p.host == oldHost && p.port == oldPort {
			if stored, _, err = s.storedCitrix(ctx, tx, deviceID, tenant, p.host, p.port); err != nil {
				return 0, nil, err
			}
		}
		if p.pin == "" {
			if stored == nil {
				return 0, nil, errNeedCitrixPin
			}
			p.pin = stored.Pin
		}
		var enc []byte
		switch {
		case p.pass != "":
			if enc, err = s.sealCitrix(id, tenant, p.host, p.port, citrixSecret{User: p.user, Password: p.pass, Pin: p.pin}); err != nil {
				return 0, nil, err
			}
		case stored == nil || stored.User != p.user || stored.Pin != p.pin:
			return 0, nil, badRequest("Bei neuer Adresse, neuem Port, neuem Benutzer oder neuem Fingerabdruck bitte das Passwort neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if enc != nil {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4,
				interval_s = $5, enabled = $6 WHERE id = $1 AND version = 'citrix'`,
				id, p.host, p.port, enc, p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'citrix'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Citrix einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "citrix.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// handleCitrixProbe: „Verbindung prüfen“. Ohne Fingerabdruck holt sie nur den
// Fingerabdruck des Zertifikats (ohne Anmeldung, ohne Anfrage), damit der
// Admin ihn bestätigt. Ohne neues Passwort nimmt die Zentrale das
// gespeicherte, aber nur für dieselbe Adresse, denselben Port, denselben
// Benutzer und denselben Fingerabdruck. Nur Admins; höchstens alle 3 Sekunden
// je Person.
func (s *Server) handleCitrixProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in citrixIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg citrix.Config
	ctx := r.Context()
	fingerprintOnly := false
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseCitrix(in)
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
		stored, _, err := s.storedCitrix(ctx, tx, deviceID, tenant, p.host, p.port)
		if err != nil {
			return err
		}
		cfg = citrix.Config{Host: p.host, Port: uint16(p.port), User: p.user, Password: p.pass, Pin: p.pin}
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
		return audit(ctx, tx, &tenant, "citrix.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "benutzer": p.user, "passwort_neu": p.pass != "", "nur_fingerabdruck": fingerprintOnly})
	})
	if err != nil {
		writeDBError(w, "citrix prüfen", err)
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
	client := s.citrixFor(probeTenant)
	if fingerprintOnly {
		fp, err := client.Fingerprint(ctx, cfg.Host, cfg.Port)
		if err != nil {
			if !notAllowed(err) {
				writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fingerabdruck_neu": citrix.FormatPin(fp),
			"fehler": "Bitte den Fingerabdruck des Zertifikats prüfen und übernehmen."})
		return
	}
	info, err := client.Probe(ctx, cfg)
	if err != nil {
		if notAllowed(err) {
			return
		}
		out := map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)}
		var pe *citrix.PinError
		if errors.As(err, &pe) && pe.Got != "" {
			out["fingerabdruck_neu"] = citrix.FormatPin(pe.Got)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	info.Fingerprint = citrix.FormatPin(info.Fingerprint)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "citrix": info})
}

func (s *Server) citrixFor(tenant string) *citrix.Client {
	return &citrix.Client{Guard: s.guardFor(tenant), Now: s.now}
}

// pollCitrix fragt den Monitor Service einer Citrix-Site ab (aus pollSNMP).
func (s *Server) pollCitrix(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, error) {
	sec, err := s.openCitrix(c.id, c.tenant, c.host, c.port, c.secret)
	if err != nil {
		return nil, err
	}
	return s.citrixFor(c.tenant).Poll(ctx, citrix.Config{Host: c.host, Port: uint16(c.port), User: sec.User, Password: sec.Password, Pin: sec.Pin})
}
