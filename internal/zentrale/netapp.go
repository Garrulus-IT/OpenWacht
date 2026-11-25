// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// NetApp-Abfragen (0.41.0): eine Abfragequelle mit version = 'ontap',
// aufgebaut wie FRITZ!Box (Fingerabdruck des Zertifikats) und vCenter (REST).
// Benutzer, Passwort und Fingerabdruck sind verschlüsselt und an Quelle,
// Mandant, Adresse und Port gebunden; ein neuer Fingerabdruck gilt nur mit
// dem Passwort zusammen. Nur Admins pflegen sie; erreichbar ist nur, was die
// Netzfreigabe erlaubt. Die Zentrale liest nur (feste Liste in ontap) und
// lehnt Konten mit Schreibrecht ab.

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
	"github.com/garrulus-it/openwacht/internal/ontap"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const versionONTAP = "ontap"

var errNeedONTAPPin = badRequest("Bitte zuerst „Verbindung prüfen“ und den Fingerabdruck des Zertifikats übernehmen.")

func ontapAAD(id, tenant, host string, port int) []byte {
	return []byte("openwacht ontap v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port))
}

// ontapSecret: alles, was die Anmeldung braucht. Pin gehört dazu, damit ein
// geänderter Fingerabdruck nur mit dem Passwort zusammen gilt.
type ontapSecret struct {
	User     string `json:"benutzer"`
	Password string `json:"passwort"`
	Pin      string `json:"pin"`
}

func (s *Server) sealONTAP(id, tenant, host string, port int, sec ontapSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, ontapAAD(id, tenant, host, port))
}

func (s *Server) openONTAP(id, tenant, host string, port int, enc []byte) (ontapSecret, error) {
	var sec ontapSecret
	pt, err := auth.Open(s.boxKey, enc, ontapAAD(id, tenant, host, port))
	if err != nil {
		return sec, errors.New("Zugangsdaten nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !ontap.ValidUser(sec.User) || !ontap.ValidPassword(sec.Password) || !ontap.ValidPin(sec.Pin) {
		return ontapSecret{}, errors.New("Zugangsdaten ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type netappIn struct {
	Adresse  string  `json:"adresse"`
	Port     int     `json:"port"`
	Benutzer string  `json:"benutzer"`
	Passwort *string `json:"passwort"` // leer/fehlt beim Ändern = bleibt
	// Fingerabdruck des Zertifikats (SHA-256, mit oder ohne Doppelpunkte); leer = bleibt
	Fingerabdruck string `json:"fingerabdruck"`
	Intervall     int    `json:"intervall_sekunden"`
	Aktiv         *bool  `json:"aktiv"`
}

type netappParsed struct {
	host, user, pass, pin string
	port, every           int
	enabled               bool
}

func (s *Server) parseNetApp(in netappIn) (netappParsed, error) {
	var p netappParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse der Cluster-Management-Schnittstelle angeben.")
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
	if !ontap.ValidUser(p.user) {
		return p, badRequest("Benutzer: wie in ONTAP angelegt (Buchstaben, Ziffern, . _ @ - und \\), höchstens 128 Zeichen.")
	}
	if in.Passwort != nil && *in.Passwort != "" {
		if !ontap.ValidPassword(*in.Passwort) {
			return p, badRequest("Passwort: 1 bis 256 Zeichen, ohne Steuerzeichen.")
		}
		p.pass = *in.Passwort
	}
	if strings.TrimSpace(in.Fingerabdruck) != "" {
		pin, ok := ontap.NormalizePin(in.Fingerabdruck)
		if !ok {
			return p, badRequest("Fingerabdruck: SHA-256 als 64 Hexziffern (mit oder ohne Doppelpunkte).")
		}
		p.pin = pin
	}
	return p, nil
}

// storedONTAP: gespeicherte Zugangsdaten, nur für dieselbe Adresse und
// denselben Port und nur für Admins (snmp_secret_for_admin).
func (s *Server) storedONTAP(ctx context.Context, tx pgx.Tx, deviceID, tenant, host string, port int) (*ontapSecret, bool, error) {
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
	sec, err := s.openONTAP(id, tenant, host, port, enc)
	if err != nil {
		return nil, true, nil
	}
	return &sec, true, nil
}

// handleNetAppSet legt die NetApp-Abfrage eines Geräts an oder ändert sie
// (nur Admins). Ohne neues Passwort bleibt das alte, aber nur bei gleicher
// Adresse, gleichem Port, gleichem Benutzer und gleichem Fingerabdruck.
func (s *Server) handleNetAppSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in netappIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "netapp speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseNetApp(in)
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
			return 0, nil, &apiError{http.StatusForbidden, "NetApp einrichten und ändern dürfen nur Admins."}
		}
		var id, oldHost, oldVersion string
		var oldPort int
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "benutzer": p.user, "passwort_neu": p.pass != ""}
		if p.pin != "" {
			details["fingerabdruck"] = ontap.FormatPin(p.pin)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if p.pass == "" {
				return 0, nil, badRequest("Bitte das Passwort angeben.")
			}
			if p.pin == "" {
				return 0, nil, errNeedONTAPPin
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealONTAP(id, tenant, p.host, p.port, ontapSecret{User: p.user, Password: p.pass, Pin: p.pin})
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched)
				VALUES ($1, $2, 'ontap', $3, $4, $5, $6, $7, '{}')`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "netapp.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion != versionONTAP {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) +
				"). Bitte diese zuerst entfernen."}
		}
		var stored *ontapSecret
		if p.host == oldHost && p.port == oldPort {
			if stored, _, err = s.storedONTAP(ctx, tx, deviceID, tenant, p.host, p.port); err != nil {
				return 0, nil, err
			}
		}
		if p.pin == "" {
			if stored == nil {
				return 0, nil, errNeedONTAPPin
			}
			p.pin = stored.Pin
		}
		var enc []byte
		switch {
		case p.pass != "":
			if enc, err = s.sealONTAP(id, tenant, p.host, p.port, ontapSecret{User: p.user, Password: p.pass, Pin: p.pin}); err != nil {
				return 0, nil, err
			}
		case stored == nil || stored.User != p.user || stored.Pin != p.pin:
			return 0, nil, badRequest("Bei neuer Adresse, neuem Port, neuem Benutzer oder neuem Fingerabdruck bitte das Passwort neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if enc != nil {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4,
				interval_s = $5, enabled = $6 WHERE id = $1 AND version = 'ontap'`,
				id, p.host, p.port, enc, p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'ontap'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "NetApp einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "netapp.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// sourceKindText: Art einer Abfragequelle für Meldungen.
func sourceKindText(version string) string {
	switch version {
	case versionPVE:
		return "Proxmox"
	case versionTR064:
		return "FRITZ!Box"
	case versionVCenter:
		return "vCenter"
	case versionONTAP:
		return "NetApp"
	case versionXAPI:
		return "XenServer"
	case versionCitrix:
		return "Citrix"
	}
	return "SNMP"
}

// handleNetAppProbe: „Verbindung prüfen“. Ohne Fingerabdruck holt sie nur den
// Fingerabdruck des Zertifikats (ohne Anmeldung, ohne Anfrage), damit der
// Admin ihn bestätigt. Ohne neues Passwort nimmt die Zentrale das
// gespeicherte, aber nur für dieselbe Adresse, denselben Port, denselben
// Benutzer und denselben Fingerabdruck. Nur Admins; höchstens alle 3 Sekunden
// je Person.
func (s *Server) handleNetAppProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in netappIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg ontap.Config
	ctx := r.Context()
	fingerprintOnly := false
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseNetApp(in)
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
		stored, _, err := s.storedONTAP(ctx, tx, deviceID, tenant, p.host, p.port)
		if err != nil {
			return err
		}
		cfg = ontap.Config{Host: p.host, Port: uint16(p.port), User: p.user, Password: p.pass, Pin: p.pin}
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
		return audit(ctx, tx, &tenant, "netapp.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "benutzer": p.user, "passwort_neu": p.pass != "", "nur_fingerabdruck": fingerprintOnly})
	})
	if err != nil {
		writeDBError(w, "netapp prüfen", err)
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
	client := s.ontapFor(probeTenant)
	if fingerprintOnly {
		fp, err := client.Fingerprint(ctx, cfg.Host, cfg.Port)
		if err != nil {
			if !notAllowed(err) {
				writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fingerabdruck_neu": ontap.FormatPin(fp),
			"fehler": "Bitte den Fingerabdruck des Zertifikats prüfen und übernehmen."})
		return
	}
	info, err := client.Probe(ctx, cfg)
	if err != nil {
		if notAllowed(err) {
			return
		}
		out := map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)}
		var pe *ontap.PinError
		if errors.As(err, &pe) && pe.Got != "" {
			out["fingerabdruck_neu"] = ontap.FormatPin(pe.Got)
		}
		var we *ontap.WritableError
		if errors.As(err, &we) {
			out["schreibrecht"] = true
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	info.Fingerprint = ontap.FormatPin(info.Fingerprint)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "netapp": info})
}

func (s *Server) ontapFor(tenant string) *ontap.Client {
	return &ontap.Client{Guard: s.guardFor(tenant), Now: s.now}
}

// pollONTAP fragt einen NetApp-Cluster ab (aus pollSNMP).
func (s *Server) pollONTAP(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, bool, error) {
	sec, err := s.openONTAP(c.id, c.tenant, c.host, c.port, c.secret)
	if err != nil {
		return nil, false, err
	}
	snap, err := s.ontapFor(c.tenant).Poll(ctx, ontap.Config{Host: c.host, Port: uint16(c.port), User: sec.User, Password: sec.Password, Pin: sec.Pin})
	if err != nil {
		return nil, false, err
	}
	var prev snmp.Snapshot
	rebooted := c.snapshot != nil && json.Unmarshal(c.snapshot, &prev) == nil && ontap.Rebooted(prev.ONTAP, snap.ONTAP)
	return snap, rebooted, nil
}
