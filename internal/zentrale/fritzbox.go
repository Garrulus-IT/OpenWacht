// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// FRITZ!Box-Abfragen (Etappe 18c): eine Abfragequelle mit version = 'tr064'
// (Migration 0022). Pflege, „Verbindung prüfen“ und Abfrage wie bei Proxmox;
// „jetzt abfragen“, Löschen, Verlauf, Alarme und Wartung laufen über die
// SNMP-Endpunkte.
//
// Benutzer, Passwort und der Fingerabdruck des TLS-Zertifikats sind
// verschlüsselt und an Quelle, Mandant, Adresse und Port gebunden. Nur Admins
// pflegen sie; erreichbar ist nur, was -check-netze freigibt. Die Zentrale
// ruft nur die lesenden Aktionen aus tr064.allowed auf.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
)

const versionTR064 = "tr064"

var errNeedPin = badRequest("Mit HTTPS bitte zuerst „Verbindung prüfen“ und den Fingerabdruck des Zertifikats übernehmen.")

func fritzAAD(id, tenant, host string, port int) []byte {
	return []byte("openwacht tr064 v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port))
}

// fritzSecret: alles, was die Anmeldung braucht. Pin gehört dazu, damit ein
// geänderter Fingerabdruck nur mit dem Passwort zusammen gilt.
type fritzSecret struct {
	User     string `json:"benutzer"`
	Password string `json:"passwort"`
	Pin      string `json:"pin,omitempty"`
}

func (s *Server) sealFritz(id, tenant, host string, port int, sec fritzSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, fritzAAD(id, tenant, host, port))
}

func (s *Server) openFritz(id, tenant, host string, port int, enc []byte) (fritzSecret, error) {
	var sec fritzSecret
	pt, err := auth.Open(s.boxKey, enc, fritzAAD(id, tenant, host, port))
	if err != nil {
		return sec, errors.New("Zugangsdaten nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !tr064.ValidUser(sec.User) || !tr064.ValidPassword(sec.Password) ||
		(sec.Pin != "" && !tr064.ValidPin(sec.Pin)) {
		return fritzSecret{}, errors.New("Zugangsdaten ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type fritzIn struct {
	Adresse  string  `json:"adresse"`
	Port     int     `json:"port"`
	HTTPS    bool    `json:"https"`
	Benutzer *string `json:"benutzer"` // mit Passwort zusammen; fehlt beim Ändern = bleibt
	Passwort *string `json:"passwort"`
	// Fingerabdruck des Zertifikats (SHA-256, mit oder ohne Doppelpunkte); nur mit https
	Fingerabdruck string `json:"fingerabdruck"`
	Intervall     int    `json:"intervall_sekunden"`
	Aktiv         *bool  `json:"aktiv"`
}

type fritzParsed struct {
	host        string
	port, every int
	enabled     bool
	https       bool
	pin         string
	user, pass  string // leer = bleibt
}

func (p fritzParsed) hasLogin() bool { return p.pass != "" }

func (s *Server) parseFritz(in fritzIn) (fritzParsed, error) {
	var p fritzParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse der FRITZ!Box angeben, z. B. 192.168.178.1 oder fritz.box.")
	}
	p.host = *host
	if err := s.checkZentraleAddr(p.host); err != nil {
		return p, err
	}
	p.https = in.HTTPS
	p.port = in.Port
	if p.port == 0 {
		p.port = tr064.PortHTTP
		if p.https {
			p.port = tr064.PortHTTPS
		}
	}
	if p.port < 1 || p.port > 65535 {
		return p, badRequest("Port: 1 bis 65535 (Standard 49000, mit HTTPS 49443).")
	}
	p.every = in.Intervall
	if p.every == 0 {
		p.every = 60
	}
	if p.every < 30 || p.every > 3600 {
		return p, badRequest("Intervall: 30 Sekunden bis 1 Stunde.")
	}
	p.enabled = in.Aktiv == nil || *in.Aktiv
	if strings.TrimSpace(in.Fingerabdruck) != "" {
		if !p.https {
			return p, badRequest("Ein Fingerabdruck gilt nur mit HTTPS.")
		}
		pin, ok := tr064.NormalizePin(in.Fingerabdruck)
		if !ok {
			return p, badRequest("Fingerabdruck: SHA-256 als 64 Hexziffern (mit oder ohne Doppelpunkte).")
		}
		p.pin = pin
	}
	user, pass := "", ""
	if in.Benutzer != nil {
		user = strings.TrimSpace(*in.Benutzer)
	}
	if in.Passwort != nil {
		pass = *in.Passwort
	}
	switch {
	case user == "" && pass == "":
	case user == "" || pass == "":
		return p, badRequest("Bitte Benutzer und Passwort zusammen angeben.")
	case !tr064.ValidUser(user):
		return p, badRequest("Benutzer: wie in der FRITZ!Box angelegt (Buchstaben, Ziffern, . _ @ -), höchstens 64 Zeichen.")
	case !tr064.ValidPassword(pass):
		return p, badRequest("Passwort: 1 bis 128 Zeichen, ohne Steuerzeichen.")
	}
	p.user, p.pass = user, pass
	return p, nil
}

// handleFritzSet legt die FRITZ!Box-Abfrage eines Geräts an oder ändert sie
// (nur Admins). Ohne neue Zugangsdaten bleiben die alten, aber nur bei
// gleicher Adresse, gleichem Port und gleichem Fingerabdruck.
func (s *Server) handleFritzSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in fritzIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "fritzbox speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseFritz(in)
		if err != nil {
			return 0, nil, err
		}
		var tenant, deviceName string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, name FROM openwacht.devices WHERE id = $1`, deviceID).
			Scan(&tenant, &deviceName); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		var id, oldHost, oldVersion string
		var oldPort int
		var oldEnc []byte
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "https": p.https, "zugang_neu": p.hasLogin()}
		if p.pin != "" {
			details["fingerabdruck"] = tr064.FormatPin(p.pin)
		}
		if p.user != "" {
			details["benutzer"] = p.user // kein Geheimnis; das Passwort nie
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if !p.hasLogin() {
				return 0, nil, badRequest("Bitte Benutzer und Passwort des FRITZ!Box-Kontos angeben.")
			}
			if p.https && p.pin == "" {
				return 0, nil, errNeedPin
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealFritz(id, tenant, p.host, p.port, fritzSecret{User: p.user, Password: p.pass, Pin: p.pin})
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched)
				VALUES ($1, $2, 'tr064', $3, $4, $5, $6, $7, '{}')`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "fritzbox.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion != versionTR064 {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) + "). Bitte diese zuerst entfernen."}
		}
		// Gespeicherte Zugangsdaten (nur Admins lesen sie, nur für dieselbe
		// Adresse und denselben Port): für „bleibt“ und den bisherigen
		// Fingerabdruck.
		var stored *fritzSecret
		if p.host == oldHost && p.port == oldPort && (!p.hasLogin() || p.https && p.pin == "") {
			err := tx.QueryRow(ctx, `SELECT secret_enc FROM openwacht.snmp_secret_for_admin($1, $2, $3)`,
				deviceID, p.host, p.port).Scan(&oldEnc)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, err
			}
			if oldEnc != nil {
				if sec, err := s.openFritz(id, tenant, p.host, p.port, oldEnc); err == nil {
					stored = &sec
				}
			}
		}
		if p.https && p.pin == "" {
			if stored == nil || stored.Pin == "" {
				return 0, nil, errNeedPin
			}
			p.pin = stored.Pin
		}
		var enc []byte
		switch {
		case p.hasLogin():
			if enc, err = s.sealFritz(id, tenant, p.host, p.port, fritzSecret{User: p.user, Password: p.pass, Pin: p.pin}); err != nil {
				return 0, nil, err
			}
		case p.host != oldHost || p.port != oldPort:
			return 0, nil, badRequest("Bei neuer Adresse oder neuem Port bitte Benutzer und Passwort neu eingeben.")
		case oldEnc == nil:
			return 0, nil, &apiError{http.StatusForbidden, "FRITZ!Box einrichten und ändern dürfen nur Admins (oder die Zugangsdaten fehlen: bitte neu eingeben)."}
		case stored == nil:
			return 0, nil, badRequest("Die gespeicherten Zugangsdaten sind nicht lesbar, bitte Benutzer und Passwort neu eingeben.")
		case stored.Pin != p.pin:
			return 0, nil, badRequest("Beim Wechsel zwischen HTTP und HTTPS oder bei neuem Fingerabdruck bitte Benutzer und Passwort neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if enc != nil {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4,
				interval_s = $5, enabled = $6 WHERE id = $1 AND version = 'tr064'`,
				id, p.host, p.port, enc, p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'tr064'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "FRITZ!Box einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "fritzbox.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// handleFritzProbe: „Verbindung prüfen“. Mit HTTPS und ohne Fingerabdruck
// holt sie nur den Fingerabdruck des Zertifikats (ohne Anmeldung), damit der
// Admin ihn bestätigt. Ohne neue Zugangsdaten nimmt die Zentrale die
// gespeicherten, aber nur für dieselbe Adresse, denselben Port und denselben
// Fingerabdruck. Nur Admins; höchstens alle 3 Sekunden je Person.
func (s *Server) handleFritzProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in fritzIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg tr064.Config
	ctx := r.Context()
	fingerprintOnly := false
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseFritz(in)
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
		cfg = tr064.Config{Host: p.host, Port: uint16(p.port), User: p.user, Password: p.pass, Pin: p.pin}
		var stored *fritzSecret
		var id string
		var enc []byte
		err = tx.QueryRow(ctx, `SELECT id::text, secret_enc FROM openwacht.snmp_secret_for_admin($1, $2, $3)`,
			deviceID, p.host, p.port).Scan(&id, &enc)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if enc != nil {
			if sec, err := s.openFritz(id, tenant, p.host, p.port, enc); err == nil {
				stored = &sec
			}
		}
		if p.https && p.pin == "" {
			if stored != nil && stored.Pin != "" {
				cfg.Pin = stored.Pin
			} else {
				fingerprintOnly = true
			}
		}
		if !fingerprintOnly && !p.hasLogin() {
			if stored == nil || stored.Pin != cfg.Pin {
				return badRequest("Bitte Benutzer und Passwort angeben (gespeichert sind keine für diese Adresse, diesen Port und dieses Zertifikat).")
			}
			cfg.User, cfg.Password = stored.User, stored.Password
		}
		probeTenant = tenant
		return audit(ctx, tx, &tenant, "fritzbox.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "https": p.https, "zugang_neu": p.hasLogin(), "nur_fingerabdruck": fingerprintOnly})
	})
	if err != nil {
		writeDBError(w, "fritzbox prüfen", err)
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
	if fingerprintOnly {
		fp, err := s.tr064For(probeTenant).Fingerprint(ctx, cfg.Host, cfg.Port)
		if err != nil {
			if !notAllowed(err) {
				writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fingerabdruck_neu": tr064.FormatPin(fp),
			"fehler": "Bitte den Fingerabdruck des Zertifikats prüfen und übernehmen."})
		return
	}
	info, err := s.tr064For(probeTenant).Probe(ctx, cfg)
	if err != nil {
		if notAllowed(err) {
			return
		}
		out := map[string]any{"ok": false, "fehler": clipRunes(err.Error(), 300)}
		var pe *tr064.PinError
		if errors.As(err, &pe) && pe.Got != "" {
			out["fingerabdruck_neu"] = tr064.FormatPin(pe.Got)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if info.Fingerprint != "" {
		info.Fingerprint = tr064.FormatPin(info.Fingerprint)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fritzbox": info})
}

// pollFritz fragt eine FRITZ!Box ab (aus pollSNMP).
func (s *Server) pollFritz(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, bool, error) {
	sec, err := s.openFritz(c.id, c.tenant, c.host, c.port, c.secret)
	if err != nil {
		return nil, false, err
	}
	var prev *snmp.Snapshot
	if c.snapshot != nil {
		var p snmp.Snapshot
		if json.Unmarshal(c.snapshot, &p) == nil && p.FritzBox != nil {
			prev = &p
		}
	}
	snap, err := s.tr064For(c.tenant).Poll(ctx, tr064.Config{Host: c.host, Port: uint16(c.port), User: sec.User, Password: sec.Password, Pin: sec.Pin}, prev)
	if err != nil {
		return nil, false, err
	}
	rebooted := prev != nil && tr064.Rebooted(prev.System.UptimeS, snap.System.UptimeS)
	// Ins Journal nur, wenn sich die fehlenden Teile ändern (nicht jede Minute).
	var before []string
	if prev != nil {
		before = prev.FritzBox.Reasons
	}
	if !slices.Equal(before, snap.FritzBox.Reasons) {
		if len(snap.FritzBox.Reasons) > 0 {
			slog.Info("FRITZ!Box: Teile nicht verfügbar", "quelle", c.id, "gruende", snap.FritzBox.Reasons)
		} else {
			slog.Info("FRITZ!Box: wieder alle Teile verfügbar", "quelle", c.id)
		}
	}
	return snap, rebooted, nil
}
