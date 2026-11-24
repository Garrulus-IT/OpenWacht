// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Proxmox-Abfragen: eine Abfragequelle mit version = 'pve' (Migration 0014).
// Pflege, „Verbindung prüfen“ und Abfrage wie bei SNMP; „jetzt abfragen“,
// Löschen, Verlauf, Alarme und Wartung laufen über die SNMP-Endpunkte.
//
// Das API-Token ist wie die Community verschlüsselt und an Quelle, Mandant,
// Adresse, Port und CA gebunden. Nur Admins pflegen es; erreichbar ist nur,
// was -check-netze freigibt. Die Zentrale schickt nur GET-Anfragen.

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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

const versionPVE = "pve"

func pveAAD(id, tenant, host string, port int, caPEM string) []byte {
	sum := sha256.Sum256([]byte(caPEM))
	return []byte("openwacht pve v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port) + "|" + hex.EncodeToString(sum[:]))
}

type pveSecret struct {
	Token string `json:"token"`
}

func (s *Server) sealPVE(id, tenant, host string, port int, caPEM, token string) ([]byte, error) {
	pt, err := json.Marshal(pveSecret{Token: token})
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, pveAAD(id, tenant, host, port, caPEM))
}

func (s *Server) openPVE(id, tenant, host string, port int, caPEM string, enc []byte) (pveSecret, error) {
	var sec pveSecret
	pt, err := auth.Open(s.boxKey, enc, pveAAD(id, tenant, host, port, caPEM))
	if err != nil {
		return sec, errors.New("API-Token nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil || !pve.ValidToken(sec.Token) {
		return sec, errors.New("API-Token ungültig, bitte neu eingeben")
	}
	return sec, nil
}

type pveIn struct {
	Adresse   string  `json:"adresse"`
	Port      int     `json:"port"`
	Token     *string `json:"token"` // leer/fehlt beim Ändern = bleibt
	CA        *string `json:"ca"`    // PEM; fehlt = bleibt, leer = System-CAs
	Intervall int     `json:"intervall_sekunden"`
	Aktiv     *bool   `json:"aktiv"`
}

type pveParsed struct {
	host, token, ca string
	port, every     int
	enabled         bool
	caSet           bool // CA angegeben (auch leer); sonst bleibt die gespeicherte
	caInfo          *pve.CA
}

func (s *Server) parsePVE(in pveIn) (pveParsed, error) {
	var p pveParsed
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse des Proxmox-Hosts angeben.")
	}
	p.host = *host
	if a, err := parseLiteral(p.host); err == nil && !s.guard.Allowed(a) {
		return p, badRequest(fmt.Sprintf("Die Adresse %s ist nicht freigegeben. Freigegebene Netze: %s.", a, s.networksText()))
	}
	p.port = in.Port
	if p.port == 0 {
		p.port = 8006
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
	if in.Token != nil && strings.TrimSpace(*in.Token) != "" {
		t := strings.TrimSpace(*in.Token)
		t = strings.TrimPrefix(t, "PVEAPIToken=")
		if !pve.ValidToken(t) {
			return p, badRequest("API-Token: in der Form benutzer@pve!tokenname=geheimnis (UUID), wie Proxmox es beim Anlegen anzeigt.")
		}
		p.token = t
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

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// handlePVESet legt die Proxmox-Abfrage eines Geräts an oder ändert sie (nur
// Admins). Ohne neues Token bleibt das alte, aber nur bei gleicher Adresse,
// gleichem Port und gleicher CA.
func (s *Server) handlePVESet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in pveIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "proxmox speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parsePVE(in)
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
		var oldCA *string
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version, ca_pem FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &oldHost, &oldPort, &oldVersion, &oldCA)
		details := map[string]any{"geraet": deviceID, "name": deviceName, "adresse": p.host, "port": p.port,
			"intervall_s": p.every, "aktiv": p.enabled, "token_neu": p.token != "", "ca": nil}
		if p.caInfo != nil {
			details["ca"] = p.caInfo.Fingerprint
		}
		if p.token != "" {
			details["token_id"] = pve.TokenID(p.token) // öffentlicher Teil, ohne Geheimnis
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if p.token == "" {
				return 0, nil, badRequest("Bitte das API-Token angeben.")
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealPVE(id, tenant, p.host, p.port, p.ca, p.token)
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched, ca_pem)
				VALUES ($1, $2, 'pve', $3, $4, $5, $6, $7, '{}', $8)`,
				id, deviceID, p.host, p.port, enc, p.every, p.enabled, nullable(p.ca)); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "proxmox.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if err != nil {
			return 0, nil, err
		}
		if oldVersion == versionTR064 || oldVersion == versionVCenter || oldVersion == versionONTAP || oldVersion == versionXAPI {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät hat schon eine andere Abfrage (" + sourceKindText(oldVersion) + "). Bitte diese zuerst entfernen."}
		}
		if oldVersion != versionPVE {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon per SNMP abgefragt. Bitte SNMP zuerst entfernen."}
		}
		oldCAText := ""
		if oldCA != nil {
			oldCAText = *oldCA
		}
		if !p.caSet {
			p.ca = oldCAText
		}
		if (p.host != oldHost || p.port != oldPort || p.ca != oldCAText) && p.token == "" {
			return 0, nil, badRequest("Bei neuer Adresse, neuem Port oder neuer CA bitte das API-Token neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if p.token != "" {
			enc, serr := s.sealPVE(id, tenant, p.host, p.port, p.ca, p.token)
			if serr != nil {
				return 0, nil, serr
			}
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET host = $2, port = $3, secret_enc = $4, ca_pem = $5,
				interval_s = $6, enabled = $7 WHERE id = $1 AND version = 'pve'`,
				id, p.host, p.port, enc, nullable(p.ca), p.every, p.enabled)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET interval_s = $2, enabled = $3
				WHERE id = $1 AND version = 'pve'`, id, p.every, p.enabled)
		}
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "Proxmox einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "proxmox.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// handlePVEProbe: „Verbindung prüfen“ liest Knoten, Version und Rechte des
// Tokens. Ohne neues Token nimmt die Zentrale das gespeicherte, aber nur für
// dieselbe Adresse, denselben Port und dieselbe CA. Nur Admins; höchstens
// alle 3 Sekunden je Person.
func (s *Server) handlePVEProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in pveIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg pve.Config
	ctx := r.Context()
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parsePVE(in)
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
			err := tx.QueryRow(ctx, `SELECT ca_pem FROM openwacht.snmp_sources WHERE device_id = $1 AND version = 'pve'`,
				deviceID).Scan(&stored)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if stored != nil {
				p.ca = *stored
			}
		}
		cfg = pve.Config{Host: p.host, Port: uint16(p.port), Token: p.token, CAPEM: p.ca}
		if cfg.Token == "" {
			var id string
			var enc []byte
			err := tx.QueryRow(ctx, `SELECT id::text, secret_enc FROM openwacht.snmp_secret_for_probe($1, $2, $3)`,
				deviceID, p.host, p.port).Scan(&id, &enc)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && enc == nil {
				return badRequest("Bitte das API-Token angeben (gespeichert ist keines für diese Adresse und diesen Port).")
			}
			if err != nil {
				return err
			}
			// Gebunden an die CA: Mit einer anderen CA lässt sich das
			// gespeicherte Token nicht öffnen.
			sec, err := s.openPVE(id, tenant, p.host, p.port, p.ca, enc)
			if err != nil {
				return badRequest("Bitte das API-Token angeben (das gespeicherte gilt nur für die bisherige Adresse, den Port und die CA).")
			}
			cfg.Token = sec.Token
		}
		probeTenant = tenant
		return audit(ctx, tx, &tenant, "proxmox.geprueft", map[string]any{"geraet": deviceID, "adresse": p.host,
			"port": p.port, "token_neu": p.token != ""})
	})
	if err != nil {
		writeDBError(w, "proxmox prüfen", err)
		return
	}
	info, err := s.pveFor(probeTenant).Probe(ctx, cfg)
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proxmox": info})
}

// caOut: was die Oberfläche über die hinterlegte CA zeigt.
type caOut struct {
	Fingerabdruck string    `json:"fingerabdruck"`
	Name          string    `json:"name"`
	GueltigBis    time.Time `json:"gueltig_bis"`
}

func caInfo(pemText *string) *caOut {
	if pemText == nil {
		return nil
	}
	ca, err := pve.ParseCA(*pemText)
	if err != nil {
		return &caOut{Name: "nicht lesbar"}
	}
	return &caOut{Fingerabdruck: ca.Fingerprint, Name: ca.Subject, GueltigBis: ca.NotAfter}
}

// pollPVE fragt einen Proxmox-Host ab (aus pollSNMP).
func (s *Server) pollPVE(ctx context.Context, c claimedSNMP) (*snmp.Snapshot, bool, error) {
	ca := ""
	if c.caPEM != nil {
		ca = *c.caPEM
	}
	sec, err := s.openPVE(c.id, c.tenant, c.host, c.port, ca, c.secret)
	if err != nil {
		return nil, false, err
	}
	var prev *snmp.Snapshot
	if c.snapshot != nil {
		var p snmp.Snapshot
		if json.Unmarshal(c.snapshot, &p) == nil && p.Proxmox != nil {
			prev = &p
		}
	}
	snap, err := s.pveFor(c.tenant).Poll(ctx, pve.Config{Host: c.host, Port: uint16(c.port), Token: sec.Token, CAPEM: ca}, prev)
	if err != nil {
		return nil, false, err
	}
	rebooted := prev != nil && pve.Rebooted(prev.System.UptimeS, snap.System.UptimeS)
	return snap, rebooted, nil
}
