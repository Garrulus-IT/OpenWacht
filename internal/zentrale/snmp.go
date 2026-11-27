// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// SNMP-Abfragen: Pflege der Quellen (je Gerät höchstens eine), „Verbindung
// prüfen“, „jetzt abfragen“ und der Planer, der fällige Quellen abfragt.
//
// Die Community liegt verschlüsselt in der Datenbank (Migration 0013) und ist
// für die Anwendung nicht lesbar. Sie ist an Quelle, Mandant, Adresse und
// Port gebunden: Wer die Adresse ändert, muss sie neu eingeben, sonst ließe
// sie sich an ein fremdes Ziel umleiten. Anlegen, ändern und löschen dürfen
// nur Admins; erreichbar ist nur, was -check-netze freigibt.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/traps"
)

// snmpSecret: der verschlüsselte Inhalt (Community oder v3-Zugangsdaten),
// als JSON. Derselbe Inhalt liegt für den Trap-Dienst mit dem Trap-Schlüssel
// in trap_secret_enc, wenn Traps eingeschaltet sind.
type snmpSecret = traps.Secret

func snmpAAD(id, tenant, host string, port int) []byte {
	return []byte("openwacht snmp v1|" + id + "|" + tenant + "|" + host + "|" + strconv.Itoa(port))
}

type snmpIn struct {
	Version   string    `json:"version"`
	Adresse   string    `json:"adresse"`
	Port      int       `json:"port"`
	Community *string   `json:"community"` // leer/fehlt beim Ändern = bleibt
	V3        *snmpV3In `json:"v3"`        // fehlt oder ohne Passwörter beim Ändern = bleibt
	Intervall int       `json:"intervall_sekunden"`
	Aktiv     *bool     `json:"aktiv"`
	Traps     *bool     `json:"traps"` // fehlt = bleibt (beim Anlegen: aus)
	Ueberwach []string  `json:"ueberwacht"`
	// Sammler: Agent, der das Gerät abfragt; "" = die Zentrale, fehlt = bleibt
	Sammler *string `json:"sammler"`
	// Zugangsprofil (Etappe 27): ID; "" = keins (eigene Zugangsdaten), fehlt =
	// bleibt. Neue eigene Zugangsdaten ohne dieses Feld lösen das Profil.
	Profil *string `json:"profil"`
}

type snmpV3In struct {
	Benutzer     string `json:"benutzer"`
	Auth         string `json:"auth"`
	AuthPasswort string `json:"auth_passwort"`
	Priv         string `json:"priv"`
	PrivPasswort string `json:"priv_passwort"`
}

type snmpOut struct {
	ID           string          `json:"id"`
	MandantID    string          `json:"mandant_id"`
	GeraetID     string          `json:"geraet_id"`
	Version      string          `json:"version"`
	Adresse      string          `json:"adresse"`
	Port         int             `json:"port"`
	HatCommunity bool            `json:"hat_community"` // auch v3: Zugangsdaten gespeichert
	V3Auth       *string         `json:"v3_auth"`
	V3Priv       *string         `json:"v3_priv"`
	Traps        bool            `json:"traps"`
	Intervall    int             `json:"intervall_sekunden"`
	Aktiv        bool            `json:"aktiv"`
	Ueberwacht   []string        `json:"ueberwacht"`
	Erstellt     time.Time       `json:"erstellt"`
	Geaendert    time.Time       `json:"geaendert"`
	Naechste     time.Time       `json:"naechste"`
	Versucht     *time.Time      `json:"zuletzt_versucht"`
	ZuletztOK    *time.Time      `json:"zuletzt_ok"`
	Fehler       *string         `json:"fehler"`
	Messwerte    json.RawMessage `json:"messwerte"`
	NeustartAm   *time.Time      `json:"neustart_am"`
	Wartung      *wartungOut     `json:"wartung"`
	// nur Proxmox: hinterlegte CA (null = System-CAs)
	CA *caOut `json:"ca"`
	// Sammler (Agent-ID und Hostname), null = die Zentrale fragt ab
	Sammler     *string `json:"sammler"`
	SammlerName *string `json:"sammler_name"`
	// Zugangsprofil; der Name nur für Admins des Profilmandanten
	Profil     *string `json:"profil_id"`
	ProfilName *string `json:"profil_name"`
}

const snmpColumns = `s.id::text, s.tenant_id::text, s.device_id::text, s.version, s.host, s.port, s.has_secret, s.interval_s,
	s.enabled, s.watched, s.created_at, s.changed_at, s.next_run, s.last_try, s.last_ok, s.last_error, s.snapshot, s.rebooted_at, s.ca_pem,
	s.v3_auth, s.v3_priv, s.traps, s.collector_id::text,
	(SELECT d.name FROM openwacht.agents a JOIN openwacht.devices d ON d.id = a.device_id WHERE a.id = s.collector_id),
	s.profile_id::text, (SELECT p.name FROM openwacht.snmp_profiles p WHERE p.id = s.profile_id)`

func scanSNMP(row pgx.CollectableRow) (snmpOut, error) {
	var o snmpOut
	var raw []byte
	var ca *string
	err := row.Scan(&o.ID, &o.MandantID, &o.GeraetID, &o.Version, &o.Adresse, &o.Port, &o.HatCommunity, &o.Intervall,
		&o.Aktiv, &o.Ueberwacht, &o.Erstellt, &o.Geaendert, &o.Naechste, &o.Versucht, &o.ZuletztOK, &o.Fehler, &raw, &o.NeustartAm, &ca,
		&o.V3Auth, &o.V3Priv, &o.Traps, &o.Sammler, &o.SammlerName, &o.Profil, &o.ProfilName)
	o.CA = caInfo(ca)
	if raw != nil {
		o.Messwerte = raw
	} else {
		o.Messwerte = json.RawMessage("null")
	}
	if o.Ueberwacht == nil {
		o.Ueberwacht = []string{}
	}
	return o, err
}

func (s *Server) handleSNMPList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "snmp", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		maint, err := visibleMaintenance(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT `+snmpColumns+` FROM openwacht.snmp_sources s
			WHERE ($1 = '' OR s.tenant_id = $1::uuid) ORDER BY s.id`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, scanSNMP)
		if err != nil {
			return 0, nil, err
		}
		for i := range list {
			list[i].Wartung = maint["s:"+list[i].ID]
		}
		if list == nil {
			list = []snmpOut{}
		}
		var nets []string
		for _, p := range s.guard.Networks() {
			nets = append(nets, p.String())
		}
		if nets == nil {
			nets = []string{}
		}
		collectors, err := visibleCollectors(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"snmp": list, "netze": nets, "sammler": collectors}, nil
	})
}

// parsed: geprüfte Eingabe.
type snmpParsed struct {
	version, host string
	port, every   int
	enabled       bool
	traps         *bool
	community     string       // "" = keine neue
	v3            *snmp.V3Auth // nil = keine neuen
	watched       []string
}

// hasSecret: neue Zugangsdaten in der Eingabe.
func (p snmpParsed) hasSecret() bool { return p.community != "" || p.v3 != nil }

func (p snmpParsed) secret() snmpSecret {
	if p.v3 != nil {
		return snmpSecret{V3: p.v3}
	}
	return snmpSecret{Community: p.community}
}

// v3Columns: Verfahren für die Spalten v3_auth/v3_priv (nil bei v1/v2c).
func (p snmpParsed) v3Columns() (*string, *string) {
	if p.v3 == nil {
		return nil, nil
	}
	return &p.v3.Auth, &p.v3.Priv
}

// snmpKind: Zugangsdaten gelten nur innerhalb einer Art (v1/v2c teilen die Community).
func snmpKind(version string) string {
	switch version {
	case snmp.V3:
		return "v3"
	case versionPVE:
		return "pve"
	case versionTR064:
		return "tr064"
	case versionVCenter:
		return "vcenter"
	case versionONTAP:
		return "ontap"
	case versionXAPI:
		return "xapi"
	case versionCitrix:
		return "citrix"
	}
	return "v1"
}

func (s *Server) parseSNMP(in snmpIn) (snmpParsed, error) {
	var p snmpParsed
	var err error
	if p.version, err = parseSNMPVersion(in.Version); err != nil {
		return p, err
	}
	host, err := cleanAddress(in.Adresse)
	if err != nil {
		return p, err
	}
	if host == nil {
		return p, badRequest("Adresse: Hostname oder IP-Adresse des Geräts angeben.")
	}
	p.host = *host
	p.port = in.Port
	if p.port == 0 {
		p.port = 161
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
	p.traps = in.Traps
	if p.community, p.v3, err = parseSNMPCreds(p.version, in.Community, in.V3); err != nil {
		return p, err
	}
	if len(in.Ueberwach) > 64 {
		return p, badRequest("Höchstens 64 überwachte Schnittstellen.")
	}
	seen := map[string]bool{}
	p.watched = []string{}
	for _, n := range in.Ueberwach {
		n = strings.TrimSpace(n)
		if n == "" || utf8.RuneCountInString(n) > 200 || strings.ContainsFunc(n, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return p, badRequest("Schnittstellen: Namen mit 1 bis 200 Zeichen ohne Steuerzeichen.")
		}
		if !seen[n] {
			seen[n] = true
			p.watched = append(p.watched, n)
		}
	}
	return p, nil
}

// parseSNMPCreds prüft neue Zugangsdaten zur Version: Community für v1/v2c,
// vollständige v3-Daten für v3. Leer bzw. ohne Passwörter = keine neuen.
func parseSNMPCreds(version string, community *string, v3 *snmpV3In) (string, *snmp.V3Auth, error) {
	if version == snmp.V3 {
		if community != nil && *community != "" {
			return "", nil, badRequest("SNMPv3 hat keine Community. Bitte Benutzer und Passwörter angeben.")
		}
		// Neue v3-Zugangsdaten nur vollständig: Die Schlüssel hängen an
		// Benutzer, Verfahren und beiden Passwörtern zugleich.
		if v := v3; v != nil && (v.AuthPasswort != "" || v.PrivPasswort != "") {
			a := &snmp.V3Auth{User: v.Benutzer, Auth: snmp.NormalizeAuth(v.Auth), AuthPass: v.AuthPasswort,
				Priv: snmp.NormalizePriv(v.Priv), PrivPass: v.PrivPasswort}
			if err := a.Validate(); err != nil {
				return "", nil, badRequest(err.Error() + ".")
			}
			return "", a, nil
		}
		return "", nil, nil
	}
	if v3 != nil && (v3.AuthPasswort != "" || v3.PrivPasswort != "") {
		return "", nil, badRequest("v3-Zugangsdaten passen nur zu SNMP-Version 3.")
	}
	if community != nil && *community != "" {
		if !snmp.ValidCommunity(*community) {
			return "", nil, badRequest("Community: 1 bis 64 druckbare ASCII-Zeichen, ohne Leerzeichen am Anfang oder Ende.")
		}
		return *community, nil, nil
	}
	return "", nil, nil
}

// parseSNMPVersion: 1, 2c (Standard) oder 3.
func parseSNMPVersion(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "v1":
		return snmp.V1, nil
	case "2c", "v2c", "2", "":
		return snmp.V2c, nil
	case "3", "v3":
		return snmp.V3, nil
	}
	return "", badRequest("Version: 1, 2c oder 3.")
}

func (s *Server) sealSNMP(id, tenant, host string, port int, sec snmpSecret) ([]byte, error) {
	pt, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return auth.Seal(s.boxKey, pt, snmpAAD(id, tenant, host, port))
}

// openSNMP entschlüsselt und prüft, ob die Zugangsdaten zur Version passen
// (eine v3-Zeile wird nie als Community benutzt und umgekehrt).
func (s *Server) openSNMP(id, tenant, host string, port int, version string, enc []byte) (snmpSecret, error) {
	var sec snmpSecret
	what := "Community"
	if version == snmp.V3 {
		what = "SNMPv3-Zugangsdaten"
	}
	pt, err := auth.Open(s.boxKey, enc, snmpAAD(id, tenant, host, port))
	if err != nil {
		return sec, errors.New(what + " nicht entschlüsselbar, bitte neu eingeben")
	}
	if err := json.Unmarshal(pt, &sec); err != nil {
		return snmpSecret{}, errors.New(what + " ungültig, bitte neu eingeben")
	}
	if err := sec.Check(version); err != nil {
		return snmpSecret{}, errors.New(what + " ungültig, bitte neu eingeben")
	}
	return sec, nil
}

// sealTrap verschlüsselt die Zugangsdaten für den Trap-Dienst (Trap-Schlüssel).
func (s *Server) sealTrap(id, tenant, host string, port int, version string, sec snmpSecret) ([]byte, error) {
	return traps.Seal(s.trapKey, sec, id, tenant, host, port, version)
}

// config baut die Abfrage aus Version und Zugangsdaten.
func snmpConfig(version, host string, port int, sec snmpSecret) snmp.Config {
	return snmp.Config{Version: version, Host: host, Port: uint16(port), Community: sec.Community, V3: sec.V3}
}

// handleSNMPSet legt die SNMP-Quelle eines Geräts an oder ändert sie (nur Admins).
func (s *Server) handleSNMPSet(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in snmpIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "snmp speichern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseSNMP(in)
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
		var oldTraps bool
		var oldCollector, oldProfile *string
		err = tx.QueryRow(ctx, `SELECT id::text, host, port, version, traps, collector_id::text, profile_id::text
			FROM openwacht.snmp_sources WHERE device_id = $1`, deviceID).
			Scan(&id, &oldHost, &oldPort, &oldVersion, &oldTraps, &oldCollector, &oldProfile)
		isNew := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !isNew {
			return 0, nil, err
		}
		profile, err := s.applyProfile(ctx, tx, &p, in.Profil, oldProfile, isNew, deviceID, oldHost, oldPort, oldVersion)
		if err != nil {
			return 0, nil, err
		}
		trapsOn := oldTraps
		if p.traps != nil {
			trapsOn = *p.traps
		}
		collector := oldCollector
		if in.Sammler != nil {
			collector = nil
			if *in.Sammler != "" {
				collector = in.Sammler
			}
		}
		collectorName := ""
		if collector != nil {
			guard, host, err := collectorFor(ctx, tx, *collector, tenant)
			if err != nil {
				return 0, nil, err
			}
			collectorName = host
			if a, err := parseLiteral(p.host); err == nil && !guard.Allowed(a) {
				return 0, nil, badRequest(fmt.Sprintf("Die Adresse %s liegt nicht in den Netzen, die der Sammler %s freigegeben hat (%s).",
					a, host, collectorNetsText(guard)))
			}
			if trapsOn {
				return 0, nil, badRequest("Traps nimmt nur die Zentrale an. Bei Abfrage durch einen Sammler bitte „Traps annehmen“ ausschalten.")
			}
		} else if err := s.checkZentraleAddr(p.host); err != nil {
			return 0, nil, err
		}
		details := map[string]any{"geraet": deviceID, "name": deviceName, "version": p.version, "adresse": p.host,
			"port": p.port, "intervall_s": p.every, "aktiv": p.enabled, "ueberwacht": p.watched,
			"community_neu": p.community != "", "v3_neu": p.v3 != nil, "traps": trapsOn, "sammler": collector,
			"sammler_name": collectorName, "profil": profile}
		if p.v3 != nil {
			details["v3_verfahren"] = p.v3.Auth + "/" + p.v3.Priv // nie Benutzer oder Passwörter
		}
		authCol, privCol := p.v3Columns()
		if isNew {
			if !p.hasSecret() {
				if p.version == snmp.V3 {
					return 0, nil, badRequest("Bitte Benutzer, Verfahren und beide Passwörter für SNMPv3 angeben.")
				}
				return 0, nil, badRequest("Bitte die Community angeben.")
			}
			if id, err = newUUID(); err != nil {
				return 0, nil, err
			}
			enc, err := s.sealSNMP(id, tenant, p.host, p.port, p.secret())
			if err != nil {
				return 0, nil, err
			}
			var trapEnc []byte
			if trapsOn {
				if trapEnc, err = s.sealTrap(id, tenant, p.host, p.port, p.version, p.secret()); err != nil {
					return 0, nil, err
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
					(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched, v3_auth, v3_priv, traps, trap_secret_enc,
					 collector_id, profile_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
				id, deviceID, p.version, p.host, p.port, enc, p.every, p.enabled, p.watched, authCol, privCol, trapsOn, trapEnc,
				collector, profile); err != nil {
				return 0, nil, err // ohne Admin-Recht: 42501 → 403
			}
			details["id"] = id
			if err := audit(ctx, tx, &tenant, "snmp.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		if oldVersion == versionPVE {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon über die Proxmox-API abgefragt. Bitte die Proxmox-Abfrage zuerst entfernen."}
		}
		if oldVersion == versionTR064 {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon als FRITZ!Box abgefragt. Bitte die FRITZ!Box-Abfrage zuerst entfernen."}
		}
		if oldVersion == versionVCenter {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon als vCenter abgefragt. Bitte die vCenter-Abfrage zuerst entfernen."}
		}
		if oldVersion == versionONTAP {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon als NetApp abgefragt. Bitte die NetApp-Abfrage zuerst entfernen."}
		}
		if oldVersion == versionXAPI {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon als XenServer abgefragt. Bitte die XenServer-Abfrage zuerst entfernen."}
		}
		if oldVersion == versionCitrix {
			return 0, nil, &apiError{http.StatusConflict, "Das Gerät wird schon als Citrix-Site abgefragt. Bitte die Citrix-Abfrage zuerst entfernen."}
		}
		if (p.host != oldHost || p.port != oldPort || snmpKind(p.version) != snmpKind(oldVersion)) && !p.hasSecret() {
			if p.version == snmp.V3 {
				return 0, nil, badRequest("Bei neuer Adresse, neuem Port oder beim Wechsel auf SNMPv3 bitte Benutzer, Verfahren und beide Passwörter angeben.")
			}
			return 0, nil, badRequest("Bei neuer Adresse, neuem Port oder beim Wechsel von SNMPv3 bitte die Community neu eingeben.")
		}
		var tag interface{ RowsAffected() int64 }
		if p.hasSecret() {
			enc, err := s.sealSNMP(id, tenant, p.host, p.port, p.secret())
			if err != nil {
				return 0, nil, err
			}
			var trapEnc []byte
			if trapsOn {
				if trapEnc, err = s.sealTrap(id, tenant, p.host, p.port, p.version, p.secret()); err != nil {
					return 0, nil, err
				}
			}
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = $2, host = $3, port = $4, secret_enc = $5,
				interval_s = $6, enabled = $7, watched = $8, v3_auth = $9, v3_priv = $10, traps = $11, trap_secret_enc = $12,
				collector_id = $13, profile_id = $14
				WHERE id = $1 AND version NOT IN ('pve', 'tr064', 'vcenter')`,
				id, p.version, p.host, p.port, enc, p.every, p.enabled, p.watched, authCol, privCol, trapsOn, trapEnc, collector, profile)
			if err != nil {
				return 0, nil, err
			}
		} else {
			// Traps an ohne neue Zugangsdaten: die gespeicherten für den
			// Trap-Dienst neu verschlüsseln (nur Admins sehen sie).
			var trapEnc []byte
			if trapsOn {
				var sid, sver string
				var enc []byte
				err := tx.QueryRow(ctx, `SELECT id::text, version, secret_enc FROM openwacht.snmp_secret_for_admin($1, $2, $3)`,
					deviceID, p.host, p.port).Scan(&sid, &sver, &enc)
				if errors.Is(err, pgx.ErrNoRows) {
					return 0, nil, &apiError{http.StatusForbidden, "SNMP einrichten und ändern dürfen nur Admins."}
				}
				if err != nil {
					return 0, nil, err
				}
				if enc != nil {
					sec, err := s.openSNMP(sid, tenant, p.host, p.port, sver, enc)
					if err != nil {
						return 0, nil, badRequest(err.Error() + ".")
					}
					if trapEnc, err = s.sealTrap(id, tenant, p.host, p.port, p.version, sec); err != nil {
						return 0, nil, err
					}
				}
			}
			tag, err = tx.Exec(ctx, `UPDATE openwacht.snmp_sources SET version = $2, interval_s = $3, enabled = $4, watched = $5,
				traps = $6, trap_secret_enc = $7, collector_id = $8, profile_id = $9
				WHERE id = $1 AND version NOT IN ('pve', 'tr064', 'vcenter')`, id, p.version, p.every, p.enabled, p.watched, trapsOn, trapEnc, collector,
				profile)
			if err != nil {
				return 0, nil, err
			}
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "SNMP einrichten und ändern dürfen nur Admins."}
		}
		details["id"] = id
		if err := audit(ctx, tx, &tenant, "snmp.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"id": id}, nil
	})
}

// applyProfile setzt Profil und Zugangsdaten der Eingabe: Mit Profil kommen
// Version und Zugangsdaten aus dem Profil (neue Kopie bei neuem Profil, neuer
// Adresse oder neuem Port), sonst bleibt alles wie in der Eingabe. Liefert
// die Profil-ID für die Quelle (nil = keins).
func (s *Server) applyProfile(ctx context.Context, tx pgx.Tx, p *snmpParsed, want, old *string, isNew bool,
	device, oldHost string, oldPort int, oldVersion string) (*string, error) {
	profile := old
	switch {
	case want != nil && *want == "":
		profile = nil
	case want != nil:
		if !uuidPattern.MatchString(*want) {
			return nil, badRequest("Profil: ungültige ID.")
		}
		if p.hasSecret() {
			return nil, badRequest("Entweder ein Profil oder eigene Zugangsdaten angeben.")
		}
		profile = want
	case p.hasSecret():
		profile = nil // eigene Zugangsdaten lösen das Profil
	}
	if profile == nil {
		return nil, nil
	}
	if !isNew && old != nil && *old == *profile && p.host == oldHost && p.port == oldPort {
		p.version = oldVersion // unverändert: die Kopie bleibt, Version wie im Profil
		return profile, nil
	}
	version, sec, err := s.profileForDevice(ctx, tx, *profile, device)
	if err != nil {
		return nil, err
	}
	p.version = version
	p.community, p.v3 = sec.Community, sec.V3
	return profile, nil
}

func (s *Server) handleSNMPDelete(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "snmp löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var id, tenant, host, version string
		if err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, host, version FROM openwacht.snmp_sources WHERE device_id = $1`,
			deviceID).Scan(&id, &tenant, &host, &version); err != nil {
			return 0, nil, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.snmp_sources WHERE id = $1`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, &apiError{http.StatusForbidden, "SNMP entfernen dürfen nur Admins."}
		}
		action := "snmp.geloescht"
		switch version {
		case versionPVE:
			action = "proxmox.geloescht"
		case versionTR064:
			action = "fritzbox.geloescht"
		case versionVCenter:
			action = "vcenter.geloescht"
		case versionONTAP:
			action = "netapp.geloescht"
		case versionXAPI:
			action = "xenserver.geloescht"
		case versionCitrix:
			action = "citrix.geloescht"
		}
		if err := audit(ctx, tx, &tenant, action, map[string]any{"id": id, "geraet": deviceID, "adresse": host}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleSNMPNow: „Jetzt abfragen“ (Admins und Operatoren).
func (s *Server) handleSNMPNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "snmp jetzt", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var res string
		if err := tx.QueryRow(ctx, `SELECT openwacht.snmp_poll_now($1)`, id).Scan(&res); err != nil {
			return 0, nil, err
		}
		switch res {
		case "ok":
			return http.StatusAccepted, nil, nil
		case "verboten":
			return 0, nil, &apiError{http.StatusForbidden, "Jetzt abfragen dürfen Admins und Operatoren."}
		case "aus":
			return 0, nil, &apiError{http.StatusConflict, "Die SNMP-Abfrage ist ausgeschaltet."}
		case "gerade":
			return 0, nil, &apiError{http.StatusTooManyRequests, "Gerade erst abgefragt. Bitte einen Moment warten."}
		}
		return 0, nil, errNotFound
	})
}

// handleSNMPProbe: „Verbindung prüfen“ liest nur die Systemdaten. Ohne neue
// Community nimmt die Zentrale die gespeicherte, aber nur für dieselbe
// Adresse und denselben Port. Nur Admins; höchstens alle 3 Sekunden je Person.
func (s *Server) handleSNMPProbe(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in snmpIn
	if !readJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r.Context())
	if !s.snmpProbeLimit.allow(sess.UserID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Bitte einen Moment warten.")
		return
	}
	var cfg snmp.Config
	ctx := r.Context()
	var probeTenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		p, err := s.parseSNMP(in)
		if err != nil {
			return err
		}
		if in.Sammler != nil && *in.Sammler != "" {
			return badRequest("„Verbindung prüfen“ fragt von der Zentrale aus ab. Mit Sammler bitte speichern; das Ergebnis erscheint nach der ersten Abfrage durch den Sammler.")
		}
		if err := s.checkZentraleAddr(p.host); err != nil {
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
		if in.Profil != nil && *in.Profil != "" {
			if p.hasSecret() {
				return badRequest("Entweder ein Profil oder eigene Zugangsdaten angeben.")
			}
			if !uuidPattern.MatchString(*in.Profil) {
				return badRequest("Profil: ungültige ID.")
			}
			version, sec, err := s.profileForDevice(ctx, tx, *in.Profil, deviceID)
			if err != nil {
				return err
			}
			p.version = version
			p.community, p.v3 = sec.Community, sec.V3
		}
		cfg = snmpConfig(p.version, p.host, p.port, p.secret())
		if !p.hasSecret() {
			var id, version string
			var enc []byte
			err := tx.QueryRow(ctx, `SELECT id::text, version, secret_enc FROM openwacht.snmp_secret_for_admin($1, $2, $3)`,
				deviceID, p.host, p.port).Scan(&id, &version, &enc)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && (enc == nil || snmpKind(version) != snmpKind(p.version)) {
				if p.version == snmp.V3 {
					return badRequest("Bitte Benutzer, Verfahren und beide Passwörter angeben (gespeichert sind keine v3-Zugangsdaten für diese Adresse und diesen Port).")
				}
				return badRequest("Bitte die Community angeben (gespeichert ist keine für diese Adresse und diesen Port).")
			}
			if err != nil {
				return err
			}
			sec, err := s.openSNMP(id, tenant, p.host, p.port, version, enc)
			if err != nil {
				return badRequest(err.Error() + ".")
			}
			cfg = snmpConfig(p.version, p.host, p.port, sec)
		}
		probeTenant = tenant
		return audit(ctx, tx, &tenant, "snmp.geprueft", map[string]any{"geraet": deviceID, "version": p.version,
			"adresse": p.host, "port": p.port, "community_neu": p.community != "", "v3_neu": p.v3 != nil})
	})
	if err != nil {
		writeDBError(w, "snmp prüfen", err)
		return
	}
	sys, err := s.snmpFor(probeTenant).Probe(ctx, cfg)
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "system": sys})
}

// --- Planer ----------------------------------------------------------------------

type claimedSNMP struct {
	id, tenant, version, host string
	port, revision            int
	secret                    []byte
	snapshot                  []byte
	caPEM                     *string
}

// RunSNMP fragt fällige SNMP-Quellen ab, bis ctx endet (wie RunChecks).
func (s *Server) RunSNMP(ctx context.Context) {
	runPool(ctx, "SNMP", s.cfg.CheckConcurrency, s.cfg.CheckPoll, nil, s.claimSNMP, s.pollSNMP)
}

func (s *Server) claimSNMP(ctx context.Context, n int) ([]claimedSNMP, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, tenant_id::text, version, host, port, secret_enc, revision, snapshot, ca_pem
		FROM openwacht.snmp_claim($1)`, n)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (claimedSNMP, error) {
		var c claimedSNMP
		err := row.Scan(&c.id, &c.tenant, &c.version, &c.host, &c.port, &c.secret, &c.revision, &c.snapshot, &c.caPEM)
		return c, err
	})
}

func (s *Server) pollSNMP(ctx context.Context, c claimedSNMP) {
	var snap, prev *snmp.Snapshot
	var oids []oidCheck
	var pollErr error
	// rebooted: zu meldender Neustart (Rechnerlaufzeit, ≥27 h davor);
	// counterReset: sysUpTime kleiner, Zähler der eigenen OIDs ungültig
	rebooted, counterReset := false, false
	switch {
	case c.secret == nil && c.version == versionPVE:
		pollErr = errors.New("kein API-Token gespeichert, bitte neu eingeben")
	case c.secret == nil && (c.version == versionTR064 || c.version == versionVCenter || c.version == versionONTAP || c.version == versionXAPI || c.version == versionCitrix):
		pollErr = errors.New("keine Zugangsdaten gespeichert, bitte neu eingeben")
	case c.secret == nil && c.version == snmp.V3:
		pollErr = errors.New("keine SNMPv3-Zugangsdaten gespeichert, bitte neu eingeben")
	case c.secret == nil:
		pollErr = errors.New("keine Community gespeichert, bitte neu eingeben")
	case !checks.ValidHost(c.host) && !isLiteral(c.host):
		pollErr = errors.New("Adresse ungültig")
	case c.version == versionPVE:
		snap, rebooted, pollErr = s.pollPVE(ctx, c)
	case c.version == versionTR064:
		snap, rebooted, pollErr = s.pollFritz(ctx, c)
	case c.version == versionVCenter:
		snap, rebooted, pollErr = s.pollVC(ctx, c)
	case c.version == versionONTAP:
		snap, rebooted, pollErr = s.pollONTAP(ctx, c)
	case c.version == versionXAPI:
		snap, rebooted, pollErr = s.pollXAPI(ctx, c)
	case c.version == versionCitrix:
		snap, pollErr = s.pollCitrix(ctx, c)
	default:
		sec, err := s.openSNMP(c.id, c.tenant, c.host, c.port, c.version, c.secret)
		if err != nil {
			pollErr = err
			break
		}
		if c.snapshot != nil {
			var p snmp.Snapshot
			if json.Unmarshal(c.snapshot, &p) == nil {
				prev = &p
			}
		}
		cfg := snmpConfig(c.version, c.host, c.port, sec)
		if byID, err := s.oidChecks(ctx, []string{c.id}); err != nil {
			slog.Warn("SNMP-OID: Sensoren nicht lesbar", "quelle", c.id, "fehler", err)
		} else {
			oids = byID[c.id]
			cfg.Extra, cfg.ExtraText, cfg.Columns = extraOIDs(oids), extraText(oids), extraColumns(oids)
		}
		snap, pollErr = s.snmpFor(c.tenant).Poll(ctx, cfg, prev)
		if pollErr == nil && prev != nil && prev.Counters != nil && snap.Counters != nil {
			dt := snap.Counters.At.Sub(prev.Counters.At).Seconds()
			counterReset = snmp.Rebooted(prev.Counters.UptimeTicks, snap.Counters.UptimeTicks, dt)
			rebooted = snmp.HostRebooted(prev, snap)
		}
	}
	if ctx.Err() != nil {
		return // Zentrale wird beendet; die Quelle bleibt reserviert und läuft danach wieder
	}
	var raw []byte
	var names []string
	var values []float64
	msg := ""
	if pollErr != nil {
		var na *checks.NotAllowedError
		if errors.As(pollErr, &na) {
			msg = fmt.Sprintf("Adresse %s ist nicht freigegeben (-check-netze)", na.Addr)
		} else {
			msg = pollErr.Error()
		}
	} else {
		var err error
		if raw, err = json.Marshal(snap); err != nil || len(raw) > 512<<10 {
			pollErr, msg, raw = ErrSnapshotTooLarge, ErrSnapshotTooLarge.Error(), nil
		} else {
			names, values = snmp.Series(snap)
		}
	}
	var stored bool
	err := s.pool.QueryRow(context.WithoutCancel(ctx), `SELECT openwacht.snmp_record($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.id, c.revision, pollErr == nil, clipRunes(msg, 300), raw, rebooted, names, values).Scan(&stored)
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn("SNMP: Ergebnis nicht gespeichert", "quelle", c.id, "fehler", err)
	}
	if stored && pollErr == nil && len(oids) > 0 {
		s.recordOIDs(ctx, oids, snap, prev, counterReset)
	}
}

func parseLiteral(host string) (netip.Addr, error) { return netip.ParseAddr(host) }

func isLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// ErrSnapshotTooLarge: Die Abfrage ergab mehr Daten, als gespeichert werden.
var ErrSnapshotTooLarge = errors.New("das Gerät liefert zu viele Daten")

// checkZentraleAddr: Fragt die Zentrale ab, muss eine IP-Adresse in
// -check-netze liegen (Namen prüft der Guard bei jeder Abfrage).
func (s *Server) checkZentraleAddr(host string) error {
	if a, err := parseLiteral(host); err == nil && !s.guard.Allowed(a) {
		return badRequest(fmt.Sprintf("Die Adresse %s ist nicht freigegeben. Freigegebene Netze: %s.", a, s.networksText()))
	}
	return nil
}
