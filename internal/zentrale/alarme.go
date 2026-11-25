// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

// --- API -----------------------------------------------------------------------

// Arten von Alarmkanälen (Etappe 20a: Mail, Webhook, Teams zusätzlich zu ntfy).
const (
	kindNtfy    = "ntfy"
	kindMail    = "mail"
	kindWebhook = "webhook"
	kindTeams   = "teams"
)

type channelIn struct {
	Art            string  `json:"art"` // fehlt = ntfy (wie vor Etappe 20)
	Name           string  `json:"name"`
	Server         string  `json:"server"`
	Topic          string  `json:"topic"`
	Token          *string `json:"token"` // fehlt/null: unverändert, "": entfernen
	URL            *string `json:"url"`   // Webhook/Teams; fehlt = unverändert
	Untermandanten bool    `json:"auch_untermandanten"`
	Aktiv          *bool   `json:"aktiv"`
	// Mail: an alle Benutzer mit Rolle im Mandanten oder an die Auswahl
	AlleBenutzer bool      `json:"alle_benutzer"`
	Empfaenger   *[]string `json:"empfaenger"` // Benutzer-IDs; fehlt = unverändert
	// SMS (0.43.0): Gateway in server
	SMSUser     string  `json:"sms_benutzer"`
	Password    *string `json:"passwort"` // fehlt/leer: unverändert
	Fingerprint string  `json:"fingerabdruck"`
	SMSTarget   string  `json:"empfaenger_art"` // benutzer, gruppe
	SMSGroup    string  `json:"gruppe"`
	Ring        bool    `json:"anrufen"`
	Watch       bool    `json:"ueberwachen"`
}

type recipientOut struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Abbestellt: bekommt keine Alarm-Mails, solange er das so eingestellt hat
	Abbestellt bool `json:"abbestellt"`
	// Mobilnummer: hat eine Mobilnummer für Alarme hinterlegt (nur ob, nicht welche)
	Mobilnummer bool `json:"mobilnummer"`
}

type channelOut struct {
	ID             string         `json:"id"`
	MandantID      string         `json:"mandant_id"`
	Name           string         `json:"name"`
	Typ            string         `json:"typ"`
	Server         string         `json:"server"` // ntfy-Server bzw. Ursprung des Webhooks
	Topic          string         `json:"topic"`
	TokenGesetzt   bool           `json:"token_gesetzt"`
	Untermandanten bool           `json:"auch_untermandanten"`
	Aktiv          bool           `json:"aktiv"`
	AlleBenutzer   bool           `json:"alle_benutzer"`
	Empfaenger     []recipientOut `json:"empfaenger"`
	ZuletztOK      *time.Time     `json:"zuletzt_ok"`
	Fehler         *string        `json:"letzter_fehler"`
	FehlerAm       *time.Time     `json:"letzter_fehler_am"`
	// Etappe 24
	Bereitschaft  *activeHours `json:"bereitschaft"`
	Eskalation    *escalation  `json:"eskalation"`
	Monatsbericht bool         `json:"monatsbericht"`
	// 1.0.1: Mail und SMS sammeln eine Minute
	Sammeln bool `json:"sammeln"`
	// SMS (0.43.0)
	SMSBenutzer   *string `json:"sms_benutzer,omitempty"`
	Fingerabdruck *string `json:"fingerabdruck,omitempty"`
	EmpfaengerArt *string `json:"empfaenger_art,omitempty"`
	Gruppe        *string `json:"gruppe,omitempty"`
	Anrufen       bool    `json:"anrufen"`
	Ueberwachen   bool    `json:"ueberwachen"`
}

type escalation struct {
	NachMinuten int    `json:"nach_minuten"`
	Kanal       string `json:"kanal"`
}

// channelAAD bindet ein verschlüsseltes Token (bzw. die Webhook-URL) an
// Kanal, Mandant und Server: In einen anderen Kanal kopiert oder nach einem
// Serverwechsel lässt es sich nicht mehr entschlüsseln.
func channelAAD(id, tenant, server string) []byte {
	return []byte("alarmkanal\x00" + id + "\x00" + tenant + "\x00" + server)
}

// hookSecretAAD: Signaturschlüssel eines Webhooks, gebunden an Kanal und Mandant.
func hookSecretAAD(id, tenant string) []byte {
	return []byte("alarmkanal-signatur\x00" + id + "\x00" + tenant)
}

// parsedChannel: geprüfte Eingabe.
type parsedChannel struct {
	kind, name, server, topic, url string // url nur Webhook/Teams und nur, wenn angegeben
	sms                            *parsedSMS
}

func (s *Server) targetsHint() string {
	list := strings.Join(s.alertTargets.List(), ", ")
	if list == "" {
		list = "keine (Einstellungen → Alarmziele)"
	}
	return list
}

// parseChannel prüft die Eingabe für die Art kind ("" = aus der Eingabe).
func (s *Server) parseChannel(in channelIn, kind string) (p parsedChannel, err error) {
	if kind == "" {
		kind = in.Art
		if kind == "" {
			kind = kindNtfy
		}
	} else if in.Art != "" && in.Art != kind {
		return p, badRequest("Die Art eines Kanals lässt sich nicht ändern.")
	}
	p.kind = kind
	if p.name, err = cleanName(in.Name); err != nil {
		return
	}
	switch kind {
	case kindNtfy:
		if p.server, err = alarm.NormalizeServer(in.Server); err != nil {
			return p, badRequest("Server: " + err.Error() + ".")
		}
		if !s.alertTargets.Allowed(p.server) {
			return p, badRequest(fmt.Sprintf("Der Server %s ist nicht als Alarmziel freigegeben. Freigegeben: %s.", p.server, s.targetsHint()))
		}
		p.topic = strings.TrimSpace(in.Topic)
		if !alarm.ValidTopic(p.topic) {
			return p, badRequest("Topic: 1 bis 64 Zeichen, nur Buchstaben, Ziffern, - und _.")
		}
		if in.Token != nil && *in.Token != "" && !alarm.ValidToken(*in.Token) {
			return p, badRequest("Token: 1 bis 200 Zeichen ohne Leerzeichen.")
		}
	case kindMail:
		if in.Empfaenger != nil {
			if len(*in.Empfaenger) > alarm.MaxRecipients {
				return p, badRequest(fmt.Sprintf("Höchstens %d Empfänger.", alarm.MaxRecipients))
			}
			for _, id := range *in.Empfaenger {
				if !uuidPattern.MatchString(id) {
					return p, badRequest("Ungültige Benutzer-ID.")
				}
			}
		}
	case kindWebhook, kindTeams:
		if in.URL != nil {
			full, origin, err := alarm.NormalizeHookURL(*in.URL)
			if err != nil {
				return p, badRequest("URL: " + err.Error() + ".")
			}
			if !s.alertTargets.AllowedURL(full) {
				return p, badRequest(fmt.Sprintf("Der Host %s ist nicht als Alarmziel freigegeben. Freigegeben: %s.", origin, s.targetsHint()))
			}
			p.url, p.server = full, origin
		}
	case kindSMS:
		if err := s.parseSMS(in, &p); err != nil {
			return p, err
		}
	default:
		return p, badRequest("Art: ntfy, mail, webhook, teams oder sms.")
	}
	return p, nil
}

func (s *Server) handleChannelList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "alarmkanaele", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, name, kind, coalesce(server, ''), coalesce(topic, ''),
				has_token, include_children, enabled, all_users, last_ok, last_error, last_error_at,
				active_hours, escalate_after_min, escalate_channel_id::text, monthly_report,
				sms_user, sms_pin, sms_target, sms_group, sms_ring, sms_watch, collect
			FROM openwacht.alert_channels WHERE ($1 = '' OR tenant_id = $1::uuid) ORDER BY lower(name)`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (channelOut, error) {
			var c channelOut
			var after *int
			var target *string
			err := row.Scan(&c.ID, &c.MandantID, &c.Name, &c.Typ, &c.Server, &c.Topic, &c.TokenGesetzt,
				&c.Untermandanten, &c.Aktiv, &c.AlleBenutzer, &c.ZuletztOK, &c.Fehler, &c.FehlerAm,
				&c.Bereitschaft, &after, &target, &c.Monatsbericht,
				&c.SMSBenutzer, &c.Fingerabdruck, &c.EmpfaengerArt, &c.Gruppe, &c.Anrufen, &c.Ueberwachen, &c.Sammeln)
			c.Sammeln = c.Sammeln && (c.Typ == kindMail || c.Typ == kindSMS)
			if after != nil && target != nil {
				c.Eskalation = &escalation{NachMinuten: *after, Kanal: *target}
			}
			c.Empfaenger = []recipientOut{}
			return c, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []channelOut{}
		}
		// Empfänger der Mail-Kanäle; Benutzer, die der Aufrufer nicht sieht,
		// erscheinen ohne Namen.
		idx := map[string]int{}
		for i, c := range list {
			idx[c.ID] = i
		}
		rows, err = tx.Query(ctx, `SELECT cu.channel_id::text, cu.user_id::text, coalesce(u.display_name, 'Benutzer'),
				coalesce(NOT u.alert_mail, false), coalesce(u.alert_mobile_set, false)
			FROM openwacht.alert_channel_users cu LEFT JOIN openwacht.users u ON u.id = cu.user_id
			WHERE ($1 = '' OR cu.tenant_id = $1::uuid) ORDER BY lower(u.display_name)`, filter)
		if err != nil {
			return 0, nil, err
		}
		for rows.Next() {
			var ch string
			var ro recipientOut
			if err := rows.Scan(&ch, &ro.ID, &ro.Name, &ro.Abbestellt, &ro.Mobilnummer); err != nil {
				rows.Close()
				return 0, nil, err
			}
			if i, ok := idx[ch]; ok {
				list[i].Empfaenger = append(list[i].Empfaenger, ro)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"kanaele": list, "ziele": s.alertTargets.List(), "regeln": s.alertRules(),
			"mail_eingerichtet": s.mailConfig() != nil}, nil
	})
}

// setRecipients ersetzt die Empfänger eines Mail-Kanals. Nur Benutzer mit
// Rolle in genau dem Mandanten des Kanals (Fremdschlüssel und Policy).
func setRecipients(ctx context.Context, tx pgx.Tx, channel, tenant string, ids []string) error {
	if len(ids) > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT ra.user_id) FROM openwacht.role_assignments ra
			JOIN openwacht.users u ON u.id = ra.user_id
			WHERE ra.tenant_id = $1 AND ra.user_id = ANY ($2::uuid[])`, tenant, ids).Scan(&n); err != nil {
			return err
		}
		if n != len(uniq(ids)) {
			return badRequest("Empfänger müssen eine Rolle in genau diesem Mandanten haben.")
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM openwacht.alert_channel_users WHERE channel_id = $1`, channel); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO openwacht.alert_channel_users (channel_id, user_id)
		SELECT $1, x FROM unnest($2::uuid[]) AS x GROUP BY x`, channel, ids)
	return err
}

func uniq(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (s *Server) handleChannelCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in channelIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "alarmkanal anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		p, err := s.parseChannel(in, "")
		if err != nil {
			return 0, nil, err
		}
		if (p.kind == kindWebhook || p.kind == kindTeams) && p.url == "" {
			return 0, nil, badRequest("URL fehlt.")
		}
		id, err := newUUID()
		if err != nil {
			return 0, nil, err
		}
		if p.kind == kindSMS {
			details := map[string]any{"id": id, "name": p.name, "art": p.kind, "auch_untermandanten": in.Untermandanten}
			if err := s.smsCreate(ctx, tx, id, tid, p, in, details); err != nil {
				return 0, nil, err
			}
			if err := audit(ctx, tx, &tid, "alarmkanal.angelegt", details); err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, map[string]any{"id": id}, nil
		}
		var tokenEnc, secretEnc []byte
		var secret string
		switch p.kind {
		case kindNtfy:
			if in.Token != nil && *in.Token != "" {
				if tokenEnc, err = auth.Seal(s.boxKey, []byte(*in.Token), channelAAD(id, tid, p.server)); err != nil {
					return 0, nil, err
				}
			}
		case kindWebhook, kindTeams:
			if tokenEnc, err = auth.Seal(s.boxKey, []byte(p.url), channelAAD(id, tid, p.server)); err != nil {
				return 0, nil, err
			}
			if p.kind == kindWebhook {
				if secret, err = alarm.NewHookSecret(); err != nil {
					return 0, nil, err
				}
				if secretEnc, err = auth.Seal(s.boxKey, []byte(secret), hookSecretAAD(id, tid)); err != nil {
					return 0, nil, err
				}
			}
		}
		enabled := in.Aktiv == nil || *in.Aktiv
		allUsers := p.kind == kindMail && in.AlleBenutzer
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.alert_channels
				(id, tenant_id, name, kind, server, topic, token_enc, secret_enc, include_children, enabled, all_users)
			VALUES ($1, $2, $3, $4, nullif($5, ''), nullif($6, ''), $7, $8, $9, $10, $11)`,
			id, tid, p.name, p.kind, p.server, p.topic, tokenEnc, secretEnc, in.Untermandanten, enabled, allUsers); err != nil {
			return 0, nil, err
		}
		details := map[string]any{"id": id, "name": p.name, "art": p.kind, "auch_untermandanten": in.Untermandanten}
		switch p.kind {
		case kindNtfy:
			details["server"], details["topic"], details["token"] = p.server, p.topic, tokenEnc != nil
		case kindWebhook, kindTeams:
			details["host"] = p.server // die URL selbst ist geheim
		case kindMail:
			details["alle_benutzer"] = allUsers
			if in.Empfaenger != nil && !allUsers {
				if err := setRecipients(ctx, tx, id, tid, *in.Empfaenger); err != nil {
					return 0, nil, err
				}
				details["empfaenger"] = len(uniq(*in.Empfaenger))
			}
		}
		if err := audit(ctx, tx, &tid, "alarmkanal.angelegt", details); err != nil {
			return 0, nil, err
		}
		out := map[string]any{"id": id}
		if secret != "" {
			// Nur jetzt, danach nie wieder lesbar.
			out["geheimnis"] = secret
		}
		return http.StatusCreated, out, nil
	})
}

func (s *Server) handleChannelUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in channelIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "alarmkanal ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		// Der Mandant gehört in die AAD des Tokens. Nur Admins des Kanals
		// erreichen die Zeile (Policy); alle anderen bekommen 404.
		var tenant, kind, oldServer string
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, kind, coalesce(server, '') FROM openwacht.alert_channels
			WHERE id = $1 AND tenant_id IN (SELECT openwacht.admin_tenants()) FOR UPDATE`, id).Scan(&tenant, &kind, &oldServer); err != nil {
			return 0, nil, err
		}
		p, err := s.parseChannel(in, kind)
		if err != nil {
			return 0, nil, err
		}
		enabled := in.Aktiv == nil || *in.Aktiv
		details := map[string]any{"id": id, "name": p.name, "art": kind, "aktiv": enabled, "auch_untermandanten": in.Untermandanten}
		out := map[string]any{}
		switch kind {
		case kindNtfy:
			setToken := in.Token != nil
			var tokenEnc []byte
			if setToken && *in.Token != "" {
				if tokenEnc, err = auth.Seal(s.boxKey, []byte(*in.Token), channelAAD(id, tenant, p.server)); err != nil {
					return 0, nil, err
				}
			}
			var hasToken bool
			// Neuer Server ohne neues Token: Der Trigger entfernt das alte.
			// token_enc nur schreiben, nie lesen: Die Anwendungsrolle hat darauf
			// kein SELECT-Recht, also auch kein „SET token_enc = token_enc“.
			q := `UPDATE openwacht.alert_channels
				SET name = $2, server = $3, topic = $4, include_children = $5, enabled = $6
				WHERE id = $1 RETURNING has_token`
			args := []any{id, p.name, p.server, p.topic, in.Untermandanten, enabled}
			if setToken {
				q = `UPDATE openwacht.alert_channels
				SET name = $2, server = $3, topic = $4, include_children = $5, enabled = $6, token_enc = $7
				WHERE id = $1 RETURNING has_token`
				args = append(args, tokenEnc)
			}
			if err := tx.QueryRow(ctx, q, args...).Scan(&hasToken); err != nil {
				return 0, nil, err
			}
			details["server"], details["topic"], details["token"] = p.server, p.topic, hasToken
			if setToken {
				details["token_geaendert"] = true
			}
			out["token_gesetzt"], out["token_entfernt"] = hasToken, p.server != oldServer && !setToken
		case kindMail:
			if _, err := tx.Exec(ctx, `UPDATE openwacht.alert_channels
				SET name = $2, include_children = $3, enabled = $4, all_users = $5 WHERE id = $1`,
				id, p.name, in.Untermandanten, enabled, in.AlleBenutzer); err != nil {
				return 0, nil, err
			}
			details["alle_benutzer"] = in.AlleBenutzer
			if in.Empfaenger != nil {
				ids := *in.Empfaenger
				if in.AlleBenutzer {
					ids = nil
				}
				if err := setRecipients(ctx, tx, id, tenant, ids); err != nil {
					return 0, nil, err
				}
				details["empfaenger"] = len(uniq(ids))
			}
		case kindSMS:
			if err := s.smsUpdate(ctx, tx, id, tenant, p, in, details); err != nil {
				return 0, nil, err
			}
		case kindWebhook, kindTeams:
			if p.url == "" {
				if _, err := tx.Exec(ctx, `UPDATE openwacht.alert_channels
					SET name = $2, include_children = $3, enabled = $4 WHERE id = $1`,
					id, p.name, in.Untermandanten, enabled); err != nil {
					return 0, nil, err
				}
				break
			}
			enc, err := auth.Seal(s.boxKey, []byte(p.url), channelAAD(id, tenant, p.server))
			if err != nil {
				return 0, nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE openwacht.alert_channels
				SET name = $2, include_children = $3, enabled = $4, server = $5, token_enc = $6 WHERE id = $1`,
				id, p.name, in.Untermandanten, enabled, p.server, enc); err != nil {
				return 0, nil, err
			}
			details["host"], details["url_geaendert"] = p.server, true
		}
		if err := audit(ctx, tx, &tenant, "alarmkanal.geaendert", details); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

func (s *Server) handleChannelDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "alarmkanal löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.alert_channels WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "alarmkanal.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleChannelRecipients: mögliche Empfänger eines Mail-Kanals, also
// Benutzer mit Rolle in genau diesem Mandanten. Nur für Admins des Mandanten.
func (s *Server) handleChannelRecipients(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "alarm-empfaenger", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, tid).Scan(&admin); err != nil {
			return 0, nil, err
		}
		if !admin {
			return 0, nil, errNotFound
		}
		type candOut struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Email      string `json:"email"`
			Rolle      string `json:"rolle"`
			Abbestellt bool   `json:"abbestellt"`
			Mobil      bool   `json:"mobilnummer"`
		}
		rows, err := tx.Query(ctx, `SELECT u.id::text, u.display_name, u.email, ra.role, NOT u.alert_mail, u.alert_mobile_set
			FROM openwacht.role_assignments ra JOIN openwacht.users u ON u.id = ra.user_id
			WHERE ra.tenant_id = $1 AND NOT u.disabled ORDER BY lower(u.display_name) LIMIT 1000`, tid)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candOut, error) {
			var c candOut
			err := row.Scan(&c.ID, &c.Name, &c.Email, &c.Rolle, &c.Abbestellt, &c.Mobil)
			return c, err
		})
		if list == nil {
			list = []candOut{}
		}
		return http.StatusOK, map[string]any{"benutzer": list}, err
	})
}

// handleChannelTest: „Test senden“, nur für Admins des Kanals, höchstens
// alle 10 Sekunden je Kanal.
func (s *Server) handleChannelTest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var tenant string
	err := s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text FROM openwacht.alert_channels
			WHERE id = $1 AND tenant_id IN (SELECT openwacht.admin_tenants())`, id).Scan(&tenant)
	})
	if err != nil {
		writeDBError(w, "alarmkanal test", err)
		return
	}
	if !s.alertTestLimit.allow(id, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Gerade erst getestet. Bitte einen Moment warten.")
		return
	}
	chs, err := s.loadChannels(ctx, []string{id})
	if err == nil && len(chs) != 1 {
		err = errNotFound
	}
	if err != nil {
		writeDBError(w, "alarmkanal test", err)
		return
	}
	ch := chs[0]
	sendErr := s.sendTest(ctx, ch)
	var errText *string
	if sendErr != nil {
		t := sendErr.Error()
		errText = &t
	}
	bg := context.WithoutCancel(ctx)
	if _, err := s.pool.Exec(bg, `SELECT openwacht.alert_channel_result($1, $2)`, id, errText); err != nil {
		slog.Warn("Alarme: Testergebnis nicht gespeichert", "kanal", id, "fehler", err)
	}
	if err := s.withUser(bg, sess.UserID, func(tx pgx.Tx) error {
		return audit(bg, tx, &tenant, "alarmkanal.test", map[string]any{"id": id, "erfolg": sendErr == nil})
	}); err != nil {
		slog.Warn("Alarme: Audit für Test fehlgeschlagen", "kanal", id, "fehler", err)
	}
	if sendErr != nil {
		writeError(w, http.StatusBadGateway, "Versand fehlgeschlagen: "+sendErr.Error()+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gesendet": true})
}

// perKeyLimit erlaubt je Schlüssel einen Vorgang je Intervall.
type perKeyLimit struct {
	mu    sync.Mutex
	every time.Duration
	last  map[string]time.Time
}

func (l *perKeyLimit) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	for k, t := range l.last { // klein halten
		if now.Sub(t) >= l.every {
			delete(l.last, k)
		}
	}
	if _, busy := l.last[key]; busy {
		return false
	}
	l.last[key] = now
	return true
}

// alertRules: was die Zentrale meldet, für die Anzeige in der Oberfläche.
// Schwellen 0 = aus.
func (s *Server) alertRules() map[string]any {
	l := s.hostLimits()
	return map[string]any{
		"check_fehlschlaege": s.cfg.AlertThreshold,
		"erinnerung_h":       max(s.cfg.AlertReminder, 0).Hours(),
		"stumm_nach_s":       l.SilentAfter.Seconds(),
		"platte_warn":        l.DiskWarn, "platte_krit": l.DiskCrit,
		"speicher_warn": l.MemWarn, "speicher_krit": l.MemCrit,
		"cpu_warn": l.CPUWarn, "cpu_krit": l.CPUCrit, "platte_tage": l.DiskDays,
	}
}

// --- Versand ---------------------------------------------------------------------

type sendChannel struct {
	id, tenantID, tenantName, name, kind, server, topic string
	tokenEnc, secretEnc                                 []byte
	collect                                             bool // 1.0.1: Mail/SMS sammeln, mehrere Ereignisse in einer Nachricht
}

// collectWindow merkt je sammelndem Kanal, seit wann Ereignisse warten
// (nur im Speicher: Nach einem Neustart beginnt das Fenster neu).
type collectWindow struct {
	mu    sync.Mutex
	since map[string]time.Time
}

// due: Ist das Fenster des Kanals abgelaufen? Das erste Ereignis startet es.
func (w *collectWindow) due(id string, now time.Time, d time.Duration) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.since == nil {
		w.since = map[string]time.Time{}
	}
	start, ok := w.since[id]
	if !ok {
		w.since[id] = now
		return false
	}
	return now.Sub(start) >= d
}

// restart: neues Fenster ab now (nach einem Fehlschlag: erst in einer Minute
// erneut versuchen, statt das Relay alle 15 Sekunden anzufragen).
func (w *collectWindow) restart(id string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.since == nil {
		w.since = map[string]time.Time{}
	}
	w.since[id] = now
}

func (w *collectWindow) clear(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.since, id)
}

// keep: Fenster von Kanälen ohne wartende Ereignisse verwerfen (z. B. Sensor
// wieder OK, bevor gemeldet wurde: Dann gibt es nichts zu melden).
func (w *collectWindow) keep(waiting map[string][]pending) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id := range w.since {
		if len(waiting[id]) == 0 {
			delete(w.since, id)
		}
	}
}

// collectingChannels: welche der Kanäle sammeln (Schalter, nur Mail und SMS).
func (s *Server) collectingChannels(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if s.cfg.AlertCollect < 0 || len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM openwacht.alert_channels_collecting($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, id := range got {
		out[id] = true
	}
	return out, nil
}

func (s *Server) loadChannels(ctx context.Context, ids []string) ([]sendChannel, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, tenant_id::text, tenant_name, name, kind, coalesce(server, ''),
		coalesce(topic, ''), token_enc, secret_enc FROM openwacht.alert_channels_for_send($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (sendChannel, error) {
		var c sendChannel
		err := row.Scan(&c.id, &c.tenantID, &c.tenantName, &c.name, &c.kind, &c.server, &c.topic, &c.tokenEnc, &c.secretEnc)
		return c, err
	})
}

// sendTo entschlüsselt das Token und verschickt m (nur ntfy).
func (s *Server) sendTo(ctx context.Context, ch sendChannel, m alarm.Message) error {
	if ch.kind != kindNtfy {
		return errors.New("kein ntfy-Kanal")
	}
	var token string
	if ch.tokenEnc != nil {
		pt, err := auth.Open(s.boxKey, ch.tokenEnc, channelAAD(ch.id, ch.tenantID, ch.server))
		if err != nil {
			return errors.New("Token nicht entschlüsselbar, bitte neu eingeben")
		}
		token = string(pt)
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return s.alertSender.Send(sctx, ch.server, ch.topic, token, m)
}

// alertLockKey: Laufen mehrere Zentralen, verschickt immer nur eine.
const alertLockKey = 0x57414c41524d // "WALARM"

// RunAlerts verschickt fällige Alarme, bis ctx endet.
func (s *Server) RunAlerts(ctx context.Context) {
	tick := time.NewTicker(s.cfg.AlertPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		beat(&s.beats.alerts, s.now())
		s.reloadIfDue(ctx)
		_, failed, err := s.alertRoundR(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("Alarme: Durchlauf fehlgeschlagen", "fehler", err)
		}
		// Totmannschalter: Erfolg nur, wenn der Durchlauf geklappt hat und
		// jede Meldung zugestellt wurde.
		s.deadMan.Load().report(ctx, s.now(), err == nil && failed == 0)
	}
}

// pending: ein zu meldendes Ereignis, entweder für einen Check (checkID)
// oder für einen Gegenstand eines Agents (agentID, subject).
type pending struct {
	checkID, agentID, snmpID, subject, status string
	item                                      alarm.Item
}

// alertRoundN: ein Durchlauf, liefert die Zahl der Kanäle, an die gesendet
// wurde (für Tests).
func (s *Server) alertRoundN(ctx context.Context) (int, error) {
	sent, _, err := s.alertRoundR(ctx)
	return sent, err
}

// suppressed: In der Wartung gehen keine neuen Probleme und keine
// Erinnerungen raus, Entwarnungen schon.
func suppressed(ev alarm.Event, inMaintenance bool) bool {
	return inMaintenance && (ev == alarm.Problem || ev == alarm.Reminder)
}

// alertRoundR: ein Durchlauf; liefert, an wie viele Kanäle gesendet wurde und
// bei wie vielen der Versand scheiterte.
func (s *Server) alertRoundR(ctx context.Context) (sent, failed int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(alertLockKey)).Scan(&locked); err != nil {
		return 0, 0, err
	}
	if !locked {
		return 0, 0, nil // eine andere Zentrale ist dran
	}
	now := s.now()
	// Laufende Wartungsfenster als Wartung anlegen (Etappe 20b).
	s.syncWindows(ctx, tx, now)
	maint, err := loadMaintenance(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	// Geräte hinter einem ausgefallenen Gerät gelten wie in Wartung (Etappe 24).
	if err := addDependencies(ctx, tx, maint); err != nil {
		return 0, 0, err
	}
	// Alarmprotokoll abgleichen; bestätigte Alarme bekommen keine Erinnerung.
	acked := s.syncAlarms(ctx, tx, now, maint)

	rows, err := tx.Query(ctx, `SELECT check_id::text, tenant_name, check_name, status, message, fails,
		channel_id::text, coalesce(alerted, ''), alerted_at FROM openwacht.alert_candidates()`)
	if err != nil {
		return 0, 0, err
	}
	byChannel := map[string][]pending{}
	var order []string
	add := func(channel string, p pending) {
		if _, seen := byChannel[channel]; !seen {
			order = append(order, channel)
		}
		byChannel[channel] = append(byChannel[channel], p)
	}
	for rows.Next() {
		var p pending
		var fails int
		var channel, alerted string
		var alertedAt *time.Time
		if err := rows.Scan(&p.checkID, &p.item.Tenant, &p.item.Check, &p.status, &p.item.Message, &fails,
			&channel, &alerted, &alertedAt); err != nil {
			rows.Close()
			return 0, 0, err
		}
		var at time.Time
		if alertedAt != nil {
			at = *alertedAt
		}
		ev := alarm.Decide(p.status, fails, alerted, at, s.cfg.AlertThreshold, s.cfg.AlertReminder, now)
		if ev == alarm.None || ev == alarm.Reminder && acked[alarmKeyCheck(p.checkID)] ||
			suppressed(ev, maint.check(p.checkID)) {
			continue
		}
		p.item.Status, p.item.Event = p.status, ev
		add(channel, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if err := s.hostAlerts(ctx, tx, now, acked, maint, add); err != nil {
		return 0, 0, err
	}
	if err := s.snmpAlerts(ctx, tx, now, acked, maint, add); err != nil {
		return 0, 0, err
	}
	// Eskalationen (Etappe 24) beziehen sich auf den Stand vor diesem Durchlauf.
	escSent, escFailed := s.escalate(ctx, tx, maint, now)
	sent, failed = escSent, escFailed
	// Bereitschaft: Kanäle außerhalb ihres Zeitfensters warten.
	if len(order) > 0 {
		inactive, err := s.inactiveChannels(ctx, tx, order, now)
		if err != nil {
			return 0, 0, err
		}
		order = slices.DeleteFunc(order, func(id string) bool { return inactive[id] })
	}
	// Sammeln (1.0.1): Mail und SMS warten ab dem ersten Ereignis AlertCollect
	// und schicken dann alles in einer Nachricht.
	s.collect.keep(byChannel)
	collecting, err := s.collectingChannels(ctx, order)
	if err != nil {
		return 0, 0, err
	}
	order = slices.DeleteFunc(order, func(id string) bool {
		return collecting[id] && !s.collect.due(id, now, s.cfg.AlertCollect)
	})
	if len(order) == 0 {
		return sent, failed, tx.Commit(ctx) // Commit: Abgleich des Alarmprotokolls und der Wartungen
	}
	chs, err := s.loadChannels(ctx, order)
	if err != nil {
		return 0, 0, err
	}
	// Mail, Webhook und Teams bekommen ausführliche Meldungen; die Details
	// liest die Zentrale vor dem Versand (ohne die Transaktion des Durchlaufs).
	d := s.prepareDelivery(ctx, chs, byChannel, maint, now)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var mu sync.Mutex
	for _, ch := range chs {
		list := byChannel[ch.id]
		ch.collect = collecting[ch.id]
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			done, err := s.deliver(ctx, ch, list, d)
			if ctx.Err() != nil {
				return // Zentrale wird beendet; beim nächsten Start erneut
			}
			bg := context.WithoutCancel(ctx)
			// Gemeldet ist, was gesendet wurde, auch wenn sich der Zustand
			// inzwischen geändert hat; das meldet dann der nächste Durchlauf.
			if len(done) > 0 {
				if e := s.commitSent(bg, ch.id, done); e != nil {
					slog.Warn("Alarme: Versand nicht vermerkt, wird wiederholt", "kanal", ch.id, "fehler", e)
					return
				}
			}
			if ch.collect {
				if err != nil {
					s.collect.restart(ch.id, now) // erst nach dem nächsten Fenster erneut
				} else {
					s.collect.clear(ch.id)
				}
			}
			if err != nil {
				slog.Warn("Alarme: Versand fehlgeschlagen", "kanal", ch.id, "art", ch.kind, "ereignisse", len(list),
					"gesendet", len(done), "fehler", err)
				mu.Lock()
				failed++
				mu.Unlock()
				if _, e := s.pool.Exec(bg, `SELECT openwacht.alert_channel_result($1, $2)`, ch.id, err.Error()); e != nil {
					slog.Warn("Alarme: Fehler nicht gespeichert", "kanal", ch.id, "fehler", e)
				}
				return
			}
			mu.Lock()
			sent++
			mu.Unlock()
		}()
	}
	wg.Wait()
	// Die Transaktion hält die Sperre und enthält den Abgleich des
	// Alarmprotokolls; der Versand selbst ist schon einzeln vermerkt.
	return sent, failed, tx.Commit(context.WithoutCancel(ctx))
}

// commitSent vermerkt in einer Transaktion, was an einen Kanal gemeldet wurde.
func (s *Server) commitSent(ctx context.Context, channel string, list []pending) error {
	var checkIDs, checkSts, agentIDs, subjects, agentSts, snmpIDs, snmpSubs, snmpSts []string
	for _, p := range list {
		if p.snmpID != "" {
			snmpIDs, snmpSubs, snmpSts = append(snmpIDs, p.snmpID), append(snmpSubs, p.subject), append(snmpSts, p.status)
		} else if p.agentID != "" {
			agentIDs, subjects, agentSts = append(agentIDs, p.agentID), append(subjects, p.subject), append(agentSts, p.status)
		} else {
			checkIDs, checkSts = append(checkIDs, p.checkID), append(checkSts, p.status)
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if len(checkIDs) > 0 {
			if _, err := tx.Exec(ctx, `SELECT openwacht.alert_commit($1, $2::uuid[], $3::text[])`, channel, checkIDs, checkSts); err != nil {
				return err
			}
		}
		if len(agentIDs) > 0 {
			if _, err := tx.Exec(ctx, `SELECT openwacht.alert_host_commit($1, $2::uuid[], $3::text[], $4::text[])`,
				channel, agentIDs, subjects, agentSts); err != nil {
				return err
			}
		}
		if len(snmpIDs) > 0 {
			if _, err := tx.Exec(ctx, `SELECT openwacht.alert_snmp_commit($1, $2::uuid[], $3::text[], $4::text[])`,
				channel, snmpIDs, snmpSubs, snmpSts); err != nil {
				return err
			}
		}
		return nil
	})
}

type hostState struct {
	alerted string
	at      time.Time
}

// hostAlerts bewertet die Agents (stumm, Platte, Arbeitsspeicher) je
// zuständigem Kanal und übergibt fällige Ereignisse an add.
func (s *Server) hostAlerts(ctx context.Context, tx pgx.Tx, now time.Time, acked map[string]bool, maint maintenanceSet,
	add func(string, pending)) error {
	// Gemeldete Probleme: Agent → Kanal → Gegenstand.
	prev := map[string]map[string]map[string]hostState{}
	rows, err := tx.Query(ctx, `SELECT agent_id::text, channel_id::text, subject, alerted, alerted_at
		FROM openwacht.alert_host_states()`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var agent, channel, subject string
		var st hostState
		if err := rows.Scan(&agent, &channel, &subject, &st.alerted, &st.at); err != nil {
			rows.Close()
			return err
		}
		if prev[agent] == nil {
			prev[agent] = map[string]map[string]hostState{}
		}
		if prev[agent][channel] == nil {
			prev[agent][channel] = map[string]hostState{}
		}
		prev[agent][channel][subject] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = tx.Query(ctx, `SELECT agent_id::text, tenant_name, hostname, revoked, silent_s, metrics, channels::text[]
		FROM openwacht.alert_host_candidates()`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var agent, tenantName string
		var raw []byte
		var silent float64
		var channels []string
		var in alarm.HostInput
		if err := rows.Scan(&agent, &tenantName, &in.Hostname, &in.Revoked, &silent, &raw, &channels); err != nil {
			return err
		}
		lim := s.limitsFor("agent", agent)
		in.Warming = now.Sub(s.started) < lim.SilentAfter
		in.Silent = time.Duration(silent * float64(time.Second))
		if raw != nil {
			var m alarm.HostMetrics
			if err := json.Unmarshal(raw, &m); err == nil {
				in.Metrics = s.withFullDays(&m, agent)
			} else {
				slog.Warn("Alarme: Messwerte eines Agents nicht lesbar", "agent", agent, "fehler", err)
			}
		}
		for _, channel := range channels {
			states := prev[agent][channel]
			alerted := make(map[string]string, len(states))
			for sub, st := range states {
				alerted[sub] = st.alerted
			}
			for _, f := range alarm.EvaluateHost(in, alerted, lim) {
				st := states[f.Subject]
				// Ein Host-Problem steht schon fest, wenn es bewertet wird
				// (stumm erst nach HostSilentAfter): keine weiteren Fehlschläge abwarten.
				ev := alarm.Decide(f.Status, s.cfg.AlertThreshold, st.alerted, st.at,
					s.cfg.AlertThreshold, s.cfg.AlertReminder, now)
				if ev == alarm.None || ev == alarm.Reminder && acked[alarmKeyHost(agent, f.Subject)] ||
					suppressed(ev, maint.agent(agent)) {
					continue
				}
				add(channel, pending{agentID: agent, subject: f.Subject, status: f.Status,
					item: alarm.Item{Tenant: tenantName, Check: f.Name, Status: f.Status, Message: f.Message, Event: ev}})
			}
		}
	}
	return rows.Err()
}

// snmpRow: was Alarme, Alarmprotokoll und Sensoren über eine SNMP-Quelle lesen.
type snmpRow struct {
	id, name, lastError string
	disabled            bool
	silent              float64
	interval            int
	raw                 []byte
	cpu15               *float64
	rebootedS           *float64
	watched             []string
	version             string    // '1', '2c', '3', 'pve', 'tr064', 'vcenter', 'ontap' oder 'xapi'
	now                 time.Time // Zeitpunkt der Bewertung (Alter der Backups)
	traps               []byte    // Trap-Zustände (snmp_trap_states_json)
	// Sammler (Etappe 15): Name des Geräts des Agents, NULL = die Zentrale fragt ab
	collector        *string
	collectorOn      *bool
	collectorRevoked *bool
	collectorSeenS   *float64
	// ausgenommene Gegenstände (0.99.2) → Begründung, leer ohne Benutzerkontext
	excluded map[string]string
}

// snmpExclusions: ausgenommene Gegenstände aller Quellen, die der Kontext sehen
// darf (ohne Kontext: alle, für die Alarme). Nur Quelle und Gegenstand.
func snmpExclusions(ctx context.Context, tx pgx.Tx) (map[string]map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT snmp_id::text, subject FROM openwacht.snmp_exclusions_all()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var src, sub string
		if err := rows.Scan(&src, &sub); err != nil {
			return nil, err
		}
		if out[src] == nil {
			out[src] = map[string]string{}
		}
		out[src][sub] = ""
	}
	return out, rows.Err()
}

// snmpCollectorColumns: die Spalten zum Sammler aus alert_snmp_candidates und
// alarm_snmp_sources (Migration 0018).
const snmpCollectorColumns = `collector, collector_on, collector_revoked, collector_seen_s`

func (q *snmpRow) collectorDest() []any {
	return []any{&q.collector, &q.collectorOn, &q.collectorRevoked, &q.collectorSeenS}
}

// collectorDown: Grund, warum der Sammler der Quelle gerade nicht abfragt
// ("" = er fragt ab oder es gibt keinen). Ein gesperrter Sammler fällt nicht
// aus, sondern ist falsch eingerichtet: Dann alarmieren die Geräte selbst.
func (q snmpRow) collectorDown(lim alarm.HostLimits) string {
	if q.collector == nil || q.collectorRevoked != nil && *q.collectorRevoked {
		return ""
	}
	c := alarm.CollectorMetrics{Devices: 1, On: q.collectorOn != nil && *q.collectorOn, FetchedAgoS: q.collectorSeenS}
	if why := c.Down(lim.SilentAfter); why != "" {
		return "Sammler " + *q.collector + " " + why
	}
	return ""
}

// input baut die Bewertungseingabe; silentOverride < 0 = gemessen.
func (q snmpRow) input(warming bool, lim alarm.HostLimits) alarm.SNMPInput {
	in := alarm.SNMPInput{Name: q.name, Disabled: q.disabled, Warming: warming, LastError: q.lastError,
		Silent: time.Duration(q.silent * float64(time.Second)), Interval: time.Duration(q.interval) * time.Second,
		CPU15: q.cpu15, Watched: q.watched, Excluded: q.excluded, Proxmox: q.version == versionPVE || q.version == versionVCenter, FritzBox: q.version == versionTR064, ONTAP: q.version == versionONTAP, XAPI: q.version == versionXAPI, Now: q.now, CollectorDown: q.collectorDown(lim)}
	if q.collector != nil && q.collectorRevoked != nil && *q.collectorRevoked {
		in.LastError = "Sammler " + *q.collector + " ist gesperrt, bitte unter „Abgefragt von“ einen anderen wählen"
	}
	if q.rebootedS != nil {
		d := time.Duration(*q.rebootedS * float64(time.Second))
		in.RebootedAgo = &d
	}
	if q.traps != nil {
		if err := json.Unmarshal(q.traps, &in.Traps); err != nil {
			slog.Warn("Trap-Zustände einer SNMP-Quelle nicht lesbar", "quelle", q.id, "fehler", err)
		}
	}
	if q.raw != nil {
		var snap snmp.Snapshot
		if err := json.Unmarshal(q.raw, &snap); err == nil {
			in.Snapshot = &snap
		} else {
			slog.Warn("Messwerte einer SNMP-Quelle nicht lesbar", "quelle", q.id, "fehler", err)
		}
	}
	return in
}

type snmpState = hostState

// snmpAlerts bewertet die SNMP-Quellen je zuständigem Kanal (wie hostAlerts).
func (s *Server) snmpAlerts(ctx context.Context, tx pgx.Tx, now time.Time, acked map[string]bool, maint maintenanceSet,
	add func(string, pending)) error {
	prev := map[string]map[string]map[string]snmpState{}
	rows, err := tx.Query(ctx, `SELECT snmp_id::text, channel_id::text, subject, alerted, alerted_at
		FROM openwacht.alert_snmp_states()`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var src, channel, subject string
		var st snmpState
		if err := rows.Scan(&src, &channel, &subject, &st.alerted, &st.at); err != nil {
			rows.Close()
			return err
		}
		if prev[src] == nil {
			prev[src] = map[string]map[string]snmpState{}
		}
		if prev[src][channel] == nil {
			prev[src][channel] = map[string]snmpState{}
		}
		prev[src][channel][subject] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	excluded, err := snmpExclusions(ctx, tx)
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT snmp_id::text, tenant_name, name, disabled, silent_s, interval_s, last_error, snapshot,
		cpu15, rebooted_s, watched, channels::text[], version, traps, `+snmpCollectorColumns+` FROM openwacht.alert_snmp_candidates()`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var q snmpRow
		var tenantName string
		var channels []string
		if err := rows.Scan(append([]any{&q.id, &tenantName, &q.name, &q.disabled, &q.silent, &q.interval, &q.lastError, &q.raw,
			&q.cpu15, &q.rebootedS, &q.watched, &channels, &q.version, &q.traps}, q.collectorDest()...)...); err != nil {
			return err
		}
		q.now = now
		q.excluded = excluded[q.id]
		lim := s.limitsFor("snmp", q.id)
		in := q.input(now.Sub(s.started) < alarm.SilentLimit(lim, time.Duration(q.interval)*time.Second), lim)
		in.FullDays = s.fullDaysFor("snmp", q.id)
		for _, channel := range channels {
			states := prev[q.id][channel]
			alerted := make(map[string]string, len(states))
			for sub, st := range states {
				alerted[sub] = st.alerted
			}
			for _, f := range alarm.EvaluateSNMP(in, alerted, lim) {
				st := states[f.Subject]
				ev := alarm.Decide(f.Status, s.cfg.AlertThreshold, st.alerted, st.at,
					s.cfg.AlertThreshold, s.cfg.AlertReminder, now)
				if ev == alarm.None || ev == alarm.Reminder && acked[alarmKeySNMP(q.id, f.Subject)] ||
					suppressed(ev, maint.source(q.id)) {
					continue
				}
				add(channel, pending{snmpID: q.id, subject: f.Subject, status: f.Status,
					item: alarm.Item{Tenant: tenantName, Check: f.Name, Status: f.Status, Message: f.Message, Event: ev}})
			}
		}
	}
	return rows.Err()
}
