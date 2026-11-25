// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/update"
)

// Automatische, gestaffelte Agent-Updates (1.0.4). Die Regel gilt je Mandant
// für dessen Agents. Beim Melden eines Agents prüft die Zentrale, ob die
// neueste hochgeladene Version für ihn dran ist, und trägt dann eine Freigabe
// ein („automatisch“). Danach läuft alles wie bei einer Freigabe von Hand:
// Der Agent lädt, prüft die Signatur und installiert über seinen getrennten
// Installationsdienst.

// autoCandidate: Zeile aus openwacht.agent_update_auto_candidate.
type autoCandidate struct {
	Version     string
	Uploaded    time.Time
	Pilot       bool
	WaitHours   int
	Days        int // Bits, Montag = 1 … Sonntag = 64
	HourFrom    int
	HourTo      int
	Pilots      int
	PilotsOK    int
	PilotsError int
}

// inWindow: liegt t (in der Zeitzone der Installation) im Zeitfenster?
// HourFrom == HourTo heißt ganzer Tag; HourFrom > HourTo reicht über
// Mitternacht und zählt zum Wochentag des Beginns.
func (c autoCandidate) inWindow(t time.Time) bool {
	bit := func(d time.Weekday) bool { return c.Days&(1<<((int(d)+6)%7)) != 0 }
	h := t.Hour()
	switch {
	case c.HourFrom == c.HourTo:
		return bit(t.Weekday())
	case c.HourFrom < c.HourTo:
		return bit(t.Weekday()) && h >= c.HourFrom && h < c.HourTo
	case h >= c.HourFrom:
		return bit(t.Weekday())
	case h < c.HourTo:
		return bit(t.AddDate(0, 0, -1).Weekday())
	}
	return false
}

// autoReason: warum ein Agent die Version (noch) nicht bekommt; "" = jetzt.
func (c autoCandidate) autoReason(agentVersion string, now time.Time) string {
	switch {
	case !update.Newer(c.Version, agentVersion):
		return "aktuell"
	case !c.inWindow(now):
		return "außerhalb des Zeitfensters"
	case c.Pilot:
		return ""
	case now.Before(c.Uploaded.Add(time.Duration(c.WaitHours) * time.Hour)):
		return "Wartezeit läuft"
	case c.PilotsError > 0:
		return "angehalten: ein Pilot meldet einen Fehler"
	case c.Pilots > 0 && c.PilotsOK == 0:
		return "wartet auf die Piloten"
	}
	return ""
}

// autoRelease: beim Melden eines Agents die Regel anwenden. Fehler nur ins
// Log; die Meldung des Agents scheitert daran nie.
func (s *Server) autoRelease(ctx context.Context, agentID, goos, arch, agentVersion string) {
	var c autoCandidate
	var days, from, to int16
	err := s.pool.QueryRow(ctx, `SELECT version, uploaded_at, pilot, wait_hours, days, hour_from, hour_to, pilots, pilots_ok, pilots_error
		FROM openwacht.agent_update_auto_candidate($1, $2, $3)`, agentID, goos, arch).
		Scan(&c.Version, &c.Uploaded, &c.Pilot, &c.WaitHours, &days, &from, &to, &c.Pilots, &c.PilotsOK, &c.PilotsError)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("Agent-Update: Automatik nicht lesbar", "fehler", err)
		}
		return
	}
	c.Days, c.HourFrom, c.HourTo = int(days), int(from), int(to)
	loc, _ := s.zone()
	if c.autoReason(agentVersion, s.now().In(loc)) != "" {
		return
	}
	var done bool
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.agent_update_auto_release($1, $2, $3, $4)`, agentID, goos, arch, c.Version).
		Scan(&done); err != nil {
		slog.Warn("Agent-Update: automatische Freigabe gescheitert", "fehler", err)
		return
	}
	if done {
		slog.Info("Agent-Update automatisch freigegeben", "agent", agentID, "version", c.Version, "pilot", c.Pilot)
	}
}

// --- Oberfläche ---------------------------------------------------------------

type autoRegel struct {
	MandantID string  `json:"mandant_id"`
	Aktiv     bool    `json:"aktiv"`
	Pilot     *string `json:"pilotgruppe"`
	Wartezeit int     `json:"wartezeit_stunden"`
	Tage      []int   `json:"tage"` // 1 = Montag … 7 = Sonntag
	Von       int     `json:"von"`
	Bis       int     `json:"bis"`
	Geaendert *string `json:"geaendert_am,omitempty"`
}

func tageAusBits(b int) []int {
	out := []int{}
	for i := 0; i < 7; i++ {
		if b&(1<<i) != 0 {
			out = append(out, i+1)
		}
	}
	return out
}

// handleAutoList: Regeln aller sichtbaren Mandanten.
func (s *Server) handleAutoList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "agent-updates automatik", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, enabled, pilot_group::text, wait_hours, days, hour_from, hour_to, updated_at
			FROM openwacht.agent_update_auto ORDER BY tenant_id`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (autoRegel, error) {
			var a autoRegel
			var days, from, to int16
			var at time.Time
			err := row.Scan(&a.MandantID, &a.Aktiv, &a.Pilot, &a.Wartezeit, &days, &from, &to, &at)
			a.Tage, a.Von, a.Bis = tageAusBits(int(days)), int(from), int(to)
			t := at.UTC().Format(time.RFC3339)
			a.Geaendert = &t
			return a, err
		})
		if list == nil {
			list = []autoRegel{}
		}
		return http.StatusOK, map[string]any{"regeln": list}, err
	})
}

// handleAutoSet: Regel eines Mandanten setzen (Admins des Mandanten oder darüber).
func (s *Server) handleAutoSet(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Aktiv     *bool   `json:"aktiv"`
		Pilot     *string `json:"pilotgruppe"`
		Wartezeit *int    `json:"wartezeit_stunden"`
		Tage      []int   `json:"tage"`
		Von       *int    `json:"von"`
		Bis       *int    `json:"bis"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "agent-updates automatik", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if in.Aktiv == nil || in.Wartezeit == nil || in.Von == nil || in.Bis == nil || len(in.Tage) == 0 {
			return 0, nil, badRequest("Es fehlen Angaben: aktiv, wartezeit_stunden, tage, von, bis.")
		}
		if *in.Wartezeit < 0 || *in.Wartezeit > 720 {
			return 0, nil, badRequest("Wartezeit: 0 bis 720 Stunden.")
		}
		if *in.Von < 0 || *in.Von > 23 || *in.Bis < 0 || *in.Bis > 23 {
			return 0, nil, badRequest("Zeitfenster: Stunden 0 bis 23.")
		}
		days := 0
		for _, d := range in.Tage {
			if d < 1 || d > 7 {
				return 0, nil, badRequest("Tage: 1 (Montag) bis 7 (Sonntag).")
			}
			days |= 1 << (d - 1)
		}
		var pilot *string
		if in.Pilot != nil && *in.Pilot != "" {
			if !uuidPattern.MatchString(*in.Pilot) {
				return 0, nil, badRequest("Ungültige Pilotgruppe.")
			}
			pilot = in.Pilot
		}
		// Nur Admins des Mandanten oder darüber (RLS); sonst 404, wie überall.
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, tid).Scan(&admin); err != nil {
			return 0, nil, err
		}
		if !admin {
			return 0, nil, errNotFound
		}
		if pilot != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.device_groups WHERE id = $1 AND tenant_id = $2)`,
				*pilot, tid).Scan(&ok); err != nil {
				return 0, nil, err
			}
			if !ok {
				return 0, nil, badRequest("Die Pilotgruppe muss eine Gruppe dieses Mandanten sein.")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_update_auto (tenant_id, enabled, pilot_group, wait_hours, days, hour_from, hour_to)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, pilot_group = EXCLUDED.pilot_group,
				wait_hours = EXCLUDED.wait_hours, days = EXCLUDED.days, hour_from = EXCLUDED.hour_from, hour_to = EXCLUDED.hour_to`,
			tid, *in.Aktiv, pilot, *in.Wartezeit, days, *in.Von, *in.Bis); err != nil {
			return 0, nil, err
		}
		out := autoRegel{MandantID: tid, Aktiv: *in.Aktiv, Pilot: pilot, Wartezeit: *in.Wartezeit, Tage: tageAusBits(days), Von: *in.Von, Bis: *in.Bis}
		return http.StatusOK, out, audit(ctx, tx, &tid, "agent_update.automatik", map[string]any{"aktiv": out.Aktiv,
			"pilotgruppe": pilot, "wartezeit_stunden": out.Wartezeit, "tage": out.Tage, "von": out.Von, "bis": out.Bis})
	})
}
