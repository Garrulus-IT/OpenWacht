// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Wartungsfenster (Etappe 20b): einmalig in der Zukunft, wöchentlich oder
// monatlich (Patchday), für ein Gerät, einen Sensor oder eine Gruppe mit
// Untergruppen. Die Termine rechnet internal/fenster aus. In jedem
// Alarmdurchlauf schreibt die Zentrale laufende Vorkommen als gewöhnliche
// Wartung in openwacht.maintenance (maintenance_window_apply); Alarme, Hosts,
// Wandanzeige und Dashboard behandeln sie damit wie jede Wartung.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/garrulus-it/openwacht/internal/fenster"
)

// windowRow: Spalten eines Fensters (ohne Ziel und Namen).
type windowRow struct {
	repeat                        string
	startsAt, endsAt              *time.Time
	weekdays, nth, weekday, offst *int16
	startTime                     pgtype.Time
	durationMin                   *int32
	tz                            string
}

func (w *windowRow) dest() []any {
	return []any{&w.repeat, &w.startsAt, &w.endsAt, &w.weekdays, &w.nth, &w.weekday, &w.offst, &w.startTime, &w.durationMin, &w.tz}
}

// rule: die Regel zur Zeile; Fehler bei unbekannter Zeitzone.
func (w *windowRow) rule() (fenster.Rule, error) {
	loc, err := fenster.LoadZone(w.tz)
	if err != nil {
		return fenster.Rule{}, err
	}
	r := fenster.Rule{Repeat: w.repeat, Loc: loc}
	i := func(p *int16) int {
		if p == nil {
			return 0
		}
		return int(*p)
	}
	switch w.repeat {
	case fenster.Once:
		if w.startsAt != nil && w.endsAt != nil {
			r.Start, r.End = *w.startsAt, *w.endsAt
		}
	default:
		r.Weekdays, r.Nth, r.Weekday, r.Offset = uint8(i(w.weekdays)), i(w.nth), i(w.weekday), i(w.offst)
		if w.startTime.Valid {
			m := w.startTime.Microseconds / 60e6
			r.Hour, r.Minute = int(m/60), int(m%60)
		}
		if w.durationMin != nil {
			r.Duration = time.Duration(*w.durationMin) * time.Minute
		}
	}
	return r, r.Validate()
}

// syncWindows: laufende Vorkommen als Wartung anlegen (im Alarmdurchlauf,
// vor dem Lesen der Wartungen). Fehler kosten nur die Fenster, nie den Durchlauf.
func (s *Server) syncWindows(ctx context.Context, outer pgx.Tx, now time.Time) {
	// Eigener Sicherungspunkt: Ein Fehler hier bricht den Durchlauf nicht ab.
	tx, err := outer.Begin(ctx)
	if err != nil {
		slog.Warn("Wartungsfenster: kein Sicherungspunkt", "fehler", err)
		return
	}
	defer tx.Rollback(ctx) // nach Commit ohne Wirkung
	rows, err := tx.Query(ctx, `SELECT id::text, repeat, starts_at, ends_at, weekdays, nth, weekday, offset_days,
		start_time, duration_min, tz FROM openwacht.maintenance_windows_all()`)
	if err != nil {
		slog.Warn("Wartungsfenster: nicht lesbar", "fehler", err)
		return
	}
	type due struct {
		id  string
		end time.Time
	}
	var list []due
	for rows.Next() {
		var id string
		var w windowRow
		if err := rows.Scan(append([]any{&id}, w.dest()...)...); err != nil {
			rows.Close()
			slog.Warn("Wartungsfenster: nicht lesbar", "fehler", err)
			return
		}
		r, err := w.rule()
		if err != nil {
			slog.Warn("Wartungsfenster: ungültig, übersprungen", "fenster", id, "fehler", err)
			continue
		}
		if end, ok := r.Active(now); ok {
			list = append(list, due{id, end})
		}
	}
	rows.Close()
	for _, d := range list {
		var n int
		if err := tx.QueryRow(ctx, `SELECT openwacht.maintenance_window_apply($1, $2)`, d.id, d.end).Scan(&n); err != nil {
			slog.Warn("Wartungsfenster: nicht angewendet", "fenster", d.id, "fehler", err)
			return // Transaktion ist abgebrochen
		}
		if n > 0 {
			slog.Info("Wartungsfenster: Wartung begonnen", "fenster", d.id, "ziele", n, "bis", d.end)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("Wartungsfenster: nicht übernommen", "fehler", err)
	}
}

// --- API -------------------------------------------------------------------------

type windowIn struct {
	Name         string  `json:"name"`
	Grund        string  `json:"grund"`
	ZielArt      string  `json:"ziel_art"` // geraet, sensor, gruppe
	ZielID       string  `json:"ziel_id"`
	Untergruppen *bool   `json:"untergruppen"`
	Wiederholung string  `json:"wiederholung"`
	Beginn       *string `json:"beginn"` // einmalig, RFC 3339
	Ende         *string `json:"ende"`
	Wochentage   []int   `json:"wochentage"` // 1 = Montag … 7 = Sonntag
	Nter         int     `json:"nter"`       // 1–4, -1 = letzter
	Wochentag    int     `json:"wochentag"`
	Versatz      int     `json:"versatz"`
	Uhrzeit      string  `json:"uhrzeit"` // HH:MM
	DauerMin     int     `json:"dauer_min"`
	Zeitzone     string  `json:"zeitzone"`
	Aktiv        *bool   `json:"aktiv"`
}

// parsedWindow: geprüfte Eingabe, als Argumente für INSERT/UPDATE.
type parsedWindow struct {
	name, reason, repeat, tz string
	device, check, group     *string
	subgroups, enabled       bool
	start, end               *time.Time
	weekdays, nth, wday, off *int16
	startTime                *string
	duration                 *int32
	rule                     fenster.Rule
}

func (p parsedWindow) args() []any {
	return []any{p.name, p.reason, p.device, p.check, p.group, p.subgroups, p.repeat, p.start, p.end, p.weekdays,
		p.nth, p.wday, p.off, p.startTime, p.duration, p.tz, p.enabled}
}

const windowCols = `name, reason, device_id, check_id, group_id, with_subgroups, repeat, starts_at, ends_at, weekdays,
	nth, weekday, offset_days, start_time, duration_min, tz, enabled`

func i16(v int) *int16 { x := int16(v); return &x }

func parseWindow(in windowIn, now time.Time, defaultTZ string) (p parsedWindow, err error) {
	if p.name, err = cleanName(in.Name); err != nil {
		return
	}
	if p.reason, err = cleanReason(in.Grund); err != nil {
		return
	}
	if !uuidPattern.MatchString(in.ZielID) {
		return p, badRequest("Ziel fehlt.")
	}
	id := in.ZielID
	switch in.ZielArt {
	case "geraet":
		p.device = &id
	case "sensor":
		p.check = &id
	case "gruppe":
		p.group = &id
	default:
		return p, badRequest("Ziel: Gerät, Sensor oder Gruppe.")
	}
	p.subgroups = in.Untergruppen == nil || *in.Untergruppen
	p.enabled = in.Aktiv == nil || *in.Aktiv
	p.tz = strings.TrimSpace(in.Zeitzone)
	if p.tz == "" {
		p.tz = defaultTZ
	}
	loc, err := fenster.LoadZone(p.tz)
	if err != nil {
		return p, badRequest(err.Error() + ".")
	}
	p.repeat = in.Wiederholung
	r := fenster.Rule{Repeat: p.repeat, Loc: loc}
	switch p.repeat {
	case fenster.Once:
		if in.Beginn == nil || in.Ende == nil {
			return p, badRequest("Beginn und Ende fehlen.")
		}
		st, err1 := time.Parse(time.RFC3339, *in.Beginn)
		en, err2 := time.Parse(time.RFC3339, *in.Ende)
		if err1 != nil || err2 != nil {
			return p, badRequest("Beginn und Ende als Zeitpunkt (RFC 3339).")
		}
		st, en = st.Truncate(time.Minute), en.Truncate(time.Minute)
		if !en.After(now) {
			return p, badRequest("Das Ende liegt in der Vergangenheit.")
		}
		r.Start, r.End = st, en
		p.start, p.end = &st, &en
	case fenster.Weekly, fenster.Monthly:
		var h, m int
		if n, _ := fmt.Sscanf(in.Uhrzeit, "%d:%d", &h, &m); n != 2 || len(in.Uhrzeit) != 5 {
			return p, badRequest("Uhrzeit als HH:MM.")
		}
		r.Hour, r.Minute = h, m
		r.Duration = time.Duration(in.DauerMin) * time.Minute
		t := fmt.Sprintf("%02d:%02d", h, m)
		d := int32(in.DauerMin)
		p.startTime, p.duration = &t, &d
		if p.repeat == fenster.Weekly {
			var bits uint8
			for _, wd := range in.Wochentage {
				if wd < 1 || wd > 7 {
					return p, badRequest("Wochentage: 1 (Montag) bis 7 (Sonntag).")
				}
				bits |= 1 << (wd - 1)
			}
			r.Weekdays = bits
			p.weekdays = i16(int(bits))
		} else {
			r.Nth, r.Weekday, r.Offset = in.Nter, in.Wochentag, in.Versatz
			p.nth, p.wday, p.off = i16(in.Nter), i16(in.Wochentag), i16(in.Versatz)
		}
	default:
		return p, badRequest("Wiederholung: einmalig, woechentlich oder monatlich.")
	}
	if err := r.Validate(); err != nil {
		return p, badRequest(strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + ".")
	}
	p.rule = r
	return p, nil
}

type windowOut struct {
	ID           string        `json:"id"`
	MandantID    string        `json:"mandant_id"`
	Name         string        `json:"name"`
	Grund        string        `json:"grund"`
	ZielArt      string        `json:"ziel_art"`
	ZielID       string        `json:"ziel_id"`
	ZielName     string        `json:"ziel_name"`
	Untergruppen bool          `json:"untergruppen"`
	Wiederholung string        `json:"wiederholung"`
	Beginn       *time.Time    `json:"beginn"`
	Ende         *time.Time    `json:"ende"`
	Wochentage   []int         `json:"wochentage"`
	Nter         *int16        `json:"nter"`
	Wochentag    *int16        `json:"wochentag"`
	Versatz      *int16        `json:"versatz"`
	Uhrzeit      *string       `json:"uhrzeit"`
	DauerMin     *int32        `json:"dauer_min"`
	Zeitzone     string        `json:"zeitzone"`
	Aktiv        bool          `json:"aktiv"`
	Von          *string       `json:"von"`
	Text         string        `json:"text"`
	LaeuftBis    *time.Time    `json:"laeuft_bis"`
	Naechstes    *[2]time.Time `json:"naechstes"`
}

type runningOut struct {
	ID        string    `json:"id"`
	MandantID string    `json:"mandant_id"`
	GeraetID  *string   `json:"geraet_id"`
	CheckID   *string   `json:"check_id"`
	Geraet    string    `json:"geraet"`
	Sensor    *string   `json:"sensor"`
	Seit      time.Time `json:"seit"`
	Bis       time.Time `json:"bis"`
	Grund     string    `json:"grund"`
	Von       *string   `json:"von"`
	FensterID *string   `json:"fenster_id"`
}

type targetOut struct {
	Art       string  `json:"art"`
	ID        string  `json:"id"`
	MandantID string  `json:"mandant_id"`
	Name      string  `json:"name"`
	Geraet    *string `json:"geraet,omitempty"`
}

// handleMaintenanceOverview: Seite „Wartung“: laufende Wartungen, Fenster
// und mögliche Ziele (alles, was der Benutzer sieht; ?mandant= grenzt ein).
func (s *Server) handleMaintenanceOverview(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	now := s.now()
	s.handle(w, r, "wartung übersicht", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT m.id::text, m.tenant_id::text, coalesce(m.device_id, c.device_id)::text, m.check_id::text,
				d.name, c.name, m.starts_at, m.ends_at, m.reason, m.created_by_name, m.window_id::text
			FROM openwacht.maintenance m
			LEFT JOIN openwacht.checks c ON c.id = m.check_id
			JOIN openwacht.devices d ON d.id = coalesce(m.device_id, c.device_id)
			WHERE m.ends_at > now() AND ($1 = '' OR m.tenant_id = $1::uuid)
			ORDER BY m.ends_at, lower(d.name) LIMIT 2000`, filter)
		if err != nil {
			return 0, nil, err
		}
		running, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (runningOut, error) {
			var o runningOut
			var dev *string
			err := row.Scan(&o.ID, &o.MandantID, &dev, &o.CheckID, &o.Geraet, &o.Sensor, &o.Seit, &o.Bis, &o.Grund, &o.Von, &o.FensterID)
			if o.CheckID == nil {
				o.GeraetID = dev
			}
			return o, err
		})
		if err != nil {
			return 0, nil, err
		}
		rows, err = tx.Query(ctx, `SELECT w.id::text, w.tenant_id::text, w.name, w.reason,
				CASE WHEN w.device_id IS NOT NULL THEN 'geraet' WHEN w.check_id IS NOT NULL THEN 'sensor' ELSE 'gruppe' END,
				coalesce(w.device_id, w.check_id, w.group_id)::text,
				coalesce(d.name, cd.name || ' · ' || c.name, g.name, '?'), w.with_subgroups, w.enabled, w.created_by_name,
				w.repeat, w.starts_at, w.ends_at, w.weekdays, w.nth, w.weekday, w.offset_days, w.start_time, w.duration_min, w.tz
			FROM openwacht.maintenance_windows w
			LEFT JOIN openwacht.devices d ON d.id = w.device_id
			LEFT JOIN openwacht.checks c ON c.id = w.check_id
			LEFT JOIN openwacht.devices cd ON cd.id = c.device_id
			LEFT JOIN openwacht.device_groups g ON g.id = w.group_id
			WHERE ($1 = '' OR w.tenant_id = $1::uuid)
			ORDER BY lower(w.name) LIMIT 2000`, filter)
		if err != nil {
			return 0, nil, err
		}
		windows, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (windowOut, error) {
			var o windowOut
			var wr windowRow
			err := row.Scan(append([]any{&o.ID, &o.MandantID, &o.Name, &o.Grund, &o.ZielArt, &o.ZielID, &o.ZielName,
				&o.Untergruppen, &o.Aktiv, &o.Von}, wr.dest()...)...)
			if err != nil {
				return o, err
			}
			o.Wiederholung, o.Beginn, o.Ende, o.Nter, o.Wochentag, o.Versatz, o.DauerMin, o.Zeitzone =
				wr.repeat, wr.startsAt, wr.endsAt, wr.nth, wr.weekday, wr.offst, wr.durationMin, wr.tz
			o.Wochentage = []int{}
			if wr.weekdays != nil {
				for i := range 7 {
					if *wr.weekdays&(1<<i) != 0 {
						o.Wochentage = append(o.Wochentage, i+1)
					}
				}
			}
			if wr.startTime.Valid {
				m := wr.startTime.Microseconds / 60e6
				t := fmt.Sprintf("%02d:%02d", m/60, m%60)
				o.Uhrzeit = &t
			}
			if rule, err := wr.rule(); err == nil {
				o.Text = rule.Text()
				if o.Aktiv {
					if end, ok := rule.Active(now); ok {
						o.LaeuftBis = &end
					}
					if st, en, ok := rule.Next(now); ok {
						o.Naechstes = &[2]time.Time{st, en}
					}
				}
			} else {
				o.Text = "ungültig: " + err.Error()
			}
			return o, nil
		})
		if err != nil {
			return 0, nil, err
		}
		// Ziele für neue Fenster: Geräte, Sensoren, Gruppen (mit Pfad).
		var targets []targetOut
		rows, err = tx.Query(ctx, `SELECT 'geraet', d.id::text, d.tenant_id::text, d.name, NULL::text FROM openwacht.devices d
				WHERE ($1 = '' OR d.tenant_id = $1::uuid)
			UNION ALL
			SELECT 'sensor', c.id::text, c.tenant_id::text, c.name, d.name FROM openwacht.checks c JOIN openwacht.devices d ON d.id = c.device_id
				WHERE ($1 = '' OR c.tenant_id = $1::uuid)
			LIMIT 10000`, filter)
		if err != nil {
			return 0, nil, err
		}
		targets, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (targetOut, error) {
			var t targetOut
			err := row.Scan(&t.Art, &t.ID, &t.MandantID, &t.Name, &t.Geraet)
			return t, err
		})
		if err != nil {
			return 0, nil, err
		}
		type grp struct{ id, tenant, name, parent string }
		rows, err = tx.Query(ctx, `SELECT id::text, tenant_id::text, name, coalesce(parent_id::text, '') FROM openwacht.device_groups
			WHERE ($1 = '' OR tenant_id = $1::uuid) LIMIT 5000`, filter)
		if err != nil {
			return 0, nil, err
		}
		groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (grp, error) {
			var g grp
			err := row.Scan(&g.id, &g.tenant, &g.name, &g.parent)
			return g, err
		})
		if err != nil {
			return 0, nil, err
		}
		byID := map[string]grp{}
		for _, g := range groups {
			byID[g.id] = g
		}
		for _, g := range groups {
			path := g.name
			for p, n := g.parent, 0; p != "" && n < 8; n++ {
				pg, ok := byID[p]
				if !ok {
					break
				}
				path, p = pg.name+" / "+path, pg.parent
			}
			targets = append(targets, targetOut{Art: "gruppe", ID: g.id, MandantID: g.tenant, Name: path})
		}
		sort.SliceStable(targets, func(i, j int) bool {
			if targets[i].Art != targets[j].Art {
				return targets[i].Art < targets[j].Art
			}
			return strings.ToLower(targets[i].Name) < strings.ToLower(targets[j].Name)
		})
		if running == nil {
			running = []runningOut{}
		}
		if windows == nil {
			windows = []windowOut{}
		}
		if targets == nil {
			targets = []targetOut{}
		}
		return http.StatusOK, map[string]any{"laufend": running, "fenster": windows, "ziele": targets}, nil
	})
}

func (s *Server) handleWindowCreate(w http.ResponseWriter, r *http.Request) {
	var in windowIn
	if !readJSON(w, r, &in) {
		return
	}
	p, err := parseWindow(in, s.now(), s.zoneName())
	if err != nil {
		writeDBError(w, "wartungsfenster", err)
		return
	}
	s.handle(w, r, "wartungsfenster anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var id, tenant string
		// Mandant aus dem Ziel (Trigger), Rechte über RLS: Leser bekommen 403,
		// wer das Ziel nicht sieht 404.
		err := tx.QueryRow(ctx, `INSERT INTO openwacht.maintenance_windows (`+windowCols+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::time, $15, $16, $17)
			RETURNING id::text, tenant_id::text`, p.args()...).Scan(&id, &tenant)
		if err != nil {
			return 0, nil, notFoundOnFK(err)
		}
		if err := audit(ctx, tx, &tenant, "wartungsfenster.angelegt", windowAudit(id, p)); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleWindowUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in windowIn
	if !readJSON(w, r, &in) {
		return
	}
	p, err := parseWindow(in, s.now(), s.zoneName())
	if err != nil {
		writeDBError(w, "wartungsfenster", err)
		return
	}
	s.handle(w, r, "wartungsfenster ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant string
		err := tx.QueryRow(ctx, `UPDATE openwacht.maintenance_windows SET (`+windowCols+`) =
			($2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::time, $16, $17, $18)
			WHERE id = $1 RETURNING tenant_id::text`, append([]any{id}, p.args()...)...).Scan(&tenant)
		if err != nil {
			return 0, nil, notFoundOnFK(err)
		}
		if err := audit(ctx, tx, &tenant, "wartungsfenster.geaendert", windowAudit(id, p)); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleWindowDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "wartungsfenster löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.maintenance_windows WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "wartungsfenster.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func windowAudit(id string, p parsedWindow) map[string]any {
	target := map[string]any{}
	switch {
	case p.device != nil:
		target["geraet"] = *p.device
	case p.check != nil:
		target["sensor"] = *p.check
	case p.group != nil:
		target["gruppe"], target["untergruppen"] = *p.group, p.subgroups
	}
	return map[string]any{"id": id, "name": p.name, "ziel": target, "plan": p.rule.Text(), "zeitzone": p.tz,
		"aktiv": p.enabled, "grund": p.reason}
}

// notFoundOnFK: Ziel nicht gefunden oder nicht sichtbar (Trigger 23503,
// keine Zeile) wird zu 404; fehlende Rechte (RLS, 42501) bleiben 403.
func notFoundOnFK(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		return errNotFound
	}
	return err
}
