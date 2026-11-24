// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/pdf"
)

// Monatsberichte (Etappe 25): Verfügbarkeit und SLA-Ziel je Gerät und
// Mandant, Alarme und Kapazitätsprognose. Erstellt immer mit den Rechten des
// Lesers (RLS): in der Oberfläche des Angemeldeten, per Mail des Empfängers.
//
// Verfügbarkeit: Ausfall ist, solange ein kritischer Alarm zur Erreichbarkeit
// offen ist (Ping-Check, Agent stumm, Abfragequelle stumm). Wartungen öffnen
// keine Alarme und zählen deshalb nicht als Ausfall.

const defaultSLA = 99.5

type reportDevice struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	MandantID     string  `json:"mandant_id"`
	Mandant       string  `json:"mandant"`
	Verfuegbar    float64 `json:"verfuegbarkeit"` // Prozent
	AusfallMin    int     `json:"ausfall_minuten"`
	Ausfaelle     int     `json:"ausfaelle"`
	Ziel          float64 `json:"ziel"`
	Erfuellt      bool    `json:"erfuellt"`
	ErfasstMinute int     `json:"erfasst_minuten"`
}

type reportTenant struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Geraete    int     `json:"geraete"`
	Verfuegbar float64 `json:"verfuegbarkeit"`
	Ziel       float64 `json:"ziel"`
	Erfuellt   bool    `json:"erfuellt"`
}

type reportAlarm struct {
	Name    string    `json:"name"`
	Mandant string    `json:"mandant"`
	Worst   string    `json:"schwere"`
	Start   time.Time `json:"beginn"`
	Minuten int       `json:"minuten"`
	Offen   bool      `json:"offen"`
}

type report struct {
	Mandant        string            `json:"mandant"`
	MandantID      string            `json:"mandant_id"`
	Untermandanten bool              `json:"untermandanten"`
	Monat          string            `json:"monat"` // YYYY-MM
	Von            time.Time         `json:"von"`
	Bis            time.Time         `json:"bis"`
	Erstellt       time.Time         `json:"erstellt"`
	Mandanten      []reportTenant    `json:"mandanten"`
	Geraete        []reportDevice    `json:"geraete"`
	Alarme         int               `json:"alarme"`
	Kritisch       int               `json:"kritisch"`
	Warnungen      int               `json:"warnungen"`
	Bestaetigt     int               `json:"bestaetigt"`
	Laengste       []reportAlarm     `json:"laengste"`
	Prognose       []diskForecastOut `json:"prognose"`
}

var monthRe = regexp.MustCompile(`^(20[0-9]{2})-(0[1-9]|1[0-2])$`)

// parseMonth: Monatsanfang in der Zeitzone der Installation.
func parseMonth(s string, loc *time.Location) (time.Time, error) {
	m := monthRe.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, errors.New("Monat als JJJJ-MM angeben")
	}
	var y, mo int
	fmt.Sscanf(m[1], "%d", &y)
	fmt.Sscanf(m[2], "%d", &mo)
	return time.Date(y, time.Month(mo), 1, 0, 0, 0, 0, loc), nil
}

type span struct{ from, to time.Time }

// downtime: Länge der Vereinigung der Intervalle innerhalb [from, to].
func downtime(list []span, from, to time.Time) (time.Duration, int) {
	var clipped []span
	for _, s := range list {
		a, b := s.from, s.to
		if a.Before(from) {
			a = from
		}
		if b.After(to) {
			b = to
		}
		if b.After(a) {
			clipped = append(clipped, span{a, b})
		}
	}
	slices.SortFunc(clipped, func(x, y span) int { return x.from.Compare(y.from) })
	var total time.Duration
	var cur *span
	for i := range clipped {
		s := clipped[i]
		if cur != nil && !s.from.After(cur.to) {
			if s.to.After(cur.to) {
				cur.to = s.to
			}
			continue
		}
		if cur != nil {
			total += cur.to.Sub(cur.from)
		}
		cur = &s
	}
	if cur != nil {
		total += cur.to.Sub(cur.from)
	}
	return total, len(clipped)
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// buildReport läuft in einer Transaktion mit Benutzerkontext (RLS).
func (s *Server) buildReport(ctx context.Context, tx pgx.Tx, tenant string, children bool, month time.Time) (*report, error) {
	from := month
	to := month.AddDate(0, 1, 0)
	now := s.now()
	end := to
	if now.Before(end) {
		end = now
	}
	r := &report{MandantID: tenant, Untermandanten: children, Monat: month.Format("2006-01"), Von: from, Bis: to, Erstellt: now,
		Geraete: []reportDevice{}, Mandanten: []reportTenant{}, Laengste: []reportAlarm{}, Prognose: []diskForecastOut{}}
	if err := tx.QueryRow(ctx, `SELECT name FROM openwacht.tenants WHERE id = $1`, tenant).Scan(&r.Mandant); err != nil {
		return nil, err // nicht sichtbar: 404
	}
	// Mandanten (sichtbar) mit SLA-Ziel: eigenes, sonst des nächsten sichtbaren Vorfahren.
	rows, err := tx.Query(ctx, `SELECT id::text, name, sla::float8 FROM openwacht.report_tenants($1, $2, $3)`, tenant, children, defaultSLA)
	if err != nil {
		return nil, err
	}
	var tenantIDs []string
	byTenant := map[string]*reportTenant{}
	for rows.Next() {
		var t reportTenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Ziel); err != nil {
			rows.Close()
			return nil, err
		}
		r.Mandanten = append(r.Mandanten, t)
		tenantIDs = append(tenantIDs, t.ID)
	}
	rows.Close()
	for i := range r.Mandanten {
		byTenant[r.Mandanten[i].ID] = &r.Mandanten[i]
	}
	// Geräte und Ausfälle
	rows, err = tx.Query(ctx, `SELECT d.id::text, d.name, d.tenant_id::text, d.created_at FROM openwacht.devices d
		WHERE d.tenant_id = ANY ($1::uuid[]) AND d.created_at < $2 ORDER BY lower(d.name)`, tenantIDs, end)
	if err != nil {
		return nil, err
	}
	created := map[string]time.Time{}
	for rows.Next() {
		var d reportDevice
		var c time.Time
		if err := rows.Scan(&d.ID, &d.Name, &d.MandantID, &c); err != nil {
			rows.Close()
			return nil, err
		}
		created[d.ID] = c
		r.Geraete = append(r.Geraete, d)
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT coalesce(c.device_id, g.device_id, q.device_id)::text, a.started_at, coalesce(a.ended_at, $3)
		FROM openwacht.alarms a
		LEFT JOIN openwacht.checks c ON c.id = a.check_id AND c.kind = 'ping' AND a.subject = 'check'
		LEFT JOIN openwacht.agents g ON g.id = a.agent_id AND a.subject = 'stumm'
		LEFT JOIN openwacht.snmp_sources q ON q.id = a.snmp_id AND a.subject = 'stumm'
		WHERE a.tenant_id = ANY ($1::uuid[]) AND a.worst = 'crit' AND a.started_at < $3 AND (a.ended_at IS NULL OR a.ended_at > $2)
		  AND coalesce(c.device_id, g.device_id, q.device_id) IS NOT NULL`, tenantIDs, from, end)
	if err != nil {
		return nil, err
	}
	outages := map[string][]span{}
	for rows.Next() {
		var dev string
		var a, b time.Time
		if err := rows.Scan(&dev, &a, &b); err != nil {
			rows.Close()
			return nil, err
		}
		outages[dev] = append(outages[dev], span{a, b})
	}
	rows.Close()
	sum := map[string][2]float64{} // Mandant: Summe Verfügbarkeit, Anzahl
	for i := range r.Geraete {
		d := &r.Geraete[i]
		start := from
		if c := created[d.ID]; c.After(start) {
			start = c
		}
		total := end.Sub(start)
		down, n := downtime(outages[d.ID], start, end)
		d.Ausfaelle, d.AusfallMin, d.ErfasstMinute = n, int(down.Minutes()+0.5), int(total.Minutes())
		d.Verfuegbar = 100
		if total > 0 {
			d.Verfuegbar = round3(100 * (1 - float64(down)/float64(total)))
		}
		if t := byTenant[d.MandantID]; t != nil {
			d.Mandant, d.Ziel = t.Name, t.Ziel
			v := sum[t.ID]
			sum[t.ID] = [2]float64{v[0] + d.Verfuegbar, v[1] + 1}
		}
		d.Erfuellt = d.Verfuegbar >= d.Ziel
	}
	for i := range r.Mandanten {
		t := &r.Mandanten[i]
		v := sum[t.ID]
		t.Geraete = int(v[1])
		t.Verfuegbar = 100
		if v[1] > 0 {
			t.Verfuegbar = round3(v[0] / v[1])
		}
		t.Erfuellt = t.Verfuegbar >= t.Ziel
	}
	// Alarme im Monat
	if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE worst = 'crit'), count(*) FILTER (WHERE worst = 'warn'),
			count(*) FILTER (WHERE ack_at IS NOT NULL)
		FROM openwacht.alarms WHERE tenant_id = ANY ($1::uuid[]) AND started_at >= $2 AND started_at < $3`, tenantIDs, from, to).
		Scan(&r.Alarme, &r.Kritisch, &r.Warnungen, &r.Bestaetigt); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT a.name, t.name, a.worst, a.started_at, a.ended_at IS NULL,
			extract(epoch FROM least(coalesce(a.ended_at, $4), $3) - greatest(a.started_at, $2))::int / 60
		FROM openwacht.alarms a JOIN openwacht.tenants t ON t.id = a.tenant_id
		WHERE a.tenant_id = ANY ($1::uuid[]) AND a.started_at < $3 AND (a.ended_at IS NULL OR a.ended_at > $2)
		ORDER BY 6 DESC, a.started_at LIMIT 10`, tenantIDs, from, to, end)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a reportAlarm
		if err := rows.Scan(&a.Name, &a.Mandant, &a.Worst, &a.Start, &a.Offen, &a.Minuten); err != nil {
			rows.Close()
			return nil, err
		}
		r.Laengste = append(r.Laengste, a)
	}
	rows.Close()
	// Kapazität: Platten, die in 90 Tagen voll laufen
	if len(tenantIDs) > 0 {
		list, _, err := diskForecasts(ctx, tx, tenantIDs, nil)
		if err != nil {
			return nil, err
		}
		for _, f := range list {
			if f.Tage != nil && *f.Tage <= 90 {
				r.Prognose = append(r.Prognose, f)
			}
		}
		slices.SortFunc(r.Prognose, func(a, b diskForecastOut) int { return *a.Tage - *b.Tage })
	}
	return r, nil
}

// --- PDF ------------------------------------------------------------------------

var monthNames = []string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober",
	"November", "Dezember"}

func pct(f float64) string { return strings.Replace(fmt.Sprintf("%.3f %%", f), ".", ",", 1) }

func hm(min int) string {
	if min < 60 {
		return fmt.Sprintf("%d Min.", min)
	}
	return fmt.Sprintf("%d:%02d Std.", min/60, min%60)
}

func (r *report) title() string {
	return fmt.Sprintf("Monatsbericht %s %d", monthNames[r.Von.Month()-1], r.Von.Year())
}

func renderReport(r *report, loc *time.Location) []byte {
	d := pdf.New("OpenWacht – "+r.title()+" – "+r.Mandant, r.Erstellt)
	const left, right = 50.0, 545.0
	y := 0.0
	page := 1
	head := func() {
		d.Rect(0, 0, pdf.Width, 6, pdf.Blue)
		d.Text(left, 40, 9, true, pdf.Blue, "OpenWacht")
		d.TextRight(right, 40, 8, false, pdf.Gray, fmt.Sprintf("%s · %s · Seite %d", r.Mandant, r.title(), page))
		y = 64
	}
	need := func(h float64) {
		if y+h > 800 {
			d.AddPage()
			page++
			head()
		}
	}
	section := func(t string) {
		need(40)
		y += 14
		d.Text(left, y, 12, true, pdf.Black, t)
		y += 6
		d.Line(left, y, right, y, 0.5, pdf.Light)
		y += 14
	}
	head()
	d.Text(left, y+10, 20, true, pdf.Black, r.title())
	y += 30
	scope := r.Mandant
	if r.Untermandanten {
		scope += " mit Untermandanten"
	}
	d.Text(left, y, 10, false, pdf.Gray, fmt.Sprintf("%s · Zeitraum %s bis %s · erstellt %s", scope,
		r.Von.In(loc).Format("02.01.2006"), r.Bis.In(loc).AddDate(0, 0, -1).Format("02.01.2006"), r.Erstellt.In(loc).Format("02.01.2006 15:04")))
	y += 24
	// Kennzahlen
	boxes := []struct{ label, value string }{
		{"Geräte", fmt.Sprint(len(r.Geraete))},
		{"Alarme im Monat", fmt.Sprint(r.Alarme)},
		{"davon kritisch", fmt.Sprint(r.Kritisch)},
		{"Platten bald voll", fmt.Sprint(len(r.Prognose))},
	}
	bw := (right - left - 3*10) / 4
	for i, b := range boxes {
		x := left + float64(i)*(bw+10)
		d.Rect(x, y, bw, 46, pdf.Light)
		d.Text(x+10, y+18, 8, false, pdf.Gray, b.label)
		d.Text(x+10, y+37, 16, true, pdf.Black, b.value)
	}
	y += 62

	section("Verfügbarkeit je Mandant")
	for _, t := range r.Mandanten {
		need(18)
		c := pdf.Green
		status := "Ziel erreicht"
		if !t.Erfuellt {
			c, status = pdf.Red, "Ziel verfehlt"
		}
		d.Text(left, y, 9, true, pdf.Black, pdf.Fit(t.Name, 200, 9, true))
		d.Text(260, y, 9, false, pdf.Gray, fmt.Sprintf("%d Geräte", t.Geraete))
		d.TextRight(400, y, 9, true, c, pct(t.Verfuegbar))
		d.Text(410, y, 9, false, pdf.Gray, "Ziel "+pct(t.Ziel))
		d.TextRight(right, y, 9, true, c, status)
		y += 16
	}

	section("Verfügbarkeit je Gerät")
	if len(r.Geraete) == 0 {
		d.Text(left, y, 9, false, pdf.Gray, "Keine Geräte.")
		y += 14
	} else {
		need(16)
		for _, h := range []struct {
			x     float64
			t     string
			right bool
		}{{left, "Gerät", false}, {215, "Mandant", false}, {390, "Verfügbar", true}, {470, "Ausfall", true}, {right, "Ziel", true}} {
			if h.right {
				d.TextRight(h.x, y, 8, true, pdf.Gray, h.t)
			} else {
				d.Text(h.x, y, 8, true, pdf.Gray, h.t)
			}
		}
		y += 12
		for _, g := range r.Geraete {
			need(16)
			c := pdf.Green
			if !g.Erfuellt {
				c = pdf.Red
			}
			d.Text(left, y, 9, false, pdf.Black, pdf.Fit(g.Name, 160, 9, false))
			d.Text(215, y, 9, false, pdf.Gray, pdf.Fit(g.Mandant, 110, 9, false))
			d.TextRight(390, y, 9, true, c, pct(g.Verfuegbar))
			out := "–"
			if g.AusfallMin > 0 {
				out = fmt.Sprintf("%s (%d×)", hm(g.AusfallMin), g.Ausfaelle)
			}
			d.TextRight(470, y, 9, false, pdf.Black, out)
			mark := "erreicht"
			if !g.Erfuellt {
				mark = "verfehlt"
			}
			d.TextRight(right, y, 9, false, c, mark)
			y += 4
			d.Rect(left, y, (right-left)*g.Verfuegbar/100, 2, c)
			y += 12
		}
	}

	section("Alarme")
	d.Text(left, y, 9, false, pdf.Black, fmt.Sprintf("%d Alarme begonnen, davon %d kritisch und %d Warnungen; %d bestätigt.",
		r.Alarme, r.Kritisch, r.Warnungen, r.Bestaetigt))
	y += 18
	if len(r.Laengste) > 0 {
		d.Text(left, y, 9, true, pdf.Black, "Längste Alarme im Zeitraum")
		y += 14
		for _, a := range r.Laengste {
			need(14)
			c := pdf.Amber
			if a.Worst == "crit" {
				c = pdf.Red
			}
			d.Rect(left, y-7, 6, 6, c)
			d.Text(left+12, y, 9, false, pdf.Black, pdf.Fit(a.Name, 300, 9, false))
			d.Text(370, y, 9, false, pdf.Gray, a.Start.In(loc).Format("02.01. 15:04"))
			dur := hm(a.Minuten)
			if a.Offen {
				dur += " (offen)"
			}
			d.TextRight(right, y, 9, false, pdf.Black, dur)
			y += 14
		}
	}

	section("Kapazität (Platten voll in höchstens 90 Tagen)")
	if len(r.Prognose) == 0 {
		d.Text(left, y, 9, false, pdf.Gray, "Keine Platte läuft in den nächsten 90 Tagen voll.")
		y += 14
	}
	for _, f := range r.Prognose {
		need(14)
		d.Text(left, y, 9, false, pdf.Black, pdf.Fit(f.Geraet+" · "+f.Platte, 330, 9, false))
		d.TextRight(450, y, 9, false, pdf.Gray, strings.Replace(fmt.Sprintf("%.1f %% belegt", f.Belegt), ".", ",", 1))
		d.TextRight(right, y, 9, true, pdf.Red, fmt.Sprintf("voll in %d Tagen", *f.Tage))
		y += 14
	}
	need(30)
	y += 16
	d.Text(left, y, 7.5, false, pdf.Gray, "Verfügbarkeit: Anteil der Zeit ohne offenen kritischen Alarm zu Ping, Agent oder Abfragequelle; Wartungen zählen nicht als Ausfall.")
	return d.Bytes()
}

// --- API ------------------------------------------------------------------------

func (s *Server) reportFromRequest(w http.ResponseWriter, r *http.Request, fn func(rep *report)) {
	q := r.URL.Query()
	tenant := q.Get("mandant")
	if !uuidPattern.MatchString(tenant) {
		writeError(w, http.StatusBadRequest, "Mandant fehlt.")
		return
	}
	loc := s.mailZone()
	monat := q.Get("monat")
	if monat == "" {
		monat = s.now().In(loc).Format("2006-01")
	}
	month, err := parseMonth(monat, loc)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error()+".")
		return
	}
	if month.After(s.now()) {
		writeError(w, http.StatusBadRequest, "Der Monat liegt in der Zukunft.")
		return
	}
	children := q.Get("untermandanten") != "0"
	var rep *report
	err = s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		var err error
		rep, err = s.buildReport(r.Context(), tx, tenant, children, month)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Nicht gefunden.")
		return
	}
	if err != nil {
		internalError(w, "bericht", err)
		return
	}
	fn(rep)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	s.reportFromRequest(w, r, func(rep *report) { writeJSON(w, http.StatusOK, rep) })
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func reportFileName(rep *report) string {
	name := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "Ä", "Ae", "Ö", "Oe", "Ü", "Ue", "ß", "ss").Replace(rep.Mandant)
	name = strings.Trim(unsafeFile.ReplaceAllString(name, "-"), "-")
	if name == "" {
		name = "Mandant"
	}
	return fmt.Sprintf("OpenWacht-Bericht-%s-%s.pdf", name, rep.Monat)
}

func (s *Server) handleReportPDF(w http.ResponseWriter, r *http.Request) {
	s.reportFromRequest(w, r, func(rep *report) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+reportFileName(rep)+`"`)
		w.Write(renderReport(rep, s.mailZone()))
	})
}

// handleSLA: SLA-Ziel eines Mandanten (Admins, RLS); null = erben.
func (s *Server) handleSLA(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Ziel *float64 `json:"ziel"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Ziel != nil && (*in.Ziel < 50 || *in.Ziel > 100 || math.IsNaN(*in.Ziel)) {
		writeDBError(w, "sla", badRequest("SLA-Ziel zwischen 50 und 100 Prozent."))
		return
	}
	s.handle(w, r, "sla", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		tag, err := tx.Exec(ctx, `UPDATE openwacht.tenants SET sla_target = $2 WHERE id = $1`, id, in.Ziel)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		return http.StatusOK, map[string]any{"ziel": in.Ziel}, audit(ctx, tx, &id, "mandant.sla", map[string]any{"ziel": in.Ziel})
	})
}

// --- Monatlicher Versand -----------------------------------------------------------

// RunReports verschickt in den ersten sieben Tagen eines Monats die Berichte
// des Vormonats (je Kanal und Empfänger einmal).
func (s *Server) RunReports(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := s.sendMonthlyReports(ctx); err != nil {
			slog.Warn("Monatsberichte", "fehler", err)
		} else if n > 0 {
			slog.Info("Monatsberichte verschickt", "anzahl", n)
		}
	}
}

func (s *Server) sendMonthlyReports(ctx context.Context) (int, error) {
	loc := s.mailZone()
	now := s.now().In(loc)
	if now.Day() > 7 || (now.Day() == 1 && now.Hour() < 6) {
		return 0, nil
	}
	c := s.mailConfig()
	if c == nil {
		return 0, nil
	}
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc).AddDate(0, -1, 0)
	rows, err := s.pool.Query(ctx, `SELECT channel_id::text, channel_name, tenant_id::text, include_children, user_id::text, email
		FROM openwacht.report_due($1)`, month.Format("2006-01-02"))
	if err != nil {
		return 0, err
	}
	type due struct {
		channel, name, tenant, user, email string
		children                           bool
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.channel, &d.name, &d.tenant, &d.children, &d.user, &d.email); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	sent := 0
	for _, d := range list {
		var rep *report
		err := s.withUser(ctx, d.user, func(tx pgx.Tx) error {
			var err error
			rep, err = s.buildReport(ctx, tx, d.tenant, d.children, month)
			return err
		})
		if err != nil {
			slog.Warn("Monatsbericht nicht erstellt", "kanal", d.channel, "fehler", err)
			continue
		}
		m := alarm.Mail{
			Subject: fmt.Sprintf("OpenWacht: %s – %s", rep.title(), rep.Mandant),
			Text: fmt.Sprintf("%s für %s (Kanal „%s“) im Anhang.\n\nGeräte: %d, Alarme: %d (davon kritisch: %d).\n",
				rep.title(), rep.Mandant, d.name, len(rep.Geraete), rep.Alarme, rep.Kritisch),
			Attachments: []alarm.MailAttachment{{Name: reportFileName(rep), Type: "application/pdf", Data: renderReport(rep, loc)}},
		}
		m.HTML = "<p>" + strings.ReplaceAll(htmlEscape(m.Text), "\n", "<br>") + "</p>"
		sctx, cancel := context.WithTimeout(ctx, time.Minute)
		_, err = s.mailer.Send(sctx, *c, []string{d.email}, m)
		cancel()
		if err != nil {
			slog.Warn("Monatsbericht nicht verschickt", "kanal", d.channel, "fehler", err)
			continue
		}
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.report_sent($1, $2, $3)`, d.channel, d.user, month.Format("2006-01-02")); err != nil {
			slog.Warn("Monatsbericht nicht vermerkt", "fehler", err)
		}
		sent++
	}
	return sent, nil
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
