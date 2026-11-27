// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Prognose für Platten: Wann ist eine Platte voll, wenn sie weiter so wächst
// wie bisher? Gilt für Agent- und SNMP-Platten, nur zur Anzeige, ohne Alarm
// (Entscheidung 19.11.2026; Alarm „voll in < N Tagen“ später).
//
// Verfahren (Entscheidung Etappe 10):
//   - Stundenmittel der letzten 30 Tage (metrics_*_1h, das noch nicht
//     Verdichtete aus den Rohdaten), lineare Regression über die Zeit.
//   - Fällt die Belegung von einer Stunde zur nächsten um mindestens
//     forecastDrop Prozentpunkte (Löschung, Platte vergrößert), beginnt die
//     Rechnung danach neu; sonst zöge der alte Stand die Steigung nach unten.
//   - Mindestens forecastMinPoints Stundenwerte über forecastMinDays Tage,
//     sonst „zu wenig Verlauf“.
//   - Steigt die Belegung um weniger als forecastMinSlope Punkte je Tag oder
//     wäre die Platte erst in mehr als forecastMaxDays Tagen voll, gilt sie als
//     „stabil“.
//
// Mandantentrennung: RLS auf metrics_*, agents und snmp_sources; der Filter
// „mandanten“ der Anfrage grenzt nur weiter ein.

import (
	"context"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	forecastWindow    = 30 * 24 * time.Hour
	forecastDrop      = 3.0 // Prozentpunkte von einer Stunde zur nächsten
	forecastMinPoints = 24
	forecastMinDays   = 3.0
	forecastMinSlope  = 0.01 // Prozentpunkte je Tag
	forecastMaxDays   = 3650
	// forecastLimit: so viele Platten liefert eine Anfrage höchstens.
	forecastLimit = 2000
	// maxTenantFilter: so viele Mandanten darf der Filter nennen.
	maxTenantFilter = 500
)

// Stand einer Prognose.
const (
	forecastTooLittle = "zu_wenig"
	forecastStable    = "stabil"
	forecastRising    = "steigt"
)

// forecastResult bewertet eine Regression: Steigung in Prozentpunkten je Tag,
// Zahl der Stundenwerte, Zeitspanne in Tagen, aktuelle Belegung in Prozent.
func forecastResult(slopePerDay float64, points int, spanDays, current float64) (string, *int) {
	if points < forecastMinPoints || spanDays < forecastMinDays || math.IsNaN(slopePerDay) || math.IsInf(slopePerDay, 0) {
		return forecastTooLittle, nil
	}
	if slopePerDay < forecastMinSlope {
		return forecastStable, nil
	}
	days := math.Floor(math.Max(0, 100-current) / slopePerDay)
	if days > forecastMaxDays {
		return forecastStable, nil
	}
	d := int(days)
	return forecastRising, &d
}

// forecastSQL: je Platte die Regression über die Stundenwerte seit dem
// letzten Sprung nach unten. $1 Mandanten (NULL = alle sichtbaren), $2 Gerät
// (NULL = alle), $3 Fenster, $4 Sprung, $5 Höchstzahl, $6 Stand der
// Stundenwerte (metrics_watermarks). Der Stand kommt als Wert und nicht aus
// einem Verbund, damit die Rohwerte über den Zeitindex gelesen werden und
// nicht die ganze Tagespartition.
const forecastSQL = `
WITH src AS (
    SELECT 'host'::text AS art, a.id AS quelle, a.tenant_id, a.device_id, m.series, m.bucket AS t, m.avg AS v
      FROM openwacht.metrics_host_1h m JOIN openwacht.agents a ON a.id = m.agent_id
     WHERE a.revoked_at IS NULL AND m.series LIKE 'platte:%' AND m.bucket >= now() - $3::interval AND m.bucket < $6::timestamptz
       AND ($1::uuid[] IS NULL OR a.tenant_id = ANY ($1)) AND ($2::uuid IS NULL OR a.device_id = $2)
    UNION ALL
    SELECT 'host', a.id, a.tenant_id, a.device_id, r.series, date_bin('1 hour', r.ts, timestamptz 'epoch'), avg(r.value)
      FROM openwacht.metrics_host_raw r JOIN openwacht.agents a ON a.id = r.agent_id
     WHERE a.revoked_at IS NULL AND r.series LIKE 'platte:%' AND r.ts >= greatest(now() - $3::interval, $6::timestamptz)
       AND ($1::uuid[] IS NULL OR a.tenant_id = ANY ($1)) AND ($2::uuid IS NULL OR a.device_id = $2)
     GROUP BY 1, 2, 3, 4, 5, 6
    UNION ALL
    SELECT 'snmp', q.id, q.tenant_id, q.device_id, m.series, m.bucket, m.avg
      FROM openwacht.metrics_snmp_1h m JOIN openwacht.snmp_sources q ON q.id = m.snmp_id
     WHERE q.enabled AND m.series LIKE 'platte:%' AND m.bucket >= now() - $3::interval AND m.bucket < $6::timestamptz
       AND ($1::uuid[] IS NULL OR q.tenant_id = ANY ($1)) AND ($2::uuid IS NULL OR q.device_id = $2)
    UNION ALL
    SELECT 'snmp', q.id, q.tenant_id, q.device_id, r.series, date_bin('1 hour', r.ts, timestamptz 'epoch'), avg(r.value)
      FROM openwacht.metrics_snmp_raw r JOIN openwacht.snmp_sources q ON q.id = r.snmp_id
     WHERE q.enabled AND r.series LIKE 'platte:%' AND r.ts >= greatest(now() - $3::interval, $6::timestamptz)
       AND ($1::uuid[] IS NULL OR q.tenant_id = ANY ($1)) AND ($2::uuid IS NULL OR q.device_id = $2)
     GROUP BY 1, 2, 3, 4, 5, 6
), d AS (
    SELECT src.*, lag(v) OVER (PARTITION BY art, quelle, series ORDER BY t) AS prev FROM src
), cut AS (
    SELECT art, quelle, series, max(t) FILTER (WHERE prev - v >= $4) AS c FROM d GROUP BY 1, 2, 3
), seg AS (
    SELECT d.*, cut.c FROM d JOIN cut USING (art, quelle, series) WHERE cut.c IS NULL OR d.t >= cut.c
)
SELECT seg.art, seg.quelle::text, seg.tenant_id::text, seg.device_id::text, dev.name, substr(seg.series, 8),
       coalesce(regr_slope(seg.v, extract(epoch FROM seg.t)) * 86400, 'NaN'::double precision),
       count(*), extract(epoch FROM max(seg.t) - min(seg.t))::double precision / 86400,
       (array_agg(seg.v ORDER BY seg.t DESC))[1], bool_or(seg.c IS NOT NULL)
  FROM seg JOIN openwacht.devices dev ON dev.id = seg.device_id
 GROUP BY seg.art, seg.quelle, seg.tenant_id, seg.device_id, dev.name, seg.series
HAVING max(seg.t) >= now() - interval '1 day'
 ORDER BY lower(dev.name), seg.art, seg.series
 LIMIT $5`

type diskForecastOut struct {
	Art       string `json:"art"` // "host" oder "snmp"
	QuelleID  string `json:"quelle_id"`
	MandantID string `json:"mandant_id"`
	GeraetID  string `json:"geraet_id"`
	Geraet    string `json:"geraet"`
	Platte    string `json:"platte"`
	// Belegt: Mittel der letzten Stunde in Prozent
	Belegt float64 `json:"belegt"`
	// ProTag: Steigung in Prozentpunkten je Tag (nil ohne Rechnung)
	ProTag *float64 `json:"pro_tag"`
	Stand  string   `json:"stand"`
	// Tage bis voll (nur bei „steigt“)
	Tage *int `json:"tage"`
	// Basis: Zeitspanne der Rechnung in Tagen
	Basis float64 `json:"basis_tage"`
	// NachSprung: Die Rechnung beginnt nach einer Löschung oder Vergrößerung.
	NachSprung bool `json:"nach_sprung"`
}

// tenantFilter liest den optionalen Filter „mandanten“ (kommagetrennte IDs).
// Er grenzt nur ein; was die Datenbank nicht zeigt, bleibt unsichtbar.
func tenantFilter(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("mandanten"))
	if raw == "" {
		return nil, true
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxTenantFilter {
		writeError(w, http.StatusBadRequest, "Zu viele Mandanten im Filter.")
		return nil, false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !uuidPattern.MatchString(p) {
			writeError(w, http.StatusBadRequest, "Ungültige Mandanten-ID im Filter.")
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// diskForecasts liefert die Prognosen der sichtbaren Platten; tenants nil =
// alle, device nil = alle Geräte. truncated: mehr als forecastLimit Platten.
func diskForecasts(ctx context.Context, tx pgx.Tx, tenants []string, device *string) (list []diskForecastOut, truncated bool, err error) {
	var done time.Time
	if err := tx.QueryRow(ctx, `SELECT done_1h FROM openwacht.metrics_watermarks()`).Scan(&done); err != nil {
		return nil, false, err
	}
	rows, err := tx.Query(ctx, forecastSQL, tenants, device, interval(forecastWindow), forecastDrop, forecastLimit+1, done)
	if err != nil {
		return nil, false, err
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (diskForecastOut, error) {
		var f diskForecastOut
		var slope float64
		var n int
		if err := row.Scan(&f.Art, &f.QuelleID, &f.MandantID, &f.GeraetID, &f.Geraet, &f.Platte, &slope, &n, &f.Basis,
			&f.Belegt, &f.NachSprung); err != nil {
			return f, err
		}
		f.Stand, f.Tage = forecastResult(slope, n, f.Basis, f.Belegt)
		if f.Stand != forecastTooLittle {
			x := round2(slope)
			f.ProTag = &x
		}
		f.Belegt, f.Basis = round2(f.Belegt), round2(f.Basis)
		return f, nil
	})
	if err != nil {
		return nil, false, err
	}
	if len(list) > forecastLimit {
		list, truncated = list[:forecastLimit], true
	}
	if list == nil {
		list = []diskForecastOut{}
	}
	return list, truncated, nil
}

func (s *Server) handleDiskForecast(w http.ResponseWriter, r *http.Request) {
	tenants, ok := tenantFilter(w, r)
	if !ok {
		return
	}
	s.handle(w, r, "prognose platten", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		list, truncated, err := diskForecasts(ctx, tx, tenants, nil)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"platten": list, "gekuerzt": truncated}, nil
	})
}
