// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/pdf"
)

// Rezertifizierung (Etappe 36): „Wer hat welche Rolle, wann zuletzt
// angemeldet?“ je Mandant und Teilbaum, als CSV oder PDF. Nur für Admins des
// Mandanten (Datenbankfunktion recert_report); jeder Abruf steht im Audit-Log.

type recertRow struct {
	Email, Name, Quelle, Heimat string
	Gesperrt, TOTP              bool
	Passkeys                    int
	Letzte                      *time.Time
	RolleMandant, Rolle         string
	RolleSeit, TokenBis         *time.Time
}

func (s *Server) handleRecertReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "pdf" {
		writeError(w, http.StatusBadRequest, "format=csv oder format=pdf angeben.")
		return
	}
	var (
		rows   []recertRow
		tenant string
	)
	ctx := r.Context()
	err := s.withUser(ctx, sessionFrom(ctx).UserID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT name FROM openwacht.tenants WHERE id = $1 AND id IN (SELECT openwacht.admin_tenants())`, id).
			Scan(&tenant); err != nil {
			return err
		}
		q, err := tx.Query(ctx, `SELECT email, display_name, source, home, disabled, totp, passkeys, last_login,
				role_tenant, role, role_since, token_expires FROM openwacht.recert_report($1)`, id)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(q, func(row pgx.CollectableRow) (recertRow, error) {
			var x recertRow
			err := row.Scan(&x.Email, &x.Name, &x.Quelle, &x.Heimat, &x.Gesperrt, &x.TOTP, &x.Passkeys, &x.Letzte,
				&x.RolleMandant, &x.Rolle, &x.RolleSeit, &x.TokenBis)
			return x, err
		})
		if err != nil {
			return err
		}
		return audit(ctx, tx, &id, "rezertifizierung.abgerufen", map[string]any{"format": format, "zeilen": len(rows)})
	})
	if err != nil {
		writeDBError(w, "rezertifizierung", err)
		return
	}
	loc := s.mailZone()
	now := s.now()
	file := "OpenWacht-Rezertifizierung-" + fileSafe(tenant) + "-" + now.In(loc).Format("2006-01-02")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+file+`.csv"`)
		w.Write(recertCSV(rows, loc))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`.pdf"`)
	w.Write(recertPDF(tenant, rows, now, loc))
}

func fileSafe(s string) string {
	s = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "Ä", "Ae", "Ö", "Oe", "Ü", "Ue", "ß", "ss").Replace(s)
	s = strings.Trim(unsafeFile.ReplaceAllString(s, "-"), "-")
	if s == "" {
		return "Mandant"
	}
	return s
}

var sourceName = map[string]string{"lokal": "lokal", "ldap": "AD/LDAP", "oidc": "SSO", "token": "API-Token"}

func ts(t *time.Time, loc *time.Location, layout string) string {
	if t == nil {
		return ""
	}
	return t.In(loc).Format(layout)
}

func yesNo(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

// csvCell verhindert, dass Tabellenprogramme Zellen als Formel ausführen
// (Namen und Adressen kommen auch aus AD oder IdP).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func recertCSV(rows []recertRow, loc *time.Location) []byte {
	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // Excel erkennt sonst kein UTF-8
	cw := csv.NewWriter(&buf)
	cw.Comma = ';'
	cw.Write([]string{"Mandant der Rolle", "Rolle", "Rolle seit", "Konto", "Name", "Herkunft", "Heimatmandant",
		"Gesperrt", "App (TOTP)", "Passkeys", "Letzte Anmeldung", "Token gültig bis"})
	for _, x := range rows {
		rolle := x.Rolle
		if rolle == "" {
			rolle = "keine"
		}
		cw.Write([]string{csvCell(x.RolleMandant), rolle, ts(x.RolleSeit, loc, "2006-01-02"), csvCell(x.Email), csvCell(x.Name),
			sourceName[x.Quelle], csvCell(x.Heimat), yesNo(x.Gesperrt), yesNo(x.TOTP), fmt.Sprint(x.Passkeys),
			ts(x.Letzte, loc, "2006-01-02 15:04"), ts(x.TokenBis, loc, "2006-01-02")})
	}
	cw.Flush()
	return buf.Bytes()
}

func recertPDF(tenant string, rows []recertRow, now time.Time, loc *time.Location) []byte {
	d := pdf.New("OpenWacht – Rezertifizierung – "+tenant, now)
	const left, right = 48.0, pdf.Width - 48
	page := 1
	y := 0.0
	header := func() {
		d.Rect(0, 0, pdf.Width, 6, pdf.Blue)
		d.Text(left, 40, 9, true, pdf.Blue, "OpenWacht")
		d.TextRight(right, 40, 8, false, pdf.Gray, fmt.Sprintf("%s · Rezertifizierung · Seite %d", pdf.Fit(tenant, 200, 8, false), page))
		y = 70
	}
	cols := []struct {
		x float64
		t string
	}{{left, "Konto"}, {250, "Rolle"}, {330, "Mandant der Rolle"}, {470, "Letzte Anmeldung"}}
	tableHead := func() {
		for _, c := range cols {
			d.Text(c.x, y, 8, true, pdf.Gray, c.t)
		}
		y += 6
		d.Line(left, y, right, y, 0.5, pdf.Light)
		y += 12
	}
	header()
	d.Text(left, y+10, 20, true, pdf.Black, "Rezertifizierung der Rollen")
	y += 32
	d.Text(left, y, 10, false, pdf.Gray, fmt.Sprintf("%s und Untermandanten · erstellt %s · %d Zeilen",
		pdf.Fit(tenant, 250, 10, false), now.In(loc).Format("02.01.2006 15:04"), len(rows)))
	y += 16
	d.Text(left, y, 8, false, pdf.Gray, "Bitte je Zeile prüfen: Braucht das Konto die Rolle noch? Nicht mehr benötigte Rollen entziehen, Konten sperren.")
	y += 24
	tableHead()
	stale := now.AddDate(0, 0, -90)
	for _, x := range rows {
		if y > pdf.Height-60 {
			d.AddPage()
			page++
			header()
			tableHead()
		}
		rolle := x.Rolle
		if rolle == "" {
			rolle = "keine Rolle"
		}
		c := pdf.Black
		if x.Gesperrt {
			c = pdf.Gray
		}
		d.Text(left, y, 9, true, c, pdf.Fit(x.Email, 195, 9, true))
		d.Text(250, y, 9, false, c, rolle)
		d.Text(330, y, 9, false, c, pdf.Fit(x.RolleMandant, 135, 9, false))
		last := ts(x.Letzte, loc, "02.01.2006")
		lc := pdf.Black
		switch {
		case x.Quelle == "token":
			last, lc = "–", pdf.Gray
		case x.Letzte == nil:
			last, lc = "nie", pdf.Amber
		case x.Letzte.Before(stale):
			lc = pdf.Amber
		}
		d.Text(470, y, 9, false, lc, last)
		y += 11
		detail := []string{pdf.Fit(x.Name, 150, 7.5, false), sourceName[x.Quelle], "Heimat " + x.Heimat}
		switch {
		case x.Quelle == "token":
			detail = append(detail, "gültig bis "+ts(x.TokenBis, loc, "02.01.2006"))
		case x.TOTP:
			detail = append(detail, fmt.Sprintf("App, %d Passkeys", x.Passkeys))
		default:
			detail = append(detail, "ohne zweiten Faktor")
		}
		if x.Gesperrt {
			detail = append(detail, "gesperrt")
		}
		d.Text(left+8, y, 7.5, false, pdf.Gray, pdf.Fit(strings.Join(detail, " · "), right-left-8, 7.5, false))
		y += 15
	}
	if len(rows) == 0 {
		d.Text(left, y, 9, false, pdf.Gray, "Keine Konten und Rollen.")
	}
	d.Text(left, pdf.Height-30, 7.5, false, pdf.Gray, "Gelb: seit über 90 Tagen nicht oder nie angemeldet. „Heimat (außerhalb)“: Konto liegt in einem anderen Teilbaum.")
	return d.Bytes()
}
