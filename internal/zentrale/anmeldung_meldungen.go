// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// 1.0.6: Meldungen bei verdächtigen Anmeldungen. Die Datenbank legt die
// Ereignisse in einen Ausgang (Migration 0057), hier gehen sie per Mail an
// das Konto und, außer bei einer neuen Quelle, an den Betreiber. Ohne
// eingerichteten Mailversand bleiben sie liegen und verfallen nach einem Tag.
// Die Mail nennt keine Adresse der Quelle: Die Zentrale speichert sie nicht.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
)

type authNotice struct {
	id        int64
	kind      string
	at        time.Time
	email     *string
	name      string
	operators []string
}

// authNoticeText: Zustand, Titel und Text einer Meldung.
func authNoticeText(n authNotice, account string, loc *time.Location) (status, title, text string) {
	when := n.at.In(loc).Format("02.01.2006 um 15:04 Uhr")
	switch n.kind {
	case "neue_quelle":
		return alarm.Warn, "Anmeldung von einem neuen Rechner",
			fmt.Sprintf("Das Konto %s hat sich am %s von einem Rechner bzw. Netz angemeldet, von dem es sich in den "+
				"letzten 90 Tagen nicht angemeldet hat. Warst du das nicht, ändere sofort dein Passwort und gib dem "+
				"Betreiber von OpenWacht Bescheid.", account, when)
	case "quelle_gesperrt":
		return alarm.Warn, "Anmeldung nach Fehlversuchen gesperrt",
			fmt.Sprintf("Für das Konto %s ist am %s ein Rechner bzw. Netz nach fünf falschen Passwörtern oder Codes "+
				"gesperrt worden. Jemand versucht möglicherweise, das Passwort zu erraten. Andere Rechner und "+
				"laufende Sitzungen sind nicht betroffen.", account, when)
	case "zweifaktor_gesperrt":
		return alarm.Crit, "Zweiter Faktor gesperrt",
			fmt.Sprintf("Für das Konto %s sind bis zum %s binnen 15 Minuten zehn falsche Codes eingegeben worden, "+
				"auch von verschiedenen Rechnern. Die Anmeldung mit Code ist 15 Minuten gesperrt, Passkeys gehen "+
				"weiter. Wer das versucht, kennt wahrscheinlich das Passwort: Passwort ändern.", account, when)
	case "zweifaktor_zurueckgesetzt":
		return alarm.Warn, "Zwei-Faktor-Anmeldung zurückgesetzt",
			fmt.Sprintf("Die Zwei-Faktor-Anmeldung des Kontos %s ist am %s auf der Zentrale zurückgesetzt worden. "+
				"Bei der nächsten Anmeldung wird die App neu eingerichtet. War das nicht abgesprochen, sofort den "+
				"Betreiber fragen.", account, when)
	case "passwort_gesetzt":
		return alarm.Warn, "Passwort auf der Zentrale gesetzt",
			fmt.Sprintf("Das Passwort des Kontos %s ist am %s auf der Zentrale neu gesetzt worden; alle Sitzungen "+
				"sind beendet. War das nicht abgesprochen, sofort den Betreiber fragen.", account, when)
	}
	return "", "", ""
}

// sendAuthNotices verschickt offene Meldungen (ein Durchlauf).
func (s *Server) sendAuthNotices(ctx context.Context) {
	c := s.mailConfig()
	if c == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT id, kind, created_at, email, display_name, operators
		FROM openwacht.auth_notices_open(20)`)
	if err != nil {
		slog.Warn("Anmeldemeldungen nicht lesbar", "fehler", err)
		return
	}
	var list []authNotice
	for rows.Next() {
		var n authNotice
		if err := rows.Scan(&n.id, &n.kind, &n.at, &n.email, &n.name, &n.operators); err != nil {
			rows.Close()
			slog.Warn("Anmeldemeldungen nicht lesbar", "fehler", err)
			return
		}
		list = append(list, n)
	}
	rows.Close()
	if rows.Err() != nil {
		return
	}
	loc := s.mailZone()
	for _, n := range list {
		var rcpts []string
		account := alarm.Clean(n.name, 100)
		if n.email != nil {
			rcpts = append(rcpts, *n.email)
			account = alarm.Clean(*n.email, 254)
		}
		rcpts = append(rcpts, n.operators...)
		status, title, text := authNoticeText(n, account, loc)
		ok := true
		if len(rcpts) > 0 && title != "" {
			msg := alarm.Notice{Status: status, Title: title, Text: text, Since: n.at, Operator: true,
				Link: s.cfg.BaseURL.String()}.Mail()
			if _, err := s.mailer.Send(ctx, *c, rcpts, msg); err != nil {
				ok = false
				slog.Warn("Anmeldemeldung nicht verschickt", "art", n.kind, "fehler", err)
			}
		}
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.auth_notice_done($1, $2)`, n.id, ok); err != nil {
			slog.Warn("Anmeldemeldung nicht quittiert", "fehler", err)
		}
	}
}
