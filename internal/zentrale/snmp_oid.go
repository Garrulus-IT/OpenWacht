// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Sensor „SNMP eigene OID“ (Etappe 18b). Die OIDs laufen mit der normalen
// Abfrage des Geräts (Zentrale oder Sammler); nach jedem gespeicherten
// Ergebnis bewertet die Zentrale die Sensoren des Geräts. Raten rechnet sie
// aus ihren eigenen gespeicherten Werten, Texte vergleicht sie nur als Hash.

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

type oidCheck struct {
	id, source string
	revision   int
	spec       checks.Spec
}

// oidChecks: aktive OID-Sensoren der Geräte dieser Quellen (ohne Benutzer-
// kontext, SECURITY DEFINER). Gespeicherte Ziele werden erneut geprüft.
func (s *Server) oidChecks(ctx context.Context, sources []string) (map[string][]oidCheck, error) {
	out := map[string][]oidCheck{}
	if len(sources) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT source_id::text, id::text, revision, target FROM openwacht.snmp_oid_checks($1::uuid[])`, sources)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c oidCheck
		var target []byte
		if err := rows.Scan(&c.source, &c.id, &c.revision, &target); err != nil {
			return nil, err
		}
		if c.spec, err = checks.Parse("snmp_oid", target); err != nil {
			slog.Warn("SNMP-OID: gespeichertes Ziel ungültig", "sensor", c.id, "fehler", err)
			continue
		}
		if len(out[c.source]) < snmp.MaxExtraOIDs {
			out[c.source] = append(out[c.source], c)
		}
	}
	return out, rows.Err()
}

// extraOIDs: die OIDs, die eine Abfrage zusätzlich lesen soll (ohne Doppel).
func extraOIDs(list []oidCheck) []string { return oidList(list, false) }

// extraText: Aufträge „Zahl aus Text“ der Sensoren (ohne Doppel, 1.0.8).
func extraText(list []oidCheck) []snmp.TextZahl {
	var out []snmp.TextZahl
	for _, c := range list {
		sp := c.spec
		if sp.TextNumber == "" || sp.Aggregate != "" {
			continue
		}
		t := textAuftrag(sp)
		if !slices.Contains(out, t) && len(out) < snmp.MaxExtraText {
			out = append(out, t)
		}
	}
	return out
}

// extraShow: eigene OIDs, deren Text ein Sensor anzeigen will (ohne Doppel, 1.0.10).
func extraShow(list []oidCheck) []string {
	var out []string
	for _, c := range list {
		if c.spec.TextShow && c.spec.Aggregate == "" && !slices.Contains(out, c.spec.OID) {
			out = append(out, c.spec.OID)
		}
	}
	return out
}

// textAuftrag: Auftrag zu einem Sensor mit „Zahl aus Text“.
func textAuftrag(sp checks.Spec) snmp.TextZahl {
	switch sp.TextNumber {
	case "nte":
		return snmp.TextZahl{OID: sp.OID, N: sp.TextIndex}
	case "nach":
		return snmp.TextZahl{OID: sp.OID, Nach: sp.TextAfter}
	}
	return snmp.TextZahl{OID: sp.OID, N: 1}
}

// extraColumns: die Tabellenspalten, die eine Abfrage zusammenfassen soll.
func extraColumns(list []oidCheck) []string { return oidList(list, true) }

func oidList(list []oidCheck, columns bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range list {
		if (c.spec.Aggregate != "") == columns && !seen[c.spec.OID] {
			seen[c.spec.OID] = true
			out = append(out, c.spec.OID)
		}
	}
	return out
}

func findColumn(snap *snmp.Snapshot, oid string) *snmp.ColumnValue {
	if snap == nil {
		return nil
	}
	for i := range snap.Columns {
		if snap.Columns[i].OID == oid {
			return &snap.Columns[i]
		}
	}
	return nil
}

// columnNumber: die Kennzahl einer Spalte, die der Sensor bewertet.
// ok=false mit Meldung: keine Aussage über Schwellen möglich.
func columnNumber(sp checks.Spec, c *snmp.ColumnValue) (x float64, msg string, ok bool) {
	switch sp.Aggregate {
	case "anzahl":
		return float64(c.Rows), "", true
	case "anzahl_gleich", "anzahl_ungleich":
		if c.Values == nil && c.Numbers > 0 {
			return 0, "Spalte hat zu viele verschiedene Werte zum Zählen", false
		}
		n := c.Values[strconv.FormatInt(*sp.Compare, 10)]
		if sp.Aggregate == "anzahl_ungleich" {
			n = c.Rows - n
		}
		return float64(n), "", true
	}
	if c.Rows == 0 {
		return 0, "Tabelle ohne Zeilen", false
	}
	if c.Numbers == 0 {
		return 0, "Spalte enthält keine Zahlen", false
	}
	switch sp.Aggregate {
	case "minimum":
		return *c.Min, "", true
	case "maximum":
		return *c.Max, "", true
	}
	return *c.Sum, "", true
}

// evalColumn bewertet einen Sensor über eine Tabellenspalte.
func evalColumn(sp checks.Spec, cur *snmp.Snapshot) (checks.Result, bool) {
	c := findColumn(cur, sp.OID)
	if c == nil {
		return checks.Result{}, false
	}
	x, msg, ok := columnNumber(sp, c)
	if !ok {
		return checks.Result{Status: checks.Unknown, Message: msg}, true
	}
	// Faktor und Einheit (1.0.8) für Minimum, Maximum und Summe, nicht für Anzahlen
	metric := numText(x)
	if !strings.HasPrefix(sp.Aggregate, "anzahl") {
		if sp.Factor != 0 {
			x *= sp.Factor
		}
		metric = numText(x)
		if sp.Unit != "" {
			metric += " " + sp.Unit
		}
	}
	res := judgeThresholds(sp, x, metric)
	if c.Truncated {
		res.Message += fmt.Sprintf(" (nur die ersten %d Zeilen)", snmp.MaxColumnRows)
	}
	return res, true
}

func findExtra(snap *snmp.Snapshot, oid string) *snmp.ExtraValue {
	if snap == nil {
		return nil
	}
	for i := range snap.Extra {
		if snap.Extra[i].OID == oid {
			return &snap.Extra[i]
		}
	}
	return nil
}

func numText(v float64) string {
	return strings.Replace(strconv.FormatFloat(math.Round(v*1000)/1000, 'f', -1, 64), ".", ",", 1)
}

// OIDs, die eine Laufzeit in Hundertstelsekunden melden (TimeTicks).
const (
	oidHrSystemUptime = "1.3.6.1.2.1.25.1.1.0"
	oidSysUpTime      = "1.3.6.1.2.1.1.3.0"
)

// durationScale (1.0.11): Faktor, mit dem der Wert eines Sensors zu Sekunden
// wird, wenn er eine Dauer misst; 0 = keine Dauer. Eine Dauer ist ein Wert mit
// der Einheit „s“ und, ohne Faktor und Einheit, die Laufzeit des Systems
// (hrSystemUptime, sysUpTime). Die Schwellen bleiben in der Zahl des Sensors;
// nur Anzeige und Meldung nennen Stunden, Minuten und Sekunden.
func durationScale(sp checks.Spec) float64 {
	switch {
	case sp.Rate || sp.Aggregate != "" || sp.TextShow:
		return 0
	case sp.Unit == "s":
		return 1
	case sp.Unit == "" && sp.Factor == 0 && (sp.OID == oidHrSystemUptime || sp.OID == oidSysUpTime):
		return 0.01
	}
	return 0
}

// dauerText: Sekunden als „26 Std. 14 Min. 5 Sek.“; unter einer Minute mit
// Bruchteilen („0,5 Sek.“).
func dauerText(sec float64) string {
	if math.IsNaN(sec) || math.IsInf(sec, 0) || sec < 0 || sec > 1e15 {
		return numText(sec) + " Sek."
	}
	if sec < 60 {
		return numText(sec) + " Sek."
	}
	total := int64(math.Round(sec))
	h, m, s := total/3600, (total%3600)/60, total%60
	if h == 0 {
		return fmt.Sprintf("%d Min. %d Sek.", m, s)
	}
	return fmt.Sprintf("%d Std. %d Min. %d Sek.", h, m, s)
}

// evalOID bewertet einen OID-Sensor. record=false: noch keine Aussage
// möglich (OID nicht gelesen, Rate ohne vorigen Wert, Neustart des Geräts).
func evalOID(sp checks.Spec, cur, prev *snmp.Snapshot, rebooted bool) (res checks.Result, record bool) {
	if sp.Aggregate != "" {
		return evalColumn(sp, cur)
	}
	e := findExtra(cur, sp.OID)
	if e == nil {
		return res, false
	}
	if e.Missing {
		return checks.Result{Status: checks.Unknown, Message: "OID fehlt am Gerät"}, true
	}
	var num *float64
	switch {
	case sp.TextNumber != "":
		// Zahl aus Text (1.0.8): Die Abfrage hat sie schon herausgelesen.
		if e.TextHash == "" {
			if e.Number == nil {
				return checks.Result{Status: checks.Unknown, Message: "Wert ist kein Text"}, true
			}
			num = e.Number // das Gerät liefert schon eine Zahl
			break
		}
		want := textAuftrag(sp)
		i := slices.IndexFunc(e.AusText, func(t snmp.TextWert) bool { return t.N == want.N && t.Nach == want.Nach })
		if i < 0 {
			// Auftrag gerade erst angelegt (nächste Abfrage) oder der Sammler ist zu alt
			return checks.Result{Status: checks.Unknown, Message: "Zahl aus Text noch nicht gelesen (ein Sammler braucht dafür den Agent ab 1.0.8)"}, true
		}
		if e.AusText[i].Zahl == nil {
			return checks.Result{Status: checks.Unknown, Message: "Im Text steht an dieser Stelle keine Zahl"}, true
		}
		num = e.AusText[i].Zahl
	case e.Number != nil:
		num = e.Number
	case e.Counter != nil:
		f := float64(*e.Counter)
		num = &f
	}
	if num != nil && sp.Factor != 0 && !sp.Rate {
		f := *num * sp.Factor
		num = &f
	}
	unit := ""
	if sp.Unit != "" {
		unit = " " + sp.Unit
	}
	metric := ""
	if sp.Rate {
		p := findExtra(prev, sp.OID)
		if p == nil || num == nil || rebooted || prev.Counters == nil || cur.Counters == nil {
			return res, false
		}
		dt := cur.Counters.At.Sub(prev.Counters.At).Seconds()
		if dt <= 0 {
			return res, false
		}
		var diff float64
		switch {
		case e.Counter != nil && p.Counter != nil:
			d := *e.Counter - *p.Counter
			if *e.Counter < *p.Counter { // Überlauf
				if e.Bits == 32 {
					d = *e.Counter + (1<<32 - *p.Counter)
				} else {
					return res, false
				}
			}
			diff = float64(d)
		case e.Number != nil && p.Number != nil:
			diff = *e.Number - *p.Number
		default:
			return res, false
		}
		rate := diff / dt
		if sp.Factor != 0 {
			rate *= sp.Factor
		}
		num = &rate
		metric = numText(rate) + unit + "/s"
	} else if num != nil {
		metric = numText(*num) + unit
		if sc := durationScale(sp); sc != 0 {
			metric = dauerText(*num * sc)
		}
	}
	if utf := []rune(metric); len(utf) > 50 {
		metric = string(utf[:50])
	}
	if sp.TextShow {
		// Text anzeigen (1.0.10): der Text des Geräts ist der Messwert.
		switch {
		case e.Text != "":
			metric = e.Text
		case e.TextHash != "":
			// gerade erst eingeschaltet (nächste Abfrage) oder der Sammler ist zu alt
			return checks.Result{Status: checks.Unknown, Message: "Text noch nicht gelesen (ein Sammler braucht dafür den Agent ab 1.0.10)"}, true
		}
	}
	if sp.Equals != nil {
		ok := false
		switch {
		case e.TextHash != "" && sp.Factor == 0:
			ok = e.TextHash == snmp.TextHash(*sp.Equals)
		case num != nil:
			if f, err := strconv.ParseFloat(strings.Replace(strings.TrimSpace(*sp.Equals), ",", ".", 1), 64); err == nil {
				ok = f == *num
			}
		}
		if !ok {
			return checks.Result{Status: checks.Crit, Message: "Wert weicht vom erwarteten ab", Metric: metric}, true
		}
		return checks.Result{Status: checks.OK, Message: "Wert wie erwartet", Metric: metric}, true
	}
	if sp.WarnAbove == nil && sp.CritAbove == nil && sp.WarnBelow == nil && sp.CritBelow == nil {
		return checks.Result{Status: checks.OK, Message: "Wert vorhanden", Metric: metric}, true
	}
	if num == nil {
		return checks.Result{Status: checks.Unknown, Message: "Wert ist keine Zahl"}, true
	}
	if sc := durationScale(sp); sc != 0 {
		// „Laufzeit“ nur für die Laufzeit des Systems, sonst allgemein „Dauer“
		label := "Dauer"
		if sp.OID == oidHrSystemUptime || sp.OID == oidSysUpTime {
			label = "Laufzeit"
		}
		return judgeWith(sp, *num, metric, label, func(v float64) string { return dauerText(v * sc) }), true
	}
	return judgeThresholds(sp, *num, metric), true
}

// judgeThresholds: Schwellen „über“ und „unter“; ohne Schwellen nur Anzeige.
func judgeThresholds(sp checks.Spec, x float64, metric string) checks.Result {
	return judgeWith(sp, x, metric, "Wert", numText)
}

// judgeWith: wie judgeThresholds, mit eigenem Wort für den Wert und eigener
// Schreibweise der Schwellen (z. B. eine Dauer).
func judgeWith(sp checks.Spec, x float64, metric, label string, text func(float64) string) checks.Result {
	if sp.WarnAbove == nil && sp.CritAbove == nil && sp.WarnBelow == nil && sp.CritBelow == nil {
		return checks.Result{Status: checks.OK, Message: "Wert vorhanden", Metric: metric}
	}
	switch {
	case sp.CritAbove != nil && x > *sp.CritAbove:
		return checks.Result{Status: checks.Crit, Message: label + " über " + text(*sp.CritAbove) + " (kritisch)", Metric: metric}
	case sp.CritBelow != nil && x < *sp.CritBelow:
		return checks.Result{Status: checks.Crit, Message: label + " unter " + text(*sp.CritBelow) + " (kritisch)", Metric: metric}
	case sp.WarnAbove != nil && x > *sp.WarnAbove:
		return checks.Result{Status: checks.Warn, Message: label + " über " + text(*sp.WarnAbove) + " (Warnung)", Metric: metric}
	case sp.WarnBelow != nil && x < *sp.WarnBelow:
		return checks.Result{Status: checks.Warn, Message: label + " unter " + text(*sp.WarnBelow) + " (Warnung)", Metric: metric}
	}
	return checks.Result{Status: checks.OK, Message: "Wert im Rahmen", Metric: metric}
}

// recordOIDs speichert die Ergebnisse der OID-Sensoren einer Quelle.
func (s *Server) recordOIDs(ctx context.Context, list []oidCheck, cur, prev *snmp.Snapshot, rebooted bool) {
	for _, c := range list {
		res, ok := evalOID(c.spec, cur, prev, rebooted)
		if !ok {
			continue
		}
		var stored bool
		if err := s.pool.QueryRow(context.WithoutCancel(ctx), `SELECT openwacht.check_record($1, $2, $3, $4, $5, NULL)`,
			c.id, c.revision, res.Status, clipRunes(res.Message, 300), clipRunes(res.Metric, 50)).Scan(&stored); err != nil {
			slog.Warn("SNMP-OID: Ergebnis nicht gespeichert", "sensor", c.id, "fehler", fmt.Sprint(err))
		}
	}
}
