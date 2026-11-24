// SPDX-License-Identifier: AGPL-3.0-only

// Package fenster rechnet die Termine von Wartungsfenstern aus (Etappe 20b):
// einmalig, wöchentlich an Wochentagen oder monatlich am n-ten Wochentag mit
// Versatz in Tagen (Patchday). Beginn ist eine Ortszeit in der Zeitzone des
// Fensters; die Dauer ist absolute Zeit. Fällt ein Beginn in die Lücke der
// Sommerzeitumstellung, gilt die Zeit, die time.Date daraus macht (eine Stunde
// später); in der doppelten Stunde im Herbst die erste.
package fenster

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Arten der Wiederholung.
const (
	Once    = "einmalig"
	Weekly  = "woechentlich"
	Monthly = "monatlich"
)

// MaxDuration: so lange dauert ein Fenster höchstens.
const MaxDuration = 7 * 24 * time.Hour

// Rule beschreibt ein Fenster.
type Rule struct {
	Repeat string
	// einmalig
	Start, End time.Time
	// wöchentlich: Bit 0 = Montag … Bit 6 = Sonntag
	Weekdays uint8
	// monatlich: n-ter (1–4, -1 = letzter) Wochentag (1 = Montag … 7 = Sonntag) plus Versatz
	Nth, Weekday, Offset int
	// wöchentlich und monatlich
	Hour, Minute int
	Duration     time.Duration
	Loc          *time.Location
}

// Validate prüft die Regel.
func (r Rule) Validate() error {
	switch r.Repeat {
	case Once:
		if r.Start.IsZero() || !r.End.After(r.Start) {
			return errors.New("Ende muss nach dem Beginn liegen")
		}
		if r.End.Sub(r.Start) > MaxDuration {
			return errors.New("ein Fenster dauert höchstens 7 Tage")
		}
		return nil
	case Weekly:
		if r.Weekdays == 0 || r.Weekdays > 127 {
			return errors.New("mindestens ein Wochentag")
		}
	case Monthly:
		if r.Nth != -1 && (r.Nth < 1 || r.Nth > 4) {
			return errors.New("n-ter Wochentag: 1. bis 4. oder letzter")
		}
		if r.Weekday < 1 || r.Weekday > 7 {
			return errors.New("Wochentag fehlt")
		}
		if r.Offset < 0 || r.Offset > 27 {
			return errors.New("Versatz: 0 bis 27 Tage")
		}
	default:
		return errors.New("Wiederholung: einmalig, wöchentlich oder monatlich")
	}
	if r.Hour < 0 || r.Hour > 23 || r.Minute < 0 || r.Minute > 59 {
		return errors.New("ungültige Uhrzeit")
	}
	if r.Duration < time.Minute || r.Duration > MaxDuration {
		return errors.New("Dauer: 1 Minute bis 7 Tage")
	}
	if r.Loc == nil {
		return errors.New("Zeitzone fehlt")
	}
	return nil
}

// LoadZone lädt eine Zeitzone (IANA-Name wie Europe/Berlin).
func LoadZone(name string) (*time.Location, error) {
	if name == "" || len(name) > 64 || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("unbekannte Zeitzone %q", name)
	}
	if name == "Local" {
		return nil, errors.New("Zeitzone bitte ausdrücklich angeben, z. B. Europe/Berlin")
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("unbekannte Zeitzone %q", name)
	}
	return l, nil
}

// isoWeekday: 1 = Montag … 7 = Sonntag.
func isoWeekday(t time.Time) int {
	w := int(t.Weekday())
	if w == 0 {
		return 7
	}
	return w
}

// at: Beginn am Kalendertag (y, m, d) in der Zone der Regel.
func (r Rule) at(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, r.Hour, r.Minute, 0, 0, r.Loc)
}

// monthDay: Tag des Monats für den n-ten Wochentag (ohne Versatz).
func (r Rule) monthDay(y int, m time.Month) int {
	if r.Nth > 0 {
		first := time.Date(y, m, 1, 12, 0, 0, 0, r.Loc)
		d := 1 + (r.Weekday-isoWeekday(first)+7)%7
		return d + (r.Nth-1)*7
	}
	last := time.Date(y, m+1, 0, 12, 0, 0, 0, r.Loc)
	return last.Day() - (isoWeekday(last)-r.Weekday+7)%7
}

// starts: Beginne der Vorkommen, deren Beginn im Bereich [from, to) liegt.
func (r Rule) starts(from, to time.Time) []time.Time {
	var out []time.Time
	switch r.Repeat {
	case Once:
		if !r.Start.Before(from) && r.Start.Before(to) {
			out = append(out, r.Start)
		}
	case Weekly:
		f := from.In(r.Loc)
		for d := time.Date(f.Year(), f.Month(), f.Day()-1, 12, 0, 0, 0, r.Loc); ; d = d.AddDate(0, 0, 1) {
			s := r.at(d.Year(), d.Month(), d.Day())
			if !s.Before(to) {
				break
			}
			if r.Weekdays&(1<<(isoWeekday(d)-1)) != 0 && !s.Before(from) {
				out = append(out, s)
			}
		}
	case Monthly:
		f := from.In(r.Loc)
		// Versatz bis 27 Tage: auch der Vormonat kann ein Vorkommen liefern.
		for m := time.Date(f.Year(), f.Month()-1, 1, 12, 0, 0, 0, r.Loc); ; m = m.AddDate(0, 1, 0) {
			if !r.at(m.Year(), m.Month(), 1).Before(to) {
				break
			}
			s := r.at(m.Year(), m.Month(), r.monthDay(m.Year(), m.Month())+r.Offset)
			if !s.Before(from) && s.Before(to) {
				out = append(out, s)
			}
		}
	}
	return out
}

func (r Rule) duration() time.Duration {
	if r.Repeat == Once {
		return r.End.Sub(r.Start)
	}
	return r.Duration
}

// Active: Läuft gerade ein Vorkommen? Dann mit seinem Ende.
func (r Rule) Active(now time.Time) (end time.Time, ok bool) {
	d := r.duration()
	if r.Repeat == Once {
		if !now.Before(r.Start) && now.Before(r.End) {
			return r.End, true
		}
		return time.Time{}, false
	}
	for _, s := range r.starts(now.Add(-d-time.Hour), now.Add(time.Second)) {
		e := s.Add(d)
		if !now.Before(s) && now.Before(e) && e.After(end) {
			end, ok = e, true
		}
	}
	return end, ok
}

// Next: das nächste Vorkommen, das nach now beginnt (bis 400 Tage voraus).
func (r Rule) Next(now time.Time) (start, end time.Time, ok bool) {
	if r.Repeat == Once {
		if r.Start.After(now) {
			return r.Start, r.End, true
		}
		return time.Time{}, time.Time{}, false
	}
	for _, s := range r.starts(now.Add(time.Nanosecond), now.Add(400*24*time.Hour)) {
		return s, s.Add(r.Duration), true
	}
	return time.Time{}, time.Time{}, false
}

var dayNames = []string{"Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"}
var dayLong = []string{"Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"}

// Text: „jeden Di, Do um 22:00 für 4 Std.“, „monatlich 2. Dienstag + 1 Tag um 20:00 für 3 Std.“.
func (r Rule) Text() string {
	switch r.Repeat {
	case Once:
		return "einmalig " + r.Start.In(r.Loc).Format("02.01.2006 15:04") + " bis " + r.End.In(r.Loc).Format("02.01.2006 15:04")
	case Weekly:
		var days []string
		for i := range 7 {
			if r.Weekdays&(1<<i) != 0 {
				days = append(days, dayNames[i])
			}
		}
		return fmt.Sprintf("jeden %s um %02d:%02d für %s", strings.Join(days, ", "), r.Hour, r.Minute, DurationText(r.Duration))
	case Monthly:
		n := fmt.Sprintf("%d.", r.Nth)
		if r.Nth == -1 {
			n = "letzten"
		}
		s := fmt.Sprintf("monatlich am %s %s", n, dayLong[r.Weekday-1])
		switch r.Offset {
		case 0:
		case 1:
			s += " + 1 Tag"
		default:
			s += fmt.Sprintf(" + %d Tage", r.Offset)
		}
		return s + fmt.Sprintf(" um %02d:%02d für %s", r.Hour, r.Minute, DurationText(r.Duration))
	}
	return ""
}

// DurationText: „45 Min.“, „4 Std.“, „2 Std. 30 Min.“, „2 Tage“.
func DurationText(d time.Duration) string {
	m := int(d.Minutes())
	switch {
	case m < 60:
		return fmt.Sprintf("%d Min.", m)
	case m%(24*60) == 0:
		if m == 24*60 {
			return "1 Tag"
		}
		return fmt.Sprintf("%d Tage", m/(24*60))
	case m%60 == 0:
		return fmt.Sprintf("%d Std.", m/60)
	}
	return fmt.Sprintf("%d Std. %d Min.", m/60, m%60)
}
