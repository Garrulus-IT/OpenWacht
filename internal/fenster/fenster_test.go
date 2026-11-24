// SPDX-License-Identifier: AGPL-3.0-only

package fenster

import (
	"testing"
	"time"
)

var berlin, _ = LoadZone("Europe/Berlin")

func at(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, berlin)
	if err != nil {
		panic(err)
	}
	return t
}

func TestWeekly(t *testing.T) {
	// Di und Do 22:00 für 4 Std. (über Mitternacht)
	r := Rule{Repeat: Weekly, Weekdays: 1<<1 | 1<<3, Hour: 22, Minute: 0, Duration: 4 * time.Hour, Loc: berlin}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for now, want := range map[string]string{
		"2026-11-24 21:59": "",                 // Di kurz davor
		"2026-11-24 22:00": "2026-11-25 02:00", // Di Beginn
		"2026-11-25 01:59": "2026-11-25 02:00", // Mi nach Mitternacht, noch im Di-Fenster
		"2026-11-25 02:00": "",                 // Ende ist exklusiv
		"2026-11-25 22:30": "",                 // Mi nicht
		"2026-11-26 23:00": "2026-11-27 02:00", // Do
	} {
		end, ok := r.Active(at(now))
		if (want == "") == ok || ok && !end.Equal(at(want)) {
			t.Errorf("%s: %v %v, erwartet %q", now, end, ok, want)
		}
	}
	s, e, ok := r.Next(at("2026-11-24 22:30"))
	if !ok || !s.Equal(at("2026-11-26 22:00")) || !e.Equal(at("2026-11-27 02:00")) {
		t.Errorf("Next: %v %v", s, e)
	}
	if got := r.Text(); got != "jeden Di, Do um 22:00 für 4 Std." {
		t.Errorf("Text: %q", got)
	}
}

func TestMonthlyPatchday(t *testing.T) {
	// Microsoft-Patchday: 2. Dienstag; Wartung am Tag danach 20:00 für 3 Std.
	r := Rule{Repeat: Monthly, Nth: 2, Weekday: 2, Offset: 1, Hour: 20, Duration: 3 * time.Hour, Loc: berlin}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// 2. Dienstag: 10.11.2026, 8.12.2026, 12.1.2027
	for _, want := range []string{"2026-11-11 20:00", "2026-12-09 20:00", "2027-01-13 20:00"} {
		if _, ok := r.Active(at(want).Add(time.Hour)); !ok {
			t.Errorf("%s nicht aktiv", want)
		}
	}
	s, _, ok := r.Next(at("2026-11-21 12:00"))
	if !ok || !s.Equal(at("2026-12-09 20:00")) {
		t.Errorf("Next: %v", s)
	}
	if _, ok := r.Active(at("2026-11-10 21:00")); ok {
		t.Error("Patchday selbst aktiv")
	}
	if got := r.Text(); got != "monatlich am 2. Dienstag + 1 Tag um 20:00 für 3 Std." {
		t.Errorf("Text: %q", got)
	}
	// Letzter Freitag
	l := Rule{Repeat: Monthly, Nth: -1, Weekday: 5, Hour: 6, Duration: time.Hour, Loc: berlin}
	s, _, _ = l.Next(at("2026-11-01 00:00"))
	if !s.Equal(at("2026-11-27 06:00")) {
		t.Errorf("letzter Freitag: %v", s)
	}
	// Versatz über das Monatsende: letzter So im November (29.11.) + 3 Tage = 2.12.
	o := Rule{Repeat: Monthly, Nth: -1, Weekday: 7, Offset: 3, Hour: 1, Duration: time.Hour, Loc: berlin}
	s, _, _ = o.Next(at("2026-12-01 00:00"))
	if !s.Equal(at("2026-12-02 01:00")) {
		t.Errorf("Versatz: %v", s)
	}
	// Vorkommen des Vormonats, das in den neuen Monat reicht (4. Mi + 20 Tage)
	v := Rule{Repeat: Monthly, Nth: 4, Weekday: 3, Offset: 20, Hour: 0, Duration: 2 * time.Hour, Loc: berlin}
	if _, ok := v.Active(at("2026-12-15 01:00")); !ok { // 4. Mi Nov = 25.11. + 20 = 15.12.
		t.Error("Vormonat nicht erkannt")
	}
}

func TestSommerzeit(t *testing.T) {
	// So 02:30 gibt es am 29.03.2026 nicht; Fenster 2 Std.
	r := Rule{Repeat: Weekly, Weekdays: 1 << 6, Hour: 2, Minute: 30, Duration: 2 * time.Hour, Loc: berlin}
	s, e, _ := r.Next(at("2026-03-28 12:00"))
	if e.Sub(s) != 2*time.Hour {
		t.Errorf("Dauer %v", e.Sub(s))
	}
	if s.UTC().Hour() != 1 || s.UTC().Minute() != 30 { // 03:30 MESZ = 01:30 UTC
		t.Errorf("Beginn %v", s)
	}
	// Ortszeit bleibt über die Umstellung gleich: 22:00 im Oktober und November
	w := Rule{Repeat: Weekly, Weekdays: 1 << 0, Hour: 22, Duration: time.Hour, Loc: berlin}
	a, _, _ := w.Next(at("2026-10-18 00:00")) // Mo 19.10., noch Sommerzeit (Umstellung 25.10.)
	b, _, _ := w.Next(at("2026-11-01 00:00"))
	if a.In(berlin).Hour() != 22 || b.In(berlin).Hour() != 22 || a.UTC().Hour() == b.UTC().Hour() {
		t.Errorf("Ortszeit: %v / %v", a, b)
	}
}

func TestOnceAndValidate(t *testing.T) {
	r := Rule{Repeat: Once, Start: at("2026-11-22 08:00"), End: at("2026-11-22 12:00"), Loc: berlin}
	if _, ok := r.Active(at("2026-11-22 09:00")); !ok {
		t.Error("einmalig nicht aktiv")
	}
	if _, _, ok := r.Next(at("2026-11-22 09:00")); ok {
		t.Error("Next nach Beginn")
	}
	for _, bad := range []Rule{
		{Repeat: Once, Start: at("2026-11-22 08:00"), End: at("2026-11-30 08:01"), Loc: berlin},
		{Repeat: Once, Start: at("2026-11-22 08:00"), End: at("2026-11-22 08:00"), Loc: berlin},
		{Repeat: Weekly, Weekdays: 0, Duration: time.Hour, Loc: berlin},
		{Repeat: Weekly, Weekdays: 1, Duration: 8 * 24 * time.Hour, Loc: berlin},
		{Repeat: Weekly, Weekdays: 1, Hour: 24, Duration: time.Hour, Loc: berlin},
		{Repeat: Monthly, Nth: 5, Weekday: 2, Duration: time.Hour, Loc: berlin},
		{Repeat: Monthly, Nth: 1, Weekday: 0, Duration: time.Hour, Loc: berlin},
		{Repeat: Monthly, Nth: 1, Weekday: 2, Offset: 28, Duration: time.Hour, Loc: berlin},
		{Repeat: "taeglich"},
	} {
		if bad.Validate() == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
	for _, z := range []string{"", "Local", "../etc/passwd", "Mars/Olympus"} {
		if _, err := LoadZone(z); err == nil {
			t.Errorf("Zone %q angenommen", z)
		}
	}
	if DurationText(150*time.Minute) != "2 Std. 30 Min." || DurationText(48*time.Hour) != "2 Tage" {
		t.Error("DurationText")
	}
}
