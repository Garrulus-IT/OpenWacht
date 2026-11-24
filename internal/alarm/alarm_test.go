// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	old := now.Add(-13 * time.Hour)
	recent := now.Add(-time.Hour)
	for _, c := range []struct {
		name      string
		status    string
		fails     int
		alerted   string
		alertedAt time.Time
		want      Event
	}{
		{"OK, nie gemeldet", OK, 0, "", time.Time{}, None},
		{"OK, OK gemeldet", OK, 0, OK, recent, None},
		{"Erholung nach Fehler", OK, 0, Crit, recent, Recovered},
		{"Erholung nach Warnung", OK, 0, Warn, recent, Recovered},
		{"Erholung nach unbekannt", OK, 0, Unknown, recent, Recovered},
		{"erster Fehlschlag", Crit, 1, OK, recent, None},
		{"erster Fehlschlag, nie gemeldet", Crit, 1, "", time.Time{}, None},
		{"zweiter Fehlschlag", Crit, 2, OK, recent, Problem},
		{"zweiter Fehlschlag, nie gemeldet", Crit, 2, "", time.Time{}, Problem},
		{"Fehler bleibt", Crit, 5, Crit, recent, None},
		{"Erinnerung nach 12 h", Crit, 50, Crit, old, Reminder},
		{"unbekannt nach Fehler", Unknown, 3, Crit, recent, Problem},
		{"unbekannt, erster", Unknown, 1, OK, recent, None},
		{"Warnung sofort", Warn, 1, OK, recent, Problem},
		{"Warnung, nie gemeldet", Warn, 1, "", time.Time{}, Problem},
		{"Warnung einmalig", Warn, 9, Warn, old, None},
		{"Warnung nach Fehler", Warn, 3, Crit, recent, Problem},
		{"Fehler nach Warnung, unter Schwelle", Crit, 1, Warn, recent, None},
		{"Fehler nach Warnung", Crit, 2, Warn, recent, Problem},
		{"noch nie gelaufen", "", 0, "", time.Time{}, None},
	} {
		if got := Decide(c.status, c.fails, c.alerted, c.alertedAt, 2, 12*time.Hour, now); got != c.want {
			t.Errorf("%s: %v, erwartet %v", c.name, got, c.want)
		}
	}
	if got := Decide(Crit, 9, Crit, old, 2, 0, now); got != None {
		t.Errorf("Erinnerung abgeschaltet: %v", got)
	}
}

func TestBuild(t *testing.T) {
	m := Build("IT", []Item{
		{Tenant: "IT", Check: "NAS", Status: OK, Message: "Port 5001 offen", Event: Recovered},
		{Tenant: "IT", Check: "Router", Status: Crit, Message: "keine\nAntwort", Event: Problem},
		{Tenant: "IT", Check: "Zert", Status: Warn, Message: "läuft in 10 Tagen ab", Event: Problem},
		{Tenant: "IT", Check: "DNS", Status: Crit, Message: "kaputt", Event: Reminder},
	})
	if m.Title != "IT: 3 Probleme, 1 wieder OK" || m.Priority != 4 || m.Tags[0] != "rotating_light" {
		t.Errorf("Titel/Priorität: %+v", m)
	}
	want := "❌ DNS: kaputt (Erinnerung)\n❌ Router: keine Antwort\n⚠️ Zert: läuft in 10 Tagen ab\n✅ NAS: Port 5001 offen"
	if m.Message != want {
		t.Errorf("Nachricht:\n%s", m.Message)
	}
	// Untermandanten: Titel nach dem Mandanten, wenn alles von einem kommt;
	// sonst nach dem Kanal, und der Mandant steht vor dem Check.
	m = Build("IT", []Item{{Tenant: "Fertigung", Check: "FW NAS", Status: Warn, Message: "x", Event: Problem}})
	if m.Title != "Fertigung: 1 Problem" || !strings.HasPrefix(m.Message, "⚠️ Fertigung / FW NAS: x") || m.Priority != 3 {
		t.Errorf("Untermandant: %+v", m)
	}
	m = Build("IT", []Item{
		{Tenant: "Fertigung", Check: "A", Status: OK, Event: Recovered},
		{Tenant: "IT", Check: "B", Status: OK, Event: Recovered},
	})
	if m.Title != "IT: 2 wieder OK" || m.Tags[0] != "white_check_mark" || !strings.Contains(m.Message, "Fertigung / A") {
		t.Errorf("gemischt: %+v", m)
	}
	// Viele Ereignisse: gekürzt, Titel zählt trotzdem alle.
	var many []Item
	for i := range 40 {
		many = append(many, Item{Tenant: "IT", Check: fmt.Sprintf("C%02d", i), Status: Crit,
			Message: strings.Repeat("x", 300), Event: Problem})
	}
	m = Build("IT", many)
	if m.Title != "IT: 40 Probleme" || len(m.Message) > 4096 || !strings.Contains(m.Message, "weitere") {
		t.Errorf("gekürzt: %q, %d Byte", m.Title, len(m.Message))
	}
}

func TestNormalizeServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://NTFY.example/":       "https://ntfy.example",
		"https://ntfy.example:8443":   "https://ntfy.example:8443",
		"https://host/ntfy/":          "https://host/ntfy",
		"http://127.0.0.1:2586":       "http://127.0.0.1:2586",
		"http://localhost:2586/":      "http://localhost:2586",
		"http://[::1]:2586":           "http://[::1]:2586",
		" https://ntfy.example  ":     "https://ntfy.example",
		"HTTPS://ntfy.example/a/b///": "https://ntfy.example/a/b",
	} {
		if got, err := NormalizeServer(in); err != nil || got != want {
			t.Errorf("%q: %q %v, erwartet %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "ntfy.example", "http://ntfy.example", "http://192.168.1.5", "ftp://x", "file:///etc/passwd",
		"https://u:p@ntfy.example", "https://ntfy.example/?x=1", "https://ntfy.example/#a", "https://ntfy.example/a b",
		"https://", "javascript:alert(1)", "https://ntfy.example/" + strings.Repeat("a", 300),
	} {
		if got, err := NormalizeServer(in); err == nil {
			t.Errorf("%q angenommen als %q", in, got)
		}
	}
}

func TestTopicUndToken(t *testing.T) {
	for _, s := range []string{"betrieb", "a-b_C9", strings.Repeat("a", 64)} {
		if !ValidTopic(s) {
			t.Errorf("Topic %q abgelehnt", s)
		}
	}
	for _, s := range []string{"", "a/b", "a b", "ä", strings.Repeat("a", 65), "a\n"} {
		if ValidTopic(s) {
			t.Errorf("Topic %q angenommen", s)
		}
	}
	if !ValidToken("tk_abcdefghijklmnopqrstuvwxyz012") {
		t.Error("ntfy-Token abgelehnt")
	}
	for _, s := range []string{"", "a b", "a\r\nX-Evil: 1", "ä", strings.Repeat("a", 201)} {
		if ValidToken(s) {
			t.Errorf("Token %q angenommen", s)
		}
	}
}

type fakeNtfy struct {
	*httptest.Server
	got  chan map[string]any
	auth chan string
	code int
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	f := &fakeNtfy{got: make(chan map[string]any, 10), auth: make(chan string, 10), code: 200}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, `{"error":"falsch"}`, 400)
			return
		}
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		f.got <- m
		f.auth <- r.Header.Get("Authorization")
		if f.code != 200 {
			w.WriteHeader(f.code)
			w.Write([]byte(`{"code":40301,"http":403,"error":"forbidden\nzweite Zeile"}`))
			return
		}
		w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(f.Close)
	return f
}

func TestSend(t *testing.T) {
	f := newFakeNtfy(t)
	server, _ := NormalizeServer(f.URL)
	s := NewSender(NewTargets(f.URL))
	ctx := context.Background()
	msg := Message{Title: "T", Message: "M", Priority: 4, Tags: []string{"warning"}}
	if err := s.Send(ctx, server, "betrieb", "tk_geheim", msg); err != nil {
		t.Fatal(err)
	}
	got := <-f.got
	if got["topic"] != "betrieb" || got["title"] != "T" || got["message"] != "M" || got["priority"] != 4.0 {
		t.Errorf("Inhalt: %v", got)
	}
	if a := <-f.auth; a != "Bearer tk_geheim" {
		t.Errorf("Authorization: %q", a)
	}
	// Ohne Token kein Authorization-Header.
	if err := s.Send(ctx, server, "betrieb", "", msg); err != nil {
		t.Fatal(err)
	}
	<-f.got
	if a := <-f.auth; a != "" {
		t.Errorf("Authorization ohne Token: %q", a)
	}
	// Fehlerantwort: Text bereinigt, Token nie in der Meldung.
	f.code = 403
	err := s.Send(ctx, server, "betrieb", "tk_geheim", msg)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403: forbidden zweite Zeile") || strings.Contains(err.Error(), "geheim") {
		t.Errorf("Fehler: %v", err)
	}
	<-f.got
	<-f.auth
	// Nicht freigegeben, nicht normalisiert, ungültige Eingaben: gar nicht erst senden.
	for name, call := range map[string]func() error{
		"fremder Server":     func() error { return NewSender(NewTargets("https://ntfy.example")).Send(ctx, server, "a", "", msg) },
		"nicht normalisiert": func() error { return s.Send(ctx, server+"/", "a", "", msg) },
		"Topic":              func() error { return s.Send(ctx, server, "a/b", "", msg) },
		"Token":              func() error { return s.Send(ctx, server, "a", "x\r\nX: y", msg) },
		"keine Ziele":        func() error { return NewSender(nil).Send(ctx, server, "a", "", msg) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: gesendet", name)
		}
	}
	select {
	case m := <-f.got:
		t.Errorf("trotzdem gesendet: %v", m)
	default:
	}
}

func TestSendOhneWeiterleitung(t *testing.T) {
	hit := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit <- struct{}{} }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	server, _ := NormalizeServer(redir.URL)
	err := NewSender(NewTargets(redir.URL)).Send(context.Background(), server, "a", "tk_x", Message{})
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("Weiterleitung: %v", err)
	}
	select {
	case <-hit:
		t.Error("Weiterleitung verfolgt")
	default:
	}
}

func TestSendNichtErreichbar(t *testing.T) {
	f := newFakeNtfy(t)
	server, _ := NormalizeServer(f.URL)
	f.Close()
	err := NewSender(NewTargets(server)).Send(context.Background(), server, "a", "tk_geheim", Message{})
	if err == nil || !strings.Contains(err.Error(), "nicht erreichbar") || strings.Contains(err.Error(), "geheim") ||
		strings.Contains(err.Error(), server) {
		t.Errorf("Fehler: %v", err)
	}
}
