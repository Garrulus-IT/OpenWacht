// SPDX-License-Identifier: AGPL-3.0-only

package alarm_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/alarm/smtptest"
)

var berlin, _ = time.LoadLocation("Europe/Berlin")

func sampleReport(now time.Time) alarm.Report {
	since := now.Add(-130 * time.Minute)
	pts := []alarm.ChartPoint{}
	for i := 0; i <= 144; i++ {
		pts = append(pts, alarm.ChartPoint{T: now.Add(-24*time.Hour + time.Duration(i)*10*time.Minute), V: 80 + float64(i)/9})
	}
	return alarm.Report{
		Item:   alarm.Item{Tenant: "IT", Check: "pve-1 · Platte /var", Status: alarm.Crit, Message: "96 % belegt (kritisch ab 95 %)", Event: alarm.Problem},
		Device: "pve-1", Sensor: "Platte /var", Since: &since,
		Others:   []alarm.Other{{Name: "pve-1 · CPU", Status: alarm.Warn, Message: "92 %", Since: now.Add(-time.Hour)}},
		Forecast: "voll in etwa 3 Tagen", Link: "https://openwacht.example/hosts?geraet=x",
		Chart: &alarm.Chart{Title: "Platte /var", Unit: "%", Percent: true, Points: pts, Warn: 90, Crit: 95,
			From: now.Add(-24 * time.Hour), To: now},
	}
}

func TestReportSubjectFacts(t *testing.T) {
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	r := sampleReport(now)
	// Kurz (1.0.3): Zustand, Gerät, Sensor; die Meldung steht im Text.
	if got, want := r.Subject("IT"), "KRIT · pve-1 · Platte /var"; got != want {
		t.Errorf("Betreff %q, erwartet %q", got, want)
	}
	if got := r.Subject("Firma"); !strings.HasPrefix(got, "KRIT · IT / pve-1 · ") {
		t.Errorf("Betreff mit fremdem Mandanten: %q", got)
	}
	r2 := r
	r2.Event, r2.Status, r2.Message = alarm.Recovered, alarm.OK, ""
	if got := r2.Subject("IT"); got != "OK · pve-1 · Platte /var" {
		t.Errorf("Entwarnung: %q", got)
	}
	r3 := r
	r3.Event = alarm.Reminder
	if !strings.HasPrefix(r3.Subject("IT"), "Erinnerung KRIT · ") {
		t.Errorf("Erinnerung: %q", r3.Subject("IT"))
	}
	// Steuerzeichen und Umbrüche aus Fremdtext landen nie im Betreff.
	r4 := r
	r4.Device = "pve\r\nBcc: x@y"
	if s := r4.Subject("IT"); strings.ContainsAny(s, "\r\n") {
		t.Errorf("Umbruch im Betreff: %q", s)
	}
	// Lange Namen werden gekürzt, der Betreff bleibt kurz.
	r5 := r
	r5.Device, r5.Sensor = strings.Repeat("g", 120), strings.Repeat("s", 120)
	if s := r5.Subject("Firma"); len([]rune(s)) > alarm.SubjectMax || !strings.HasPrefix(s, "KRIT · IT / ggg") {
		t.Errorf("langer Betreff (%d Zeichen): %q", len([]rune(s)), s)
	}
	facts := map[string]string{}
	for _, f := range r.Facts("IT", now, berlin) {
		facts[f.Label] = f.Value
	}
	if facts["Seit"] != "21.11.2026 13:50 (vor 2 Std. 10 Min.)" {
		t.Errorf("Seit: %q", facts["Seit"])
	}
	if facts["Prognose"] != "voll in etwa 3 Tagen" || facts["Gerät"] != "pve-1" || facts["Zustand"] != "kritisch" {
		t.Errorf("Angaben: %v", facts)
	}
	if got := alarm.SplitLabel("pve-1 · Ping", "pve-1"); got != "Ping" {
		t.Errorf("SplitLabel: %q", got)
	}
	if got := alarm.SplitLabel("pve-1", "pve-1"); got != "Erreichbarkeit" {
		t.Errorf("SplitLabel stumm: %q", got)
	}
}

func TestChartPNG(t *testing.T) {
	now := time.Now()
	r := sampleReport(now)
	b := r.Chart.PNG()
	if b == nil {
		t.Fatal("kein Bild")
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != alarm.ChartWidth || img.Bounds().Dy() != alarm.ChartHeight {
		t.Errorf("Größe %v", img.Bounds())
	}
	if len(b) > 40000 {
		t.Errorf("Bild zu groß: %d Byte", len(b))
	}
	// Die Linie hat die Markenfarbe (--marke #0b6a8a), mindestens ein Pixel davon.
	blue := false
	for x := 0; x < img.Bounds().Dx() && !blue; x += 3 {
		for y := 0; y < img.Bounds().Dy(); y++ {
			if r, g, bb, _ := img.At(x, y).RGBA(); r>>8 == 0x0b && g>>8 == 0x6a && bb>>8 == 0x8a {
				blue = true
				break
			}
		}
	}
	if !blue {
		t.Error("keine Linie gezeichnet")
	}
	if (alarm.Chart{From: now, To: now.Add(time.Hour)}).PNG() != nil {
		t.Error("Bild ohne Punkte")
	}
	if c := r.Chart.Caption(); !strings.Contains(c, "min 80 %") || !strings.Contains(c, "Warnung 90 %, kritisch 95 %") {
		t.Errorf("Beschriftung: %q", c)
	}
}

// parseMail zerlegt eine Mail und liefert Kopf, Text, HTML und Bilder.
func parseMail(t *testing.T, data string) (*mail.Message, string, string, int) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var text, html string
	imgs := 0
	var walk func(ct string, r io.Reader)
	walk = func(ct string, r io.Reader) {
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(mt, "multipart/") {
			return
		}
		mr := multipart.NewReader(r, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pct := p.Header.Get("Content-Type")
			body, _ := io.ReadAll(p) // quoted-printable wird von multipart dekodiert
			switch {
			case strings.HasPrefix(pct, "multipart/"):
				walk(pct, bytes.NewReader(body))
			case strings.HasPrefix(pct, "text/plain"):
				text = string(body)
			case strings.HasPrefix(pct, "text/html"):
				html = string(body)
			case strings.HasPrefix(pct, "image/png"):
				imgs++
				if p.Header.Get("Content-Id") != "<graph1@openwacht>" {
					t.Errorf("Content-ID %q", p.Header.Get("Content-Id"))
				}
			}
		}
	}
	walk(m.Header.Get("Content-Type"), m.Body)
	return m, text, html, imgs
}

func TestBuildMailMIME(t *testing.T) {
	now := time.Now()
	r := sampleReport(now)
	r.Others[0].Name = `<script>alert(1)</script>`
	m := alarm.BuildMail("IT", "Bereitschaft", r, now, berlin)
	data, err := alarm.BuildMIME("openwacht@example.de", m, now)
	if err != nil {
		t.Fatal(err)
	}
	msg, text, html, imgs := parseMail(t, string(data))
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(msg.Header.Get("Subject"))
	if subj != r.Subject("IT") {
		t.Errorf("Betreff %q", subj)
	}
	if msg.Header.Get("To") != "undisclosed-recipients:;" || msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("Kopf: %v", msg.Header)
	}
	if imgs != 1 {
		t.Errorf("%d Bilder, erwartet 1", imgs)
	}
	if !strings.Contains(text, "Prognose: voll in etwa 3 Tagen") || !strings.Contains(text, "In OpenWacht öffnen: https://openwacht.example/hosts?geraet=x") {
		t.Errorf("Text:\n%s", text)
	}
	// Die Meldung steht oben (zweite Zeile), nicht noch einmal unter den Angaben.
	if lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"); len(lines) < 2 || lines[1] != "96 % belegt (kritisch ab 95 %)" || strings.Contains(text, "Meldung:") {
		t.Errorf("Meldung oben:\n%s", text)
	}
	if !strings.Contains(html, "96 % belegt (kritisch ab 95 %)") {
		t.Error("Meldung fehlt im HTML")
	}
	if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
		t.Error("HTML nicht maskiert")
	}
	if !strings.Contains(html, `src="cid:graph1@openwacht"`) {
		t.Error("Bild nicht eingebunden")
	}
	// Ohne Graph: nur Alternativen
	r.Chart = nil
	data, _ = alarm.BuildMIME("openwacht@example.de", alarm.BuildMail("IT", "x", r, now, berlin), now)
	if _, _, _, n := parseMail(t, string(data)); n != 0 {
		t.Error("Bild ohne Graph")
	}
}

func TestSummaryMail(t *testing.T) {
	now := time.Now()
	var rs []alarm.Report
	for i := 0; i < 12; i++ {
		r := sampleReport(now)
		if i%3 == 0 {
			r.Event, r.Status = alarm.Recovered, alarm.OK
		}
		rs = append(rs, r)
	}
	m := alarm.BuildSummary("IT", "x", rs, "https://w/alarme")
	if m.Subject != "KRIT · OpenWacht: 8 Probleme, 4 wieder OK" {
		t.Errorf("Betreff %q", m.Subject)
	}
	if len(m.Images) != 0 || strings.Count(m.Text, "KRIT · pve-1") != 8 || !strings.Contains(m.Text, "Probleme (8)") ||
		!strings.Contains(m.Text, "Wieder in Ordnung (4)") || strings.Index(m.Text, "Probleme (8)") > strings.Index(m.Text, "Wieder in Ordnung (4)") {
		t.Errorf("Sammelmail:\n%s", m.Text)
	}
	if !strings.Contains(m.HTML, "Probleme (8)") || !strings.Contains(m.HTML, "Wieder in Ordnung (4)") {
		t.Error("Abschnitte fehlen im HTML")
	}
	if e := alarm.BuildSummary("IT", "x", nil, "https://w/alarme"); e.HTML == "" {
		t.Error("leere Sammelmail")
	}
}

func smtpCfg(s *smtptest.Server, mode string) alarm.SMTPConfig {
	return alarm.SMTPConfig{Host: s.Host, Port: s.Port, TLS: mode, From: "openwacht@example.de", User: s.User, Pass: s.Pass, CA: s.CAPEM}
}

func TestMailerModes(t *testing.T) {
	ctx := context.Background()
	m := alarm.NewMailer("test")
	msg := alarm.TestMail("IT", "x")
	for _, tc := range []struct {
		name     string
		implicit bool
		mode     string
		only     string
	}{{"starttls plain", false, "starttls", ""}, {"tls", true, "tls", ""}, {"starttls login", false, "starttls", "LOGIN"}} {
		t.Run(tc.name, func(t *testing.T) {
			s := smtptest.Start(t, tc.implicit, "relay", "geheim")
			s.OnlyAuth = tc.only
			rej, err := m.Send(ctx, smtpCfg(s, tc.mode), []string{"a@example.de", "abgelehnt@example.de"}, msg)
			if err != nil {
				t.Fatal(err)
			}
			if len(rej) != 1 || rej[0] != "abgelehnt@example.de" {
				t.Errorf("abgelehnt: %v", rej)
			}
			got := s.Messages()
			if len(got) != 1 || !got[0].TLS || got[0].User != "relay" || len(got[0].To) != 1 {
				t.Fatalf("Mails: %+v", got)
			}
			if strings.Contains(got[0].Data, "<a@example.de>") || strings.Contains(got[0].Data, "To: a@") {
				t.Error("Empfänger steht im Kopf")
			}
		})
	}
	// Negativfälle
	s := smtptest.Start(t, false, "relay", "geheim")
	cfg := smtpCfg(s, "starttls")
	cfg.Pass = "Pw-nicht-im-Fehler"
	if _, err := m.Send(ctx, cfg, []string{"a@example.de"}, msg); err == nil || strings.Contains(err.Error(), "Pw-nicht") {
		t.Errorf("falsches Passwort: %v", err)
	}
	cfg = smtpCfg(s, "starttls")
	cfg.CA = ""
	if _, err := m.Send(ctx, cfg, []string{"a@example.de"}, msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("unbekannte CA muss scheitern: %v", err)
	}
	s.NoTLS = true
	if _, err := m.Send(ctx, smtpCfg(s, "starttls"), []string{"a@example.de"}, msg); err == nil || !strings.Contains(err.Error(), "kein STARTTLS") {
		t.Errorf("ohne STARTTLS: %v", err)
	}
	if _, err := m.Send(ctx, smtpCfg(s, "starttls"), []string{"abgelehnt@x.de"}, msg); err == nil {
		t.Error("ohne angenommene Empfänger kein Fehler")
	}
	if len(s.Messages()) != 0 {
		t.Error("trotz Fehler zugestellt")
	}
	// Unverschlüsselt nur zu Loopback
	if err := alarm.ValidateSMTP(alarm.SMTPConfig{Host: "mail.example.de", Port: 25, TLS: "keine", From: "a@b.de"}); err == nil {
		t.Error("Klartext zu fremdem Server erlaubt")
	}
	if err := alarm.ValidateSMTP(alarm.SMTPConfig{Host: "127.0.0.1", Port: 25, TLS: "keine", From: "a@b.de"}); err != nil {
		t.Error(err)
	}
	for _, from := range []string{"Name <a@b.de>", "a@b.de\r\nBcc: x@y", "kein"} {
		if err := alarm.ValidateSMTP(alarm.SMTPConfig{Host: "h", Port: 587, TLS: "starttls", From: from}); err == nil {
			t.Errorf("Absender %q angenommen", from)
		}
	}
}

func TestHookSignature(t *testing.T) {
	sec, err := alarm.NewHookSecret()
	if err != nil || !strings.HasPrefix(sec, "whsec_") {
		t.Fatal(sec, err)
	}
	now := time.Now()
	body := []byte(`{"a":1}`)
	sig, err := alarm.HookSignature(sec, "msg_1", now.Unix(), body)
	if err != nil {
		t.Fatal(err)
	}
	tsNow := strconv.FormatInt(now.Unix(), 10)
	if !alarm.VerifyHookSignature(sec, "msg_1", tsNow, sig, body, now, 5*time.Minute) {
		t.Error("gültige Signatur abgelehnt")
	}
	if alarm.VerifyHookSignature(sec, "msg_1", tsNow, sig, []byte(`{"a":2}`), now, 5*time.Minute) {
		t.Error("veränderter Rumpf angenommen")
	}
	if alarm.VerifyHookSignature(sec, "msg_2", tsNow, sig, body, now, 5*time.Minute) {
		t.Error("andere ID angenommen")
	}
	if alarm.VerifyHookSignature(sec, "msg_1", tsNow, sig, body, now.Add(10*time.Minute), 5*time.Minute) {
		t.Error("alte Signatur angenommen")
	}
	other, _ := alarm.NewHookSecret()
	if alarm.VerifyHookSignature(other, "msg_1", tsNow, sig, body, now, 5*time.Minute) {
		t.Error("fremder Schlüssel angenommen")
	}
	// Bekannter Testvektor von standardwebhooks.com
	got, _ := alarm.HookSignature("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330,
		[]byte(`{"test": 2432232314}`))
	if got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Errorf("Testvektor: %s", got)
	}
}

func TestHookTargets(t *testing.T) {
	tg := alarm.NewTargets("https://prod-12.westeurope.logic.azure.com", "https://hooks.example.de/openwacht", "http://127.0.0.1:9000")
	for url, want := range map[string]bool{
		"https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x": true,
		"https://hooks.example.de/openwacht/kanal1":                                                       true,
		"https://hooks.example.de/openwacht":                                                              true,
		"https://hooks.example.de/openwachtx":                                                             false,
		"https://hooks.example.de/anders":                                                                 false,
		"https://evil.example.de/openwacht":                                                               false,
		"http://127.0.0.1:9000/x":                                                                         true,
		"http://127.0.0.1:9001/x":                                                                         false,
		"https://prod-12.westeurope.logic.azure.com.evil.de/x":                                            false,
	} {
		full, _, err := alarm.NormalizeHookURL(url)
		if err != nil {
			t.Fatal(url, err)
		}
		if got := tg.AllowedURL(full); got != want {
			t.Errorf("%s: %v, erwartet %v", url, got, want)
		}
	}
	for _, bad := range []string{"http://hooks.example.de/x", "https://user:pw@h.de/x", "https://h.de/x#a", "ftp://h.de", "https://h.de/ x"} {
		if _, _, err := alarm.NormalizeHookURL(bad); err == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	if _, o, _ := alarm.NormalizeHookURL("HTTPS://Prod.Example.DE:443/a?b=c"); o != "https://prod.example.de" {
		t.Errorf("Ursprung %q", o)
	}
}

func TestPostHook(t *testing.T) {
	sec, _ := alarm.NewHookSecret()
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
		if r.URL.Path == "/umleitung" {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	tg := alarm.NewTargets(srv.URL)
	s := alarm.NewSender(tg)
	now := time.Now()
	payload := alarm.HookTest("IT", "x", now)
	full, _, _ := alarm.NormalizeHookURL(srv.URL + "/hook?sig=geheim")
	if err := s.PostHook(context.Background(), full, sec, payload, now); err != nil {
		t.Fatal(err)
	}
	if !alarm.VerifyHookSignature(sec, got.Header.Get("webhook-id"), got.Header.Get("webhook-timestamp"),
		got.Header.Get("webhook-signature"), body, now, time.Minute) {
		t.Error("Signatur beim Empfänger ungültig")
	}
	var p alarm.HookPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Type != "openwacht.test" {
		t.Errorf("Rumpf %s", body)
	}
	// Teams ohne Signatur
	if err := s.PostHook(context.Background(), full, "", payload, now); err != nil || got.Header.Get("webhook-signature") != "" {
		t.Errorf("ohne Signatur: %v", err)
	}
	// Weiterleitung wird nicht verfolgt, URL nie im Fehler
	red, _, _ := alarm.NormalizeHookURL(srv.URL + "/umleitung?sig=geheim")
	if err := s.PostHook(context.Background(), red, "", payload, now); err == nil || strings.Contains(err.Error(), "geheim") {
		t.Errorf("Weiterleitung: %v", err)
	}
	// Nicht (mehr) freigegeben
	tg.Set(alarm.NewTargets())
	if err := s.PostHook(context.Background(), full, "", payload, now); err == nil {
		t.Error("Ziel ohne Freigabe angenommen")
	}
	// Nicht erreichbar: Fehler ohne URL
	tg.Set(alarm.NewTargets("http://127.0.0.1:1"))
	if err := s.PostHook(context.Background(), "http://127.0.0.1:1/x?sig=geheim", "", payload, now); err == nil || strings.Contains(err.Error(), "geheim") {
		t.Errorf("unerreichbar: %v", err)
	}
}

func TestTeamsCard(t *testing.T) {
	now := time.Now()
	var rs []alarm.Report
	for i := 0; i < 60; i++ {
		r := sampleReport(now)
		r.Device = "[klick](https://evil.example)"
		r.Message = strings.Repeat("x", 300)
		rs = append(rs, r)
	}
	b := alarm.BuildTeams("IT", rs, now, berlin, "https://w/alarme")
	if len(b) > alarm.TeamsLimit {
		t.Errorf("Karte zu groß: %d", len(b))
	}
	if strings.Contains(string(b), "[klick](https") {
		t.Error("Markdown-Link aus Fremdtext")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["type"] != "message" {
		t.Fatalf("Karte: %v", err)
	}
	if !strings.Contains(string(b), "weitere Ereignisse") {
		t.Error("Hinweis auf weggelassene Ereignisse fehlt")
	}
	att := m["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType %v", att["contentType"])
	}
}

func TestMailMitAnhang(t *testing.T) {
	now := time.Now()
	pdf := []byte("%PDF-1.4 Testinhalt " + strings.Repeat("x", 200))
	m := alarm.Mail{Subject: "Monatsbericht", Text: "Hallo", HTML: "<p>Hallo</p>",
		Attachments: []alarm.MailAttachment{{Name: "bericht.pdf", Type: "application/pdf", Data: pdf}}}
	data, err := alarm.BuildMIME("openwacht@example.de", m, now)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/mixed" {
		t.Fatalf("Typ %s", mt)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var got []byte
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(p.Header.Get("Content-Type"), "application/pdf") {
			raw, _ := io.ReadAll(p)
			got, _ = base64.StdEncoding.DecodeString(strings.ReplaceAll(string(raw), "\r\n", ""))
			if p.Header.Get("Content-Disposition") != `attachment; filename="bericht.pdf"` {
				t.Errorf("Disposition %q", p.Header.Get("Content-Disposition"))
			}
		}
	}
	if !bytes.Equal(got, pdf) {
		t.Error("Anhang nicht gleich")
	}
	for _, bad := range []string{"a\"b.pdf", "a\r\nX: y", "../x.pdf", ""} {
		m.Attachments[0].Name = bad
		if _, err := alarm.BuildMIME("openwacht@example.de", m, now); err == nil {
			t.Errorf("Name %q angenommen", bad)
		}
	}
}
