// SPDX-License-Identifier: AGPL-3.0-only

package alarm_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/alarm/brevistest"
)

func smsSetup(t *testing.T) (*brevistest.Fake, *brevistest.Server, *alarm.Sender, alarm.SMSConfig) {
	t.Helper()
	f := brevistest.NewFake()
	srv := brevistest.Start(t, f)
	s := alarm.NewSender(alarm.NewTargets(srv.Gateway))
	c := alarm.SMSConfig{Gateway: srv.Gateway, User: brevistest.User, Password: brevistest.Password, Pin: srv.Pin}
	return f, srv, s, c
}

var number = alarm.SMSTarget{Mode: alarm.SMSModeNumber, To: "+491701234567"}

func TestSMSSendPOST(t *testing.T) {
	f, _, s, c := smsSetup(t)
	if err := s.SendSMS(context.Background(), c, number, "Test äöü", false); err != nil {
		t.Fatal(err)
	}
	r := f.Requests()
	if len(r) != 1 {
		t.Fatalf("Anfragen: %d", len(r))
	}
	got := r[0]
	if got.Method != "ok" || got.RawQuery != "" || !strings.HasPrefix(got.ContentType, "application/x-www-form-urlencoded") {
		t.Errorf("nicht als Formular per POST ohne Abfrage: %+v", got)
	}
	if got.To != "00491701234567" || got.Mode != "number" || got.Text != "Test äöü" || got.Ring || got.Flash {
		t.Errorf("Parameter: %+v", got)
	}
}

func TestSMSMethodIsPost(t *testing.T) {
	// Eigene Gegenstelle: Methode, Abfrage und Passwort im Rumpf.
	_, srv, s, c := smsSetup(t)
	var method, query string
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, query = r.Method, r.URL.RawQuery
		_ = r.ParseForm()
		if r.PostForm.Get("password") != brevistest.Password {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte("OK"))
	})
	if err := s.SendSMS(context.Background(), c, number, "x", false); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || query != "" {
		t.Errorf("Methode %s, Abfrage %q", method, query)
	}
}

func TestSMSRingGroup(t *testing.T) {
	f, _, s, c := smsSetup(t)
	g := alarm.SMSTarget{Mode: alarm.SMSModeGroup, To: "Bereitschaft"}
	if err := s.SendSMS(context.Background(), c, g, "Alarm", true); err != nil {
		t.Fatal(err)
	}
	r := f.Requests()
	if len(r) != 2 || r[0].Ring || !r[1].Ring || r[1].Mode != "group" || r[1].To != "Bereitschaft" {
		t.Fatalf("erwartet SMS und Anruf an die Gruppe: %+v", r)
	}
	f.Reset()
	err := s.SendSMS(context.Background(), c, alarm.SMSTarget{Mode: alarm.SMSModeGroup, To: "Gibtsnicht"}, "x", false)
	var se *alarm.SMSError
	if !errors.As(err, &se) || se.Status != 400 || !strings.Contains(err.Error(), "unbekannt") {
		t.Fatalf("unbekannte Gruppe: %v", err)
	}
}

func TestSMSErrors(t *testing.T) {
	cases := map[string]struct {
		prep   func(*brevistest.Fake, *alarm.SMSConfig)
		status int
		want   string
	}{
		"401 falsches Passwort":  {func(_ *brevistest.Fake, c *alarm.SMSConfig) { c.Password = "falsch-123" }, 401, "Passwort falsch"},
		"401 falscher Benutzer":  {func(_ *brevistest.Fake, c *alarm.SMSConfig) { c.User = "jemand" }, 401, "Passwort falsch"},
		"403 ohne Recht":         {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.NoRight(true) }, 403, "HTTP API"},
		"408 Zeitüberschreitung": {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Timeout(true) }, 408, "Zeitüberschreitung"},
		"400 Parameter fehlt": {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Respond(400, "Error: Parameter miss.") }, 400,
			"Pflichtangabe"},
		"400 Nummer":         {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Respond(400, "Error. See Gateway logs") }, 400, "ungültig"},
		"500":                {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Respond(500, "kaputt") }, 500, "HTTP 500"},
		"302 Weiterleitung":  {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Redirect(true) }, 302, "Weiterleitung"},
		"200 mit Fehlertext": {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Respond(200, "Error. See Gateway logs") }, 200, "Fehler"},
		"200 FAILED":         {func(f *brevistest.Fake, _ *alarm.SMSConfig) { f.Respond(200, "FAILED - Timeout") }, 200, "Fehler"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, s, c := smsSetup(t)
			tc.prep(f, &c)
			err := s.SendSMS(context.Background(), c, number, "x", false)
			var se *alarm.SMSError
			if !errors.As(err, &se) || se.Status != tc.status || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fehler %v, erwartet HTTP %d mit %q", err, tc.status, tc.want)
			}
			for _, secret := range []string{brevistest.Password, "falsch-123", "1701234567", "Gateway logs", "kaputt"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("Fehlertext enthält %q: %v", secret, err)
				}
			}
			if name == "302 Weiterleitung" && len(f.Requests()) != 1 {
				t.Errorf("Weiterleitung verfolgt: %d Anfragen", len(f.Requests()))
			}
		})
	}
}

func TestSMSRingFailsAfterSMS(t *testing.T) {
	f, _, s, c := smsSetup(t)
	f.NoRing(true)
	err := s.SendSMS(context.Background(), c, number, "a", true)
	if err == nil || !strings.Contains(err.Error(), "SMS gesendet, Anruf fehlgeschlagen") {
		t.Fatalf("erwartet Hinweis auf gescheiterten Anruf: %v", err)
	}
	if len(f.Sent()) != 1 {
		t.Fatalf("SMS nicht angenommen: %+v", f.Requests())
	}
	// Scheitert schon die SMS, wird kein Anruf versucht.
	f.Reset()
	f.Timeout(true)
	if err := s.SendSMS(context.Background(), c, number, "a", true); err == nil || strings.Contains(err.Error(), "Anruf") {
		t.Fatalf("erwartet 408 ohne Anruf: %v", err)
	}
	if r := f.Requests(); len(r) != 1 || r[0].Ring {
		t.Fatalf("Anruf trotz gescheiterter SMS: %+v", r)
	}
}

func TestSMSWrongCertificate(t *testing.T) {
	f, _, s, c := smsSetup(t)
	_, other, _, _ := smsSetup(t)
	c.Pin = other.Pin
	err := s.SendSMS(context.Background(), c, number, "x", false)
	var pe *alarm.PinError
	if !errors.As(err, &pe) {
		t.Fatalf("erwartet PinError: %v", err)
	}
	if len(f.Requests()) != 0 {
		t.Fatal("Anfrage (mit Passwort) trotz falschem Zertifikat gesendet")
	}
	if err := s.SMSReachable(context.Background(), c.Gateway, other.Pin); !errors.As(err, &pe) {
		t.Fatalf("Erreichbarkeit mit falschem Zertifikat: %v", err)
	}
}

func TestSMSHugeResponse(t *testing.T) {
	f, _, s, c := smsSetup(t)
	f.Huge(true)
	start := time.Now()
	if err := s.SendSMS(context.Background(), c, number, "x", false); err != nil {
		t.Fatalf("2xx mit großem Inhalt gilt als gesendet: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("übergroße Antwort ganz gelesen")
	}
}

func TestSMSTimeoutClient(t *testing.T) {
	f, _, s, c := smsSetup(t)
	f.Delay(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := s.SendSMS(ctx, c, number, "x", false)
	if err == nil || !strings.Contains(err.Error(), "Zeitüberschreitung") {
		t.Fatalf("Zeitüberschreitung: %v", err)
	}
}

func TestSMSTargets(t *testing.T) {
	_, srv, _, c := smsSetup(t)
	ctx := context.Background()
	for name, s := range map[string]*alarm.Sender{
		"keine Ziele":      alarm.NewSender(nil),
		"anderer Host":     alarm.NewSender(alarm.NewTargets("https://sms.example")),
		"anderer Port":     alarm.NewSender(alarm.NewTargets("https://127.0.0.1:1")),
		"nur anderer Pfad": alarm.NewSender(alarm.NewTargets(srv.Gateway + "/webhook")),
	} {
		if err := s.SendSMS(ctx, c, number, "x", false); err == nil || !strings.Contains(err.Error(), "Alarmziel") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := s.SMSFingerprint(ctx, c.Gateway); err == nil {
			t.Errorf("%s: Fingerabdruck ohne Freigabe geholt", name)
		}
	}
	// Ein Ziel mit Pfad /api.php gibt genau die API frei.
	if err := alarm.NewSender(alarm.NewTargets(srv.Gateway+"/api.php")).SendSMS(ctx, c, number, "x", false); err != nil {
		t.Errorf("Ziel mit /api.php: %v", err)
	}
}

func TestSMSFingerprint(t *testing.T) {
	f, srv, s, c := smsSetup(t)
	pin, err := s.SMSFingerprint(context.Background(), c.Gateway)
	if err != nil || pin != srv.Pin {
		t.Fatalf("Fingerabdruck %q, %v", pin, err)
	}
	if err := s.SMSReachable(context.Background(), c.Gateway, srv.Pin); err != nil {
		t.Fatal(err)
	}
	if len(f.Requests()) != 0 {
		t.Fatal("Fingerabdruck/Erreichbarkeit hat eine Anfrage gesendet")
	}
	srv.Close()
	if err := s.SMSReachable(context.Background(), c.Gateway, srv.Pin); err == nil || !strings.Contains(err.Error(), "nicht erreichbar") {
		t.Fatalf("gestopptes Gateway: %v", err)
	}
}

func TestSMSInvalidInput(t *testing.T) {
	_, _, s, c := smsSetup(t)
	ctx := context.Background()
	bad := map[string]func(*alarm.SMSConfig, *alarm.SMSTarget){
		"admin":         func(c *alarm.SMSConfig, _ *alarm.SMSTarget) { c.User = "Admin" },
		"ohne Pin":      func(c *alarm.SMSConfig, _ *alarm.SMSTarget) { c.Pin = "" },
		"ohne Passwort": func(c *alarm.SMSConfig, _ *alarm.SMSTarget) { c.Password = "" },
		"Nummer":        func(_ *alarm.SMSConfig, t *alarm.SMSTarget) { t.To = "0170" },
		"Gruppe":        func(_ *alarm.SMSConfig, t *alarm.SMSTarget) { *t = alarm.SMSTarget{Mode: "group", To: "a&b=c"} },
		"Modus":         func(_ *alarm.SMSConfig, t *alarm.SMSTarget) { t.Mode = "user" },
		"http": func(c *alarm.SMSConfig, _ *alarm.SMSTarget) {
			c.Gateway = strings.Replace(c.Gateway, "https", "http", 1)
		},
	}
	for name, fn := range bad {
		cc, tt := c, number
		fn(&cc, &tt)
		if err := s.SendSMS(ctx, cc, tt, "x", false); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
}

func TestNormalizeGateway(t *testing.T) {
	ok := map[string]string{
		"https://10.20.0.60":          "https://10.20.0.60",
		"10.20.0.60":                  "https://10.20.0.60",
		"HTTPS://SMS.Example:443/":    "https://sms.example",
		"https://sms.example:8443":    "https://sms.example:8443",
		"https://sms.example/api.php": "https://sms.example",
	}
	for in, want := range ok {
		if got, err := alarm.NormalizeGateway(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "http://10.20.0.60", "https://u:p@sms.example", "https://sms.example/x", "https://sms.example?a=1",
		"https://sms.example#x", "ftp://sms.example", "https://"} {
		if _, err := alarm.NormalizeGateway(in); err == nil {
			t.Errorf("%q angenommen", in)
		}
	}
}

func TestNormalizeMobile(t *testing.T) {
	ok := map[string]string{"+49 170 1234567": "+491701234567", "0049 (170) 123-45-67": "+491701234567",
		"0170/1234567": "+491701234567", "+43 664 1234567": "+436641234567"}
	for in, want := range ok {
		if got, ok := alarm.NormalizeMobile(in); !ok || got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	for _, in := range []string{"", "+0123456789", "123", "+49170abc", "+4917012345678901234", "+49 170 1234567;+49"} {
		if _, ok := alarm.NormalizeMobile(in); ok {
			t.Errorf("%q angenommen", in)
		}
	}
	if m := alarm.MaskMobile("+491701234567"); strings.Contains(m, "1234") || !strings.HasSuffix(m, "67") {
		t.Errorf("Maske %q", m)
	}
}

func gsmLen(s string) int { _, n := alarm.GSM7(s); return n }

func TestBuildSMS(t *testing.T) {
	one := []alarm.Report{{Item: alarm.Item{Tenant: "IT", Check: "nas-01 · Platte /", Status: alarm.Crit,
		Message: "96 % belegt …", Event: alarm.Problem}, Device: "nas-01", Sensor: "Platte /"}}
	got := alarm.BuildSMS("IT", one)
	if got != "OpenWacht: KRIT nas-01 - Platte /: 96 % belegt ..." {
		t.Errorf("eine Meldung: %q", got)
	}
	var many []alarm.Report
	for i := 0; i < 30; i++ {
		st := alarm.Warn
		if i == 17 {
			st = alarm.Crit
		}
		many = append(many, alarm.Report{Item: alarm.Item{Tenant: "Standort Nord", Status: st, Event: alarm.Problem,
			Message: strings.Repeat("lang ", 40)}, Device: "geraet-" + strings.Repeat("x", i%5), Sensor: "Ping"})
	}
	many = append(many, alarm.Report{Item: alarm.Item{Tenant: "IT", Status: alarm.OK, Event: alarm.Recovered}, Device: "sw-02", Sensor: "Ping"})
	got = alarm.BuildSMS("IT", many)
	if n := gsmLen(got); n > alarm.MaxSMSLen {
		t.Errorf("zu lang: %d %q", n, got)
	}
	if !strings.HasPrefix(got, "OpenWacht: 31 Meldungen. KRIT Standort Nord/geraet-xx - Ping") || !strings.Contains(got, "weitere") {
		t.Errorf("Sammel-SMS: %q", got)
	}
	if strings.Contains(got, "lang lang") {
		t.Errorf("Meldungstexte in der Sammel-SMS: %q", got)
	}
	// Fremdtext: Steuerzeichen, Emojis, Erweiterungszeichen
	evil := []alarm.Report{{Item: alarm.Item{Status: alarm.Crit, Event: alarm.Reminder, Message: "a\nb\x00c 😀 {[€]}" + strings.Repeat("€", 200)},
		Device: "x", Sensor: "y"}}
	got = alarm.BuildSMS("IT", evil)
	if n := gsmLen(got); n > alarm.MaxSMSLen || strings.ContainsAny(got, "\n\x00😀") || !utf8.ValidString(got) {
		t.Errorf("Fremdtext: %d %q", n, got)
	}
	if alarm.BuildSMS("IT", nil) != "" {
		t.Error("leere Liste")
	}
	if n := gsmLen(alarm.TestSMS(strings.Repeat("M", 300), strings.Repeat("K", 300))); n > alarm.MaxSMSLen {
		t.Errorf("Test-SMS zu lang: %d", n)
	}
	n := alarm.Notice{Status: alarm.Crit, Title: strings.Repeat("T", 300), Text: strings.Repeat("ü", 300), Tenant: "IT"}
	if l := gsmLen(n.SMS()); l > alarm.MaxSMSLen {
		t.Errorf("Hinweis zu lang: %d", l)
	}
}

func TestGSM7(t *testing.T) {
	out, n := alarm.GSM7("äÖß€„x“…")
	if out != "äÖß€\"x\"..." || n != 1+1+1+2+1+1+1+3 {
		t.Errorf("%q %d", out, n)
	}
	if got := alarm.FitSMS(strings.Repeat("€", 100)); gsmLen(got) > alarm.MaxSMSLen || !strings.HasSuffix(got, "...") {
		t.Errorf("Erweiterungszeichen: %d", gsmLen(got))
	}
}

func TestValidSMSUser(t *testing.T) {
	for _, u := range []string{"admin", "ADMIN", "", "a b", "x\x00", strings.Repeat("u", 65)} {
		if alarm.ValidSMSUser(u) == nil {
			t.Errorf("%q angenommen", u)
		}
	}
	if alarm.ValidSMSUser("openwacht-api") != nil || alarm.ValidSMSUser("administrator") != nil {
		t.Error("gültiger Benutzer abgelehnt")
	}
}
