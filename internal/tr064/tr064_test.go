// SPDX-License-Identifier: AGPL-3.0-only

package tr064

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064/tr064test"
)

type direct struct{}

func (direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func client() *Client { return &Client{Guard: direct{}, Timeout: 3 * time.Second} }

func cfgFor(s *tr064test.Server) Config {
	return Config{Host: s.Host, Port: s.Port, User: tr064test.User, Password: tr064test.Password, Pin: s.Pin}
}

func TestPollVollstaendig(t *testing.T) {
	f := tr064test.NewFake()
	srv := tr064test.Start(t, f)
	snap, err := client().Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := snap.FritzBox
	if fb.Model != "FRITZ!Box 7590" || fb.Version != "154.07.57" || snap.System.UptimeS != 100000 || snap.System.UptimeTicks != 10000000 {
		t.Errorf("Gerät: %+v %+v", fb, snap.System)
	}
	if !fb.Connected || fb.Connection != "Connected" || fb.ConnUptimeS != 3600 || fb.ExternalIP != "203.0.113.7" || fb.AccessType != "DSL" {
		t.Errorf("Verbindung: %+v", fb)
	}
	if fb.Layer1DnBps != 250000000 || fb.DSL == nil || fb.DSL.DownBps != 250000000 || fb.DSL.UpBps != 40000000 ||
		fb.DSL.DownMaxBps != 280000000 || fb.DSL.Status != "Up" {
		t.Errorf("DSL: %+v %+v", fb, fb.DSL)
	}
	if len(snap.Interfaces) != 1 || snap.Interfaces[0].Name != WANName || !snap.Interfaces[0].HC ||
		snap.Interfaces[0].InOctets != 90000000000 || snap.Interfaces[0].Oper != "up" {
		t.Errorf("WAN: %+v", snap.Interfaces)
	}
	if len(fb.Missing) != 0 || fb.TLS {
		t.Errorf("fehlt: %v, TLS %v", fb.Missing, fb.TLS)
	}
	// Datensparsam: Seriennummer und Protokoll landen nirgends.
	raw, _ := json.Marshal(snap)
	for _, bad := range []string{"GEHEIM", "geheimes Protokoll", tr064test.Password} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("Snapshot enthält %q", bad)
		}
	}
	// Nur Aktionen der festen Liste, nichts sonst.
	for k := range f.AllCalls() {
		svc, act, _ := strings.Cut(k, "#")
		if !Allowed("urn:dslforum-org:service:"+svc+":1", act) {
			t.Errorf("nicht erlaubte Aktion aufgerufen: %s", k)
		}
	}
	if f.Count("WANCommonInterfaceConfig#GetTotalBytesSent") != 0 {
		t.Error("32-Bit-Zähler gelesen, obwohl 64 Bit da sind")
	}
	if f.Paths["GET /upnp/control/deviceconfig"]+f.Paths["POST /upnp/control/deviceconfig"]+f.Paths["POST /upnp/control/x_homeauto"] != 0 {
		t.Errorf("fremder Dienst angesprochen: %v", f.Paths)
	}
	// Anmeldung: einmal 401 für den ersten Nonce, danach mit Digest.
	if f.Unauth != 1 {
		t.Errorf("Anfragen ohne Anmeldung: %d", f.Unauth)
	}
}

func TestPollRaten(t *testing.T) {
	f := tr064test.NewFake()
	srv := tr064test.Start(t, f)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	c := client()
	c.Now = func() time.Time { return now }
	first, err := c.Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Second)
	f.Set("WANCommonInterfaceConfig#GetAddonInfos", "NewX_AVM_DE_TotalBytesReceived64", "90075000000") // 75 MB in 60 s = 10 Mbit/s
	f.Set("WANCommonInterfaceConfig#GetAddonInfos", "NewX_AVM_DE_TotalBytesSent64", "5000750000")
	f.Set("WANPPPConnection#GetStatusInfo", "NewUptime", "3660")
	f.Set("DeviceInfo#GetInfo", "NewUpTime", "100060")
	second, err := c.Poll(context.Background(), cfgFor(srv), first)
	if err != nil {
		t.Fatal(err)
	}
	it := second.Interfaces[0]
	if it.InBps == nil || *it.InBps != 10e6 || it.OutBps == nil || *it.OutBps != 0.1e6 {
		t.Errorf("Raten: %v %v", it.InBps, it.OutBps)
	}
	names, _ := snmp.Series(second)
	for _, want := range []string{"if_ein:WAN", "if_aus:WAN", "dsl_ab", "dsl_auf"} {
		if !contains(names, want) {
			t.Errorf("Reihe %s fehlt: %v", want, names)
		}
	}
	// Neu verbunden: Zähler beginnen bei 0, keine Rate.
	now = now.Add(60 * time.Second)
	f.Set("WANPPPConnection#GetStatusInfo", "NewUptime", "20")
	f.Set("WANCommonInterfaceConfig#GetAddonInfos", "NewX_AVM_DE_TotalBytesReceived64", "1000")
	third, err := c.Poll(context.Background(), cfgFor(srv), second)
	if err != nil {
		t.Fatal(err)
	}
	if third.Interfaces[0].InBps != nil {
		t.Errorf("Rate nach Neuverbindung: %v", *third.Interfaces[0].InBps)
	}
	if !Rebooted(97260, 30) || Rebooted(97260, 97320) || Rebooted(0, 5) || Rebooted(86460, 30) {
		t.Error("Rebooted")
	}
}

func TestPollGetrenntUndKabel(t *testing.T) {
	f := tr064test.NewFake()
	f.NoPPP = true
	f.Values["WANIPConnection#GetStatusInfo"] = map[string]string{"NewConnectionStatus": "Disconnected",
		"NewLastConnectionError": "ERROR_NO_CARRIER", "NewUptime": "0"}
	f.Values["WANCommonInterfaceConfig#GetCommonLinkProperties"]["NewWANAccessType"] = "X_AVM-DE_Fiber"
	srv := tr064test.Start(t, f)
	snap, err := client().Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := snap.FritzBox
	if fb.Connected || fb.Connection != "Disconnected" || fb.LastError != "ERROR_NO_CARRIER" || fb.ExternalIP != "" || fb.DSL != nil {
		t.Errorf("getrennt: %+v", fb)
	}
	if snap.Interfaces[0].Oper != "down" {
		t.Errorf("WAN: %+v", snap.Interfaces[0])
	}
	if f.Count("WANIPConnection#GetExternalIPAddress") != 0 || f.Count("WANDSLInterfaceConfig#GetInfo") != 0 {
		t.Error("unnötige Abfragen")
	}
}

// Ohne das Recht „FRITZ!Box Einstellungen“: Teile fehlen, kein Abbruch.
func TestPollOhneRechte(t *testing.T) {
	f := tr064test.NewFake()
	f.Deny("DeviceInfo#GetInfo", "WANCommonInterfaceConfig#GetAddonInfos", "WANCommonInterfaceConfig#GetTotalBytesSent",
		"WANCommonInterfaceConfig#GetTotalBytesReceived", "WANPPPConnection#GetExternalIPAddress", "WANDSLInterfaceConfig#GetInfo")
	srv := tr064test.Start(t, f)
	snap, err := client().Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := snap.FritzBox
	want := []string{PartDevice, PartIP, PartTraffic, PartDSL}
	for _, w := range want {
		if !contains(fb.Missing, w) {
			t.Errorf("fehlt nicht: %s (%v)", w, fb.Missing)
		}
	}
	if contains(fb.Missing, PartLink) || contains(fb.Missing, PartConnection) || !fb.Connected || len(snap.Interfaces) != 0 {
		t.Errorf("%+v %+v", fb, snap.Interfaces)
	}
	// Alles verweigert: Fehlermeldung mit dem nötigen Recht.
	f.Deny("WANCommonInterfaceConfig#GetCommonLinkProperties", "WANPPPConnection#GetStatusInfo", "WANIPConnection#GetStatusInfo")
	if _, err := client().Poll(context.Background(), cfgFor(srv), nil); !errors.Is(err, ErrNoRights) {
		t.Errorf("alles verweigert: %v", err)
	}
	// 64 Bit verweigert, 32 Bit erlaubt: Rückfall
	f2 := tr064test.NewFake()
	f2.Deny("WANCommonInterfaceConfig#GetAddonInfos")
	snap, err = client().Poll(context.Background(), cfgFor(tr064test.Start(t, f2)), nil)
	if err != nil || len(snap.Interfaces) != 1 || snap.Interfaces[0].HC || snap.Interfaces[0].InOctets != 4100654080 ||
		contains(snap.FritzBox.Missing, PartTraffic) || len(snap.FritzBox.Reasons) != 0 {
		t.Errorf("32 Bit: %v %+v %v %v", err, snap.Interfaces, snap.FritzBox.Missing, snap.FritzBox.Reasons)
	}
}

// Gründe: je fehlendem Teil Aktion und UPnP-Code (für Journal und Oberfläche).
func TestPollGruende(t *testing.T) {
	f := tr064test.NewFake()
	f.Deny("WANCommonInterfaceConfig#GetAddonInfos", "WANCommonInterfaceConfig#GetTotalBytesSent", "WANDSLInterfaceConfig#GetInfo")
	f.Unknown("WANPPPConnection#GetExternalIPAddress")
	snap, err := client().Poll(context.Background(), cfgFor(tr064test.Start(t, f)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(snap.FritzBox.Reasons, " | ")
	for _, want := range []string{"Verkehr: WANCommonInterfaceConfig.GetAddonInfos: Recht fehlt (606)",
		"Verkehr: WANCommonInterfaceConfig.GetTotalBytesSent: Recht fehlt (606)",
		"DSL: WANDSLInterfaceConfig.GetInfo: Recht fehlt (606)",
		"Externe IP: WANPPPConnection.GetExternalIPAddress: Aktion unbekannt (401)"} {
		if !strings.Contains(got, want) {
			t.Errorf("Grund fehlt: %q in %q", want, got)
		}
	}
	info, err := client().Probe(context.Background(), cfgFor(tr064test.Start(t, f)))
	if err != nil || len(info.Reasons) != len(snap.FritzBox.Reasons) {
		t.Errorf("Probe ohne Gründe: %v %v", err, info.Reasons)
	}
	// GetAddonInfos unbekannt ist kein Grund, nur das fehlende Recht am Rückfall.
	f2 := tr064test.NewFake()
	f2.Unknown("WANCommonInterfaceConfig#GetAddonInfos")
	f2.Deny("WANCommonInterfaceConfig#GetTotalBytesReceived")
	snap, err = client().Poll(context.Background(), cfgFor(tr064test.Start(t, f2)), nil)
	if err != nil || !contains(snap.FritzBox.Missing, PartTraffic) || len(snap.FritzBox.Reasons) != 1 ||
		snap.FritzBox.Reasons[0] != "Verkehr: WANCommonInterfaceConfig.GetTotalBytesReceived: Recht fehlt (606)" {
		t.Errorf("Rückfall verweigert: %v %v %v", err, snap.FritzBox.Missing, snap.FritzBox.Reasons)
	}
}

// Echte FRITZ!Box 7590, FRITZ!OS 8.51 (Entscheidung, 22.11.2026): GetAddonInfos
// gibt es über TR-064 nicht (401), GetTotalBytesSent/Received liefern trotz
// ui4 64-Bit-Werte. Früher: „Verkehr nicht verfügbar … Recht fehlt“.
func TestPollEchteBox7590(t *testing.T) {
	f := tr064test.NewFake()
	f.Unknown("WANCommonInterfaceConfig#GetAddonInfos")
	f.Set("WANCommonInterfaceConfig#GetTotalBytesSent", "NewTotalBytesSent", "41436074157")
	f.Set("WANCommonInterfaceConfig#GetTotalBytesReceived", "NewTotalBytesReceived", "846820105309")
	srv := tr064test.Start(t, f)
	now := time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC)
	c := client()
	c.Now = func() time.Time { return now }
	first, err := c.Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.FritzBox.Missing) != 0 || len(first.FritzBox.Reasons) != 0 {
		t.Fatalf("fehlt: %v %v", first.FritzBox.Missing, first.FritzBox.Reasons)
	}
	if len(first.Interfaces) != 1 || !first.Interfaces[0].HC || first.Interfaces[0].InOctets != 846820105309 ||
		first.Interfaces[0].OutOctets != 41436074157 {
		t.Fatalf("WAN: %+v", first.Interfaces)
	}
	now = now.Add(60 * time.Second)
	f.Set("WANCommonInterfaceConfig#GetTotalBytesReceived", "NewTotalBytesReceived", "846895105309") // +75 MB = 10 Mbit/s
	f.Set("WANCommonInterfaceConfig#GetTotalBytesSent", "NewTotalBytesSent", "41436824157")
	f.Set("WANPPPConnection#GetStatusInfo", "NewUptime", "3660")
	f.Set("DeviceInfo#GetInfo", "NewUpTime", "100060")
	second, err := c.Poll(context.Background(), cfgFor(srv), first)
	if err != nil {
		t.Fatal(err)
	}
	it := second.Interfaces[0]
	if it.InBps == nil || *it.InBps != 10e6 || it.OutBps == nil || *it.OutBps != 0.1e6 {
		t.Errorf("Raten: %v %v", it.InBps, it.OutBps)
	}
}

func TestAnmeldung(t *testing.T) {
	f := tr064test.NewFake()
	srv := tr064test.Start(t, f)
	cfg := cfgFor(srv)
	cfg.Password = "falsch"
	_, err := client().Poll(context.Background(), cfg, nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("falsches Passwort: %v", err)
	}
	// Falsches Passwort: Abbruch nach der ersten Aktion (Sperre der Box).
	if n := len(f.AllCalls()); n != 0 || f.Unauth > 2 {
		t.Errorf("weiter gefragt: %d Aufrufe, %d abgelehnt", n, f.Unauth)
	}
	// SHA-256 statt MD5
	f2 := tr064test.NewFake()
	f2.SHA256 = true
	if _, err := client().Poll(context.Background(), cfgFor(tr064test.Start(t, f2)), nil); err != nil {
		t.Errorf("SHA-256: %v", err)
	}
	// Neuer Nonce mitten in der Abfrage (stale)
	f3 := tr064test.NewFake()
	srv3 := tr064test.Start(t, f3)
	c := client()
	s, err := c.open(cfgFor(srv3))
	if err != nil {
		t.Fatal(err)
	}
	defer s.closer()
	if err := s.describeBox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.call(context.Background(), svcDeviceInfo, "GetInfo"); err != nil {
		t.Fatal(err)
	}
	f3.Rotate()
	if _, err := s.call(context.Background(), svcDeviceInfo, "GetInfo"); err != nil {
		t.Errorf("nach neuem Nonce: %v", err)
	}
	// Nicht erlaubte Aktion: wird gar nicht erst gesendet.
	if _, err := s.call(context.Background(), svcDeviceInfo, "Reboot"); err == nil || f3.Count("DeviceInfo#Reboot") != 0 {
		t.Errorf("Reboot: %v", err)
	}
	// Ungültige Eingaben
	for _, bad := range []Config{{Host: "x", User: "", Password: "p"}, {Host: "x", User: "a b", Password: "p"},
		{Host: "x", User: "a", Password: ""}, {Host: "x", User: "a", Password: "a\nb"}, {Host: "x", User: "a", Password: "p", Pin: "abc"}} {
		if _, err := client().Poll(context.Background(), bad, nil); err == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
}

func TestTLSFingerabdruck(t *testing.T) {
	f := tr064test.NewFake()
	srv := tr064test.StartTLS(t, f)
	fp, err := client().Fingerprint(context.Background(), srv.Host, srv.Port)
	if err != nil || fp != srv.Pin {
		t.Fatalf("Fingerabdruck: %q %v (erwartet %s)", fp, err, srv.Pin)
	}
	if f.Unauth != 0 || len(f.AllCalls()) != 0 {
		t.Error("Fingerabdruck hat sich angemeldet")
	}
	snap, err := client().Poll(context.Background(), cfgFor(srv), nil)
	if err != nil || !snap.FritzBox.TLS || snap.FritzBox.Fingerprint != srv.Pin {
		t.Fatalf("TLS: %v %+v", err, snap)
	}
	// Anderer Fingerabdruck: abgelehnt, bevor ein Passwort-Hash die Box erreicht.
	cfg := cfgFor(srv)
	cfg.Pin = strings.Repeat("ab", 32)
	before := f.Unauth + len(f.AllCalls())
	_, err = client().Poll(context.Background(), cfg, nil)
	var pe *PinError
	if !errors.As(err, &pe) || pe.Got != srv.Pin {
		t.Errorf("falscher Fingerabdruck: %v", err)
	}
	if f.Unauth+len(f.AllCalls()) != before {
		t.Error("trotz falschem Zertifikat angefragt")
	}
	// HTTPS gegen HTTP-Port
	plain := tr064test.Start(t, tr064test.NewFake())
	if _, err := client().Fingerprint(context.Background(), plain.Host, plain.Port); err == nil {
		t.Error("HTTP als HTTPS angenommen")
	}
	if p, ok := NormalizePin(FormatPin(srv.Pin)); !ok || p != srv.Pin {
		t.Errorf("NormalizePin: %q", p)
	}
}

// Der Guard (-check-netze) gilt auch hier.
func TestGuard(t *testing.T) {
	srv := tr064test.Start(t, tr064test.NewFake())
	c := &Client{Guard: checks.NewGuard([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}), Timeout: 2 * time.Second}
	_, err := c.Poll(context.Background(), cfgFor(srv), nil)
	var na *checks.NotAllowedError
	if !errors.As(err, &na) {
		t.Errorf("Loopback nicht abgewiesen: %v", err)
	}
}

// Fremde Antworten: kaputt, zu groß, falsche Beschreibung.
func TestAntwortenNichtVertrauenswuerdig(t *testing.T) {
	if _, _, err := parseResponse([]byte("<kaputt"), "GetInfo"); err == nil {
		t.Error("kaputtes XML")
	}
	if _, _, err := parseResponse([]byte(`<a><b><c><d><e><f><g><h><i/></h></g></f></e></d></c></b></a>`), "GetInfo"); err == nil {
		t.Error("zu tief")
	}
	big := `<s:Envelope><s:Body><u:GetInfoResponse>` + strings.Repeat("<NewX>1</NewX>", 0)
	for i := 0; i < maxValues+1; i++ {
		big += "<NewV" + string(rune('a'+i%26)) + strings.Repeat("x", i) + ">1</NewV" + string(rune('a'+i%26)) + strings.Repeat("x", i) + ">"
	}
	big += `</u:GetInfoResponse></s:Body></s:Envelope>`
	if _, _, err := parseResponse([]byte(big), "GetInfo"); !errors.Is(err, ErrTooMuch) {
		t.Errorf("zu viele Werte: %v", err)
	}
	v, code, err := parseResponse([]byte(`<s:Envelope><s:Body><u:GetInfoResponse><NewModelName>A&lt;b</NewModelName></u:GetInfoResponse></s:Body></s:Envelope>`), "GetInfo")
	if err != nil || code != 0 || v["ModelName"] != "A<b" {
		t.Errorf("gültig: %v %d %v", v, code, err)
	}
	if clean("a‮b\x00c", 10) != "ab c" {
		t.Errorf("clean: %q", clean("a‮b\x00c", 10))
	}
	if _, ok := parseChallenge([]string{`Basic realm="x"`}); ok {
		t.Error("Basic angenommen")
	}
	if _, ok := parseChallenge([]string{`Digest realm="x", nonce="a\"b"`}); ok {
		t.Error("Anführungszeichen im Nonce")
	}
	if ch, ok := parseChallenge([]string{`Digest realm="x", nonce="n", algorithm=MD5-sess`}); ok {
		t.Errorf("MD5-sess: %+v", ch)
	}
}

// Neu verbunden mit 32-Bit-Zählern: Der kleinere Wert ist kein Überlauf.
func TestRatenNeuverbindung32Bit(t *testing.T) {
	f := tr064test.NewFake()
	f.Deny("WANCommonInterfaceConfig#GetAddonInfos")
	srv := tr064test.Start(t, f)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	c := client()
	c.Now = func() time.Time { return now }
	first, err := c.Poll(context.Background(), cfgFor(srv), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Second)
	f.Set("WANPPPConnection#GetStatusInfo", "NewUptime", "100") // neu verbunden, länger als die Pause
	f.Set("WANCommonInterfaceConfig#GetTotalBytesReceived", "NewTotalBytesReceived", "1000")
	f.Set("WANCommonInterfaceConfig#GetTotalBytesSent", "NewTotalBytesSent", "1000")
	second, err := c.Poll(context.Background(), cfgFor(srv), first)
	if err != nil {
		t.Fatal(err)
	}
	if it := second.Interfaces[0]; it.HC || it.InBps != nil || it.OutBps != nil {
		t.Errorf("Rate nach Neuverbindung: %+v", it)
	}
}

// Steuer-Adressen aus der Beschreibung: nur eigene Pfade, nur erlaubte Dienste.
func TestBeschreibungNichtVertrauenswuerdig(t *testing.T) {
	for name, desc := range map[string]string{
		"fremder Host": `<root><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>` +
			`<controlURL>//evil.example/upnp/control/deviceinfo</controlURL></service></root>`,
		"Pfad hoch": `<root><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>` +
			`<controlURL>/upnp/control/../../x</controlURL></service></root>`,
		"nur fremder Dienst": `<root><service><serviceType>urn:dslforum-org:service:DeviceConfig:1</serviceType>` +
			`<controlURL>/upnp/control/deviceinfo</controlURL></service></root>`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, desc) }))
		host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		p, _ := strconv.Atoi(port)
		s, err := client().open(Config{Host: host, Port: uint16(p), User: "a", Password: "b"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.describeBox(context.Background()); !errors.Is(err, ErrNoTR064) {
			t.Errorf("%s: %v %v", name, err, s.control)
		}
		srv.Close()
	}
}
