// SPDX-License-Identifier: AGPL-3.0-only

package ontap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/ontap/ontaptest"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

func client() *Client { return &Client{Guard: &net.Dialer{}, Timeout: 5 * time.Second} }

func cfgFor(s *ontaptest.Server) Config {
	return Config{Host: s.Host, Port: s.Port, User: ontaptest.User, Password: ontaptest.Password, Pin: s.Pin}
}

func TestPollAlles(t *testing.T) {
	f := ontaptest.NewFake()
	srv := ontaptest.Start(t, f)
	snap, err := client().Poll(context.Background(), cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	o := snap.ONTAP
	if o.Cluster != "aff-test" || !strings.HasPrefix(o.Version, "NetApp Release 9.16.1") || o.Fingerprint != srv.Pin {
		t.Errorf("Cluster: %+v", o)
	}
	if len(o.Nodes) != 2 || o.Nodes[0].Name != "aff-01" || o.Nodes[0].Partner != "aff-02" || !o.Nodes[0].HA ||
		o.Nodes[0].State != "up" || o.Nodes[0].Takeover != "not_attempted" || o.Nodes[0].UptimeS != 3000000 {
		t.Errorf("Knoten: %+v", o.Nodes)
	}
	if snap.System.UptimeS != 3000100 || snap.System.Name != "aff-test" || !strings.Contains(snap.System.Descr, "AFF-C250") {
		t.Errorf("System: %+v", snap.System)
	}
	a := o.Aggregates[1]
	if len(o.Aggregates) != 2 || a.Name != "aggr2" || a.TotalBytes != 1e12 || a.UsedBytes != 95e10 || *a.IOPS != 800 || *a.LatencyMs != 0.9 {
		t.Errorf("Aggregate: %+v", o.Aggregates)
	}
	if len(o.Volumes) != 3 || o.Volumes[0].Name != "svm1/archiv" || o.Volumes[0].State != "offline" {
		t.Errorf("Volumes: %+v", o.Volumes)
	}
	mounts := []string{}
	for _, d := range snap.Disks {
		mounts = append(mounts, d.Mount)
	}
	// Spiegelziel (dp) und offline zählen nicht für „voll“.
	if strings.Join(mounts, ",") != "Aggregat aggr1,Aggregat aggr2,Volume svm1/daten" {
		t.Errorf("Platten: %v", mounts)
	}
	if o.Disks.Total != 4 || o.Disks.Spares != 1 || len(o.Disks.Bad) != 1 || o.Disks.Bad[0].Name != "1.0.2" {
		t.Errorf("Platten: %+v", o.Disks)
	}
	sh := o.Shelves[0]
	if len(o.Shelves) != 1 || sh.ID != "1.0" || sh.State != "error" || len(sh.Parts) != 4 || len(sh.Temps) != 1 ||
		*sh.Temps[0].Celsius != 32 || *sh.Temps[0].Warn != 50 || *sh.Temps[0].Crit != 60 {
		t.Errorf("Shelf: %+v", sh)
	}
	if len(o.Mirrors) != 1 || *o.Mirrors[0].LagS != 60*3600+5*60 || !o.Mirrors[0].Healthy {
		t.Errorf("SnapMirror: %+v", o.Mirrors)
	}
	if len(o.Events) != 1 || o.Events[0].Name != "disk.outOfService" || o.Events[0].Severity != "alert" {
		t.Errorf("EMS: %+v", o.Events)
	}
	// Nur GET auf erlaubte Pfade, Rechteprüfung zuerst.
	calls := f.Calls()
	if calls[0] != "GET /api/security/login/whoami" {
		t.Errorf("erste Anfrage: %v", calls)
	}
	for _, c := range calls {
		m, p, _ := strings.Cut(c, " ")
		if m != "GET" || !AllowedPath(p) {
			t.Errorf("Anfrage %s", c)
		}
	}
	q, _ := url.ParseQuery(f.Query("/api/support/ems/events"))
	if q.Get("message.severity") != "emergency|alert" || !strings.HasPrefix(q.Get("time"), ">") || q.Get("max_records") != "51" {
		t.Errorf("EMS-Abfrage: %v", q)
	}
	// Seriennummern werden weder angefordert noch gespeichert (datensparsam).
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "nicht-gelesen") || strings.Contains(f.Query("/api/cluster/nodes"), "serial") {
		t.Error("Seriennummer gelesen")
	}
	c := *snap
	c.Counters = &snmp.CounterInfo{At: c.CollectedAt, UptimeTicks: c.System.UptimeTicks}
	if err := c.ValidateCollected(time.Now()); err == nil || !strings.Contains(err.Error(), "ontap") {
		t.Error("Sammler darf keine ONTAP-Daten liefern")
	}
}

func TestRechteVor919(t *testing.T) {
	f := ontaptest.NewFake()
	f.SetLegacy(true)
	srv := ontaptest.Start(t, f)
	if _, err := client().Poll(context.Background(), cfgFor(srv)); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.Calls(), ",")
	if !strings.Contains(joined, "GET /api/security/accounts") || !strings.Contains(joined, "/privileges") {
		t.Errorf("Rechte nicht über Rolle geprüft: %s", joined)
	}
}

func TestSchreibrechtAbgelehnt(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, access := range []string{"all", "read_create", "read_modify", "read_create_modify", "read_create_delete"} {
			f := ontaptest.NewFake()
			f.SetLegacy(legacy)
			f.Writable("/api/storage/volumes", access)
			srv := ontaptest.Start(t, f)
			_, err := client().Poll(context.Background(), cfgFor(srv))
			var we *WritableError
			if !errors.As(err, &we) || we.Path != "/api/storage/volumes" || we.Access != access {
				t.Errorf("legacy=%v %s: %v", legacy, access, err)
			}
			// Nach der Ablehnung liest der Client nichts mehr.
			for _, c := range f.Calls() {
				if !strings.Contains(c, "/api/security/") {
					t.Errorf("nach Ablehnung gelesen: %s", c)
				}
			}
		}
	}
	// Befehle für die eigene Sitzung zählen nicht, CLI-Verzeichnisse schon.
	f := ontaptest.NewFake()
	f.Writable("set", "all")
	f.Writable("security login password", "all")
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); err != nil {
		t.Errorf("harmlose Befehle: %v", err)
	}
	f.Writable("volume", "all")
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); err == nil {
		t.Error("CLI-Schreibrecht nicht erkannt")
	}
	// Leere Rechte gelten als nicht prüfbar.
	f = ontaptest.NewFake()
	f.Privileges = nil
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); !errors.Is(err, ErrRightsUnknown) {
		t.Errorf("leere Rechte: %v", err)
	}
}

func TestRechteNichtPruefbar(t *testing.T) {
	cases := map[string]func(*ontaptest.Fake){
		"whoami 403": func(f *ontaptest.Fake) { f.Forbid("/api/security/login/whoami") },
		"Konten 403": func(f *ontaptest.Fake) { f.SetLegacy(true); f.Forbid("/api/security/accounts") },
		"Rolle 403": func(f *ontaptest.Fake) {
			f.SetLegacy(true)
			f.Forbid("/api/security/roles/" + ontaptest.OwnerUUID + "/" + ontaptest.Role + "/privileges")
		},
		"kein Konto": func(f *ontaptest.Fake) { f.SetLegacy(true); f.Set("/api/security/accounts", nil) },
		"zwei Konten": func(f *ontaptest.Fake) {
			f.SetLegacy(true)
			a := map[string]any{"name": ontaptest.User, "scope": "cluster", "owner": map[string]any{"uuid": ontaptest.OwnerUUID}, "role": map[string]any{"name": "admin"}}
			f.Set("/api/security/accounts", []map[string]any{a, a})
		},
		"nur SVM-Konto": func(f *ontaptest.Fake) {
			f.SetLegacy(true)
			f.Update("/api/security/accounts", 0, func(m map[string]any) { m["scope"] = "svm" })
		},
		"Rolle mit Pfad": func(f *ontaptest.Fake) {
			f.SetLegacy(true)
			f.Update("/api/security/accounts", 0, func(m map[string]any) { m["role"] = map[string]any{"name": "../../storage/volumes"} })
		},
		"Owner kein UUID": func(f *ontaptest.Fake) {
			f.SetLegacy(true)
			f.Update("/api/security/accounts", 0, func(m map[string]any) { m["owner"] = map[string]any{"uuid": "x/../../a"} })
		},
	}
	for name, setup := range cases {
		f := ontaptest.NewFake()
		setup(f)
		_, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f)))
		if !errors.Is(err, ErrRightsUnknown) {
			t.Errorf("%s: %v", name, err)
		}
		for _, c := range f.Calls() {
			if !strings.Contains(c, "/api/security/") {
				t.Errorf("%s: gelesen %s", name, c)
			}
		}
	}
}

func TestFehlerfaelle(t *testing.T) {
	ctx := context.Background()
	f := ontaptest.NewFake()
	srv := ontaptest.Start(t, f)

	// 401: verständlich, ohne Passwort im Text
	c := cfgFor(srv)
	c.Password = "falsch-999"
	if _, err := client().Poll(ctx, c); !errors.Is(err, ErrLogin) || strings.Contains(err.Error(), "falsch-999") {
		t.Errorf("401: %v", err)
	}

	// Falsches Zertifikat: Abbruch im Handshake, keine Anfrage (also kein Passwort) beim Server.
	f.ResetCalls()
	other := ontaptest.Start(t, ontaptest.NewFake())
	c = cfgFor(srv)
	c.Pin = other.Pin
	_, err := client().Poll(ctx, c)
	var pe *PinError
	if !errors.As(err, &pe) || pe.Got != srv.Pin {
		t.Errorf("falsches Zertifikat: %v", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("trotz falschem Zertifikat %d Anfragen", n)
	}
	// Ohne Fingerabdruck gar keine Verbindung.
	c.Pin = ""
	if _, err := client().Poll(ctx, c); err == nil || len(f.Calls()) != 0 {
		t.Errorf("ohne Fingerabdruck: %v", err)
	}

	// 403 auf Pflichtteile: Fehler; auf übrige: Teil fehlt, Rest bleibt.
	f2 := ontaptest.NewFake()
	f2.Forbid("/api/cluster/nodes")
	var fe *ForbiddenError
	if _, err := client().Poll(ctx, cfgFor(ontaptest.Start(t, f2))); !errors.As(err, &fe) {
		t.Errorf("403 Knoten: %v", err)
	}
	f3 := ontaptest.NewFake()
	f3.Forbid("/api/storage/shelves")
	f3.Forbid("/api/support/ems/events")
	snap, err := client().Poll(ctx, cfgFor(ontaptest.Start(t, f3)))
	if err != nil || strings.Join(snap.Partial, ",") != "Shelves,EMS" || len(snap.ONTAP.Shelves) != 0 || len(snap.ONTAP.Nodes) != 2 {
		t.Errorf("403 Shelves: %v %+v", err, snap)
	}

	// Übergroße Antwort
	for _, p := range []string{"/api/storage/volumes", "/api/cluster/nodes", "/api/security/login/whoami"} {
		f4 := ontaptest.NewFake()
		f4.Huge(p)
		if _, err := client().Poll(ctx, cfgFor(ontaptest.Start(t, f4))); !errors.Is(err, ErrTooMuch) {
			t.Errorf("übergroß %s: %v", p, err)
		}
	}

	// Zu viele Einträge: Pflichtteile Fehler, Volumes gekürzt.
	many := func(n int, mk func(i int) map[string]any) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = mk(i)
		}
		return out
	}
	f5 := ontaptest.NewFake()
	f5.Set("/api/cluster/nodes", many(MaxNodes+1, func(i int) map[string]any { return map[string]any{"name": fmt.Sprintf("n%d", i), "state": "up"} }))
	if _, err := client().Poll(ctx, cfgFor(ontaptest.Start(t, f5))); !errors.Is(err, ErrTooMuch) {
		t.Errorf("zu viele Knoten: %v", err)
	}
	f6 := ontaptest.NewFake()
	f6.Set("/api/storage/volumes", many(MaxVolumes+5, func(i int) map[string]any {
		return map[string]any{"name": fmt.Sprintf("v%04d", i), "state": "online", "type": "rw", "svm": map[string]any{"name": "s"},
			"space": map[string]any{"used": 1, "available": 9}}
	}))
	snap, err = client().Poll(ctx, cfgFor(ontaptest.Start(t, f6)))
	if err != nil || len(snap.ONTAP.Volumes) != MaxVolumes || strings.Join(snap.Truncated, ",") != "Volumes" {
		t.Errorf("zu viele Volumes: %v %v", err, snap.Truncated)
	}
	raw, _ := json.Marshal(snap)
	if len(raw) > 512<<10 {
		t.Errorf("Snapshot zu groß: %d", len(raw))
	}

	// Weiterleitung wird nicht verfolgt.
	f7 := ontaptest.NewFake()
	f7.Redirect("/api/cluster")
	if _, err := client().Poll(ctx, cfgFor(ontaptest.Start(t, f7))); err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("Weiterleitung: %v", err)
	}

	// Netzfreigabe: Der Guard lehnt ab, bevor verbunden wird.
	if _, err := (&Client{Guard: denyAll{}}).Poll(ctx, cfgFor(srv)); err == nil || !strings.Contains(err.Error(), "nicht freigegeben") {
		t.Errorf("Guard: %v", err)
	}
}

type denyAll struct{}

func (denyAll) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("Adresse nicht freigegeben")
}

func TestFingerabdruck(t *testing.T) {
	f := ontaptest.NewFake()
	srv := ontaptest.Start(t, f)
	fp, err := client().Fingerprint(context.Background(), srv.Host, srv.Port)
	if err != nil || fp != srv.Pin {
		t.Fatalf("%v %s", err, fp)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("Fingerabdruck sendet %d Anfragen", n)
	}
	if _, err := (&Client{Guard: denyAll{}}).Fingerprint(context.Background(), srv.Host, srv.Port); err == nil {
		t.Error("Guard umgangen")
	}
}

func TestProbe(t *testing.T) {
	srv := ontaptest.Start(t, ontaptest.NewFake())
	info, err := client().Probe(context.Background(), cfgFor(srv))
	if err != nil || info.Nodes != 2 || info.Aggregates != 2 || info.Volumes != 3 || info.Disks != 4 || info.Shelves != 1 ||
		info.Mirrors != 1 || info.Cluster != "aff-test" || info.Fingerprint != srv.Pin {
		t.Errorf("%v %+v", err, info)
	}
}

func TestBuildUngueltigeWerte(t *testing.T) {
	neg, big := int64(-5), int64(10)
	var raw Raw
	raw.Cluster.Name = "aff\u202e-x\x00"
	raw.Nodes = []node{{Name: ""}, {Name: "n1", State: "UP; DROP"}, {Name: "n1"}}
	raw.Aggregates = []aggregate{{Name: "a1", State: "online"}}
	raw.Aggregates[0].Space.BlockStorage.Size, raw.Aggregates[0].Space.BlockStorage.Used = &big, &neg
	raw.Volumes = []volume{{Name: "v1", State: "online", Type: "rw"}}
	raw.Volumes[0].Space.Used, raw.Volumes[0].Space.Available = &big, &neg
	raw.Events = []event{{Time: "gestern", LogMessage: "x"}, {Time: time.Now().Format(time.RFC3339), LogMessage: "y"}}
	raw.Events[1].Message.Name, raw.Events[1].Message.Severity = "a b", "alert"
	snap := Build(raw, time.Now())
	o := snap.ONTAP
	if o.Cluster != "aff-x" {
		t.Errorf("Name nicht bereinigt: %q", o.Cluster)
	}
	if len(o.Nodes) != 1 || o.Nodes[0].State != "unknown" {
		t.Errorf("Knoten: %+v", o.Nodes)
	}
	if len(snap.Disks) != 0 || o.Aggregates[0].TotalBytes != 0 || o.Volumes[0].TotalBytes != 0 {
		t.Errorf("negative Größen übernommen: %+v %+v", snap.Disks, o.Aggregates)
	}
	if len(o.Events) != 0 {
		t.Errorf("ungültige Ereignisse übernommen: %+v", o.Events)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]int64{"PT8H35M42S": 8*3600 + 35*60 + 42, "P2DT1H": 2*86400 + 3600, "PT0S": 0, "PT1.5S": 1, "PT90M": 5400} {
		if got, ok := ParseDuration(in); !ok || got != want {
			t.Errorf("%s: %d %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "P", "PT", "8H", "PT-1H", "P1Y", "PT1H2", "P99999999D"} {
		if _, ok := ParseDuration(in); ok {
			t.Errorf("%q angenommen", in)
		}
	}
}

func TestRebooted(t *testing.T) {
	prev := &snmp.ONTAP{Nodes: []snmp.ONTAPNode{{Name: "a", UptimeS: 5000}, {Name: "b", UptimeS: 5000}}}
	if Rebooted(prev, &snmp.ONTAP{Nodes: []snmp.ONTAPNode{{Name: "a", UptimeS: 5060}, {Name: "b", UptimeS: 5060}}}) {
		t.Error("ohne Neustart")
	}
	if !Rebooted(prev, &snmp.ONTAP{Nodes: []snmp.ONTAPNode{{Name: "a", UptimeS: 5060}, {Name: "b", UptimeS: 100}}}) {
		t.Error("Neustart von b nicht erkannt")
	}
	if Rebooted(nil, prev) || Rebooted(prev, &snmp.ONTAP{Nodes: []snmp.ONTAPNode{{Name: "c", UptimeS: 1}}}) {
		t.Error("neuer Knoten ist kein Neustart")
	}
}

func TestAllowedPath(t *testing.T) {
	for _, p := range []string{"/api/storage/volumes/x", "/api/cluster/../storage", "/api/security/roles/" + ontaptest.OwnerUUID + "/a/b/privileges",
		"/api/private/cli", "/api/security/accounts/x"} {
		if AllowedPath(p) {
			t.Errorf("%s erlaubt", p)
		}
	}
}

// ONTAP 9.18.1: whoami antwortet 200 mit „{}“. OpenWacht prüft dann über Konto
// und Rolle (vorher: „Rechte des Kontos nicht lesbar“ trotz Nur-Lese-Rolle).
func TestWhoamiLeerONTAP918(t *testing.T) {
	f := ontaptest.NewFake()
	f.WhoamiEmpty = true
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); err != nil {
		t.Fatalf("Nur-Lese-Rolle bei leerem whoami abgelehnt: %v", err)
	}
	f = ontaptest.NewFake()
	f.WhoamiEmpty = true
	f.Writable("/api/storage/volumes", "all")
	var we *WritableError
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); !errors.As(err, &we) {
		t.Fatalf("Schreibrecht bei leerem whoami nicht erkannt: %v", err)
	}
	f = ontaptest.NewFake()
	f.WhoamiEmpty = true
	f.Privileges = nil
	if _, err := client().Poll(context.Background(), cfgFor(ontaptest.Start(t, f))); !errors.Is(err, ErrRightsUnknown) {
		t.Fatalf("leere Rolle bei leerem whoami: %v", err)
	}
}
