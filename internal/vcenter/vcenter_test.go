// SPDX-License-Identifier: AGPL-3.0-only

package vcenter

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/vcenter/vcentertest"
)

func cfgFor(t *testing.T, f *vcentertest.Fake) Config {
	u, _ := url.Parse(f.Server.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	return Config{Host: host, Port: uint16(p), User: f.User, Password: f.Password, CAPEM: f.CAPEM}
}

func TestAbfrage(t *testing.T) {
	f := vcentertest.Start(t)
	c := &Client{Guard: &net.Dialer{}}
	snap, err := c.Poll(context.Background(), cfgFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	px := snap.Proxmox
	if len(px.Guests) != 4 || len(px.Storages) != 2 || len(snap.Disks) != 1 {
		t.Fatalf("%+v", px)
	}
	byName := map[string]string{}
	for _, g := range px.Guests {
		byName[g.Type+":"+g.Name] = g.Status
		if g.Type == "esxi" && (g.OnBoot == nil || !*g.OnBoot || g.VMID < hostBase) || g.Type == "vm" && (g.OnBoot != nil || g.VMID < vmBase) {
			t.Errorf("Gast %+v", g)
		}
	}
	if byName["esxi:esx01"] != "running" || byName["esxi:esx02"] != "not_responding" || byName["vm:dc01"] != "running" || byName["vm:alt"] != "stopped" {
		t.Errorf("%v", byName)
	}
	if d := snap.Disks[0]; d.Mount != "ds-ssd" || d.TotalBytes != 1000 || d.FreeBytes != 250 {
		t.Errorf("Datastore %+v", d)
	}
	for _, st := range px.Storages {
		if st.Name == "ds-nfs" && st.Active {
			t.Error("Datastore ohne Kapazität als erreichbar gemeldet")
		}
	}
	if f.Sessions != 0 {
		t.Error("Sitzung nicht abgemeldet")
	}
	for _, m := range f.Methods {
		if !strings.HasPrefix(m, "GET ") && m != "POST /api/session" && m != "DELETE /api/session" {
			t.Errorf("unerwartete Anfrage %s", m)
		}
	}
	// Negativfälle
	bad := cfgFor(t, f)
	bad.Password = "falsch"
	if _, err := c.Poll(context.Background(), bad); !errors.Is(err, ErrLogin) {
		t.Errorf("falsches Passwort: %v", err)
	}
	noCA := cfgFor(t, f)
	noCA.CAPEM = ""
	if _, err := c.Poll(context.Background(), noCA); err == nil {
		t.Error("ohne CA angenommen")
	}
	for _, u := range []string{"", "a b", "x;rm", strings.Repeat("a", 200)} {
		if ValidUser(u) {
			t.Errorf("Benutzer %q", u)
		}
	}
	f.Set("vms", []map[string]any{{"vm": "../etc", "name": "x\x00y", "power_state": "POWERED_ON"}, {"vm": "vm-7", "name": "a\nb", "power_state": "X"}})
	snap, err = c.Poll(context.Background(), cfgFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range snap.Proxmox.Guests {
		if g.Type == "vm" {
			n++
			if g.Name != "ab" || g.Status != "unbekannt" {
				t.Errorf("bereinigt: %+v", g)
			}
		}
	}
	if n != 1 {
		t.Errorf("ungültige ID übernommen: %d", n)
	}
	many := make([]map[string]any, MaxHosts+1)
	for i := range many {
		many[i] = map[string]any{"host": "host-" + strconv.Itoa(i+1), "name": "h"}
	}
	f.Set("hosts", many)
	if _, err := c.Poll(context.Background(), cfgFor(t, f)); !errors.Is(err, ErrTooMuch) {
		t.Errorf("zu viele Hosts: %v", err)
	}
}
