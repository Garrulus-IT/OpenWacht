// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/snmp"
)

func TestSammlerFreigabe(t *testing.T) {
	dir := t.TempDir()
	if nets, err := ReadCollectorConfig(dir); nets != nil || err != nil {
		t.Fatalf("ohne Datei: %v %v", nets, err)
	}
	if _, err := WriteCollectorConfig(dir, []string{"0.0.0.0/0"}); err == nil {
		t.Error("/0 angenommen")
	}
	if _, err := os.Stat(filepath.Join(dir, fileCollector)); !errors.Is(err, os.ErrNotExist) {
		t.Error("Datei trotz Fehler geschrieben")
	}
	if _, err := WriteCollectorConfig(dir, []string{"10.20.0.0/16", "127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	nets, err := ReadCollectorConfig(dir)
	if err != nil || len(nets) != 2 || nets[0] != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("gelesen: %v %v", nets, err)
	}
	os.WriteFile(filepath.Join(dir, fileCollector), []byte(`{"netze":["10.20.1.1/16"]}`), 0o644)
	if nets, err := ReadCollectorConfig(dir); err == nil || nets != nil {
		t.Errorf("kaputte Datei: %v %v", nets, err)
	}
	if err := RemoveCollectorConfig(dir); err != nil {
		t.Fatal(err)
	}
	if err := RemoveCollectorConfig(dir); err != nil {
		t.Errorf("zweites Entfernen: %v", err)
	}
	if nets, _ := ReadCollectorConfig(dir); nets != nil {
		t.Error("nach Entfernen noch an")
	}
}

func TestSammlerGeraetPruefen(t *testing.T) {
	good := agentproto.CollectorDevice{ID: "0b6a3c84-2a43-4f7e-9b6e-8f6b2a7a1c11", Revision: 1, Version: "2c", Host: "10.20.0.5",
		Port: 161, IntervalSeconds: 60, Community: "public-x"}
	if cfg, err := deviceConfig(good); err != nil || cfg.Community != "public-x" || cfg.Port != 161 {
		t.Fatalf("gültig: %+v %v", cfg, err)
	}
	v3 := good
	v3.Version, v3.Community = "3", ""
	v3.V3 = &agentproto.CollectorV3{User: "u", Auth: "sha256", AuthPass: "auth-pass-123", Priv: "aes", PrivPass: "priv-pass-123"}
	if _, err := deviceConfig(v3); err != nil {
		t.Errorf("v3: %v", err)
	}
	cols := good
	cols.Columns = []string{"1.3.6.1.4.1.5951.4.1.1.56.1.1.5"}
	if cfg, err := deviceConfig(cols); err != nil || len(cfg.Columns) != 1 {
		t.Errorf("Spalte: %+v %v", cfg, err)
	}
	for name, mod := range map[string]func(d *agentproto.CollectorDevice){
		"ID":         func(d *agentproto.CollectorDevice) { d.ID = "../../etc" },
		"Revision":   func(d *agentproto.CollectorDevice) { d.Revision = 0 },
		"Port":       func(d *agentproto.CollectorDevice) { d.Port = 70000 },
		"Intervall":  func(d *agentproto.CollectorDevice) { d.IntervalSeconds = 1 },
		"Adresse":    func(d *agentproto.CollectorDevice) { d.Host = "a b;rm" },
		"Version":    func(d *agentproto.CollectorDevice) { d.Version = "pve" },
		"Community":  func(d *agentproto.CollectorDevice) { d.Community = "" },
		"v3 bei v2c": func(d *agentproto.CollectorDevice) { d.V3 = v3.V3 },
		"v3 ohne":    func(d *agentproto.CollectorDevice) { d.Version = "3"; d.Community = "" },
		"v3 MD5": func(d *agentproto.CollectorDevice) {
			*d = v3
			d.V3 = &agentproto.CollectorV3{User: "u", Auth: "md5", AuthPass: "auth-pass-123", Priv: "aes", PrivPass: "priv-pass-123"}
		},
		"v3 Community":    func(d *agentproto.CollectorDevice) { *d = v3; d.Community = "x" },
		"eigene OID":      func(d *agentproto.CollectorDevice) { d.Extra = []string{"1.3.6;x"} },
		"Spalte":          func(d *agentproto.CollectorDevice) { d.Columns = []string{"1.3.6", "1.3.6"} },
		"Spalte ungültig": func(d *agentproto.CollectorDevice) { d.Columns = []string{"x"} },
	} {
		d := good
		mod(&d)
		if _, err := deviceConfig(d); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}
}

func TestSammlerFehlertexte(t *testing.T) {
	nets := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	msg := collectorError(&checks.NotAllowedError{Addr: netip.MustParseAddr("10.30.0.1")}, nets)
	if !strings.Contains(msg, "10.30.0.1") || !strings.Contains(msg, "10.20.0.0/16") {
		t.Errorf("nicht freigegeben: %s", msg)
	}
	if msg := collectorError(snmp.ErrNoResponse, nets); strings.Contains(msg, "Zentrale") {
		t.Errorf("keine Antwort: %s", msg)
	}
	// Der Guard des Sammlers lässt nur seine Netze durch, auch keine Loopback-Adresse.
	g := checks.NewGuard(nets)
	for addr, want := range map[string]bool{"10.20.3.4": true, "10.21.0.1": false, "127.0.0.1": false, "169.254.169.254": false} {
		if got := g.Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}
