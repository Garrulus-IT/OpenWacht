// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/garrulus-it/openwacht/internal/checks"
)

// Die Notiz jedes Satzes nennt die Freigabe am Agent: alle Arten und alle
// Objekte der Leistungsindikatoren, die der Satz braucht. Sonst meldet der
// Agent „nicht freigegeben“, obwohl der Satz richtig angewandt wurde.
func TestVorlagensaetzeFreigabe(t *testing.T) {
	// mit Anführungszeichen (PowerShell) oder ohne
	arten := regexp.MustCompile(`-arten "?([a-z_,]+)"?`)
	objekte := regexp.MustCompile(`-indikatoren (?:"([^"]+)"|(\S+))`)
	for _, set := range builtinSets {
		var kinds []string
		if m := arten.FindStringSubmatch(set.Notiz); m != nil {
			kinds = strings.Split(m[1], ",")
		}
		var objs []string
		if m := objekte.FindStringSubmatch(set.Notiz); m != nil {
			objs = strings.Split(m[1]+m[2], ",")
		}
		for _, v := range set.Sensoren {
			if !checks.IsAgentKind(v.Typ) {
				continue
			}
			if !slices.Contains(kinds, v.Typ) {
				t.Errorf("%s: Art %s fehlt in der Freigabe: %s", set.Name, v.Typ, set.Notiz)
			}
			if v.Typ != "leistungsindikator" {
				continue
			}
			spec, err := checks.ParseTemplate(v.Typ, v.Ziel)
			if err != nil {
				t.Fatal(err)
			}
			var sp checks.Spec
			json.Unmarshal(spec, &sp)
			if !slices.ContainsFunc(objs, func(o string) bool { return strings.EqualFold(o, sp.Object) }) {
				t.Errorf("%s: Objekt %q fehlt in der Freigabe: %s", set.Name, sp.Object, set.Notiz)
			}
		}
	}
}

func setByID(t *testing.T, id string) vorlagenSatz {
	t.Helper()
	set, ok := builtinSet(id)
	if !ok {
		t.Fatalf("Satz %s fehlt", id)
	}
	return set
}

func specOf(t *testing.T, v vorlageOut) checks.Spec {
	t.Helper()
	sp, err := checks.Parse(v.Typ, checks.Substitute(v.Ziel, "srv.beispiel.example"))
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	return sp
}

func TestVorlagensaetze047(t *testing.T) {
	// Leitprinzip 5: Warteschlangen und Sitzungen nur zusammengefasst, nie
	// einzeln (Instanzen sind Drucker- bzw. Benutzernamen).
	for _, id := range []string{"satz-druck", "satz-citrix-vda"} {
		for _, v := range setByID(t, id).Sensoren {
			sp := specOf(t, v)
			if (sp.Object == "Print Queue" || sp.Object == "ICA Session") && (sp.Instance != "*" || sp.Aggregate == "") {
				t.Errorf("%s einzeln: %s", v.Name, v.Ziel)
			}
		}
	}
	// Citrix: beide LTSR-Stände genannt
	for _, id := range []string{"satz-citrix-vda", "satz-citrix-vda-snmp", "satz-citrix-sf", "satz-citrix-ddc"} {
		if n := setByID(t, id).Notiz; !strings.Contains(n, "2402") || !strings.Contains(n, "2507") {
			t.Errorf("%s ohne beide LTSR: %s", id, n)
		}
	}
	// StoreFront: Store-Erkennung über HTTPS und Zertifikat
	var discovery, tls bool
	for _, v := range setByID(t, "satz-citrix-sf").Sensoren {
		sp := specOf(t, v)
		discovery = discovery || sp.URL == "https://srv.beispiel.example/Citrix/Store/discovery"
		tls = tls || v.Typ == "tls" && sp.WarnDays == 30 && sp.CritDays == 14
	}
	if !discovery || !tls {
		t.Errorf("StoreFront: Erkennung %v, Zertifikat %v", discovery, tls)
	}
	// Hyper-V: kritische VMs alarmieren ab der ersten
	var critical bool
	for _, v := range setByID(t, "satz-hyperv").Sensoren {
		sp := specOf(t, v)
		critical = critical || sp.Counter == "Health Critical" && sp.CritAbove != nil && *sp.CritAbove == 0
	}
	if !critical {
		t.Error("Hyper-V: kritische VMs fehlen")
	}
	// NetScaler: nur NS-ROOT-MIB, Zertifikate und virtuelle Server über
	// Spalten, ohne Namen; Zertifikat wird früh gemeldet.
	var cert, vs bool
	for _, v := range setByID(t, "satz-netscaler").Sensoren {
		sp := specOf(t, v)
		if v.Typ != "snmp_oid" {
			continue
		}
		if !strings.HasPrefix(sp.OID, "1.3.6.1.4.1.5951.4.") {
			t.Errorf("%s: OID außerhalb der NS-ROOT-MIB: %s", v.Name, sp.OID)
		}
		if sp.OID == "1.3.6.1.4.1.5951.4.1.1.56.1.1.5" && sp.Aggregate == "minimum" {
			cert = sp.WarnBelow != nil && *sp.WarnBelow == 30 && sp.CritBelow != nil && *sp.CritBelow == 14
		}
		if sp.OID == "1.3.6.1.4.1.5951.4.1.3.1.1.5" {
			vs = sp.Aggregate == "anzahl_gleich" && sp.Compare != nil && *sp.Compare == 1
		}
	}
	if !cert || !vs {
		t.Errorf("NetScaler: Zertifikate %v, virtuelle Server %v", cert, vs)
	}
}

// NetScaler-Satz an einem Gerät mit SNMP-Abfrage: alle SNMP-Sensoren werden
// angelegt, die Spalten gehen mit der Geräteliste an den Sammler; ohne
// SNMP-Abfrage wird übersprungen. Mandanten: Geschwister nicht, Eltern ja.
func TestVorlagensatzNetScaler(t *testing.T) {
	verwaltungSetup(t)
	resetLimits(t)
	agentServer(t)
	coll := collectorAgent(t, "v_fw", "Fertigung", "ns-sammler", "10.20.0.0/16")
	r := newDevice(t, "v_fw", "Fertigung", "NetScaler A", "ns-a.fw.test")
	expectStatus(t, "Gerät", r, 201)
	ns := r.body["id"].(string)
	r = newDevice(t, "v_fw", "Fertigung", "NetScaler ohne SNMP", "ns-b.fw.test")
	expectStatus(t, "Gerät 2", r, 201)
	bare := r.body["id"].(string)
	cleanupChecks(t, ns, bare)
	r = as(t, "v_fw").do("PUT", "/api/v1/geraete/"+ns+"/snmp", snmpBody("10.20.0.40", map[string]any{"sammler": coll.id}))
	expectStatus(t, "SNMP", r, 201)
	src := r.body["id"].(string)

	set := setByID(t, "satz-netscaler")
	snmpItems := 0
	for _, v := range set.Sensoren {
		if v.Typ == "snmp_oid" {
			snmpItems++
		}
	}
	apply := func(user string, devs ...string) response {
		return as(t, user).do("POST", "/api/v1/sensor-vorlagen/anwenden", map[string]any{"satz_id": "satz-netscaler", "geraete": devs})
	}
	expectStatus(t, "Geschwister", apply("v_oa", ns), 400)
	expectStatus(t, "Leser Kind", apply("v_lz", ns), 400)
	r = apply("v_it", ns, bare)
	expectStatus(t, "Eltern", r, 200)
	skipped := r.body["uebersprungen"].([]any)
	if int(r.body["angelegt"].(float64)) != len(set.Sensoren)+(len(set.Sensoren)-snmpItems) || len(skipped) != snmpItems {
		t.Fatalf("angewandt: %v", r.body)
	}
	for _, x := range skipped {
		if m := x.(map[string]any); m["geraet_id"] != bare || !strings.Contains(m["grund"].(string), "SNMP") {
			t.Errorf("übersprungen: %v", m)
		}
	}
	_, list, _ := coll.devices("")
	for _, d := range list.Devices {
		if d.ID != src {
			continue
		}
		// Spalten ohne Doppel (Zertifikate zweimal: Minimum und Anzahl)
		want := []string{"1.3.6.1.4.1.5951.4.1.3.1.1.5", "1.3.6.1.4.1.5951.4.1.3.1.1.37", "1.3.6.1.4.1.5951.4.1.1.56.1.1.5"}
		got := slices.Clone(d.Columns)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) || len(d.Extra) != 3 {
			t.Errorf("Geräteliste: Spalten %v, Werte %v", d.Columns, d.Extra)
		}
		return
	}
	t.Error("Gerät fehlt in der Liste des Sammlers")
}
