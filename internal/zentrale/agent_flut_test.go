// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"testing"

	"github.com/garrulus-it/openwacht/internal/agentproto"
)

// Ein Agent mit gültigem Zertifikat darf die Zentrale nicht fluten: Meldungen,
// Erneuerungen und Update-Abrufe sind je Agent und Minute begrenzt. Ohne die
// Grenze schreibt jede Meldung bis zu 100 Zeilen in die Rohdaten, beliebig oft.
func TestAgentFlutBegrenzt(t *testing.T) {
	agentServer(t)
	token, r := newAgentToken(t, "v_fw", "Fertigung", 2)
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, token, "flut-01")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	other, status, body := register(t, token, "flut-02")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.metrics_host_raw WHERE agent_id = ANY($1::uuid[])`, []string{a.id, other.id})
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = ANY($1::uuid[])`, []string{a.id, other.id})
	})

	ok, limited := 0, 0
	for range 3 * agentReportsPerMinute {
		switch s, b := a.report("flut-01"); s {
		case 200:
			ok++
		case 429:
			limited++
		default:
			t.Fatalf("Meldung: %d %s", s, b)
		}
	}
	if ok != agentReportsPerMinute || limited != 2*agentReportsPerMinute {
		t.Errorf("Meldungen: %d angenommen, %d begrenzt; erwartet %d und %d", ok, limited, agentReportsPerMinute, 2*agentReportsPerMinute)
	}
	var stamps int
	if err := owner.QueryRow(ctx, `SELECT count(DISTINCT ts) FROM openwacht.metrics_host_raw WHERE agent_id = $1`, a.id).Scan(&stamps); err != nil {
		t.Fatal(err)
	}
	if stamps > agentReportsPerMinute {
		t.Errorf("Rohdaten: %d Messzeitpunkte gespeichert, höchstens %d erwartet", stamps, agentReportsPerMinute)
	}
	// Die Grenze gilt je Agent: Ein anderer Agent meldet weiter.
	if s, b := other.report("flut-02"); s != 200 {
		t.Errorf("anderer Agent: %d %s", s, b)
	}

	// Erneuerung: Jede Anfrage lässt die Zentrale ein Zertifikat signieren.
	ok, limited = 0, 0
	for range 3 * agentRenewalsPerMinute {
		_, csr := newCSR(t)
		s, _, err := postJSON(a.client(), agentSrv.URL+agentproto.PathRenew, agentproto.RenewRequest{CSR: csr})
		if err != nil {
			t.Fatal(err)
		}
		if s == 429 {
			limited++
		} else {
			ok++
		}
	}
	if ok > agentRenewalsPerMinute || limited == 0 {
		t.Errorf("Erneuerungen: %d bearbeitet, %d begrenzt; höchstens %d je Minute erwartet", ok, limited, agentRenewalsPerMinute)
	}

	// Update-Abrufe (Signatur und Binary teilen sich die Grenze).
	ok, limited = 0, 0
	for i := range 3 * agentUpdateFetchesPerMinute {
		path := agentproto.PathUpdateSignature
		if i%2 == 1 {
			path = agentproto.PathUpdateBinary
		}
		s, _, err := postJSON(other.client(), agentSrv.URL+path, map[string]string{"version": "9.9.9", "plattform": "linux/amd64"})
		if err != nil {
			t.Fatal(err)
		}
		if s == 429 {
			limited++
		} else {
			ok++
		}
	}
	if ok > agentUpdateFetchesPerMinute || limited == 0 {
		t.Errorf("Update-Abrufe: %d bearbeitet, %d begrenzt; höchstens %d je Minute erwartet", ok, limited, agentUpdateFetchesPerMinute)
	}
}

// H6: Auch ohne die Grenze der Zentrale nimmt agent_report je Agent und
// Minute höchstens 20 Meldungen mit Messwerten an.
func TestAgentReportGrenzeDB(t *testing.T) {
	agentServer(t)
	token, r := newAgentToken(t, "v_fw", "Fertigung", 1)
	expectStatus(t, "Token", r, 201)
	a, status, body := register(t, token, "flut-db-01")
	if status != 200 {
		t.Fatalf("Registrierung: %d %s", status, body)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		owner.Exec(ctx, `DELETE FROM openwacht.metrics_host_raw WHERE agent_id = $1`, a.id)
		owner.Exec(ctx, `DELETE FROM openwacht.agents WHERE id = $1`, a.id)
	})
	var serial string
	if err := owner.QueryRow(ctx, `SELECT cert_serial FROM openwacht.agents WHERE id = $1`, a.id).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		var ok bool
		// als App-Rolle, wie die Zentrale
		if err := vServer.pool.QueryRow(ctx, `SELECT openwacht.agent_report($1, $2, 'flut-db-01', '{}'::jsonb,
				ARRAY['cpu','speicher'], ARRAY[1.0, 2.0]::double precision[], NULL)`, a.id, serial).Scan(&ok); err != nil || !ok {
			t.Fatalf("Meldung %d: %v %v", i, ok, err)
		}
	}
	var n int
	owner.QueryRow(ctx, `SELECT count(DISTINCT ts) FROM openwacht.metrics_host_raw WHERE agent_id = $1`, a.id).Scan(&n)
	if n != 20 {
		t.Errorf("%d Meldungen mit Messwerten gespeichert, erwartet 20", n)
	}
	// nächste Minute: wieder angenommen
	owner.Exec(ctx, `UPDATE openwacht.agents SET report_window = now() - interval '61 seconds' WHERE id = $1`, a.id)
	vServer.pool.Exec(ctx, `SELECT openwacht.agent_report($1, $2, 'flut-db-01', '{}'::jsonb, ARRAY['cpu'], ARRAY[1.0]::double precision[], NULL)`, a.id, serial)
	owner.QueryRow(ctx, `SELECT count(DISTINCT ts) FROM openwacht.metrics_host_raw WHERE agent_id = $1`, a.id).Scan(&n)
	if n != 21 {
		t.Errorf("nach einer Minute: %d", n)
	}
}
