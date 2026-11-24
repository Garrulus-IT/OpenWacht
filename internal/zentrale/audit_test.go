// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// auditDB: eigene Datenbank mit einigen Einträgen (die gemeinsame bleibt
// unberührt, weil diese Tests die Kette verändern).
func auditDB(t *testing.T, n int) (*pgx.Conn, *pgxpool.Pool, string) {
	t.Helper()
	o, p := freshInstall(t)
	ctx := context.Background()
	var tenant string
	if err := o.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := o.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details) VALUES ($1, 'test.eintrag', $2)`,
			tenant, map[string]any{"nr": i}); err != nil {
			t.Fatal(err)
		}
	}
	return o, p, tenant
}

// rewrite: Einträge als Eigentümer ändern (Trigger aus) und die Kette danach
// vollständig neu berechnen, wie es ein Angreifer mit Eigentümer-Rechten tun
// könnte. sql läuft zwischen Aus- und Einschalten.
func rewrite(t *testing.T, o *pgx.Conn, sql string, rechain bool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{`ALTER TABLE openwacht.audit_log DISABLE TRIGGER audit_no_update`, sql}
	if rechain {
		stmts = append(stmts, `DO $$
			DECLARE e openwacht.audit_log; prev bytea := (SELECT prev_hash FROM openwacht.audit_anchor);
			BEGIN
				FOR e IN SELECT * FROM openwacht.audit_log ORDER BY chain_seq LOOP
					e.prev_hash := prev;
					UPDATE openwacht.audit_log SET prev_hash = prev, hash = openwacht.audit_entry_hash(e) WHERE chain_seq = e.chain_seq;
					prev := openwacht.audit_entry_hash(e);
				END LOOP;
			END $$`)
	}
	stmts = append(stmts, `ALTER TABLE openwacht.audit_log ENABLE TRIGGER audit_no_update`)
	for _, q := range stmts {
		if _, err := o.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestAuditPruefungErkenntManipulation(t *testing.T) {
	o, p, _ := auditDB(t, 5)
	ctx := context.Background()
	c, err := CheckAudit(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.OK || c.Entries != 5 || *c.FirstSeq != 1 || *c.LastSeq != 5 || len(c.LastHash) != 32 {
		t.Fatalf("heile Kette: %+v", c)
	}
	// Inhalt geändert, Hash nicht neu berechnet
	rewrite(t, o, `UPDATE openwacht.audit_log SET details = '{"nr": 99}' WHERE chain_seq = 3`, false)
	c, err = CheckAudit(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if c.OK || c.BrokenSeq == nil || *c.BrokenSeq != 3 {
		t.Fatalf("Manipulation nicht erkannt: %+v", c)
	}
	// Der Bruch steht selbst im Audit-Log, und der Hinweis an den Betreiber entsteht.
	var n int
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'audit.kette_gebrochen' AND details->>'stelle' = '3'`).Scan(&n)
	if n != 1 {
		t.Errorf("Eintrag zum Bruch: %d", n)
	}
	s := auditServer(t, p, Config{})
	notices := s.selfNotices(ctx, time.Now())
	if !hasNotice(notices, "zentrale:audit", "crit") {
		t.Fatalf("kein Hinweis: %+v", notices)
	}
	// Eine vollständig neu berechnete Kette ist in sich heil: Das erkennt nur
	// der Vergleich mit einem Export (Befehl audit-pruefen -datei).
	rewrite(t, o, `SELECT 1`, true)
	if c, _ := CheckAudit(ctx, p); !c.OK {
		t.Fatalf("neu berechnete Kette: %+v", c)
	}
	if notices := s.selfNotices(ctx, time.Now()); hasNotice(notices, "zentrale:audit", "crit") {
		t.Error("Hinweis nach heiler Prüfung")
	}
	// Folgenummer übersprungen (Eintrag gelöscht)
	rewrite(t, o, `DELETE FROM openwacht.audit_log WHERE chain_seq = 2`, false)
	if c, _ := CheckAudit(ctx, p); c.OK || *c.BrokenSeq != 3 {
		t.Fatalf("Lücke nicht erkannt: %+v", c)
	}
}

func hasNotice(list []Notice, key, status string) bool {
	for _, n := range list {
		if n.Key == key && n.Status == status {
			return true
		}
	}
	return false
}

func auditServer(t *testing.T, p *pgxpool.Pool, cfg Config) *Server {
	t.Helper()
	cfg.BaseURL = mustURL("https://openwacht.example.com")
	s, err := New(cfg, p, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuditAufbewahrung(t *testing.T) {
	o, p, _ := auditDB(t, 6)
	ctx := context.Background()
	// Einträge 1–4 sind 400 Tage alt (Kette neu berechnet, damit sie heil bleibt).
	rewrite(t, o, `UPDATE openwacht.audit_log SET at = at - interval '400 days' WHERE chain_seq <= 4`, true)
	prune := func(days int, max *int64) (int64, error) {
		var n int64
		err := p.QueryRow(ctx, `SELECT openwacht.audit_prune($1, $2)`, days, max).Scan(&n)
		return n, err
	}
	if _, err := prune(30, nil); err == nil {
		t.Fatal("Aufbewahrung unter einem Jahr angenommen")
	}
	// nicht über den Stand des Exports hinaus
	two := int64(2)
	if n, err := prune(365, &two); err != nil || n != 2 {
		t.Fatalf("mit Grenze: %d %v", n, err)
	}
	var first int64
	var anchor []byte
	o.QueryRow(ctx, `SELECT first_seq, prev_hash FROM openwacht.audit_anchor`).Scan(&first, &anchor)
	if first != 3 || len(anchor) != 32 {
		t.Fatalf("Anker: %d %x", first, anchor)
	}
	if c, _ := CheckAudit(ctx, p); !c.OK {
		t.Fatalf("Kette nach dem Kürzen: %+v", c)
	}
	if n, err := prune(365, nil); err != nil || n != 2 {
		t.Fatalf("Rest: %d %v", n, err)
	}
	var seqs []int64
	rows, _ := o.Query(ctx, `SELECT chain_seq FROM openwacht.audit_log ORDER BY chain_seq`)
	seqs, _ = pgx.CollectRows(rows, pgx.RowTo[int64])
	// 5, 6, zwei Einträge „audit.gekuerzt“, ein Prüflauf ohne Bruch schreibt nichts
	if len(seqs) != 4 || seqs[0] != 5 {
		t.Fatalf("übrig: %v", seqs)
	}
	var cut int
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'audit.gekuerzt'`).Scan(&cut)
	if cut != 2 {
		t.Errorf("Anker-Einträge: %d", cut)
	}
	if c, _ := CheckAudit(ctx, p); !c.OK || *c.FirstSeq != 5 {
		t.Fatalf("Kette ab dem Anker: %+v", c)
	}
	// Anker gefälscht: fällt auf
	rewrite(t, o, `UPDATE openwacht.audit_anchor SET prev_hash = sha256('x')`, false)
	if c, _ := CheckAudit(ctx, p); c.OK {
		t.Fatal("falscher Anker nicht erkannt")
	}
	// gebrochene Kette: nichts wird gelöscht
	rewrite(t, o, `UPDATE openwacht.audit_log SET at = at - interval '800 days' WHERE chain_seq = 5`, false)
	if _, err := prune(365, nil); err == nil || !strings.Contains(err.Error(), "gebrochen") {
		t.Fatalf("Löschen trotz Bruch: %v", err)
	}
	// Die App-Rolle kann nicht selbst löschen, auch nicht mit der Einstellung.
	_, err := p.Exec(ctx, `SELECT set_config('openwacht.audit_prune', 'an', false); DELETE FROM openwacht.audit_log`)
	if err == nil {
		t.Fatal("App-Rolle darf löschen")
	}
}

// Sind alle Einträge alt, bleibt der jüngste stehen (die Kette endet nie leer).
func TestAuditAufbewahrungJuengsterBleibt(t *testing.T) {
	o, p, _ := auditDB(t, 3)
	ctx := context.Background()
	rewrite(t, o, `UPDATE openwacht.audit_log SET at = at - interval '400 days'`, true)
	var n int64
	if err := p.QueryRow(ctx, `SELECT openwacht.audit_prune(365, NULL)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("gelöscht: %d %v", n, err)
	}
	var left int
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'test.eintrag'`).Scan(&left)
	if left != 1 {
		t.Fatalf("übrig: %d", left)
	}
}

// Täglicher Lauf: nur fällig nach 24 Stunden; kürzt danach mit Grenze des Exports.
func TestAuditTaeglich(t *testing.T) {
	o, p, _ := auditDB(t, 3)
	ctx := context.Background()
	rewrite(t, o, `UPDATE openwacht.audit_log SET at = at - interval '400 days' WHERE chain_seq <= 2`, true)
	if _, err := o.Exec(ctx, `UPDATE openwacht.settings SET audit_days = 365`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := auditServer(t, p, Config{AuditFile: filepath.Join(dir, "audit.jsonl")})
	c, err := s.auditDaily(ctx)
	if err != nil || c == nil || !c.OK {
		t.Fatalf("erster Lauf: %+v %v", c, err)
	}
	var n int
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log`).Scan(&n)
	if n != 3 {
		t.Fatalf("ohne Export gelöscht: %d Einträge", n)
	}
	if c, err := s.auditDaily(ctx); c != nil || err != nil {
		t.Fatalf("zweiter Lauf am selben Tag: %+v %v", c, err)
	}
	if err := s.ExportAudit(ctx); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if c, err := s.auditDaily(ctx); c == nil || err != nil {
		t.Fatalf("Lauf nach 25 Stunden: %+v %v", c, err)
	}
	o.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'test.eintrag'`).Scan(&n)
	if n != 1 {
		t.Fatalf("nach Export und Lauf: %d Testeinträge", n)
	}
}

func readLines(t *testing.T, path string) []AuditLine {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []AuditLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l AuditLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("Zeile %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

func checkChain(t *testing.T, lines []AuditLine) {
	t.Helper()
	for i := 1; i < len(lines); i++ {
		if lines[i].Seq != lines[i-1].Seq+1 || lines[i].Prev == nil || *lines[i].Prev != lines[i-1].Hash {
			t.Fatalf("Zeile %d schließt nicht an: %+v nach %+v", i, lines[i], lines[i-1])
		}
	}
}

func TestAuditExportDatei(t *testing.T) {
	o, p, tenant := auditDB(t, 3)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := auditServer(t, p, Config{AuditFile: path})
	if err := s.ExportAudit(ctx); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 3 || lines[0].Seq != 1 || lines[0].Prev != nil || lines[0].Action != "test.eintrag" ||
		lines[0].Tenant == nil || *lines[0].Tenant != tenant || *lines[0].TenantName != "IT" || len(lines[2].Hash) != 64 {
		t.Fatalf("Zeilen: %+v", lines)
	}
	checkChain(t, lines)
	var hash []byte
	o.QueryRow(ctx, `SELECT hash FROM openwacht.audit_log WHERE chain_seq = 3`).Scan(&hash)
	if lines[2].Hash != hexOf(hash) {
		t.Error("Hash im Export weicht ab")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("Rechte %v", st.Mode().Perm())
	}
	// Neue Einträge: nur diese kommen dazu.
	o.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action) VALUES ($1, 'test.neu')`, tenant)
	if err := s.ExportAudit(ctx); err != nil {
		t.Fatal(err)
	}
	lines = readLines(t, path)
	if len(lines) != 4 || lines[3].Action != "test.neu" {
		t.Fatalf("nach dem zweiten Lauf: %d Zeilen", len(lines))
	}
	checkChain(t, lines)
	// Der Stand geht nie zurück (sonst doppelte Zeilen).
	p.Exec(ctx, `SELECT openwacht.audit_export_done('datei', 1, NULL)`)
	var cur int64
	p.QueryRow(ctx, `SELECT openwacht.audit_export_cursor('datei')`).Scan(&cur)
	if cur != 4 {
		t.Fatalf("Stand nach Rückschritt: %d", cur)
	}
	// Datei nicht schreibbar: Fehler, Stand bleibt; danach wird nachgeholt.
	s.cfg.AuditFile = filepath.Join(t.TempDir(), "fehlt", "audit.jsonl")
	o.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action) VALUES ($1, 'test.spaeter')`, tenant)
	if err := s.ExportAudit(ctx); err == nil {
		t.Fatal("Fehler nicht gemeldet")
	}
	if since, _ := s.auditExportFailure(); since.IsZero() {
		t.Error("Fehler nicht vermerkt")
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if !hasNotice(s.selfNotices(ctx, s.now()), "zentrale:audit-export", "warn") {
		t.Error("kein Hinweis nach einer Stunde Fehler")
	}
	s.cfg.AuditFile = path
	if err := s.ExportAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if lines = readLines(t, path); len(lines) != 5 || lines[4].Action != "test.spaeter" {
		t.Fatalf("nachgeholt: %d", len(lines))
	}
	if since, _ := s.auditExportFailure(); !since.IsZero() {
		t.Error("Fehler nicht zurückgesetzt")
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}

// syslogServer: TLS-Gegenstelle, liest Rahmen nach RFC 5425.
func syslogServer(t *testing.T) (addr string, caPEM []byte, got chan string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.test"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 100)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := bufio.NewReader(c)
				for {
					lenStr, err := rd.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(lenStr))
					if err != nil || n > 1<<20 {
						got <- "UNGUELTIG"
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(rd, buf); err != nil {
						return
					}
					got <- string(buf)
				}
			}()
		}
	}()
	return ln.Addr().String(), caPEM, got
}

func TestAuditExportSyslog(t *testing.T) {
	o, p, _ := auditDB(t, 2)
	ctx := context.Background()
	addr, ca, got := syslogServer(t)
	s := auditServer(t, p, Config{CheckNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AuditSyslog: &AuditSyslog{Addr: addr, CAPEM: ca, Source: "openwacht.example.com"}})
	if err := s.ExportAudit(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		select {
		case m := <-got:
			if !strings.HasPrefix(m, "<109>1 ") || !strings.Contains(m, " openwacht.example.com openwacht - audit - {") {
				t.Fatalf("Kopf: %q", m)
			}
			var l AuditLine
			if err := json.Unmarshal([]byte(m[strings.Index(m, "{"):]), &l); err != nil || l.Seq != int64(i) {
				t.Fatalf("Inhalt %d: %v %q", i, err, m)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Nachricht %d fehlt", i)
		}
	}
	// Ziel außerhalb der Netzfreigabe: keine Verbindung (Stand zurück, damit es etwas zu senden gibt).
	o.Exec(ctx, `DELETE FROM openwacht.audit_export_state`)
	s2 := auditServer(t, p, Config{CheckNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AuditSyslog: &AuditSyslog{Addr: addr, CAPEM: ca}})
	if err := s2.ExportAudit(ctx); err == nil || !strings.Contains(err.Error(), "freigegeben") && !strings.Contains(err.Error(), "nicht erlaubt") {
		t.Fatalf("außerhalb der Netzfreigabe: %v", err)
	}
	// Falsches Zertifikat (andere CA): abgelehnt.
	_, otherCA, _ := syslogServer(t)
	s3 := auditServer(t, p, Config{CheckNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AuditSyslog: &AuditSyslog{Addr: addr, CAPEM: otherCA}})
	if err := s3.ExportAudit(ctx); err == nil {
		t.Fatal("fremdes Zertifikat angenommen")
	}
	select {
	case m := <-got:
		t.Fatalf("Nachricht trotz Fehler: %q", m)
	default:
	}
}

// API: Admins sehen nur Einträge ihrer Mandanten (Teilbaum), Einträge ohne
// Mandant nur Admins des Hauptmandanten; Leser bekommen 403.
func TestAuditExportAPIMandanten(t *testing.T) {
	verwaltungSetup(t)
	ctx := context.Background()
	mark := "t31-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, tn := range []string{"IT", "Fertigung", "Lager Nord", "Organisation", ""} {
		var id *string
		if tn != "" {
			v := ids[tn]
			id = &v
		}
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details) VALUES ($1, 'test.export', $2)`,
			id, map[string]any{"mark": mark, "wo": tn}); err != nil {
			t.Fatal(err)
		}
	}
	seen := func(user, query string) (map[string]bool, response) {
		r := as(t, user).do("GET", "/api/v1/audit/export?anzahl=5000"+query, nil)
		out := map[string]bool{}
		if r.status != 200 {
			return out, r
		}
		if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
			t.Errorf("Content-Type %q", ct)
		}
		for _, line := range strings.Split(strings.TrimSpace(r.raw), "\n") {
			var l AuditLine
			if err := json.Unmarshal([]byte(line), &l); err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			var d map[string]string
			json.Unmarshal(l.Details, &d)
			if d["mark"] == mark {
				out[d["wo"]] = true
			}
		}
		return out, r
	}
	want := func(user, query string, expect ...string) {
		t.Helper()
		got, r := seen(user, query)
		expectStatus(t, user+query, r, 200)
		if len(got) != len(expect) {
			t.Errorf("%s%s sieht %v, erwartet %v", user, query, got, expect)
		}
		for _, e := range expect {
			if !got[e] {
				t.Errorf("%s%s sieht %q nicht (%v)", user, query, e, got)
			}
		}
	}
	want("v_it", "", "IT", "Fertigung", "Lager Nord", "Organisation", "")
	want("v_fw", "", "Fertigung", "Lager Nord")
	want("v_oa", "", "Organisation")
	want("v_it", "&mandant="+ids["Fertigung"], "Fertigung", "Lager Nord")
	want("v_fw", "&mandant="+ids["Lager Nord"], "Lager Nord")
	_, r := seen("v_fw", "&mandant="+ids["Organisation"])
	expectStatus(t, "Geschwister", r, 403)
	_, r = seen("v_fw", "&mandant="+ids["IT"])
	expectStatus(t, "Eltern", r, 403)
	_, r = seen("v_lz", "")
	expectStatus(t, "Leser", r, 403)
	_, r = seen("v_it", "&ab=-1")
	expectStatus(t, "ab negativ", r, 400)
	_, r = seen("v_it", "&mandant=kaputt")
	expectStatus(t, "Mandant ungültig", r, 400)
	// Blättern: ab der letzten Folgenummer
	r = as(t, "v_fw").do("GET", "/api/v1/audit/export?anzahl=1", nil)
	last := r.header.Get("X-OpenWacht-Letzte")
	if r.status != 200 || last == "" {
		t.Fatalf("Blättern: %d %q", r.status, last)
	}
	r2 := as(t, "v_fw").do("GET", "/api/v1/audit/export?anzahl=1&ab="+last, nil)
	var l AuditLine
	json.Unmarshal([]byte(strings.TrimSpace(r2.raw)), &l)
	if n, _ := strconv.ParseInt(last, 10, 64); l.Seq <= n {
		t.Fatalf("nächste Seite beginnt bei %d (ab %d)", l.Seq, n)
	}
	// Export ist im Audit vermerkt.
	var n int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.audit_log WHERE action = 'audit.exportiert' AND actor_user_id = $1`, ids["v_fw"]).Scan(&n)
	if n == 0 {
		t.Error("Export nicht vermerkt")
	}
	// Status nur für den Betreiber
	expectStatus(t, "Status ohne Betreiber", as(t, "v_it").do("GET", "/api/v1/einstellungen/audit", nil), 403)
	setOperator(t, "v_it", true)
	t.Cleanup(func() { setOperator(t, "v_it", false) })
	r = as(t, "v_it").do("GET", "/api/v1/einstellungen/audit", nil)
	expectStatus(t, "Status", r, 200)
	if _, ok := r.body["export"].([]any); !ok {
		t.Errorf("Status: %s", r.raw)
	}
}

// Aufbewahrung in den Installations-Einstellungen (nur Betreiber, auditiert).
func TestAuditAufbewahrungEinstellung(t *testing.T) {
	verwaltungSetup(t)
	resetSettings(t)
	setOperator(t, "v_it", true)
	t.Cleanup(func() {
		setOperator(t, "v_it", false)
		owner.Exec(context.Background(), `UPDATE openwacht.settings SET audit_days = NULL, timezone = NULL, backup_hour = NULL, backup_days = NULL`)
	})
	it := as(t, "v_it")
	base := map[string]any{"zeitzone": "Europe/Berlin", "sicherung": map[string]int{"uhr": 2, "tage": 14}}
	put := func(v any, set bool) response {
		b := map[string]any{}
		for k, x := range base {
			b[k] = x
		}
		if set {
			b["audit_tage"] = v
		}
		return it.do("PUT", "/api/v1/einstellungen/installation", b)
	}
	expectStatus(t, "zu kurz", put(30, true), 400)
	expectStatus(t, "zu lang", put(4000, true), 400)
	expectStatus(t, "730", put(730, true), 200)
	r := it.do("GET", "/api/v1/einstellungen/installation", nil)
	if r.body["audit_tage"] != float64(730) {
		t.Fatalf("gelesen: %v", r.body["audit_tage"])
	}
	expectStatus(t, "ohne Feld", put(nil, false), 200)
	if r := it.do("GET", "/api/v1/einstellungen/installation", nil); r.body["audit_tage"] != float64(730) {
		t.Fatalf("ohne Feld verändert: %v", r.body["audit_tage"])
	}
	expectStatus(t, "unbegrenzt", put(nil, true), 200)
	if r := it.do("GET", "/api/v1/einstellungen/installation", nil); r.body["audit_tage"] != nil {
		t.Fatalf("unbegrenzt: %v", r.body["audit_tage"])
	}
	var n int
	owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE action = 'audit.aufbewahrung' AND actor_user_id = $1`,
		ids["v_it"]).Scan(&n)
	if n != 2 {
		t.Errorf("Audit-Einträge: %d", n)
	}
	setOperator(t, "v_it", false)
	expectStatus(t, "ohne Betreiber", put(730, true), 403)
}
