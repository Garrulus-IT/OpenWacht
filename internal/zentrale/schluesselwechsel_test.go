// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/traps"
)

// Jede verschlüsselte Spalte im Schema muss in secretColumns stehen, sonst
// bliebe sie beim Schlüsselwechsel mit dem alten Schlüssel zurück.
func TestSchluesselwechselKenntAlleGeheimnisse(t *testing.T) {
	ctx := context.Background()
	rows, err := owner.Query(ctx, `SELECT c.table_name || '.' || c.column_name
		  FROM information_schema.columns c
		  JOIN information_schema.tables t USING (table_schema, table_name)
		 WHERE c.table_schema = 'openwacht' AND t.table_type = 'BASE TABLE' AND c.data_type = 'bytea'
		   AND c.column_name LIKE '%\_enc' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var known []string
	for _, c := range secretColumns {
		known = append(known, c.Table+"."+c.Column)
		// Spalten der Zusatzdaten gibt es wirklich.
		if _, err := owner.Exec(ctx, "SELECT "+strings.Join(c.Fields, ", ")+" FROM openwacht."+c.Table+" LIMIT 0"); err != nil {
			t.Errorf("%s.%s: %v", c.Table, c.Column, err)
		}
	}
	sort.Strings(known)
	if strings.Join(have, ",") != strings.Join(known, ",") {
		t.Fatalf("verschlüsselte Spalten im Schema:\n%v\nin secretColumns:\n%v", have, known)
	}
	if len(have) < 12 {
		t.Fatalf("nur %d Spalten gefunden", len(have))
	}
}

func keyServer(master []byte, pool *pgxpool.Pool) *Server {
	return &Server{key: master, boxKey: deriveKey(master, "openwacht secretbox v1"), trapKey: traps.DeriveKey(master),
		pool: pool, now: time.Now}
}

// sealV1Box: Geheimtext im Format bis 0.32 (ohne Kennzeichen).
func sealV1Box(t *testing.T, key, pt, aad []byte) []byte {
	t.Helper()
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	out := make([]byte, 1+g.NonceSize())
	out[0] = 1
	rand.Read(out[1:])
	return g.Seal(out, out[1:], pt, aad)
}

type rekeyFixture struct {
	tenant, user, devSNMP, devPVE, devVC, devFritz, devNetApp, devXen, srcSNMP, srcPVE, srcVC, srcFritz, srcNetApp, srcXen, profile, channel, smsChannel, dir string
}

func rekeySeed(t *testing.T, o *pgx.Conn, p *pgxpool.Pool, s *Server) rekeyFixture {
	t.Helper()
	ctx := context.Background()
	var f rekeyFixture
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(o.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ('IT') RETURNING id::text`).Scan(&f.tenant))
	must(o.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name) VALUES ($1, 'rk@example.com', 'RK') RETURNING id::text`, f.tenant).Scan(&f.user))
	// TOTP im alten Format (bis 0.32), damit beide Formate durchlaufen.
	_, err := o.Exec(ctx, `UPDATE openwacht.users SET totp_secret_enc = $2 WHERE id = $1`, f.user, sealV1Box(t, s.boxKey, []byte("totp-geheim"), []byte(f.user)))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.recovery_codes (user_id, code_hash) VALUES ($1, $2)`, f.user, bytes.Repeat([]byte{1}, 32))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.login_sources (user_id, source_hash) VALUES ($1, $2)`, f.user, bytes.Repeat([]byte{2}, 32))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.sessions (token_hash, user_id, idle, expires_at, kind) VALUES ($1, $2, '1 hour', now() + interval '1 hour', 'voll')`, bytes.Repeat([]byte{3}, 32), f.user)
	must(err)
	dev := func(name string) string {
		var id string
		must(o.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`, f.tenant, name).Scan(&id))
		return id
	}
	f.devSNMP, f.devPVE, f.devVC, f.devFritz, f.devNetApp, f.devXen = dev("sw-core01"), dev("pve-1"), dev("vc-1"), dev("fritz"), dev("aff"), dev("xs-pool")
	insertSrc := func(dev, version, host string, port int, seal func(id string) ([]byte, []byte)) string {
		var id string
		must(o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id))
		box, trap := seal(id)
		_, err := o.Exec(ctx, `INSERT INTO openwacht.snmp_sources (id, tenant_id, device_id, version, host, port, secret_enc, traps, trap_secret_enc)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, id, f.tenant, dev, version, host, port, box, trap != nil, trap)
		must(err)
		return id
	}
	f.srcSNMP = insertSrc(f.devSNMP, "2c", "10.10.0.2", 161, func(id string) ([]byte, []byte) {
		b, err := s.sealSNMP(id, f.tenant, "10.10.0.2", 161, snmpSecret{Community: "geheim-c"})
		must(err)
		tb, err := s.sealTrap(id, f.tenant, "10.10.0.2", 161, "2c", snmpSecret{Community: "geheim-c"})
		must(err)
		return b, tb
	})
	f.srcPVE = insertSrc(f.devPVE, "pve", "10.10.0.3", 8006, func(id string) ([]byte, []byte) {
		b, err := s.sealPVE(id, f.tenant, "10.10.0.3", 8006, "", "openwacht@pve!ow=12345678-1234-1234-1234-123456789abc")
		must(err)
		return b, nil
	})
	f.srcVC = insertSrc(f.devVC, "vcenter", "10.10.0.4", 443, func(id string) ([]byte, []byte) {
		b, err := s.sealVC(id, f.tenant, "10.10.0.4", 443, "", vcSecret{User: "leser", Password: "vc-geheim"})
		must(err)
		return b, nil
	})
	f.srcNetApp = insertSrc(f.devNetApp, "ontap", "10.10.0.5", 443, func(id string) ([]byte, []byte) {
		b, err := s.sealONTAP(id, f.tenant, "10.10.0.5", 443, ontapSecret{User: "leser", Password: "na-geheim", Pin: strings.Repeat("ab", 32)})
		must(err)
		return b, nil
	})
	f.srcXen = insertSrc(f.devXen, "xapi", "10.10.0.6", 443, func(id string) ([]byte, []byte) {
		b, err := s.sealXAPI(id, f.tenant, "10.10.0.6", 443, xapiSecret{User: "leser@beispiel.example", Password: "xs-geheim", Pin: strings.Repeat("cd", 32)})
		must(err)
		return b, nil
	})
	f.srcFritz = insertSrc(f.devFritz, "tr064", "10.10.0.1", 49000, func(id string) ([]byte, []byte) {
		b, err := s.sealFritz(id, f.tenant, "10.10.0.1", 49000, fritzSecret{User: "svc", Password: "fb-geheim"})
		must(err)
		return b, nil
	})
	must(o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&f.profile))
	pb, err := s.sealProfile(f.profile, f.tenant, "2c", snmpSecret{Community: "profil-c"})
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.snmp_profiles (id, tenant_id, name, version, secret_enc) VALUES ($1, $2, 'Standard', '2c', $3)`, f.profile, f.tenant, pb)
	must(err)
	must(o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&f.channel))
	tok, err := auth.Seal(s.boxKey, []byte("https://hooks.example.com/x"), channelAAD(f.channel, f.tenant, "https://hooks.example.com"))
	must(err)
	sec, err := auth.Seal(s.boxKey, []byte("whsec-geheim"), hookSecretAAD(f.channel, f.tenant))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, kind, server, token_enc, secret_enc)
		VALUES ($1, $2, 'Hook', 'webhook', 'https://hooks.example.com', $3, $4)`, f.channel, f.tenant, tok, sec)
	must(err)
	// SMS-Kanal (0.43.0): Passwort an Gateway, Benutzer und Fingerabdruck gebunden
	must(o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&f.smsChannel))
	sms, err := auth.Seal(s.boxKey, []byte("sms-geheim"), smsAAD(f.smsChannel, f.tenant, "https://sms.example.com", "ow-api", strings.Repeat("ef", 32)))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.alert_channels (id, tenant_id, name, kind, server, token_enc, sms_user, sms_pin, sms_target, sms_group)
		VALUES ($1, $2, 'SMS', 'sms', 'https://sms.example.com', $3, 'ow-api', $4, 'gruppe', 'Bereitschaft')`, f.smsChannel, f.tenant, sms, strings.Repeat("ef", 32))
	must(err)
	must(o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&f.dir))
	lp, err := auth.Seal(s.ldapKey(), []byte("ldap-geheim"), ldapAAD(f.dir, f.tenant, "ldaps://dc.example.com", "CN=svc,DC=example,DC=com"))
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.directories (id, tenant_id, name, url, bind_dn, base_dn, bind_pass_enc)
		VALUES ($1, $2, 'AD', 'ldaps://dc.example.com', 'CN=svc,DC=example,DC=com', 'DC=example,DC=com', $3)`, f.dir, f.tenant, lp)
	must(err)
	dm, err := s.sealDeadMan("https://hc.example.com/ping/x")
	must(err)
	sp, err := auth.Seal(s.smtpKey(), []byte("smtp-geheim"), smtpAAD("mail.example.com", "relay"))
	must(err)
	_, err = o.Exec(ctx, `UPDATE openwacht.settings SET deadman_enc = $1, smtp_host = 'mail.example.com', smtp_port = 587, smtp_tls = 'starttls',
		smtp_from = 'ow@example.com', smtp_user = 'relay', smtp_pass_enc = $2`, dm, sp)
	must(err)
	names := []string{"openwacht.example.com"}
	ca, err := pki.NewHTTPSCA(names, time.Now())
	must(err)
	m, _ := ca.HTTPSLeaf(names, time.Now())
	sm, err := sealMaterial(s.key, "eigene-ca", m, ca, names)
	must(err)
	_, err = o.Exec(ctx, `INSERT INTO openwacht.https_material (kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names) VALUES ($1, $2, $3, $4, $5, $6)`,
		sm.kind, sm.cert, sm.key, sm.caCert, sm.caKey, sm.names)
	must(err)
	must(s.InitAgentCA(ctx))
	return f
}

// rekeyOpenAll öffnet jedes Geheimnis mit dem Schlüssel von s.
func rekeyOpenAll(t *testing.T, o *pgx.Conn, p *pgxpool.Pool, s *Server, f rekeyFixture) error {
	t.Helper()
	ctx := context.Background()
	var errs []error
	add := func(what string, err error) {
		if err != nil {
			errs = append(errs, errors.New(what+": "+err.Error()))
		}
	}
	box := func(q string, args ...any) []byte {
		var b []byte
		if err := o.QueryRow(ctx, q, args...).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	pt, err := auth.Open(s.boxKey, box(`SELECT totp_secret_enc FROM openwacht.users WHERE id = $1`, f.user), []byte(f.user))
	if err == nil && string(pt) != "totp-geheim" {
		err = errors.New("Inhalt falsch")
	}
	add("totp", err)
	sec, err := s.openSNMP(f.srcSNMP, f.tenant, "10.10.0.2", 161, "2c", box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcSNMP))
	if err == nil && sec.Community != "geheim-c" {
		err = errors.New("Inhalt falsch")
	}
	add("snmp", err)
	_, err = traps.Open(s.trapKey, box(`SELECT trap_secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcSNMP), f.srcSNMP, f.tenant, "10.10.0.2", 161, "2c")
	add("trap", err)
	_, err = s.openPVE(f.srcPVE, f.tenant, "10.10.0.3", 8006, "", box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcPVE))
	add("pve", err)
	_, err = s.openVC(f.srcVC, f.tenant, "10.10.0.4", 443, "", box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcVC))
	add("vcenter", err)
	_, err = s.openFritz(f.srcFritz, f.tenant, "10.10.0.1", 49000, box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcFritz))
	add("fritz", err)
	_, err = s.openONTAP(f.srcNetApp, f.tenant, "10.10.0.5", 443, box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcNetApp))
	add("netapp", err)
	_, err = s.openXAPI(f.srcXen, f.tenant, "10.10.0.6", 443, box(`SELECT secret_enc FROM openwacht.snmp_sources WHERE id = $1`, f.srcXen))
	add("xenserver", err)
	_, err = s.openProfile(f.profile, f.tenant, "2c", box(`SELECT secret_enc FROM openwacht.snmp_profiles WHERE id = $1`, f.profile))
	add("profil", err)
	_, err = auth.Open(s.boxKey, box(`SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, f.channel), channelAAD(f.channel, f.tenant, "https://hooks.example.com"))
	add("kanal", err)
	_, err = auth.Open(s.boxKey, box(`SELECT secret_enc FROM openwacht.alert_channels WHERE id = $1`, f.channel), hookSecretAAD(f.channel, f.tenant))
	add("signatur", err)
	pt, err = auth.Open(s.boxKey, box(`SELECT token_enc FROM openwacht.alert_channels WHERE id = $1`, f.smsChannel),
		smsAAD(f.smsChannel, f.tenant, "https://sms.example.com", "ow-api", strings.Repeat("ef", 32)))
	if err == nil && string(pt) != "sms-geheim" {
		err = errors.New("Inhalt falsch")
	}
	add("sms", err)
	_, err = auth.Open(s.ldapKey(), box(`SELECT bind_pass_enc FROM openwacht.directories WHERE id = $1`, f.dir), ldapAAD(f.dir, f.tenant, "ldaps://dc.example.com", "CN=svc,DC=example,DC=com"))
	add("ldap", err)
	_, err = s.openDeadMan(box(`SELECT deadman_enc FROM openwacht.settings`))
	add("totmann", err)
	_, err = auth.Open(s.smtpKey(), box(`SELECT smtp_pass_enc FROM openwacht.settings`), smtpAAD("mail.example.com", "relay"))
	add("smtp", err)
	_, err = LoadHTTPS(ctx, p, s.key)
	add("https", err)
	add("agent-ca", CheckAgentCAKey(s.key, box(`SELECT key_enc FROM openwacht.agent_ca`)))
	return errors.Join(errs...)
}

func TestSchluesselWechseln(t *testing.T) {
	o, p := freshInstall(t)
	ctx := context.Background()
	oldKey := bytes.Repeat([]byte{11}, auth.KeySize)
	newKey := bytes.Repeat([]byte{12}, auth.KeySize)
	old, neu := keyServer(oldKey, p), keyServer(newKey, p)
	f := rekeySeed(t, o, p, old)
	if err := rekeyOpenAll(t, o, p, old, f); err != nil {
		t.Fatalf("vor dem Wechsel: %v", err)
	}

	// Gleicher Schlüssel: abgelehnt.
	tx, _ := o.Begin(ctx)
	if _, err := Rekey(ctx, tx, oldKey, oldKey); !errors.Is(err, ErrSameKey) {
		t.Errorf("gleicher Schlüssel: %v", err)
	}
	tx.Rollback(ctx)

	// Ein kaputtes Geheimnis: Abbruch, nichts geändert.
	var before []byte
	o.QueryRow(ctx, `SELECT secret_enc FROM openwacht.alert_channels WHERE id = $1`, f.channel).Scan(&before)
	bad := bytes.Clone(before)
	bad[len(bad)-1] ^= 1
	o.Exec(ctx, `UPDATE openwacht.alert_channels SET secret_enc = $2 WHERE id = $1`, f.channel, bad)
	tx, _ = o.Begin(ctx)
	_, err := Rekey(ctx, tx, oldKey, newKey)
	tx.Rollback(ctx)
	var re *RekeyError
	if !errors.As(err, &re) || len(re.Broken) != 1 || re.Broken[0] != "alert_channels.secret_enc "+f.channel {
		t.Fatalf("kaputtes Geheimnis: %v", err)
	}
	o.Exec(ctx, `UPDATE openwacht.alert_channels SET secret_enc = $2 WHERE id = $1`, f.channel, before)
	if err := rekeyOpenAll(t, o, p, old, f); err != nil {
		t.Fatalf("nach Abbruch: %v", err)
	}

	// Zentrale läuft (App-Verbindung offen): RekeyBusy meldet sie.
	pc, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := RekeyBusy(ctx, o); err != nil || n < 1 {
		t.Errorf("RekeyBusy mit offener App-Verbindung: %d %v", n, err)
	}
	pc.Release()
	p.Reset()

	tx, err = o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Rekey(ctx, tx, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rep.Total() != 18 || rep.V1 != 1 || rep.Sessions != 1 || rep.RecoveryUser != 1 || rep.Sources != 1 {
		t.Errorf("Bericht: %+v", rep)
	}
	if err := rekeyOpenAll(t, o, p, neu, f); err != nil {
		t.Fatalf("mit neuem Schlüssel: %v", err)
	}
	// Mit dem alten Schlüssel geht nichts mehr.
	if err := rekeyOpenAll(t, o, p, old, f); err == nil || strings.Count(err.Error(), "\n") < 13 {
		t.Fatalf("alter Schlüssel öffnet noch: %v", err)
	}
	// Alles im Format 2 mit dem Kennzeichen des neuen Schlüssels.
	var b []byte
	o.QueryRow(ctx, `SELECT totp_secret_enc FROM openwacht.users WHERE id = $1`, f.user).Scan(&b)
	if v, id := auth.BoxKeyID(b); v != 2 || !bytes.Equal(id, auth.KeyID(neu.boxKey)) {
		t.Errorf("TOTP danach: Version %d", v)
	}
	for _, q := range []string{`SELECT count(*) FROM openwacht.recovery_codes`, `SELECT count(*) FROM openwacht.login_sources`, `SELECT count(*) FROM openwacht.sessions`} {
		var n int
		o.QueryRow(ctx, q).Scan(&n)
		if n != 0 {
			t.Errorf("%s: %d", q, n)
		}
	}
	var details string
	if err := o.QueryRow(ctx, `SELECT details::text FROM openwacht.audit_log WHERE action = 'schluessel.gewechselt'`).Scan(&details); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !strings.Contains(details, `"geheimnisse": 18`) {
		t.Errorf("Audit: %s", details)
	}
	// Zweiter Lauf: alles schon neu, nichts zu tun.
	tx, _ = o.Begin(ctx)
	rep, err = Rekey(ctx, tx, oldKey, newKey)
	tx.Rollback(ctx)
	if err != nil || rep.Total() != 0 {
		t.Errorf("zweiter Lauf: %+v %v", rep, err)
	}
	// Die Zentrale mit dem neuen Schlüssel lädt die Agent-CA.
	if err := neu.InitAgentCA(ctx); err != nil {
		t.Fatal(err)
	}
	if err := keyServer(oldKey, p).InitAgentCA(ctx); err == nil {
		t.Error("Zentrale mit altem Schlüssel startet noch")
	}
}
