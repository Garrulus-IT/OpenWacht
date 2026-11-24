// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/traps"
)

// Wechsel des Hauptschlüssels (Etappe 32, Befund M5).
//
// Jedes Geheimnis in der Datenbank ist mit einem aus dem Hauptschlüssel
// abgeleiteten Schlüssel und eigenen Zusatzdaten (AAD) verschlüsselt. Die
// Liste secretColumns beschreibt jede Spalte: woraus der Schlüssel abgeleitet
// wird und wie die Zusatzdaten aus der Zeile entstehen. Ein Test prüft, dass
// jede bytea-Spalte mit der Endung _enc hier steht; eine neue verschlüsselte
// Spalte ohne Eintrag lässt die Tests scheitern.

// secretColumn: eine verschlüsselte Spalte.
type secretColumn struct {
	Table, Column string
	// Fields: weitere Spalten (als Text, NULL = ""), die für Schlüssel oder
	// AAD nötig sind. Die erste ist immer der Primärschlüssel.
	Fields []string
	// Key leitet den Schlüssel aus dem Hauptschlüssel ab (f = Fields).
	Key func(master []byte, f []string) []byte
	// AAD baut die Zusatzdaten (f = Fields).
	AAD func(f []string) []byte
}

func boxKeyOf(master []byte) []byte { return deriveKey(master, "openwacht secretbox v1") }

func fixedKey(k func([]byte) []byte) func([]byte, []string) []byte {
	return func(m []byte, _ []string) []byte { return k(m) }
}

func fixedAAD(b []byte) func([]string) []byte { return func([]string) []byte { return b } }

func atoiOr0(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// snmpSourceAAD: Die Spalte secret_enc einer Abfragequelle hängt an der Art
// (SNMP, Proxmox, vCenter, FRITZ!Box); alle nutzen den Secretbox-Schlüssel.
func snmpSourceAAD(f []string) []byte {
	id, tenant, version, host, port, ca := f[0], f[1], f[2], f[3], atoiOr0(f[4]), f[5]
	switch version {
	case "pve":
		return pveAAD(id, tenant, host, port, ca)
	case "vcenter":
		return vcAAD(id, tenant, host, port, ca)
	case "tr064":
		return fritzAAD(id, tenant, host, port)
	case "ontap":
		return ontapAAD(id, tenant, host, port)
	case "xapi":
		return xapiAAD(id, tenant, host, port)
	}
	return snmpAAD(id, tenant, host, port)
}

var secretColumns = []secretColumn{
	{Table: "users", Column: "totp_secret_enc", Fields: []string{"id"},
		Key: fixedKey(boxKeyOf), AAD: func(f []string) []byte { return []byte(f[0]) }},
	{Table: "agent_ca", Column: "key_enc", Fields: []string{"id"},
		Key: fixedKey(func(m []byte) []byte { return deriveKey(m, "openwacht agent-ca v1") }), AAD: fixedAAD([]byte("agent-ca"))},
	{Table: "alert_channels", Column: "token_enc", Fields: []string{"id", "tenant_id", "server", "kind", "sms_user", "sms_pin"},
		Key: fixedKey(boxKeyOf), AAD: channelTokenAAD},
	{Table: "alert_channels", Column: "secret_enc", Fields: []string{"id", "tenant_id"},
		Key: fixedKey(boxKeyOf), AAD: func(f []string) []byte { return hookSecretAAD(f[0], f[1]) }},
	{Table: "directories", Column: "bind_pass_enc", Fields: []string{"id", "tenant_id", "url", "bind_dn"},
		Key: fixedKey(func(m []byte) []byte { return deriveKey(boxKeyOf(m), "openwacht ldap v1") }),
		AAD: func(f []string) []byte { return ldapAAD(f[0], f[1], f[2], f[3]) }},
	{Table: "https_material", Column: "key_enc", Fields: []string{"id"},
		Key: fixedKey(httpsKey), AAD: fixedAAD(httpsLeafAAD)},
	{Table: "https_material", Column: "ca_key_enc", Fields: []string{"id"},
		Key: fixedKey(httpsKey), AAD: fixedAAD(httpsCAAAD)},
	{Table: "settings", Column: "deadman_enc", Fields: []string{"id"},
		Key: fixedKey(func(m []byte) []byte { return deriveKey(boxKeyOf(m), "openwacht totmann v1") }), AAD: fixedAAD(deadManAAD)},
	{Table: "settings", Column: "smtp_pass_enc", Fields: []string{"id", "smtp_host", "smtp_user"},
		Key: fixedKey(func(m []byte) []byte { return deriveKey(boxKeyOf(m), "openwacht smtp v1") }),
		AAD: func(f []string) []byte { return smtpAAD(f[1], f[2]) }},
	{Table: "snmp_profiles", Column: "secret_enc", Fields: []string{"id", "tenant_id", "version"},
		Key: fixedKey(boxKeyOf), AAD: func(f []string) []byte { return snmpProfileAAD(f[0], f[1], f[2]) }},
	{Table: "snmp_sources", Column: "secret_enc", Fields: []string{"id", "tenant_id", "version", "host", "port", "ca_pem"},
		Key: fixedKey(boxKeyOf), AAD: snmpSourceAAD},
	{Table: "snmp_sources", Column: "trap_secret_enc", Fields: []string{"id", "tenant_id", "version", "host", "port"},
		Key: fixedKey(traps.DeriveKey),
		AAD: func(f []string) []byte { return traps.AAD(f[0], f[1], f[3], atoiOr0(f[4]), f[2]) }},
}

// RekeyReport: Ergebnis eines Schlüsselwechsels.
type RekeyReport struct {
	Secrets      map[string]int // „Tabelle.Spalte“ → neu verschlüsselt
	V1           int            // davon im alten Format ohne Kennzeichen
	Sessions     int            // beendete Sitzungen
	RecoveryUser int            // Konten, deren Wiederherstellungscodes verfallen
	Sources      int            // zurückgesetzte Anmeldequellen (Sperren, Wartezeiten)
}

// Total: Zahl aller neu verschlüsselten Geheimnisse.
func (r RekeyReport) Total() int {
	n := 0
	for _, v := range r.Secrets {
		n += v
	}
	return n
}

// Lines: Bericht für die Shell, sortiert.
func (r RekeyReport) Lines() []string {
	keys := make([]string, 0, len(r.Secrets))
	for k := range r.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%-32s %d", k, r.Secrets[k]))
	}
	return out
}

// RekeyError: Geheimnisse, die sich mit dem alten Schlüssel nicht öffnen ließen.
type RekeyError struct{ Broken []string }

func (e *RekeyError) Error() string {
	return fmt.Sprintf("%d Geheimnis(se) lassen sich mit dem bisherigen Schlüssel nicht entschlüsseln (nichts geändert): %v", len(e.Broken), e.Broken)
}

// ErrSameKey: alter und neuer Schlüssel sind gleich.
var ErrSameKey = errors.New("der neue Schlüssel ist derselbe wie der bisherige")

// Rekey verschlüsselt alle Geheimnisse in tx (Eigentümer der Datenbank) mit
// dem neuen Hauptschlüssel neu. Lässt sich ein Geheimnis nicht öffnen, bricht
// Rekey ab, ohne etwas zu ändern (der Aufrufer rollt tx zurück); Geheimnisse,
// die schon mit dem neuen Schlüssel verschlüsselt sind, bleiben unverändert.
// Was nur als HMAC mit einem abgeleiteten Schlüssel vorliegt, lässt sich
// nicht umrechnen: Wiederherstellungscodes verfallen, Anmeldequellen und
// Sitzungen werden gelöscht.
func Rekey(ctx context.Context, tx pgx.Tx, oldMaster, newMaster []byte) (RekeyReport, error) {
	rep := RekeyReport{Secrets: map[string]int{}}
	if len(oldMaster) != auth.KeySize || len(newMaster) != auth.KeySize {
		return rep, errors.New("Schlüssel ungültig")
	}
	if string(oldMaster) == string(newMaster) {
		return rep, ErrSameKey
	}
	tables := map[string]bool{}
	for _, c := range secretColumns {
		tables[c.Table] = true
	}
	names := make([]string, 0, len(tables)+3)
	for t := range tables {
		names = append(names, "openwacht."+t)
	}
	sort.Strings(names)
	names = append(names, "openwacht.sessions", "openwacht.recovery_codes", "openwacht.login_sources")
	// Niemand schreibt dazwischen (die Zentrale soll ohnehin gestoppt sein).
	if _, err := tx.Exec(ctx, "LOCK TABLE "+joinComma(names)+" IN EXCLUSIVE MODE"); err != nil {
		return rep, fmt.Errorf("Tabellen sperren: %w", err)
	}
	type change struct {
		col *secretColumn
		id  string
		box []byte
	}
	var changes []change
	var broken []string
	for i := range secretColumns {
		c := &secretColumns[i]
		q := "SELECT "
		for _, f := range c.Fields {
			q += "coalesce(" + f + "::text, ''), "
		}
		q += c.Column + " FROM openwacht." + c.Table + " WHERE " + c.Column + " IS NOT NULL ORDER BY 1"
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return rep, fmt.Errorf("%s.%s lesen: %w", c.Table, c.Column, err)
		}
		for rows.Next() {
			f := make([]string, len(c.Fields))
			dest := make([]any, 0, len(f)+1)
			for j := range f {
				dest = append(dest, &f[j])
			}
			var box []byte
			dest = append(dest, &box)
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return rep, err
			}
			aad := c.AAD(f)
			newKey := c.Key(newMaster, f)
			if _, err := auth.Open(newKey, box, aad); err == nil {
				continue // schon neu (z. B. zweiter Lauf)
			}
			pt, err := auth.Open(c.Key(oldMaster, f), box, aad)
			if err != nil {
				broken = append(broken, c.Table+"."+c.Column+" "+f[0])
				continue
			}
			if v, _ := auth.BoxKeyID(box); v == 1 {
				rep.V1++
			}
			nb, err := auth.Seal(newKey, pt, aad)
			if err != nil {
				rows.Close()
				return rep, err
			}
			changes = append(changes, change{col: c, id: f[0], box: nb})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return rep, err
		}
	}
	if len(broken) > 0 {
		return rep, &RekeyError{Broken: broken}
	}
	for _, ch := range changes {
		tag, err := tx.Exec(ctx, "UPDATE openwacht."+ch.col.Table+" SET "+ch.col.Column+" = $2 WHERE "+ch.col.Fields[0]+"::text = $1", ch.id, ch.box)
		if err != nil {
			return rep, fmt.Errorf("%s.%s schreiben: %w", ch.col.Table, ch.col.Column, err)
		}
		if tag.RowsAffected() != 1 {
			return rep, fmt.Errorf("%s.%s %s: %d Zeilen geändert", ch.col.Table, ch.col.Column, ch.id, tag.RowsAffected())
		}
		rep.Secrets[ch.col.Table+"."+ch.col.Column]++
	}
	if err := tx.QueryRow(ctx, `SELECT count(DISTINCT user_id) FROM openwacht.recovery_codes`).Scan(&rep.RecoveryUser); err != nil {
		return rep, err
	}
	for _, d := range []struct {
		q string
		n *int
	}{
		{`DELETE FROM openwacht.recovery_codes`, nil},
		{`DELETE FROM openwacht.login_sources`, &rep.Sources},
		{`DELETE FROM openwacht.sessions`, &rep.Sessions},
	} {
		tag, err := tx.Exec(ctx, d.q)
		if err != nil {
			return rep, err
		}
		if d.n != nil {
			*d.n = int(tag.RowsAffected())
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details)
		SELECT t.id, 'schluessel.gewechselt', jsonb_build_object('quelle', 'shell', 'geheimnisse', $1::int,
		       'altes_format', $2::int, 'sitzungen', $3::int, 'codes_verfallen', $4::int,
		       'kennzeichen', encode($5::bytea, 'hex'))
		  FROM openwacht.tenants t WHERE t.parent_id IS NULL`,
		rep.Total(), rep.V1, rep.Sessions, rep.RecoveryUser, auth.KeyID(newMaster)); err != nil {
		return rep, fmt.Errorf("Audit: %w", err)
	}
	return rep, nil
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// RekeyBusy zählt fremde Verbindungen der Rollen von Zentrale und
// Trap-Dienst: Solange eine läuft, schreibt sie Geheimnisse mit dem alten
// Schlüssel und der Wechsel wäre nicht vollständig.
func RekeyBusy(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity a
		 WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() AND a.usesysid IS NOT NULL
		   AND (pg_has_role(a.usesysid, 'openwacht_app', 'MEMBER') OR pg_has_role(a.usesysid, 'openwacht_traps', 'MEMBER'))`).Scan(&n)
	return n, err
}
