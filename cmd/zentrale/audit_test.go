// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/db"
	"github.com/garrulus-it/openwacht/internal/dbtest"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// audit-pruefen: Eine neu berechnete (in sich heile) Kette fällt erst beim
// Vergleich mit einem älteren Export auf.
func TestAuditPruefenMitExport(t *testing.T) {
	ctx := context.Background()
	tdb, err := dbtest.New(ctx)
	if errors.Is(err, dbtest.ErrSkip) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	owner, err := pgx.ConnectConfig(ctx, tdb.OwnerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err := db.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.audit_log (action, details) VALUES ('test.eintrag', $1)`,
			map[string]any{"nr": i}); err != nil {
			t.Fatal(err)
		}
	}
	// Export wie -audit-datei
	rows, _ := owner.Query(ctx, `SELECT chain_seq, prev_hash, hash, action FROM openwacht.audit_log ORDER BY chain_seq`)
	var buf bytes.Buffer
	for rows.Next() {
		var l zentrale.AuditLine
		var prev, hash []byte
		rows.Scan(&l.Seq, &prev, &hash, &l.Action)
		if prev != nil {
			p := hex.EncodeToString(prev)
			l.Prev = &p
		}
		l.Hash = hex.EncodeToString(hash)
		l.Details = json.RawMessage(`{}`)
		b, _ := json.Marshal(l)
		buf.Write(append(b, '\n'))
	}
	rows.Close()
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(file, buf.Bytes(), 0o600)
	oc := tdb.OwnerCfg
	t.Setenv("OPENWACHT_DB_EIGENTUEMER", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		oc.Host, oc.Port, oc.User, oc.Password, oc.Database))

	var out bytes.Buffer
	if err := cmdAuditCheck(ctx, []string{"-datei", file}, &out); err != nil {
		t.Fatalf("heil: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "stimmen überein") || !strings.Contains(out.String(), "4 Zeilen") {
		t.Fatalf("Ausgabe: %s", out.String())
	}
	// Eintrag 2 geändert und die Kette neu berechnet
	for _, q := range []string{
		`ALTER TABLE openwacht.audit_log DISABLE TRIGGER audit_no_update`,
		`UPDATE openwacht.audit_log SET details = '{"nr": 42}' WHERE chain_seq = 2`,
		`DO $$ DECLARE e openwacht.audit_log; prev bytea := NULL; BEGIN
			FOR e IN SELECT * FROM openwacht.audit_log ORDER BY chain_seq LOOP
				e.prev_hash := prev;
				UPDATE openwacht.audit_log SET prev_hash = prev, hash = openwacht.audit_entry_hash(e) WHERE chain_seq = e.chain_seq;
				prev := openwacht.audit_entry_hash(e);
			END LOOP; END $$`,
		`ALTER TABLE openwacht.audit_log ENABLE TRIGGER audit_no_update`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := cmdAuditCheck(ctx, nil, &out); err != nil {
		t.Fatalf("ohne Export sieht die Kette heil aus: %v", err)
	}
	out.Reset()
	err = cmdAuditCheck(ctx, []string{"-datei", file}, &out)
	if err == nil || !strings.Contains(out.String(), "Eintrag 2: Hash in der Datenbank weicht vom Export ab") {
		t.Fatalf("Manipulation nicht erkannt: %v\n%s", err, out.String())
	}
	// Export selbst unterbrochen (Zeile entfernt und eine verändert)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	broken := strings.Replace(lines[2], `"hash":"`, `"hash":"00`, 1)
	os.WriteFile(file, []byte(lines[0]+"\n"+lines[1]+"\n"+broken[:len(broken)-3]+`"}`+"\n"+lines[3]+"\n"), 0o600)
	out.Reset()
	if err := cmdAuditCheck(ctx, []string{"-datei", file}, &out); err == nil || !strings.Contains(out.String(), "schließt nicht an") {
		t.Fatalf("unterbrochener Export: %v\n%s", err, out.String())
	}
}
