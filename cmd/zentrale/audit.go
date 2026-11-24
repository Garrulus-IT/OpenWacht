// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// cmdAuditCheck: Hash-Kette prüfen (wie der tägliche Lauf, Ergebnis wird
// gespeichert) und auf Wunsch einen Export vergleichen. Der Export ist der
// Anker außerhalb der Datenbank: Wer die Datenbank ändert und die Kette neu
// berechnet, fällt beim Vergleich mit einem älteren Export auf.
func cmdAuditCheck(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit-pruefen", flag.ContinueOnError)
	file := fs.String("datei", "", "Export (JSON-Zeilen von -audit-datei oder /api/v1/audit/export) mit der Kette vergleichen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	c, err := zentrale.CheckAudit(ctx, conn)
	if err != nil {
		return err
	}
	if c.FirstSeq != nil {
		fmt.Fprintf(out, "Einträge: %d (Folgenummer %d bis %d)\n", c.Entries, *c.FirstSeq, *c.LastSeq)
		fmt.Fprintf(out, "Letzter Hash: %s\n", hex.EncodeToString(c.LastHash))
	} else {
		fmt.Fprintln(out, "Das Audit-Log ist leer.")
	}
	var problems []string
	if !c.OK {
		problems = append(problems, fmt.Sprintf("Hash-Kette ab Eintrag %d gebrochen", *c.BrokenSeq))
	} else {
		fmt.Fprintln(out, "Hash-Kette in Ordnung.")
	}
	if *file != "" {
		n, diff, err := compareExport(ctx, conn, *file)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Export: %d Zeilen verglichen.\n", n)
		problems = append(problems, diff...)
		if len(diff) == 0 {
			fmt.Fprintln(out, "Export und Datenbank stimmen überein.")
		}
	}
	if len(problems) > 0 {
		for i, p := range problems {
			if i == 20 {
				fmt.Fprintf(out, "… und %d weitere\n", len(problems)-i)
				break
			}
			fmt.Fprintln(out, "ABWEICHUNG:", p)
		}
		return errors.New("Audit-Log nicht in Ordnung")
	}
	return nil
}

// compareExport liest die Datei zeilenweise: Jede Zeile muss an ihren
// Vorgänger in der Datei anschließen (vorher = Hash der vorigen Zeile, bei
// aufeinanderfolgenden Nummern) und, solange der Eintrag noch in der
// Datenbank steht, denselben Hash haben. Gelöschte Einträge (Aufbewahrung)
// prüft der Anker: Der erste vorhandene Eintrag muss an den letzten
// gelöschten anschließen.
func compareExport(ctx context.Context, conn *pgx.Conn, path string) (int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var diff []string
	var prev *zentrale.AuditLine
	n := 0
	for sc.Scan() {
		var l zentrale.AuditLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return n, nil, fmt.Errorf("Zeile %d: %w", n+1, err)
		}
		n++
		if prev != nil && l.Seq == prev.Seq+1 && (l.Prev == nil || *l.Prev != prev.Hash) {
			diff = append(diff, fmt.Sprintf("Export Zeile %d (Eintrag %d) schließt nicht an die vorige an", n, l.Seq))
		}
		var h []byte
		err := conn.QueryRow(ctx, `SELECT hash FROM openwacht.audit_log WHERE chain_seq = $1`, l.Seq).Scan(&h)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			var first *int64
			if err := conn.QueryRow(ctx, `SELECT first_seq FROM openwacht.audit_anchor`).Scan(&first); err != nil &&
				!errors.Is(err, pgx.ErrNoRows) {
				return n, nil, err
			}
			if first == nil || l.Seq >= *first {
				diff = append(diff, fmt.Sprintf("Eintrag %d fehlt in der Datenbank", l.Seq))
			}
		case err != nil:
			return n, nil, err
		case hex.EncodeToString(h) != l.Hash:
			diff = append(diff, fmt.Sprintf("Eintrag %d: Hash in der Datenbank weicht vom Export ab", l.Seq))
		}
		// Anker: letzter gelöschter Eintrag
		var anchorSeq *int64
		var anchorHash []byte
		if err := conn.QueryRow(ctx, `SELECT first_seq - 1, prev_hash FROM openwacht.audit_anchor`).Scan(&anchorSeq, &anchorHash); err == nil &&
			anchorSeq != nil && *anchorSeq == l.Seq && hex.EncodeToString(anchorHash) != l.Hash {
			diff = append(diff, fmt.Sprintf("Anker (Eintrag %d) weicht vom Export ab", l.Seq))
		}
		lc := l
		prev = &lc
	}
	return n, diff, sc.Err()
}
