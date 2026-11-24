// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// cmdAgentCA zeigt die Agent-CAs oder führt einen Schritt des Wechsels aus
// (Etappe 32). Ohne Option nur anzeigen.
func cmdAgentCA(ctx context.Context, args []string, out io.Writer) error {
	fl := flag.NewFlagSet("agent-ca", flag.ContinueOnError)
	neu := fl.Bool("neu", false, "Schritt 1: neue CA neben der aktiven anlegen (braucht -schluessel)")
	umstellen := fl.Bool("umstellen", false, "Schritt 2: neue CA aktiv setzen, sobald alle Agents sie kennen")
	entfernen := fl.Bool("alte-entfernen", false, "Schritt 3: alte CA entfernen, sobald kein Agent mehr ein Zertifikat von ihr hat")
	trotzdem := fl.Bool("trotzdem", false, "Schritt 2 oder 3 auch ausführen, wenn noch Agents fehlen (diese müssen neu registriert werden)")
	keyFile := fl.String("schluessel", "/etc/openwacht/schluessel", "Hauptschlüssel (nur für -neu)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	steps := 0
	for _, b := range []bool{*neu, *umstellen, *entfernen} {
		if b {
			steps++
		}
	}
	if steps > 1 {
		return errors.New("nur einen Schritt auf einmal")
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if steps == 1 {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		switch {
		case *neu:
			key, err := auth.LoadKeyFile(*keyFile)
			if err != nil {
				return err
			}
			info, err := zentrale.AgentCANew(ctx, tx, key, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Neue Agent-CA angelegt: %s (gültig bis %s)\n", info.Fingerprint, info.NotAfter.Format("02.01.2006"))
		case *umstellen:
			if err := zentrale.AgentCASwitch(ctx, tx, *trotzdem); err != nil {
				return err
			}
			fmt.Fprintln(out, "Neue Agent-CA ist aktiv. Registrierungs-Token und Einzeiler neu erzeugen (sie enthalten den Fingerabdruck der CA).")
		case *entfernen:
			if err := zentrale.AgentCARemoveOld(ctx, tx, *trotzdem); err != nil {
				return err
			}
			fmt.Fprintln(out, "Alte Agent-CA entfernt.")
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "Jetzt die Zentrale neu starten: systemctl restart openwacht-zentrale")
		fmt.Fprintln(out)
	}
	st, err := zentrale.AgentCAStatusOwner(ctx, conn)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Agents (in den letzten 30 Tagen gemeldet): %d, ohne Meldung: %d\n", st.Agents, st.Stale)
	for _, c := range st.CAs {
		fmt.Fprintf(out, "  %-6s %s  %s  gültig bis %s  kennen sie: %d  Zertifikat von ihr: %d\n",
			c.State, c.Fingerprint, c.Subject, c.NotAfter.Format("02.01.2006"), c.Known, c.Issued)
	}
	return nil
}
