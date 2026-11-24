// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/traps"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// cmdRekey: Hauptschlüssel wechseln (Etappe 32, M5). Alle Geheimnisse der
// Datenbank werden in einer Transaktion mit dem neuen Schlüssel neu
// verschlüsselt. Erst danach werden die Dateien getauscht; der alte Schlüssel
// bleibt als <datei>.alt-<zeit> liegen, weil ältere Sicherungen ihn brauchen.
func cmdRekey(ctx context.Context, args []string, out io.Writer) error {
	fl := flag.NewFlagSet("schluessel-wechseln", flag.ContinueOnError)
	keyFile := fl.String("schluessel", keyPath, "bisheriger Hauptschlüssel")
	newFile := fl.String("neu", "", "neuer Hauptschlüssel (Pflicht; vorher mit „openwacht-zentrale schluessel > datei“ erzeugen, Rechte 0600, im selben Ordner)")
	trapFile := fl.String("trap-schluessel", trapKeyPath, "Trap-Schlüssel, der neu abgeleitet wird (fehlt die Datei, wird sie übersprungen)")
	dry := fl.Bool("nur-pruefen", false, "alles prüfen und neu verschlüsseln, dann zurückrollen; nichts ändern")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *newFile == "" {
		return errors.New("-neu ist Pflicht")
	}
	oldKey, err := auth.LoadKeyFile(*keyFile)
	if err != nil {
		return fmt.Errorf("bisheriger Schlüssel: %w", err)
	}
	newKey, err := auth.LoadKeyFile(*newFile)
	if err != nil {
		return fmt.Errorf("neuer Schlüssel: %w", err)
	}
	if string(oldKey) == string(newKey) {
		return zentrale.ErrSameKey
	}
	oldAbs, _ := filepath.Abs(*keyFile)
	newAbs, _ := filepath.Abs(*newFile)
	if filepath.Dir(oldAbs) != filepath.Dir(newAbs) {
		return errors.New("der neue Schlüssel muss im selben Ordner liegen wie der bisherige (Umbenennen statt Kopieren)")
	}
	oldInfo, err := os.Stat(oldAbs)
	if err != nil {
		return err
	}
	st, ok := oldInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("Rechte des Schlüssels nicht lesbar")
	}
	// Trap-Schlüssel vorbereiten (neben die Datei, gleiche Rechte), bevor die
	// Datenbank etwas ändert: Was danach noch schiefgehen kann, ist nur Umbenennen.
	trapTmp := ""
	if *trapFile != "" {
		ti, err := os.Stat(*trapFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(out, "Kein Trap-Schlüssel unter %s: übersprungen.\n", *trapFile)
		case err != nil:
			return err
		default:
			tst, ok := ti.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("Rechte des Trap-Schlüssels nicht lesbar")
			}
			if !*dry {
				trapTmp = *trapFile + ".neu"
				os.Remove(trapTmp)
				tk := []byte(base64.StdEncoding.EncodeToString(traps.DeriveKey(newKey)) + "\n")
				if _, err := writeNew(trapTmp, tk, int(tst.Uid), int(tst.Gid), ti.Mode().Perm()); err != nil {
					return fmt.Errorf("Trap-Schlüssel vorbereiten: %w", err)
				}
				defer os.Remove(trapTmp) // nach dem Umbenennen wirkungslos
			}
		}
	}
	if !*dry {
		if err := os.Chown(newAbs, int(st.Uid), int(st.Gid)); err != nil {
			return fmt.Errorf("Besitzer des neuen Schlüssels setzen: %w", err)
		}
		if err := os.Chmod(newAbs, oldInfo.Mode().Perm()); err != nil {
			return err
		}
	}

	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	busy, err := zentrale.RekeyBusy(ctx, conn)
	if err != nil {
		return err
	}
	if busy > 0 {
		return fmt.Errorf("%d Verbindung(en) von Zentrale oder Trap-Dienst offen: erst „systemctl stop openwacht-zentrale.socket openwacht-zentrale openwacht-traps“", busy)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rep, err := zentrale.Rekey(ctx, tx, oldKey, newKey)
	var re *zentrale.RekeyError
	if errors.As(err, &re) {
		fmt.Fprintln(out, "Nicht entschlüsselbar (in der Oberfläche neu eingeben oder löschen, dann erneut aufrufen):")
		for _, b := range re.Broken {
			fmt.Fprintln(out, "  "+b)
		}
		return errors.New("Schlüsselwechsel abgebrochen, nichts geändert")
	}
	if err != nil {
		return err
	}
	for _, l := range rep.Lines() {
		fmt.Fprintln(out, "  "+l)
	}
	fmt.Fprintf(out, "%d Geheimnis(se) neu verschlüsselt (%d davon im alten Format).\n", rep.Total(), rep.V1)
	if *dry {
		fmt.Fprintln(out, "Nur geprüft: Alles ließ sich öffnen und neu verschlüsseln. Nichts geändert.")
		return nil
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Ab hier gilt in der Datenbank der neue Schlüssel.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	keep := oldAbs + ".alt-" + stamp
	steps := []struct{ from, to string }{{oldAbs, keep}, {newAbs, oldAbs}}
	if trapTmp != "" {
		steps = append(steps, struct{ from, to string }{trapTmp, *trapFile})
	}
	for i, s := range steps {
		if err := os.Rename(s.from, s.to); err != nil {
			fmt.Fprintln(out, "FEHLER: Die Datenbank nutzt schon den neuen Schlüssel, aber eine Datei ließ sich nicht umbenennen. Bitte von Hand:")
			for _, r := range steps[i:] {
				fmt.Fprintf(out, "  mv %s %s\n", r.from, r.to)
			}
			return err
		}
	}
	fmt.Fprintf(out, "Neuer Schlüssel aktiv (Kennzeichen %s): %s\n", hex.EncodeToString(auth.KeyID(newKey)), oldAbs)
	fmt.Fprintf(out, "Bisheriger Schlüssel aufbewahrt: %s (für ältere Sicherungen; getrennt sichern, nicht löschen)\n", keep)
	if trapTmp != "" {
		fmt.Fprintf(out, "Trap-Schlüssel neu abgeleitet: %s\n", *trapFile)
	}
	fmt.Fprintf(out, "%d Sitzung(en) beendet: Alle melden sich neu an.\n", rep.Sessions)
	if rep.RecoveryUser > 0 {
		fmt.Fprintf(out, "Wiederherstellungscodes von %d Konto/Konten verfallen: neue Codes in der Oberfläche erzeugen (Seitenleiste › Zwei-Faktor).\n", rep.RecoveryUser)
	}
	fmt.Fprintln(out, "Jetzt starten: systemctl start openwacht-zentrale.socket openwacht-traps")
	fmt.Fprintln(out, "Danach eine Sicherung anlegen (openwacht-zentrale sichern -jetzt); sie gehört zum neuen Schlüssel.")
	return nil
}
