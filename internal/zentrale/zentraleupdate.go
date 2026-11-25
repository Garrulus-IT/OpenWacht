// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/update"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Update der Zentrale aus der Oberfläche (1.0.4, Entscheidung des Herausgebers:
// Upload im Browser). Der Webdienst wird dabei nie root: Er prüft das Paket
// (Signatur von SHA256SUMS mit dem Update-Schlüssel, Prüfsumme, Plattform,
// nur neuere Versionen) und legt es mit einem Auftrag in ZentraleUpdateDir
// ab. Den Rest macht der getrennte Dienst openwacht-zentrale-update (root),
// der dieselbe Prüfung mit den Schlüsseln seines eigenen Programms wiederholt
// und erst dann apt aufruft. Nur der Betreiber, mit frischem Zweitfaktor.

// Dateien in ZentraleUpdateDir; der Auftrag zuletzt (er startet den Dienst).
const (
	zuPaket     = "paket.deb"
	zuSummen    = "SHA256SUMS"
	zuSignatur  = "SHA256SUMS.sig"
	zuAuftrag   = "auftrag"
	zuInArbeit  = "in-arbeit" // der Installationsdienst arbeitet daran
	zuErgebnis  = "ergebnis.json"
	zuMaxKlein  = 64 << 10
	zuMaxGesamt = update.MaxZentralePaket + 1<<20
)

// ZentraleAuftrag: was der Installationsdienst installieren soll.
type ZentraleAuftrag struct {
	update.ZentralePaket
	Von  string    `json:"von"`
	Zeit time.Time `json:"zeit"`
}

// ZentraleErgebnis schreibt der Installationsdienst.
type ZentraleErgebnis struct {
	Zeit    time.Time `json:"zeit"`
	Version string    `json:"version"`
	OK      bool      `json:"ok"`
	Meldung string    `json:"meldung"`
	Ausgabe string    `json:"ausgabe,omitempty"`
}

func (s *Server) zentraleUpdateDir() string { return s.cfg.ZentraleUpdateDir }

// handleZentraleUpdateStand: aktuelle Version, ob eingerichtet, laufender Auftrag, letztes Ergebnis.
func (s *Server) handleZentraleUpdateStand(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "zentrale-update", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		dir := s.zentraleUpdateDir()
		out := map[string]any{"version": version.Version, "plattform": runtime.GOARCH, "eingerichtet": false, "laeuft": false}
		if dir == "" {
			return http.StatusOK, out, nil
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return http.StatusOK, out, nil
		}
		out["eingerichtet"] = true
		out["laeuft"] = updateLaeuft(dir)
		if b, err := readSmall(filepath.Join(dir, zuErgebnis), zuMaxKlein); err == nil {
			var e ZentraleErgebnis
			if json.Unmarshal(b, &e) == nil {
				out["ergebnis"] = e
			}
		}
		return http.StatusOK, out, nil
	})
}

// handleZentraleUpdateUpload: multipart mit paket (Datei), summen, signatur, code.
func (s *Server) handleZentraleUpdateUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dir := s.zentraleUpdateDir()
	if dir == "" {
		writeError(w, http.StatusConflict, "Das Update über die Oberfläche ist auf dieser Installation nicht eingerichtet (nur mit dem Debian-Paket).")
		return
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		writeError(w, http.StatusConflict, "Das Update über die Oberfläche ist auf dieser Installation nicht eingerichtet (nur mit dem Debian-Paket).")
		return
	}
	// Erst die Rolle, dann der große Rumpf.
	if err := s.withUser(ctx, sessionFrom(ctx).UserID, func(tx pgx.Tx) error { return requireOperator(ctx, tx) }); err != nil {
		writeDBError(w, "zentrale-update", err)
		return
	}
	if updateLaeuft(dir) {
		writeError(w, http.StatusConflict, "Es läuft schon ein Update. Bitte warten, bis es fertig ist.")
		return
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		writeError(w, http.StatusUnsupportedMediaType, "Erwartet wird multipart/form-data.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, zuMaxGesamt)
	mr := multipart.NewReader(r.Body, params["boundary"])
	tmp, err := os.CreateTemp(dir, ".paket-*")
	if err != nil {
		internalError(w, "zentrale-update", err)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	var datei, code string
	var summen, signatur []byte
	var sum string
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "Upload nicht lesbar oder zu groß.")
			return
		}
		switch p.FormName() {
		case "paket":
			if sum != "" {
				writeError(w, http.StatusBadRequest, "Nur ein Paket je Upload.")
				return
			}
			datei = filepath.Base(p.FileName())
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(p, update.MaxZentralePaket+1))
			if err != nil || n == 0 || n > update.MaxZentralePaket {
				writeError(w, http.StatusBadRequest, "Paket nicht lesbar, leer oder zu groß.")
				return
			}
			sum = hex.EncodeToString(h.Sum(nil))
		case "summen", "signatur", "code":
			b, err := io.ReadAll(io.LimitReader(p, zuMaxKlein+1))
			if err != nil || len(b) > zuMaxKlein {
				writeError(w, http.StatusBadRequest, "Feld "+p.FormName()+" zu groß.")
				return
			}
			switch p.FormName() {
			case "summen":
				summen = b
			case "signatur":
				signatur = b
			default:
				code = string(b)
			}
		default:
			writeError(w, http.StatusBadRequest, "Unbekanntes Feld im Upload.")
			return
		}
	}
	if sum == "" || len(summen) == 0 || len(signatur) == 0 {
		writeError(w, http.StatusBadRequest, "Bitte Paket (.deb), SHA256SUMS und SHA256SUMS.sig aus demselben Build hochladen.")
		return
	}
	if err := s.confirmCode(r, code); err != nil {
		writeDBError(w, "zentrale-update", err)
		return
	}
	var paket update.ZentralePaket
	var abgelehnt error
	err = s.withUser(ctx, sessionFrom(ctx).UserID, func(tx pgx.Tx) error {
		k, err := s.updateKeys(ctx, tx)
		if err != nil {
			return err
		}
		if k == nil || !k.Usable() {
			return &apiError{http.StatusConflict, "In diesem Build ist kein Update-Schlüssel eingetragen: Updates über die Oberfläche sind aus."}
		}
		paket, abgelehnt = k.PruefeZentrale(summen, signatur, datei, sum, version.Version, runtime.GOARCH)
		if abgelehnt != nil {
			return audit(ctx, tx, nil, "zentrale.update_abgelehnt", map[string]any{"datei": clipRunes(datei, 100), "grund": abgelehnt.Error()})
		}
		return audit(ctx, tx, nil, "zentrale.update_hochgeladen", map[string]any{"datei": paket.Datei, "version": paket.Version,
			"sha256": paket.SHA256})
	})
	if err == nil && abgelehnt != nil {
		err = badRequest(abgelehnt.Error())
	}
	if err != nil {
		writeDBError(w, "zentrale-update", err)
		return
	}
	if err := tmp.Sync(); err != nil {
		internalError(w, "zentrale-update", err)
		return
	}
	tmp.Close()
	auftrag, _ := json.Marshal(ZentraleAuftrag{ZentralePaket: paket, Von: sessionFrom(ctx).UserID, Zeit: s.now().UTC()})
	if err := firstErr(
		os.Rename(tmp.Name(), filepath.Join(dir, zuPaket)),
		writeAtomic(dir, zuSummen, summen),
		writeAtomic(dir, zuSignatur, signatur),
		os.Remove(filepath.Join(dir, zuErgebnis)),
		writeAtomic(dir, zuAuftrag, auftrag),
	); err != nil && !errors.Is(err, os.ErrNotExist) {
		internalError(w, "zentrale-update", err)
		return
	}
	slog.Info("Update der Zentrale hochgeladen", "version", paket.Version, "datei", paket.Datei)
	writeJSON(w, http.StatusAccepted, map[string]any{"version": paket.Version, "datei": paket.Datei})
}

// updateLaeuft: Auftrag liegt bereit oder wird gerade installiert.
func updateLaeuft(dir string) bool {
	for _, n := range []string{zuAuftrag, zuInArbeit} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			return true
		}
	}
	return false
}

// firstErr: erster Fehler außer „gibt es nicht“ (das alte Ergebnis darf fehlen).
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}

func writeAtomic(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("zu groß")
	}
	return b, nil
}
