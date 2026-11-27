// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/checks"
)

// --- API -----------------------------------------------------------------------

type checkIn struct {
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Aktiv     *bool           `json:"aktiv"`
	// Beim Ändern: anderes Gerät desselben Mandanten (leer = bleibt)
	GeraetID string `json:"geraet_id"`
	// Beim Anlegen: Name der Vorlage, aus der der Sensor stammt (nur Anzeige)
	Herkunft string `json:"herkunft"`
	// Fehlversuche bis zum Alarm (1.0.6): 1 bis 10, 0 = Standard der
	// Zentrale; fehlt das Feld beim Ändern, bleibt der Wert.
	Fehlversuche *int `json:"fehlversuche"`
}

// parseThreshold prüft „fehlversuche“; nil bleibt nil, 0 heißt Standard.
func parseThreshold(v *int) (*int, error) {
	if v == nil {
		return nil, nil
	}
	if *v < 0 || *v > maxFailThreshold {
		return nil, badRequest(fmt.Sprintf("Fehlversuche: 1 bis %d, 0 für den Standard.", maxFailThreshold))
	}
	n := *v
	return &n, nil
}

type checkOut struct {
	ID         string          `json:"id"`
	MandantID  string          `json:"mandant_id"`
	GeraetID   string          `json:"geraet_id"`
	Name       string          `json:"name"`
	Typ        string          `json:"typ"`
	Ziel       json.RawMessage `json:"ziel"`
	Intervall  int             `json:"intervall_sekunden"`
	Aktiv      bool            `json:"aktiv"`
	Status     *string         `json:"status"`
	Meldung    *string         `json:"meldung"`
	Messwert   *string         `json:"messwert"`
	Seit       *time.Time      `json:"seit"`
	Zuletzt    *time.Time      `json:"zuletzt"`
	FehlerFolg int             `json:"fehler_in_folge"`
	Naechste   time.Time       `json:"naechste"`
	Wartung    *wartungOut     `json:"wartung"`
	// Etappe 18: Herkunft (Vorlage) und ob der Agent den Sensor misst
	Herkunft *string `json:"herkunft"`
	AmAgent  bool    `json:"am_agent"`
	// Agent-Sensor ohne Ergebnis seit mehr als drei Intervallen
	Veraltet bool `json:"veraltet"`
	// 1.0.6: eigene Fehlversuche (nil = Standard) und die geltende Zahl
	Fehlversuche *int `json:"fehlversuche"`
	FehlGrenze   int  `json:"fehlversuche_gilt"`
}

func (s *Server) networksText() string {
	var n []string
	for _, p := range s.guard.Networks() {
		n = append(n, p.String())
	}
	if len(n) == 0 {
		return "keine"
	}
	return strings.Join(n, ", ")
}

// parseCheck prüft die Eingabe und liefert Name, Ziel (bereinigt), Intervall.
// Ist der Name leer, kommt der automatische Name aus Art und Ziel zurück und
// auto ist wahr; dann hängt der Aufrufer bei Bedarf eine Nummer an (freeName).
func (s *Server) parseCheck(in checkIn) (name string, target []byte, interval int, auto bool, err error) {
	if strings.TrimSpace(in.Name) != "" {
		if name, err = cleanName(in.Name); err != nil {
			return "", nil, 0, false, err
		}
	}
	if in.Intervall == 0 {
		in.Intervall = 300
	}
	if in.Intervall < 30 || in.Intervall > 86400 {
		return "", nil, 0, false, badRequest("Intervall: 30 Sekunden bis 1 Tag.")
	}
	if checks.IsAgentKind(in.Typ) && in.Intervall < 60 {
		return "", nil, 0, false, badRequest("Intervall: Sensoren auf dem Agent mindestens 60 Sekunden.")
	}
	if len(in.Ziel) == 0 {
		in.Ziel = json.RawMessage("{}")
	}
	spec, err := checks.Parse(in.Typ, in.Ziel)
	if err != nil {
		return "", nil, 0, false, badRequest(err.Error() + ".")
	}
	// Steht eine IP-Adresse direkt im Ziel, gleich sagen, ob sie erreichbar ist.
	for _, a := range spec.LiteralAddrs() {
		if !s.guard.Allowed(a) {
			return "", nil, 0, false, badRequest(fmt.Sprintf("Die Adresse %s ist für Sensoren der Zentrale nicht freigegeben. Freigegebene Netze: %s.",
				a, s.networksText()))
		}
	}
	if name == "" {
		name, auto = checks.DefaultName(in.Typ, spec), true
	}
	target, err = json.Marshal(spec)
	return name, target, in.Intervall, auto, err
}

// freeName: der automatische Name, mit Nummer, falls er am Gerät schon
// vergeben ist („Ping“, „Ping 2“, …). except: dieser Check zählt nicht mit
// (beim Ändern). Gleichzeitiges Anlegen fängt der eindeutige Index ab.
func freeName(ctx context.Context, tx pgx.Tx, device, base, except string) (string, error) {
	rows, err := tx.Query(ctx, `SELECT lower(name) FROM openwacht.checks
		WHERE device_id = $1 AND ($2 = '' OR id <> $2::uuid)`, device, except)
	if err != nil {
		return "", err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", err
	}
	taken := make(map[string]bool, len(names))
	for _, n := range names {
		taken[n] = true
	}
	for i := 1; i <= len(names)+1; i++ {
		if c := checks.NumberedName(base, i); !taken[strings.ToLower(c)] {
			return c, nil
		}
	}
	return "", &apiError{http.StatusConflict, "Kein freier Name gefunden, bitte einen Namen eingeben."}
}

// nameTaken übersetzt einen doppelten Namen am Gerät in eine klare Meldung.
func nameTaken(err error, name string) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "checks_device_name" {
		return &apiError{http.StatusConflict, "Am Gerät gibt es schon einen Sensor mit dem Namen „" + name +
			"“. Bitte einen anderen Namen wählen oder das Feld leer lassen, dann nummeriert OpenWacht selbst."}
	}
	return err
}

func (s *Server) handleCheckList(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("mandant")
	if filter != "" && !uuidPattern.MatchString(filter) {
		writeError(w, http.StatusBadRequest, "Ungültige ID.")
		return
	}
	s.handle(w, r, "checks", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		maint, err := visibleMaintenance(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT c.id::text, c.tenant_id::text, c.device_id::text, c.name, c.kind, c.target,
				c.interval_s, c.enabled, c.status, c.message, c.metric, c.since, c.last_run, c.fails, c.next_run, c.origin,
				openwacht.is_agent_kind(c.kind),
				openwacht.is_agent_kind(c.kind) AND c.enabled AND coalesce(c.last_run, c.created_at)
					< now() - make_interval(secs => 3 * c.interval_s + 120),
				c.fail_threshold
			FROM openwacht.checks c
			WHERE ($1 = '' OR c.tenant_id = $1::uuid) ORDER BY lower(c.name)`, filter)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (checkOut, error) {
			var c checkOut
			var target []byte
			err := row.Scan(&c.ID, &c.MandantID, &c.GeraetID, &c.Name, &c.Typ, &target, &c.Intervall, &c.Aktiv,
				&c.Status, &c.Meldung, &c.Messwert, &c.Seit, &c.Zuletzt, &c.FehlerFolg, &c.Naechste, &c.Herkunft,
				&c.AmAgent, &c.Veraltet, &c.Fehlversuche)
			c.Ziel = target
			c.FehlGrenze = s.threshold(c.Fehlversuche)
			c.Wartung = maint[alarmKeyCheck(c.ID)]
			return c, err
		})
		if list == nil {
			list = []checkOut{}
		}
		var nets []string
		for _, p := range s.guard.Networks() {
			nets = append(nets, p.String())
		}
		if nets == nil {
			nets = []string{}
		}
		return http.StatusOK, map[string]any{"checks": list, "netze": nets}, err
	})
}

// handleCheckCreate legt einen Check an einem Gerät an. Den Mandanten setzt
// die Datenbank aus dem Gerät (Migration 0012); ein Gerät, das der Aufrufer
// nicht sieht, gibt es für ihn nicht (404).
func (s *Server) handleCheckCreate(w http.ResponseWriter, r *http.Request) {
	device, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in checkIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "check anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, target, interval, auto, err := s.parseCheck(in)
		if err != nil {
			return 0, nil, err
		}
		threshold, err := parseThreshold(in.Fehlversuche)
		if err != nil {
			return 0, nil, err
		}
		enabled := in.Aktiv == nil || *in.Aktiv
		origin, err := cleanOrigin(in.Herkunft)
		if err != nil {
			return 0, nil, err
		}
		var x string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.devices WHERE id = $1`, device).Scan(&x); err != nil {
			return 0, nil, err // nicht sichtbar: 404
		}
		if err := requireAgentFor(ctx, tx, in.Typ, device); err != nil {
			return 0, nil, err
		}
		if auto {
			if name, err = freeName(ctx, tx, device, name, ""); err != nil {
				return 0, nil, err
			}
		}
		var id, tid string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s, enabled, origin, fail_threshold)
			VALUES ($1, $2, $3, $4, $5, $6, $7, nullif($8::smallint, 0)) RETURNING id::text, tenant_id::text`,
			device, name, in.Typ, target, interval, enabled, origin, threshold).
			Scan(&id, &tid); err != nil {
			return 0, nil, nameTaken(err, name) // Leser: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "check.angelegt", map[string]any{"id": id, "name": name, "typ": in.Typ,
			"geraet": device, "herkunft": origin, "fehlversuche": threshold}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id, "name": name}, nil
	})
}

func (s *Server) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in checkIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.GeraetID != "" && !uuidPattern.MatchString(in.GeraetID) {
		writeError(w, http.StatusBadRequest, "Ungültige Geräte-ID.")
		return
	}
	s.handle(w, r, "check ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, target, interval, auto, err := s.parseCheck(in)
		if err != nil {
			return 0, nil, err
		}
		threshold, err := parseThreshold(in.Fehlversuche)
		if err != nil {
			return 0, nil, err
		}
		enabled := in.Aktiv == nil || *in.Aktiv
		if in.GeraetID != "" {
			// Das neue Gerät muss sichtbar sein und zum Mandanten des Checks
			// gehören; Letzteres erzwingt auch der Fremdschlüssel.
			var same bool
			if err := tx.QueryRow(ctx, `SELECT d.tenant_id = c.tenant_id FROM openwacht.devices d, openwacht.checks c
				WHERE d.id = $1 AND c.id = $2`, in.GeraetID, id).Scan(&same); err != nil {
				return 0, nil, err
			}
			if !same {
				return 0, nil, &apiError{http.StatusConflict, "Ein Sensor kann nur zu einem Gerät desselben Mandanten wechseln."}
			}
		}
		dev := in.GeraetID
		if dev == "" {
			if err := tx.QueryRow(ctx, `SELECT device_id::text FROM openwacht.checks WHERE id = $1`, id).Scan(&dev); err != nil {
				return 0, nil, err
			}
		}
		if err := requireAgentFor(ctx, tx, in.Typ, dev); err != nil {
			return 0, nil, err
		}
		if auto {
			if name, err = freeName(ctx, tx, dev, name, id); err != nil {
				return 0, nil, err
			}
		}
		var tenant, device string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.checks SET name = $2, kind = $3, target = $4, interval_s = $5, enabled = $6,
				device_id = coalesce(nullif($7, '')::uuid, device_id),
				fail_threshold = CASE WHEN $8::smallint IS NULL THEN fail_threshold ELSE nullif($8::smallint, 0) END
			WHERE id = $1 RETURNING tenant_id::text, device_id::text`, id, name, in.Typ, target, interval, enabled, in.GeraetID, threshold).
			Scan(&tenant, &device); err != nil {
			return 0, nil, nameTaken(err, name)
		}
		if err := audit(ctx, tx, &tenant, "check.geaendert", map[string]any{"id": id, "name": name, "typ": in.Typ,
			"aktiv": enabled, "geraet": device, "fehlversuche": threshold}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleCheckDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "check löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.checks WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tenant, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tenant, "check.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleCheckDeleteOrigin: „Satz von diesem Gerät entfernen“ (0.99.2) löscht
// alle Sensoren eines Geräts mit derselben Herkunft (Name der Vorlage bzw. des
// Satzes) in einer Transaktion. Rechte über RLS wie beim einzelnen Löschen;
// sieht oder darf der Aufrufer nichts davon löschen, ist das Ergebnis 404.
func (s *Server) handleCheckDeleteOrigin(w http.ResponseWriter, r *http.Request) {
	device, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Herkunft string `json:"herkunft"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	origin, err := cleanOrigin(in.Herkunft)
	if err != nil || origin == nil {
		writeError(w, http.StatusBadRequest, "Herkunft fehlt oder ist ungültig.")
		return
	}
	s.handle(w, r, "checks einer herkunft löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `DELETE FROM openwacht.checks WHERE device_id = $1 AND origin = $2
			RETURNING id::text, tenant_id::text, name`, device, *origin)
		if err != nil {
			return 0, nil, err
		}
		type gone struct{ id, tenant, name string }
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gone, error) {
			var g gone
			err := row.Scan(&g.id, &g.tenant, &g.name)
			return g, err
		})
		if err != nil {
			return 0, nil, err
		}
		if len(list) == 0 {
			return 0, nil, errNotFound
		}
		ids, names := make([]string, len(list)), make([]string, len(list))
		for i, g := range list {
			ids[i], names[i] = g.id, g.name
		}
		if err := audit(ctx, tx, &list[0].tenant, "check.herkunft_geloescht", map[string]any{"geraet": device, "herkunft": *origin,
			"anzahl": len(list), "checks": ids[:min(len(ids), 100)], "namen": names[:min(len(names), 100)]}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"geloescht": len(list)}, nil
	})
}

// handleCheckNow: „Jetzt prüfen“, höchstens alle 10 Sekunden je Check.
func (s *Server) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "check jetzt", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var recent bool
		if err := tx.QueryRow(ctx, `SELECT coalesce(last_run > now() - interval '10 seconds', false)
			FROM openwacht.checks WHERE id = $1`, id).Scan(&recent); err != nil {
			return 0, nil, err
		}
		if recent {
			return 0, nil, &apiError{http.StatusTooManyRequests, "Gerade erst geprüft. Bitte einen Moment warten."}
		}
		var x string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.checks SET next_run = now() WHERE id = $1 AND enabled
			RETURNING id::text`, id).Scan(&x); err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, nil, nil
	})
}

// cleanOrigin: Herkunft aus einer Vorlage, nur Anzeige; leer = eigener Sensor.
func cleanOrigin(s string) (*string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if utf8.RuneCountInString(s) > 100 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, badRequest("Herkunft: höchstens 100 Zeichen, keine Steuerzeichen.")
	}
	return &s, nil
}

// requireAgentFor: Sensoren auf dem Agent nur an einem Gerät mit Agent. Die
// Datenbank prüft dasselbe noch einmal (Trigger checks_agent_device).
func requireAgentFor(ctx context.Context, tx pgx.Tx, kind, device string) error {
	if checks.IsSNMPKind(kind) {
		var has bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.snmp_sources
				WHERE device_id = $1 AND version IN ('1', '2c', '3'))`, device).Scan(&has); err != nil {
			return err
		}
		if !has {
			return &apiError{http.StatusConflict, "SNMP-Sensoren brauchen ein Gerät mit SNMP-Abfrage (nicht Proxmox)."}
		}
		return nil
	}
	if !checks.IsAgentKind(kind) {
		return nil
	}
	var has bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.agents
			WHERE device_id = $1 AND revoked_at IS NULL)`, device).Scan(&has); err != nil {
		return err
	}
	if !has {
		return &apiError{http.StatusConflict, "Sensoren auf dem Agent (Dienst, Prozess, Datei) brauchen ein Gerät mit Agent."}
	}
	return nil
}

// --- Planer ----------------------------------------------------------------------

type claimedCheck struct {
	id, kind, tenant string
	target           []byte
	revision         int
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// RunChecks führt fällige Checks aus, bis ctx endet. Höchstens
// CheckConcurrency gleichzeitig; wer fällig ist, bestimmt die Datenbank.
func (s *Server) RunChecks(ctx context.Context) {
	runPool(ctx, "Checks", s.cfg.CheckConcurrency, s.cfg.CheckPoll,
		func() { beat(&s.beats.checks, s.now()) }, s.claimChecks, s.runCheck)
}

func (s *Server) claimChecks(ctx context.Context, n int) ([]claimedCheck, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, kind, target, revision, tenant_id::text FROM openwacht.checks_claim($1)`, n)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (claimedCheck, error) {
		var c claimedCheck
		err := row.Scan(&c.id, &c.kind, &c.target, &c.revision, &c.tenant)
		return c, err
	})
}

func (s *Server) runCheck(ctx context.Context, c claimedCheck) {
	var res checks.Result
	// Auch gespeicherte Ziele erneut prüfen: Die Datenbank ist nicht die einzige Schutzschicht.
	spec, err := checks.Parse(c.kind, c.target)
	if err != nil {
		res = checks.Result{Status: checks.Unknown, Message: "Ziel ungültig: " + err.Error()}
	} else {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		res = s.runnerFor(c.tenant).Run(rctx, c.kind, spec)
		cancel()
	}
	if ctx.Err() != nil {
		return // Zentrale wird beendet; der Check bleibt reserviert und läuft danach wieder
	}
	var stored bool
	err = s.pool.QueryRow(context.WithoutCancel(ctx), `SELECT openwacht.check_record($1, $2, $3, $4, $5, $6)`,
		c.id, c.revision, res.Status, clipRunes(res.Message, 300), clipRunes(res.Metric, 50), latencyMs(res.Latency)).Scan(&stored)
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn("Checks: Ergebnis nicht gespeichert", "check", c.id, "fehler", err)
	}
}

// handleOriginKennfarbe (1.0.1): Kennfarbe für alle Sensoren einer Herkunft
// (Vorlage oder Vorlagensatz) setzen oder entfernen, an einem Gerät oder an
// allen Geräten, die der Aufrufer ändern darf (RLS wie beim einzelnen Sensor).
// Sensoren in Mandanten, zu denen die Kennfarbe nicht passt, bleiben, wie sie
// sind, und werden gezählt.
func (s *Server) handleOriginKennfarbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Herkunft  string  `json:"herkunft"`
		Kennfarbe *string `json:"kennfarbe_id"` // null = entfernen
		Geraet    string  `json:"geraet"`       // leer = alle Geräte
	}
	if !readJSON(w, r, &in) {
		return
	}
	origin, err := cleanOrigin(in.Herkunft)
	if err != nil || origin == nil {
		writeError(w, http.StatusBadRequest, "Herkunft fehlt oder ist ungültig.")
		return
	}
	if in.Kennfarbe != nil && !uuidPattern.MatchString(*in.Kennfarbe) {
		writeError(w, http.StatusBadRequest, "Kennfarbe unbekannt.")
		return
	}
	if in.Geraet != "" && !uuidPattern.MatchString(in.Geraet) {
		writeError(w, http.StatusBadRequest, "Gerät: ungültige ID.")
		return
	}
	s.handle(w, r, "kennfarbe einer herkunft", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if in.Kennfarbe != nil {
			var x string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.kennfarben WHERE id = $1`, *in.Kennfarbe).Scan(&x); err != nil {
				return 0, nil, err // nicht sichtbar: 404
			}
		}
		rows, err := tx.Query(ctx, `UPDATE openwacht.checks SET kennfarbe_id = $2::uuid
			WHERE origin = $1 AND ($3 = '' OR device_id = $3::uuid)
			  AND ($2::uuid IS NULL OR openwacht.kennfarbe_allowed($2::uuid, tenant_id))
			RETURNING id::text, tenant_id::text`, *origin, in.Kennfarbe, in.Geraet)
		if err != nil {
			return 0, nil, err // Leser: 42501 → 403
		}
		byTenant := map[string][]string{}
		n := 0
		for rows.Next() {
			var id, tid string
			if err := rows.Scan(&id, &tid); err != nil {
				rows.Close()
				return 0, nil, err
			}
			byTenant[tid] = append(byTenant[tid], id)
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, nil, err
		}
		var other int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.checks WHERE origin = $1 AND ($2 = '' OR device_id = $2::uuid)
			AND kennfarbe_id IS DISTINCT FROM $3::uuid`, *origin, in.Geraet, in.Kennfarbe).Scan(&other); err != nil {
			return 0, nil, err
		}
		if n == 0 && other == 0 {
			return 0, nil, errNotFound
		}
		for tid, ids := range byTenant {
			if err := audit(ctx, tx, &tid, "check.herkunft_kennfarbe", map[string]any{"herkunft": *origin, "kennfarbe": in.Kennfarbe,
				"geraet": in.Geraet, "anzahl": len(ids), "checks": ids[:min(len(ids), 100)]}); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusOK, map[string]any{"geaendert": n, "unveraendert": other}, nil
	})
}
