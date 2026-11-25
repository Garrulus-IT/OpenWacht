// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// CSV-Import von Geräten (Etappe 27): Spalten name;adresse;gruppe;profil;vorlage,
// Kopfzeile Pflicht, Trennzeichen ; oder , (aus der Kopfzeile erkannt),
// höchstens 500 Zeilen.
//
// Vorschau und Anlegen laufen durch denselben Code in einer Transaktion: Jede
// Zeile bekommt einen Sicherungspunkt, damit ein Fehler die übrigen Zeilen
// nicht verdeckt. Bei der Vorschau und bei jedem Fehler wird am Ende alles
// zurückgerollt: ein Fehler, und nichts wird angelegt. Rechte und Mandant
// prüft die Datenbank wie beim Anlegen einzelner Geräte (RLS, Trigger).
//
// Entscheidungen (22.11.2026, kleinere bzw. sicherere Variante):
//   - Gruppen müssen schon bestehen (kein Anlegen beim Import).
//   - Ein Name darf im Mandanten noch nicht vergeben sein und in der Datei nur
//     einmal vorkommen (Schutz gegen doppelten Import).
//   - Profil und Vorlage über den Namen; gibt es ihn auf mehreren Ebenen,
//     gilt der nächstgelegene Mandant (eigener vor Eltern). Eingebaute
//     Vorlagen auch über ihre ID (std-…).
//   - Eine Vorlage je Zeile. Agent-Vorlagen gehen nicht (neue Geräte haben
//     keinen Agent), SNMP-Vorlagen nur mit Profil.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/checks"
)

const (
	maxImportRows  = 500
	maxImportBytes = 256 << 10
)

var importColumns = []string{"name", "adresse", "gruppe", "profil", "vorlage"}

type importIn struct {
	CSV        string `json:"csv"`
	NurPruefen bool   `json:"nur_pruefen"`
}

type importRowOut struct {
	Zeile   int     `json:"zeile"` // Zeilennummer in der Datei (Kopfzeile = 1)
	Name    string  `json:"name"`
	OK      bool    `json:"ok"`
	Fehler  string  `json:"fehler,omitempty"`
	ID      *string `json:"id,omitempty"` // nur beim Anlegen
	Gruppe  string  `json:"gruppe,omitempty"`
	Profil  string  `json:"profil,omitempty"`
	Vorlage string  `json:"vorlage,omitempty"`
}

type importRow struct {
	line                                 int
	name, addr, group, profile, template string
}

// unwrapExcelLines erkennt eine Datei, in der jede Zeile als ein einziges Feld
// in Anführungszeichen steht. So speichert Excel, wenn fertige CSV-Zeilen in
// Spalte A eingefügt und dann als CSV gespeichert wurden
// („"name;adresse;…"“). Dann gilt der Inhalt der Felder als die eigentliche
// Datei (1.0.3). Nur wenn wirklich jede Zeile genau ein Feld ist und die
// Kopfzeile ein Trennzeichen enthält; sonst bleibt alles, wie es ist.
func unwrapExcelLines(text string) (string, bool) {
	if !strings.HasPrefix(text, `"`) {
		return "", false
	}
	rd := csv.NewReader(strings.NewReader(text))
	rd.FieldsPerRecord = -1
	var lines []string
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) != 1 || strings.ContainsAny(rec[0], "\r\n") {
			return "", false
		}
		lines = append(lines, rec[0])
	}
	if len(lines) == 0 || !strings.ContainsAny(lines[0], ";,") {
		return "", false
	}
	return strings.Join(lines, "\n") + "\n", true
}

// parseImportCSV liest die Datei. Fehler der Datei als Ganzes (Kopfzeile,
// Größe, Zeilenzahl) brechen ab; Fehler einzelner Felder prüft der Aufrufer.
func parseImportCSV(text string) ([]importRow, error) {
	if len(text) > maxImportBytes {
		return nil, badRequest(fmt.Sprintf("Die Datei ist zu groß (höchstens %d KiB).", maxImportBytes>>10))
	}
	if !utf8.ValidString(text) {
		return nil, badRequest("Die Datei ist nicht UTF-8 (bitte als „CSV UTF-8“ speichern).")
	}
	text = strings.TrimPrefix(text, "\ufeff")
	if inner, ok := unwrapExcelLines(text); ok {
		text = inner
	}
	first, _, _ := strings.Cut(text, "\n")
	comma := ';'
	if strings.Count(first, ",") > strings.Count(first, ";") {
		comma = ','
	}
	rd := csv.NewReader(strings.NewReader(text))
	rd.Comma = comma
	rd.FieldsPerRecord = -1
	rd.ReuseRecord = false
	header, err := rd.Read()
	if errors.Is(err, io.EOF) {
		return nil, badRequest("Die Datei ist leer.")
	}
	if err != nil {
		return nil, badRequest("Kopfzeile nicht lesbar.")
	}
	col := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		known := false
		for _, c := range importColumns {
			known = known || c == h
		}
		if !known {
			return nil, badRequest(fmt.Sprintf("Unbekannte Spalte „%s“. Erlaubt: %s.", clipRunes(h, 40), strings.Join(importColumns, ";")))
		}
		if _, dup := col[h]; dup {
			return nil, badRequest(fmt.Sprintf("Spalte „%s“ doppelt.", h))
		}
		col[h] = i
	}
	if _, ok := col["name"]; !ok {
		return nil, badRequest("Die Kopfzeile braucht die Spalte „name“ (" + strings.Join(importColumns, ";") + ").")
	}
	field := func(rec []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var rows []importRow
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				return nil, badRequest(fmt.Sprintf("Zeile %d: nicht lesbar (Anführungszeichen prüfen).", pe.StartLine))
			}
			return nil, badRequest("Datei nicht lesbar.")
		}
		line, _ := rd.FieldPos(0)
		if len(rec) > len(header) {
			return nil, badRequest(fmt.Sprintf("Zeile %d: mehr Felder als Spalten in der Kopfzeile.", line))
		}
		empty := true
		for _, f := range rec {
			empty = empty && strings.TrimSpace(f) == ""
		}
		if empty {
			continue
		}
		if len(rows) == maxImportRows {
			return nil, badRequest(fmt.Sprintf("Höchstens %d Geräte je Import.", maxImportRows))
		}
		rows = append(rows, importRow{line: line, name: field(rec, "name"), addr: field(rec, "adresse"), group: field(rec, "gruppe"),
			profile: field(rec, "profil"), template: field(rec, "vorlage")})
	}
	if len(rows) == 0 {
		return nil, badRequest("Die Datei enthält keine Geräte.")
	}
	return rows, nil
}

// errImportRollback: Vorschau oder Fehler; die Transaktion wird zurückgerollt.
var errImportRollback = errors.New("import zurückgerollt")

func (s *Server) handleDeviceImport(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in importIn
	if !readJSONMax(w, r, &in, 2*maxImportBytes+4096) {
		return
	}
	rows, err := parseImportCSV(in.CSV)
	if err != nil {
		writeDBError(w, "import", err)
		return
	}
	ctx := r.Context()
	sess := sessionFrom(ctx)
	var out []importRowOut
	failed, created := 0, 0
	err = s.withUser(ctx, sess.UserID, func(tx pgx.Tx) error {
		var visible, writable bool
		if err := tx.QueryRow(ctx, `SELECT $1::uuid IN (SELECT openwacht.visible_tenants()), $1::uuid IN (SELECT openwacht.operator_tenants())`,
			tid).Scan(&visible, &writable); err != nil {
			return err
		}
		if !visible {
			return errNotFound
		}
		if !writable {
			return &apiError{http.StatusForbidden, "Geräte importieren dürfen Admins und Operatoren."}
		}
		imp, err := s.newImporter(ctx, tx, tid)
		if err != nil {
			return err
		}
		var ids []string
		for _, row := range rows {
			o := importRowOut{Zeile: row.line, Name: row.name, Gruppe: row.group, Profil: row.profile, Vorlage: row.template}
			id, err := imp.row(ctx, tx, row)
			if err != nil && !rowError(err) {
				return err
			}
			if err != nil {
				failed++
				o.Fehler = importErrorText(err)
			} else {
				o.OK = true
				created++
				if !in.NurPruefen {
					o.ID = &id
				}
				ids = append(ids, id)
			}
			out = append(out, o)
		}
		if in.NurPruefen || failed > 0 {
			return errImportRollback
		}
		return audit(ctx, tx, &tid, "geraete.importiert", map[string]any{"anzahl": len(ids), "geraete": ids[:min(len(ids), 100)],
			"mit_profil": imp.withProfile, "mit_vorlage": imp.withTemplate})
	})
	if err != nil && !errors.Is(err, errImportRollback) {
		writeDBError(w, "import", err)
		return
	}
	body := map[string]any{"zeilen": out, "fehlerhaft": failed, "nur_pruefen": in.NurPruefen}
	switch {
	case failed > 0:
		body["angelegt"] = 0
		body["fehler"] = fmt.Sprintf("Nichts angelegt: %d von %d Zeilen haben Fehler.", failed, len(rows))
		status := http.StatusUnprocessableEntity
		if in.NurPruefen {
			status = http.StatusOK
		}
		writeJSON(w, status, body)
	case in.NurPruefen:
		body["angelegt"] = 0
		writeJSON(w, http.StatusOK, body)
	default:
		body["angelegt"] = created
		writeJSON(w, http.StatusCreated, body)
	}
}

type importer struct {
	s            *Server
	tenant       string
	groups       map[string]string // Pfad (klein) → ID
	profiles     map[string]string // Name (klein) → ID, nächster Mandant
	templates    map[string]vorlageOut
	existing     map[string]bool // Gerätenamen im Mandanten (klein)
	seen         map[string]int  // Namen in der Datei → Zeile
	withProfile  int
	withTemplate int
}

func (s *Server) newImporter(ctx context.Context, tx pgx.Tx, tenant string) (*importer, error) {
	imp := &importer{s: s, tenant: tenant, groups: map[string]string{}, profiles: map[string]string{},
		templates: map[string]vorlageOut{}, existing: map[string]bool{}, seen: map[string]int{}}
	// Gruppenpfade des Mandanten (höchstens 4 Ebenen, 1000 Gruppen).
	rows, err := tx.Query(ctx, `WITH RECURSIVE g AS (
			SELECT id, name::text AS path, 1 AS depth FROM openwacht.device_groups WHERE tenant_id = $1 AND parent_id IS NULL
			UNION ALL
			SELECT c.id, g.path || '/' || c.name, g.depth + 1 FROM openwacht.device_groups c JOIN g ON c.parent_id = g.id
			 WHERE c.tenant_id = $1 AND g.depth < 8)
		SELECT id::text, lower(path) FROM g`, tenant)
	if err != nil {
		return nil, err
	}
	if err := collectPairs(rows, imp.groups); err != nil {
		return nil, err
	}
	// Profile des Mandanten und darüber (RLS: nur für Admins sichtbar); der
	// nächstgelegene Mandant gewinnt.
	rows, err = tx.Query(ctx, `WITH RECURSIVE a AS (
			SELECT id, parent_id, 0 AS depth FROM openwacht.tenants WHERE id = $1
			UNION ALL
			SELECT t.id, t.parent_id, a.depth + 1 FROM openwacht.tenants t JOIN a ON t.id = a.parent_id WHERE a.depth < 64)
		SELECT DISTINCT ON (lower(p.name)) p.id::text, lower(p.name)
		FROM openwacht.snmp_profiles p JOIN a ON a.id = p.tenant_id
		ORDER BY lower(p.name), a.depth, p.id`, tenant)
	if err != nil {
		return nil, err
	}
	if err := collectPairs(rows, imp.profiles); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `WITH RECURSIVE a AS (
			SELECT id, parent_id, 0 AS depth FROM openwacht.tenants WHERE id = $1
			UNION ALL
			SELECT t.id, t.parent_id, a.depth + 1 FROM openwacht.tenants t JOIN a ON t.id = a.parent_id WHERE a.depth < 64)
		SELECT DISTINCT ON (lower(t.name)) t.id::text, t.name, t.kind, t.target, t.interval_s
		FROM openwacht.sensor_templates t JOIN a ON a.id = t.tenant_id
		ORDER BY lower(t.name), a.depth, t.id`, tenant)
	if err != nil {
		return nil, err
	}
	custom, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (vorlageOut, error) {
		var v vorlageOut
		var target []byte
		err := row.Scan(&v.ID, &v.Name, &v.Typ, &target, &v.Intervall)
		v.Ziel = target
		return v, err
	})
	if err != nil {
		return nil, err
	}
	// Eingebaute zuerst über ID und Name, eigene Vorlagen gehen beim Namen vor.
	for _, t := range builtinTemplates {
		imp.templates[strings.ToLower(t.ID)] = t
		imp.templates[strings.ToLower(t.Name)] = t
	}
	for _, t := range custom {
		imp.templates[strings.ToLower(t.Name)] = t
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT lower(name) FROM openwacht.devices WHERE tenant_id = $1`, tenant)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		imp.existing[n] = true
	}
	return imp, nil
}

func collectPairs(rows pgx.Rows, into map[string]string) error {
	pairs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]string, error) {
		var p [2]string
		err := row.Scan(&p[0], &p[1])
		return p, err
	})
	for _, p := range pairs {
		into[p[1]] = p[0]
	}
	return err
}

// row prüft und legt eine Zeile in einem eigenen Sicherungspunkt an.
func (imp *importer) row(ctx context.Context, tx pgx.Tx, row importRow) (string, error) {
	name, err := cleanName(row.name)
	if err != nil {
		return "", err
	}
	key := strings.ToLower(name)
	if l, dup := imp.seen[key]; dup {
		return "", badRequest(fmt.Sprintf("Name kommt schon in Zeile %d vor.", l))
	}
	imp.seen[key] = row.line
	if imp.existing[key] {
		return "", badRequest("Ein Gerät mit diesem Namen gibt es im Mandanten schon.")
	}
	addr, err := cleanAddress(row.addr)
	if err != nil {
		return "", err
	}
	var group *string
	if row.group != "" {
		parts := strings.Split(row.group, "/")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		id, ok := imp.groups[strings.ToLower(strings.Join(parts, "/"))]
		if !ok {
			return "", badRequest("Gruppe „" + clipRunes(row.group, 120) + "“ gibt es im Mandanten nicht.")
		}
		group = &id
	}
	var profile string
	if row.profile != "" {
		var ok bool
		if profile, ok = imp.profiles[strings.ToLower(row.profile)]; !ok {
			return "", badRequest("Profil „" + clipRunes(row.profile, 60) + "“ nicht gefunden (Profile sehen und zuordnen nur Admins).")
		}
		if addr == nil {
			return "", badRequest("Mit Profil braucht das Gerät eine Adresse.")
		}
		if err := imp.s.checkZentraleAddr(*addr); err != nil {
			return "", err
		}
	}
	var tmpl *vorlageOut
	if row.template != "" {
		t, ok := imp.templates[strings.ToLower(row.template)]
		if !ok {
			return "", badRequest("Vorlage „" + clipRunes(row.template, 60) + "“ nicht gefunden.")
		}
		if checks.IsAgentKind(t.Typ) {
			return "", badRequest("Vorlage „" + t.Name + "“ braucht einen Agent; neue Geräte haben noch keinen.")
		}
		if checks.IsSNMPKind(t.Typ) && profile == "" {
			return "", badRequest("Vorlage „" + t.Name + "“ braucht SNMP: bitte ein Profil angeben.")
		}
		if checks.UsesPlaceholder(t.Ziel) && addr == nil {
			return "", badRequest("Vorlage „" + t.Name + "“ braucht die Adresse des Geräts.")
		}
		tmpl = &t
	}

	sp, err := tx.Begin(ctx) // Sicherungspunkt
	if err != nil {
		return "", err
	}
	id, err := imp.create(ctx, sp, name, addr, group, profile, tmpl)
	if err != nil {
		if rbErr := sp.Rollback(ctx); rbErr != nil {
			return "", rbErr
		}
		return "", err
	}
	if err := sp.Commit(ctx); err != nil {
		return "", err
	}
	if profile != "" {
		imp.withProfile++
	}
	if tmpl != nil {
		imp.withTemplate++
	}
	return id, nil
}

func (imp *importer) create(ctx context.Context, tx pgx.Tx, name string, addr, group *string, profile string, tmpl *vorlageOut) (string, error) {
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name, address, group_id) VALUES ($1, $2, $3, $4)
		RETURNING id::text`, imp.tenant, name, addr, group).Scan(&id); err != nil {
		return "", groupError(err)
	}
	if profile != "" {
		version, sec, err := imp.s.profileForDevice(ctx, tx, profile, id)
		if err != nil {
			return "", err
		}
		src, err := newUUID()
		if err != nil {
			return "", err
		}
		enc, err := imp.s.sealSNMP(src, imp.tenant, *addr, 161, sec)
		if err != nil {
			return "", err
		}
		var a, p *string
		if sec.V3 != nil {
			a, p = &sec.V3.Auth, &sec.V3.Priv
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.snmp_sources
				(id, device_id, version, host, port, secret_enc, interval_s, enabled, watched, v3_auth, v3_priv, profile_id)
			VALUES ($1, $2, $3, $4, 161, $5, 60, true, '{}', $6, $7, $8)`, src, id, version, *addr, enc, a, p, profile); err != nil {
			return "", err
		}
	}
	if tmpl != nil {
		raw := []byte(tmpl.Ziel)
		if checks.UsesPlaceholder(raw) {
			raw = checks.Substitute(raw, *addr)
		}
		spec, err := checks.Parse(tmpl.Typ, raw)
		if err != nil {
			return "", badRequest("Vorlage „" + tmpl.Name + "“ passt nicht: " + err.Error() + ".")
		}
		for _, a := range spec.LiteralAddrs() {
			if !imp.s.guard.Allowed(a) {
				return "", badRequest("Adresse " + a.String() + " ist für Sensoren nicht freigegeben.")
			}
		}
		target, err := json.Marshal(spec)
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s, enabled, origin)
			VALUES ($1, $2, $3, $4, $5, true, $6)`, id, templateSensorName(tmpl.Name), tmpl.Typ, target, tmpl.Intervall, tmpl.Name); err != nil {
			return "", err
		}
	}
	return id, nil
}

// rowError: Fehler, der nur die Zeile betrifft (Eingabe, Rechte, Grenzen
// der Datenbank); alles andere bricht den ganzen Import ab.
func rowError(err error) bool {
	var ae *apiError
	var pe *pgconn.PgError
	return errors.As(err, &ae) || errors.As(err, &pe) && (strings.HasPrefix(pe.Code, "23") || strings.HasPrefix(pe.Code, "22") || pe.Code == "42501")
}

// importErrorText: Meldung für eine Zeile, ohne interne Details.
func importErrorText(err error) string {
	var ae *apiError
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &ae):
		return ae.msg
	case errors.As(err, &pe) && pe.Code == "42501":
		return "Keine Berechtigung."
	case errors.As(err, &pe) && pe.Code == "23514" && pe.ConstraintName == "" && pe.Message != "":
		return pe.Message
	case errors.As(err, &pe) && pe.Code == "23505":
		return "Ein Eintrag mit diesem Namen gibt es schon."
	case errors.As(err, &pe):
		return "Ungültige Eingabe."
	}
	return "Ungültige Eingabe."
}
