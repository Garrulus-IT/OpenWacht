// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Wandanzeige (Etappe 12): ein Bildschirm ohne Benutzerkonto, der den
// Zustand eines Mandanten als Sonnendiagramm zeigt: Mandant, Untermandanten,
// Gruppen und Geräte (Hosts) als grober Überblick, ohne einzelne Sensoren.
//
// Anmeldung: Ein Admin legt die Anzeige an und bekommt einmalig einen Link
// https://…/anzeige#<Schlüssel>. Der Schlüssel steht im Fragment, damit er
// weder in Server- noch in Proxy-Logs landet. Die Oberfläche schickt ihn
// einmal an /api/v1/anzeige/anmelden und bekommt ein HttpOnly-Cookie; danach
// entfernt sie ihn aus der Adresszeile. Gespeichert ist nur der Hash.
//
// Rechte: Die Anfragen der Anzeige laufen mit dem Datenbankkontext
// app.display_id statt app.user_id. Welche Mandanten sie sieht, leitet die
// Datenbank aus der Anzeige ab (Migration 0015). Die API gibt ihr nur Namen
// und Farben, keine Meldungen, Messwerte oder Personennamen.

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const displayCookie = "__Host-openwacht-anzeige"

// Ein Wandbildschirm soll nicht nach Wochen dunkel werden. Das Cookie wird
// bei jeder Datenabfrage verlängert; Browser begrenzen auf 400 Tage.
const displayCookieAge = 400 * 24 * time.Hour

const displayCtxKey ctxKey = 3

type displayIdentity struct {
	ID       string
	TenantID string
	Name     string
}

func displayFrom(ctx context.Context) *displayIdentity {
	d, _ := ctx.Value(displayCtxKey).(*displayIdentity)
	return d
}

// --- Verwaltung (nur Admins des Mandanten, per RLS) --------------------------

type anzeigeIn struct {
	Name              string `json:"name"`
	MitUntermandanten bool   `json:"mit_untermandanten"`
	Netz              string `json:"netz"`
}

type anzeigeOut struct {
	ID                string     `json:"id"`
	MandantID         string     `json:"mandant_id"`
	Name              string     `json:"name"`
	MitUntermandanten bool       `json:"mit_untermandanten"`
	Netz              *string    `json:"netz"`
	Erstellt          time.Time  `json:"erstellt"`
	ZuletztDa         *time.Time `json:"zuletzt_da"`
}

// cleanNet prüft das optionale Netz einer Anzeige (CIDR oder einzelne Adresse).
func cleanNet(s string) (*string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var p netip.Prefix
	var err error
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
	} else {
		var a netip.Addr
		a, err = netip.ParseAddr(s)
		if err == nil && a.Zone() == "" {
			p = netip.PrefixFrom(a, a.BitLen())
		}
	}
	if err != nil || !p.IsValid() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return nil, badRequest("Netz: Adresse oder Netz in CIDR-Schreibweise angeben, z. B. 10.10.0.0/24.")
	}
	c := p.Masked().String()
	return &c, nil
}

func (s *Server) handleDisplayList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "anzeigen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, name, include_children, allowed_net::text, created_at, last_seen
			FROM openwacht.displays ORDER BY lower(name), id`)
		if err != nil {
			return 0, nil, err
		}
		list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (anzeigeOut, error) {
			var a anzeigeOut
			err := row.Scan(&a.ID, &a.MandantID, &a.Name, &a.MitUntermandanten, &a.Netz, &a.Erstellt, &a.ZuletztDa)
			return a, err
		})
		if err != nil {
			return 0, nil, err
		}
		if list == nil {
			list = []anzeigeOut{}
		}
		return http.StatusOK, map[string]any{"anzeigen": list}, nil
	})
}

func (s *Server) handleDisplayCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in anzeigeIn
	if !readJSON(w, r, &in) {
		return
	}
	raw, hash, err := newToken()
	if err != nil {
		internalError(w, "anzeige", err)
		return
	}
	s.handle(w, r, "anzeige anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		name, err := cleanName(in.Name)
		if err != nil {
			return 0, nil, err
		}
		netz, err := cleanNet(in.Netz)
		if err != nil {
			return 0, nil, err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.displays (tenant_id, name, token_hash, include_children, allowed_net)
			VALUES ($1, $2, $3, $4, $5::cidr) RETURNING id::text`, tid, name, hash, in.MitUntermandanten, netz).Scan(&id); err != nil {
			return 0, nil, err // nur Admins: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "anzeige.angelegt", map[string]any{"id": id, "name": name,
			"mit_untermandanten": in.MitUntermandanten, "netz": netz}); err != nil {
			return 0, nil, err
		}
		// Den Link gibt es nur in dieser Antwort.
		link := s.cfg.BaseURL.Scheme + "://" + s.cfg.BaseURL.Host + "/anzeige#" + raw
		return http.StatusCreated, map[string]any{"id": id, "link": link}, nil
	})
}

func (s *Server) handleDisplayDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "anzeige löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.displays WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tenant, &name); err != nil {
			return 0, nil, err // nicht sichtbar (kein Admin): 404
		}
		if err := audit(ctx, tx, &tenant, "anzeige.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// handleDisplayNewLink: „Neuer Link“ (0.99.2). Neuer Schlüssel, alter Link
// und angemeldete Bildschirme sofort ungültig; den Link gibt es nur hier.
func (s *Server) handleDisplayNewLink(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	raw, hash, err := newToken()
	if err != nil {
		internalError(w, "anzeige neuer link", err)
		return
	}
	s.handle(w, r, "anzeige neuer link", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tenant, name string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.displays SET token_hash = $2 WHERE id = $1 RETURNING tenant_id::text, name`,
			id, hash).Scan(&tenant, &name); err != nil {
			return 0, nil, err // nicht sichtbar (kein Admin): 404
		}
		if err := audit(ctx, tx, &tenant, "anzeige.neuer_link", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		link := s.cfg.BaseURL.Scheme + "://" + s.cfg.BaseURL.Host + "/anzeige#" + raw
		return http.StatusOK, map[string]any{"id": id, "name": name, "link": link}, nil
	})
}

// handleDisplayPreview: dieselben Daten, die der Bildschirm sieht, für einen
// Admin der Anzeige in seiner Sitzung (0.99.2). Erst prüft RLS mit dem
// Benutzer, ob er die Anzeige verwalten darf; die Daten selbst kommen dann
// mit dem Kontext der Anzeige (ohne Benutzer), damit die Vorschau genau den
// Ausschnitt zeigt, den die Wand zeigt, nicht alles, was der Admin sieht.
// Die Netzfreigabe der Anzeige gilt für die Vorschau nicht.
func (s *Server) handleDisplayPreview(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var d displayIdentity
	err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT id::text, tenant_id::text, name FROM openwacht.displays WHERE id = $1`, id).
			Scan(&d.ID, &d.TenantID, &d.Name)
	})
	if err != nil {
		writeDBError(w, "anzeige vorschau", err)
		return
	}
	var body any
	if err := s.withDisplay(r.Context(), d.ID, func(tx pgx.Tx) error {
		var err error
		body, err = s.displayTree(r.Context(), tx, &d)
		return err
	}); err != nil {
		writeDBError(w, "anzeige vorschau", err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// --- Anmeldung der Anzeige --------------------------------------------------

const msgDisplayInvalid = "Dieser Anzeige-Link gilt nicht (mehr). Bitte einen neuen Link anlegen lassen."

// lookupDisplay prüft den Schlüssel und das Netz der Anzeige.
func (s *Server) lookupDisplay(r *http.Request, raw string) (*displayIdentity, int, string, error) {
	th, ok := hashToken(raw)
	if !ok {
		return nil, http.StatusUnauthorized, msgDisplayInvalid, nil
	}
	var d displayIdentity
	var allowed *netip.Prefix
	err := s.pool.QueryRow(r.Context(), `SELECT display_id::text, tenant_id::text, name, allowed_net FROM openwacht.display_login($1)`, th).
		Scan(&d.ID, &d.TenantID, &d.Name, &allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, http.StatusUnauthorized, msgDisplayInvalid, nil
	}
	if err != nil {
		return nil, 0, "", err
	}
	if allowed != nil {
		ip := s.clientIP(r)
		if !ip.IsValid() || !allowed.Contains(ip) {
			return nil, http.StatusForbidden, "Diese Anzeige ist von hier aus nicht freigegeben (Netz der Anzeige prüfen).", nil
		}
	}
	return &d, 0, "", nil
}

func (s *Server) handleDisplayLogin(w http.ResponseWriter, r *http.Request) {
	if !s.displayLimiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Versuche. Bitte kurz warten.")
		return
	}
	var in struct {
		Schluessel string `json:"schluessel"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	d, status, msg, err := s.lookupDisplay(r, in.Schluessel)
	if err != nil {
		internalError(w, "anzeige anmelden", err)
		return
	}
	if d == nil {
		writeError(w, status, msg)
		return
	}
	s.setCookie(w, displayCookie, in.Schluessel, displayCookieAge)
	writeJSON(w, http.StatusOK, map[string]string{"name": d.Name})
}

// requireDisplay lässt nur Anfragen mit gültigem Anzeige-Cookie durch.
func (s *Server) requireDisplay(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(displayCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Diese Anzeige ist nicht angemeldet. Bitte den Anzeige-Link öffnen.")
			return
		}
		d, status, msg, err := s.lookupDisplay(r, c.Value)
		if err != nil {
			internalError(w, "anzeige", err)
			return
		}
		if d == nil {
			if status == http.StatusUnauthorized {
				clearCookie(w, displayCookie)
			}
			writeError(w, status, msg)
			return
		}
		// Gültig: Cookie verlängern.
		s.setCookie(w, displayCookie, c.Value, displayCookieAge)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), displayCtxKey, d)))
	})
}

// withDisplay führt fn mit dem Datenbankkontext der Anzeige aus.
func (s *Server) withDisplay(ctx context.Context, displayID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.display_id', $1, true)`, displayID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// --- Daten der Anzeige ------------------------------------------------------

// Zustände im Sonnendiagramm. „wartung“ steht für Wartung und Pausiert (blau),
// „quittiert“ für einen bestätigten Alarm (hellrot).
const (
	dispOK          = "ok"
	dispWarn        = "warn"
	dispCrit        = "crit"
	dispAcked       = "quittiert"
	dispUnknown     = "unknown"
	dispMaintenance = "wartung"
)

// Rangfolge wie in der Übersicht: Alarm vor Unbekannt vor Warnung.
var dispRank = map[string]int{dispMaintenance: 0, dispOK: 1, dispWarn: 2, dispUnknown: 3, dispAcked: 4, dispCrit: 5}

type anzeigeKnoten struct {
	Name   string `json:"name"`
	Art    string `json:"art"` // mandant | gruppe | geraet
	Status string `json:"status"`
	// Kennfarbe des schlimmsten Sensors (0.99.2), nur bei Warnung, Kritisch
	// und Bestätigt: Farbe „#rrggbb“ und Name für Legende und Tooltip.
	Farbe     string           `json:"farbe,omitempty"`
	Kennfarbe string           `json:"kennfarbe,omitempty"`
	Kinder    []*anzeigeKnoten `json:"kinder,omitempty"`
}

// kennfarbeZaehlt: Bei diesen Zuständen ersetzt die Kennfarbe Gelb bzw. Rot.
func kennfarbeZaehlt(status string) bool {
	return status == dispWarn || status == dispCrit || status == dispAcked
}

// schlimmer: Ist (st, kenn) schlimmer als der bisherige Stand (cur, curKenn)?
// Erst zählt die Schwere; bei gleicher Schwere gewinnt der Zustand ohne
// Kennfarbe („Rot gewinnt immer“), damit eine Kennfarbe nie ein echtes Rot
// oder Gelb verdeckt.
func schlimmer(st string, kenn bool, cur string, curKenn bool) bool {
	if dispRank[st] != dispRank[cur] {
		return dispRank[st] > dispRank[cur]
	}
	return curKenn && !kenn
}

// setzeKennfarbe übernimmt die Kennfarbe nur, wo sie gilt.
func (k *anzeigeKnoten) setzeKennfarbe(ref *kennfarbeRef) {
	k.Farbe, k.Kennfarbe = "", ""
	if ref != nil && kennfarbeZaehlt(k.Status) {
		k.Farbe, k.Kennfarbe = ref.Farbe, ref.Name
	}
}

// sensorDisplayStatus bildet den Zustand eines Sensors auf die Farben ab.
func sensorDisplayStatus(sn *sensorOut) string {
	switch {
	case sn.Status == "pause" || sn.Wartung != nil:
		return dispMaintenance
	case sn.Status == "neu" || sn.Status == "unknown":
		return dispUnknown
	case sn.Status == "crit":
		if sn.Alarm != nil && sn.Alarm.BestaetigtAm != nil {
			return dispAcked
		}
		return dispCrit
	case sn.Status == "warn":
		return dispWarn
	case sn.Status == "ok":
		return dispOK
	}
	return dispUnknown
}

// worst bestimmt den Zustand eines Knotens aus seinen Kindern. Ohne Kinder
// gilt er als unbekannt (nichts überwacht).
// prune entfernt Gruppen ohne Geräte (auch über Untergruppen) und meldet,
// ob der Knoten selbst bleibt. Mandanten bleiben immer.
func (k *anzeigeKnoten) prune() bool {
	kept := k.Kinder[:0]
	for _, c := range k.Kinder {
		if c.prune() {
			kept = append(kept, c)
		}
	}
	k.Kinder = kept
	return k.Art != "gruppe" || len(k.Kinder) > 0
}

func (k *anzeigeKnoten) worst() string {
	if len(k.Kinder) == 0 {
		if k.Status == "" {
			k.Status = dispUnknown
		}
		return k.Status
	}
	first := true
	for _, c := range k.Kinder {
		st := c.worst()
		if first || schlimmer(st, c.Farbe != "", k.Status, k.Farbe != "") {
			first = false
			k.Status, k.Farbe, k.Kennfarbe = st, c.Farbe, c.Kennfarbe
		}
	}
	return k.Status
}

func (s *Server) handleDisplayData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := displayFrom(ctx)
	var body any
	err := s.withDisplay(ctx, d.ID, func(tx pgx.Tx) error {
		var err error
		body, err = s.displayTree(ctx, tx, d)
		return err
	})
	if err != nil {
		writeDBError(w, "anzeige daten", err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) displayTree(ctx context.Context, tx pgx.Tx, d *displayIdentity) (any, error) {
	type tenantRow struct {
		id     string
		parent *string
		name   string
	}
	rows, err := tx.Query(ctx, `SELECT id::text, parent_id::text, name FROM openwacht.tenants`)
	if err != nil {
		return nil, err
	}
	tenants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantRow, error) {
		var t tenantRow
		err := row.Scan(&t.id, &t.parent, &t.name)
		return t, err
	})
	if err != nil {
		return nil, err
	}
	nodes := map[string]*anzeigeKnoten{}
	for _, t := range tenants {
		nodes[t.id] = &anzeigeKnoten{Name: t.name, Art: "mandant"}
	}
	root := nodes[d.TenantID]
	if root == nil {
		return nil, errNotFound
	}
	// Untermandanten zuerst, alphabetisch.
	sort.Slice(tenants, func(i, j int) bool { return strings.ToLower(tenants[i].name) < strings.ToLower(tenants[j].name) })
	for _, t := range tenants {
		if t.id == d.TenantID || t.parent == nil {
			continue
		}
		if p := nodes[*t.parent]; p != nil {
			p.Kinder = append(p.Kinder, nodes[t.id])
		}
	}

	maint, err := visibleMaintenance(ctx, tx)
	if err != nil {
		return nil, err
	}
	sensors, err := s.collectSensors(ctx, tx)
	if err != nil {
		return nil, err
	}
	// Die Anzeige zeigt nur Hosts (Entscheidung, 20.11.2026): Ein Gerät trägt den
	// schlimmsten Zustand seiner Sensoren, die Sensoren selbst bleiben unsichtbar.
	// Proxmox-Gäste und Backups sind Sensoren des Hosts und färben ihn mit.
	type devState struct {
		status string
		kenn   *kennfarbeRef
	}
	byDevice := map[string]devState{}
	for i := range sensors {
		sn := &sensors[i]
		st := sensorDisplayStatus(sn)
		kenn := sn.Kennfarbe
		if !kennfarbeZaehlt(st) {
			kenn = nil
		}
		if cur, ok := byDevice[sn.GeraetID]; !ok || schlimmer(st, kenn != nil, cur.status, cur.kenn != nil) {
			byDevice[sn.GeraetID] = devState{st, kenn}
		}
	}

	// Gruppenbaum (Etappe 13): Gruppen in ihrer eingestellten Reihenfolge,
	// unter einem Mandanten nach den Untermandanten und vor den Geräten ohne
	// Gruppe; in einer Gruppe erst die Untergruppen, dann die Geräte.
	type groupRow struct {
		id, tenant, name string
		parent           *string
	}
	rows, err = tx.Query(ctx, `SELECT id::text, tenant_id::text, name, parent_id::text FROM openwacht.device_groups
		ORDER BY position, lower(name), id`)
	if err != nil {
		return nil, err
	}
	groupRows, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (groupRow, error) {
		var g groupRow
		err := row.Scan(&g.id, &g.tenant, &g.name, &g.parent)
		return g, err
	})
	if err != nil {
		return nil, err
	}
	groups := map[string]*anzeigeKnoten{}
	for _, g := range groupRows {
		groups[g.id] = &anzeigeKnoten{Name: g.name, Art: "gruppe"}
	}
	for _, g := range groupRows {
		parent := nodes[g.tenant]
		if g.parent != nil {
			parent = groups[*g.parent]
		}
		if parent != nil {
			parent.Kinder = append(parent.Kinder, groups[g.id])
		}
	}

	type deviceRow struct {
		id, tenant, name string
		group            *string
	}
	rows, err = tx.Query(ctx, `SELECT id::text, tenant_id::text, name, group_id::text FROM openwacht.devices
		ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	devices, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (deviceRow, error) {
		var x deviceRow
		err := row.Scan(&x.id, &x.tenant, &x.name, &x.group)
		return x, err
	})
	if err != nil {
		return nil, err
	}
	ungrouped := map[string][]*anzeigeKnoten{}
	for _, x := range devices {
		if nodes[x.tenant] == nil {
			continue
		}
		// Blatt im Diagramm: jedes Gerät ist gleich breit.
		ds := byDevice[x.id]
		dev := &anzeigeKnoten{Name: x.name, Art: "geraet", Status: ds.status}
		dev.setzeKennfarbe(ds.kenn)
		if dev.Status == "" && maint["d:"+x.id] != nil {
			dev.Status = dispMaintenance // Gerät ohne Sensoren, aber in Wartung
		}
		if x.group != nil && groups[*x.group] != nil {
			g := groups[*x.group]
			g.Kinder = append(g.Kinder, dev)
			continue
		}
		ungrouped[x.tenant] = append(ungrouped[x.tenant], dev)
	}
	for tenant, list := range ungrouped {
		nodes[tenant].Kinder = append(nodes[tenant].Kinder, list...)
	}
	// Leere Gruppen zeigt die Anzeige nicht: Sie hätten keine Farbe.
	root.prune()
	root.worst()

	// Legende: alle Kennfarben, die die Anzeige sieht (eigener Mandant, darunter
	// und darüber), mit der Zahl der Geräte, die gerade in dieser Farbe stehen.
	rows, err = tx.Query(ctx, `SELECT name, color FROM openwacht.kennfarben ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	legende, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (anzeigeKennfarbe, error) {
		var k anzeigeKennfarbe
		err := row.Scan(&k.Name, &k.Farbe)
		return k, err
	})
	if err != nil {
		return nil, err
	}
	zahl := map[string]int{}
	root.zaehleKennfarben(zahl)
	for i := range legende {
		legende[i].Geraete = zahl[legende[i].Name+"\x00"+legende[i].Farbe]
	}
	if legende == nil {
		legende = []anzeigeKennfarbe{}
	}
	return map[string]any{"anzeige": d.Name, "stand": s.now().UTC().Truncate(time.Second), "baum": root,
		"kennfarben": legende}, nil
}

type anzeigeKennfarbe struct {
	Name    string `json:"name"`
	Farbe   string `json:"farbe"`
	Geraete int    `json:"geraete"`
}

func (k *anzeigeKnoten) zaehleKennfarben(n map[string]int) {
	if k.Art == "geraet" && k.Farbe != "" {
		n[k.Kennfarbe+"\x00"+k.Farbe]++
	}
	for _, c := range k.Kinder {
		c.zaehleKennfarben(n)
	}
}
