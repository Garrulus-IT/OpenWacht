// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/auth"
)

// ownerGroupPath legt den Pfad „a/b/c“ als Gruppen an (als Eigentümer, ohne
// RLS) oder findet ihn und liefert die ID der letzten Ebene.
func ownerGroupPath(t *testing.T, tenant, path string) *string {
	t.Helper()
	ctx := context.Background()
	var parent *string
	for _, part := range strings.Split(path, "/") {
		var id string
		err := owner.QueryRow(ctx, `SELECT id::text FROM openwacht.device_groups
			WHERE tenant_id = $1 AND parent_id IS NOT DISTINCT FROM $2::uuid AND lower(name) = lower($3)`, tenant, parent, part).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			err = owner.QueryRow(ctx, `INSERT INTO openwacht.device_groups (tenant_id, parent_id, name) VALUES ($1, $2, $3) RETURNING id::text`,
				tenant, parent, part).Scan(&id)
		}
		if err != nil {
			t.Fatal(err)
		}
		parent = &id
	}
	return parent
}

// deleteGroups entfernt alle Gruppen der Mandanten (Blätter zuerst).
func deleteGroups(t *testing.T, tenants ...string) {
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `UPDATE openwacht.devices SET group_id = NULL WHERE tenant_id = ANY($1::uuid[])`, tenants); err != nil {
		t.Error(err)
	}
	for range 5 {
		if _, err := owner.Exec(ctx, `DELETE FROM openwacht.device_groups g WHERE g.tenant_id = ANY($1::uuid[])
			AND NOT EXISTS (SELECT 1 FROM openwacht.device_groups c WHERE c.parent_id = g.id)`, tenants); err != nil {
			t.Error(err)
		}
	}
}

var gbOnce sync.Once

// groupSetup: Operator „gb_op“ im Lager Nord und je Mandant ein Gerät.
//
//	IT ─┬─ Fertigung ── Lager Nord
//	    └─ Organisation
func groupSetup(t *testing.T) (devs map[string]string) {
	t.Helper()
	verwaltungSetup(t)
	ctx := context.Background()
	gbOnce.Do(func() {
		hash, _ := auth.HashPassword(testPassword, testParams)
		var uid string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
			VALUES ($1, 'gb_op@test.invalid', 'gb_op', $2) RETURNING id::text`, ids["Lager Nord"], hash).Scan(&uid); err != nil {
			t.Fatal(err)
		}
		ids["gb_op"] = uid
		if _, err := owner.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'operator')`,
			uid, ids["Lager Nord"]); err != nil {
			t.Fatal(err)
		}
	})
	devs = map[string]string{}
	all := []string{}
	for _, tn := range []string{"IT", "Fertigung", "Lager Nord", "Organisation"} {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
			ids[tn], "GB "+tn).Scan(&id); err != nil {
			t.Fatal(err)
		}
		devs[tn] = id
		all = append(all, ids[tn])
	}
	t.Cleanup(func() {
		deleteGroups(t, all...)
		for _, d := range devs {
			owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = $1`, d)
		}
	})
	return devs
}

func newGroup(t *testing.T, user, tenant, name, parent string) response {
	t.Helper()
	return as(t, user).do("POST", "/api/v1/mandanten/"+ids[tenant]+"/gruppen", map[string]any{"name": name, "eltern_id": parent})
}

func createdID(t *testing.T, what string, r response) string {
	t.Helper()
	expectStatus(t, what, r, 201)
	id, _ := r.body["id"].(string)
	if id == "" {
		t.Fatalf("%s: keine ID", what)
	}
	return id
}

func groupMap(t *testing.T, user string) map[string]map[string]any {
	t.Helper()
	r := as(t, user).do("GET", "/api/v1/gruppen", nil)
	expectStatus(t, "Liste "+user, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.body["gruppen"].([]any) {
		e := x.(map[string]any)
		out[e["id"].(string)] = e
	}
	return out
}

func TestGruppenMandantentrennung(t *testing.T) {
	devs := groupSetup(t)
	gIT := createdID(t, "IT legt an", newGroup(t, "v_it", "IT", "GB Kern", ""))
	gFW := createdID(t, "Eltern legen beim Kind an", newGroup(t, "v_it", "Fertigung", "GB Halle", ""))
	gFW2 := createdID(t, "Admin legt an", newGroup(t, "v_fw", "Fertigung", "GB Maschinen", ""))
	gLZ := createdID(t, "Operator legt an", newGroup(t, "gb_op", "Lager Nord", "GB Regale", ""))
	gFWunterLZ := createdID(t, "Eltern legen im Enkel an", newGroup(t, "v_fw", "Lager Nord", "GB Netz", ""))
	gOA := createdID(t, "Organisation legt an", newGroup(t, "v_oa", "Organisation", "GB Büro", ""))

	expectStatus(t, "Kind legt bei Eltern an", newGroup(t, "v_fw", "IT", "GB x", ""), 403)
	expectStatus(t, "Geschwister legt an", newGroup(t, "v_oa", "Fertigung", "GB x", ""), 403)
	expectStatus(t, "Leser legt an", newGroup(t, "v_lz", "Lager Nord", "GB x", ""), 403)
	expectStatus(t, "Operator legt bei Eltern an", newGroup(t, "gb_op", "Fertigung", "GB x", ""), 403)
	expectStatus(t, "Eltern-Gruppe aus anderem Mandanten", newGroup(t, "v_it", "Fertigung", "GB x", gOA), 400)
	expectStatus(t, "Eltern-Gruppe unsichtbar", newGroup(t, "v_fw", "Fertigung", "GB x", gOA), 404)
	expectStatus(t, "Eltern-Gruppe des Eltern-Mandanten", newGroup(t, "v_it", "Lager Nord", "GB x", gFW), 400)

	// Lesen
	seen := func(user string, want, not []string) {
		t.Helper()
		m := groupMap(t, user)
		for _, id := range want {
			if m[id] == nil {
				t.Errorf("%s sieht %s nicht", user, id)
			}
		}
		for _, id := range not {
			if m[id] != nil {
				t.Errorf("%s sieht %s", user, id)
			}
		}
	}
	seen("v_it", []string{gIT, gFW, gFW2, gLZ, gOA}, nil)
	seen("v_fw", []string{gFW, gFW2, gLZ, gFWunterLZ}, []string{gIT, gOA})
	seen("v_lz", []string{gLZ, gFWunterLZ}, []string{gIT, gFW, gOA})
	seen("v_oa", []string{gOA}, []string{gIT, gFW, gLZ})
	if r := as(t, "v_oa").do("GET", "/api/v1/gruppen?mandant="+ids["Fertigung"], nil); r.status != 200 || len(r.body["gruppen"].([]any)) != 0 {
		t.Errorf("Filter auf fremden Mandanten: %d %s", r.status, r.raw)
	}
	expectStatus(t, "Filter kaputt", as(t, "v_it").do("GET", "/api/v1/gruppen?mandant=x", nil), 400)

	// Ändern
	upd := func(user, id, name, parent string) response {
		return as(t, user).do("PUT", "/api/v1/gruppen/"+id, map[string]any{"name": name, "eltern_id": parent})
	}
	expectStatus(t, "Geschwister benennt um", upd("v_oa", gFW, "gekapert", ""), 404)
	expectStatus(t, "Kind benennt Eltern-Gruppe um", upd("v_fw", gIT, "gekapert", ""), 404)
	expectStatus(t, "Leser benennt um", upd("v_lz", gLZ, "gekapert", ""), 404)
	expectStatus(t, "Operator benennt um", upd("gb_op", gLZ, "GB Regale neu", ""), 204)
	expectStatus(t, "Eltern benennen beim Kind um", upd("v_it", gFW, "GB Halle 1", ""), 204)
	expectStatus(t, "in anderen Mandanten verschieben", upd("v_it", gFW, "GB Halle 1", gOA), 400)
	expectStatus(t, "in Eltern-Mandant verschieben", upd("v_it", gLZ, "GB Regale neu", gFW), 400)
	expectStatus(t, "in unsichtbare Gruppe verschieben", upd("v_fw", gFW, "GB Halle 1", gIT), 404)
	if m := groupMap(t, "v_it"); m[gFW]["name"] != "GB Halle 1" || m[gLZ]["name"] != "GB Regale neu" || m[gFW]["eltern_id"] != nil {
		t.Errorf("nach Ändern: %v %v", m[gFW], m[gLZ])
	}

	// Sortieren
	pos := func(user, id, before string) response {
		return as(t, user).do("POST", "/api/v1/gruppen/"+id+"/position", map[string]any{"vor_id": before})
	}
	expectStatus(t, "Geschwister sortiert", pos("v_oa", gFW2, gFW), 404)
	expectStatus(t, "Leser sortiert", pos("v_lz", gFWunterLZ, gLZ), 404)
	expectStatus(t, "Leser sortiert (schon so)", pos("v_lz", gLZ, gFWunterLZ), 404)
	expectStatus(t, "Vor aus anderem Mandanten", pos("v_it", gFW2, gOA), 400)

	// Zuordnen
	assign := func(user, group string, devices ...string) response {
		return as(t, user).do("POST", "/api/v1/geraete/gruppe", map[string]any{"geraete": devices, "gruppe_id": group})
	}
	devGroup := func(dev string) any {
		var g *string
		if err := owner.QueryRow(context.Background(), `SELECT group_id::text FROM openwacht.devices WHERE id = $1`, dev).Scan(&g); err != nil {
			t.Fatal(err)
		}
		if g == nil {
			return nil
		}
		return *g
	}
	expectStatus(t, "Geschwister ordnet zu", assign("v_oa", gOA, devs["Fertigung"]), 404)
	expectStatus(t, "fremde Gruppe", assign("v_fw", gOA, devs["Fertigung"]), 404)
	expectStatus(t, "Gerät des Eltern-Mandanten", assign("v_fw", gFW, devs["IT"]), 404)
	expectStatus(t, "Leser ordnet zu", assign("v_lz", gLZ, devs["Lager Nord"]), 403)
	expectStatus(t, "Gerät in Gruppe des Kinds", assign("v_it", gLZ, devs["Fertigung"]), 400)
	expectStatus(t, "gemischt: eins unsichtbar", assign("v_fw", gFW, devs["Fertigung"], devs["Organisation"]), 404)
	expectStatus(t, "gemischt: zwei Mandanten", assign("v_it", gFW, devs["Fertigung"], devs["Lager Nord"]), 400)
	if devGroup(devs["Fertigung"]) != nil || devGroup(devs["Lager Nord"]) != nil {
		t.Error("abgelehnte Zuordnung hat etwas geändert")
	}
	expectStatus(t, "Eltern ordnen zu", assign("v_it", gFW, devs["Fertigung"]), 204)
	expectStatus(t, "Operator ordnet zu", assign("gb_op", gLZ, devs["Lager Nord"]), 204)
	if devGroup(devs["Fertigung"]) != gFW || devGroup(devs["Lager Nord"]) != gLZ {
		t.Error("Zuordnung fehlt")
	}
	// Ohne Gruppe geht über Mandanten hinweg, aber nur mit Recht auf alle.
	expectStatus(t, "lösen mit Leser-Gerät", assign("gb_op", "", devs["Lager Nord"], devs["Fertigung"]), 404)
	expectStatus(t, "lösen über Mandanten", assign("v_it", "", devs["Lager Nord"], devs["Fertigung"]), 204)
	if devGroup(devs["Fertigung"]) != nil || devGroup(devs["Lager Nord"]) != nil {
		t.Error("lösen hat nicht gewirkt")
	}

	// Löschen
	del := func(user, id string) response { return as(t, user).do("DELETE", "/api/v1/gruppen/"+id, nil) }
	expectStatus(t, "Geschwister löscht", del("v_oa", gFW), 404)
	expectStatus(t, "Kind löscht Eltern-Gruppe", del("v_fw", gIT), 404)
	expectStatus(t, "Leser löscht", del("v_lz", gLZ), 404)
	expectStatus(t, "Operator löscht", del("gb_op", gLZ), 200)
	expectStatus(t, "Eltern löschen beim Kind", del("v_it", gFW), 200)
	expectStatus(t, "zweimal", del("v_it", gFW), 404)
	if m := groupMap(t, "v_it"); m[gLZ] != nil || m[gFW] != nil || m[gFW2] == nil {
		t.Error("Löschen")
	}
}

func TestGruppenBaum(t *testing.T) {
	devs := groupSetup(t)
	mk := func(name, parent string) string {
		t.Helper()
		return createdID(t, "anlegen "+name, newGroup(t, "v_fw", "Fertigung", name, parent))
	}
	upd := func(id, name, parent string) response {
		return as(t, "v_fw").do("PUT", "/api/v1/gruppen/"+id, map[string]any{"name": name, "eltern_id": parent})
	}

	// Namen
	for name, n := range map[string]string{
		"leer": "  ", "Schrägstrich": "a/b", "zu lang": strings.Repeat("ä", 51), "Steuerzeichen": "a\x07", "Tab": "a\tb",
	} {
		expectStatus(t, "Name "+name, newGroup(t, "v_fw", "Fertigung", n, ""), 400)
	}
	expectStatus(t, "unbekanntes Feld", as(t, "v_fw").do("POST", "/api/v1/mandanten/"+ids["Fertigung"]+"/gruppen",
		map[string]any{"name": "x", "pfad": "a/b"}), 400)
	expectStatus(t, "Eltern kein UUID", newGroup(t, "v_fw", "Fertigung", "x", "Netzwerk"), 400)
	a := mk(strings.Repeat("ä", 50), "")
	expectStatus(t, "Name auf 50 gekürzt umbenannt", upd(a, "  Netzwerk  ", ""), 204)
	expectStatus(t, "doppelt ohne Groß/Klein", newGroup(t, "v_fw", "Fertigung", "NETZWERK", ""), 409)
	b := mk("Switche", a)
	mk("Netzwerk", b) // gleicher Name auf anderer Ebene geht
	if m := groupMap(t, "v_fw"); m[a]["name"] != "Netzwerk" {
		t.Errorf("Name nicht getrimmt: %v", m[a]["name"])
	}

	// Tiefe: a > b > c > d geht, e darunter nicht.
	c := mk("Lancom", b)
	d := mk("Etage 1", c)
	expectStatus(t, "fünfte Ebene", newGroup(t, "v_fw", "Fertigung", "zu tief", d), 400)
	// Zyklen
	expectStatus(t, "in sich selbst", upd(a, "Netzwerk", a), 400)
	r := upd(a, "Netzwerk", c)
	expectStatus(t, "in Enkel", r, 400)
	if msg, _ := r.body["fehler"].(string); !strings.Contains(msg, "in sich selbst") {
		t.Errorf("Meldung bei Zyklus: %q", msg)
	}
	expectStatus(t, "in Urenkel", upd(b, "Switche", d), 400)
	// Teilbaum zu tief: x > y unter c wäre Ebene 4 und 5.
	x := mk("X", "")
	y := mk("Y", x)
	expectStatus(t, "Teilbaum zu tief", upd(x, "X", c), 400)
	expectStatus(t, "Teilbaum passt", upd(x, "X", b), 204)
	if m := groupMap(t, "v_fw"); m[x]["eltern_id"] != b || m[y]["eltern_id"] != x {
		t.Errorf("verschoben: %v %v", m[x], m[y])
	}
	expectStatus(t, "Name kollidiert beim Verschieben", upd(mk("lancom", ""), "lancom", b), 409)

	// Reihenfolge: neu und verschoben jeweils ans Ende.
	order := func(parent string) string {
		t.Helper()
		type g struct {
			name string
			pos  float64
		}
		var list []g
		for _, e := range groupMap(t, "v_fw") {
			p, _ := e["eltern_id"].(string)
			if e["mandant_id"] == ids["Fertigung"] && p == parent {
				list = append(list, g{e["name"].(string), e["position"].(float64)})
			}
		}
		names := make([]string, len(list))
		for i := range list {
			for j := range list {
				if int(list[j].pos) == i {
					names[i] = list[j].name
				}
			}
		}
		return strings.Join(names, ",")
	}
	if got := order(b); got != "Netzwerk,Lancom,X" {
		t.Errorf("Reihenfolge unter Switche: %s", got)
	}
	pos := func(id, before string) response {
		return as(t, "v_fw").do("POST", "/api/v1/gruppen/"+id+"/position", map[string]any{"vor_id": before})
	}
	var netz2 string
	for id, e := range groupMap(t, "v_fw") {
		if e["eltern_id"] == b && e["name"] == "Netzwerk" {
			netz2 = id
		}
	}
	expectStatus(t, "X nach vorn", pos(x, netz2), 204)
	if got := order(b); got != "X,Netzwerk,Lancom" {
		t.Errorf("nach vorn: %s", got)
	}
	expectStatus(t, "X ans Ende", pos(x, ""), 204)
	if got := order(b); got != "Netzwerk,Lancom,X" {
		t.Errorf("ans Ende: %s", got)
	}
	expectStatus(t, "vor sich selbst", pos(x, x), 204)
	expectStatus(t, "vor Nicht-Geschwister", pos(x, a), 400)
	expectStatus(t, "vor kein UUID", pos(x, "x"), 400)
	expectStatus(t, "unbekannt", pos("00000000-0000-0000-0000-000000000001", ""), 404)

	// Löschen: Inhalt wandert eine Ebene höher.
	assign := func(group string, devices ...string) response {
		return as(t, "v_fw").do("POST", "/api/v1/geraete/gruppe", map[string]any{"geraete": devices, "gruppe_id": group})
	}
	expectStatus(t, "Gerät in Lancom", assign(c, devs["Fertigung"], devs["Lager Nord"]), 400) // zwei Mandanten
	expectStatus(t, "Gerät in Lancom", assign(c, devs["Fertigung"]), 204)
	expectStatus(t, "doppelte ID", assign(c, devs["Fertigung"], devs["Fertigung"]), 400)
	expectStatus(t, "keine Geräte", assign(c), 400)
	many := make([]string, maxAssign+1)
	for i := range many {
		many[i] = devs["Fertigung"]
	}
	expectStatus(t, "zu viele", assign(c, many...), 400)
	// Viele Geräte auf einmal: Das Audit-Log teilt die Liste (8 KiB je Eintrag).
	ctx := context.Background()
	bulk := make([]string, maxAssign)
	for i := range bulk {
		if err := owner.QueryRow(ctx, `INSERT INTO openwacht.devices (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
			ids["Fertigung"], "GB Massen "+string(rune('A'+i%26))).Scan(&bulk[i]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { owner.Exec(ctx, `DELETE FROM openwacht.devices WHERE id = ANY($1::uuid[])`, bulk) })
	expectStatus(t, "300 auf einmal", assign(c, bulk...), 204)
	var nb int
	owner.QueryRow(ctx, `SELECT count(*) FROM openwacht.devices WHERE id = ANY($1::uuid[]) AND group_id = $2`, bulk, c).Scan(&nb)
	if nb != maxAssign {
		t.Errorf("300 auf einmal: %d zugeordnet", nb)
	}
	expectStatus(t, "300 lösen", assign("", bulk...), 204)
	r = as(t, "v_fw").do("DELETE", "/api/v1/gruppen/"+c, nil)
	expectStatus(t, "Lancom löschen", r, 200)
	if r.body["geraete"] != 1.0 || r.body["untergruppen"] != 1.0 {
		t.Errorf("Antwort: %s", r.raw)
	}
	m := groupMap(t, "v_fw")
	if m[d]["eltern_id"] != b {
		t.Errorf("Untergruppe nicht hochgewandert: %v", m[d])
	}
	if e, _ := deviceEntry(t, "v_fw", devs["Fertigung"]); e["gruppe_id"] != b {
		t.Errorf("Gerät nicht hochgewandert: %v", e["gruppe_id"])
	}
	// Konflikt: Unter Switche gibt es „Netzwerk“; eine Untergruppe „netzwerk“ von X kollidiert.
	z := mk("netzwerk", x)
	expectStatus(t, "Konflikt beim Hochwandern", as(t, "v_fw").do("DELETE", "/api/v1/gruppen/"+x, nil), 409)
	if m := groupMap(t, "v_fw"); m[x] == nil || m[z]["eltern_id"] != x || m[y]["eltern_id"] != x {
		t.Error("Konflikt hat trotzdem etwas geändert")
	}
	// Oberste Ebene löschen: Geräte sind danach ohne Gruppe.
	top := mk("Oben", "")
	expectStatus(t, "Gerät nach oben", assign(top, devs["Fertigung"]), 204)
	expectStatus(t, "oberste Gruppe löschen", as(t, "v_fw").do("DELETE", "/api/v1/gruppen/"+top, nil), 200)
	if e, _ := deviceEntry(t, "v_fw", devs["Fertigung"]); e["gruppe_id"] != nil {
		t.Errorf("Gerät nach Löschen der obersten Gruppe: %v", e["gruppe_id"])
	}

	// Audit
	var n int
	if err := owner.QueryRow(context.Background(), `SELECT count(*) FROM openwacht.audit_log WHERE tenant_id = $1
		AND action IN ('gruppe.angelegt', 'gruppe.geaendert', 'gruppe.sortiert', 'gruppe.geloescht', 'geraete.gruppe')
		AND at > now() - interval '5 minutes'`, ids["Fertigung"]).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 15 {
		t.Errorf("Audit-Einträge: %d", n)
	}
}

// Die Datenbank schützt den Baum auch ohne Anwendung.
func TestGruppenDatenbank(t *testing.T) {
	groupSetup(t)
	ctx := context.Background()
	fw, oa := ids["Fertigung"], ids["Organisation"]
	a := ownerGroupPath(t, fw, "DB A")
	b := ownerGroupPath(t, fw, "DB B")
	o := ownerGroupPath(t, oa, "DB O")
	for name, q := range map[string]string{
		"Mandant ändern":         `UPDATE openwacht.device_groups SET tenant_id = '` + oa + `' WHERE id = '` + *a + `'`,
		"Eltern anderer Mandant": `UPDATE openwacht.device_groups SET parent_id = '` + *o + `' WHERE id = '` + *a + `'`,
		"Name mit Schrägstrich":  `UPDATE openwacht.device_groups SET name = 'a/b' WHERE id = '` + *a + `'`,
		"Name mit Leerzeichen":   `UPDATE openwacht.device_groups SET name = ' a' WHERE id = '` + *a + `'`,
		"in sich selbst":         `UPDATE openwacht.device_groups SET parent_id = id WHERE id = '` + *a + `'`,
		"Position negativ":       `UPDATE openwacht.device_groups SET position = -1 WHERE id = '` + *a + `'`,
		"Gruppe löschen mit Kind": `WITH c AS (INSERT INTO openwacht.device_groups (tenant_id, parent_id, name) VALUES ('` + fw + `', '` + *a +
			`', 'Kind') RETURNING id) DELETE FROM openwacht.device_groups WHERE id = '` + *a + `'`,
	} {
		if _, err := owner.Exec(ctx, q); err == nil {
			t.Errorf("%s: angenommen", name)
		}
	}

	// Gleichzeitig A in B und B in A: Die Sperre macht daraus nacheinander,
	// die zweite Änderung scheitert am Zyklus.
	// Beide als Admin der Fertigung über die App-Rolle, also mit RLS.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(ctx)
	move := func(tx pgx.Tx, id, parent string) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, ids["v_fw"]); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.device_groups SET parent_id = $2 WHERE id = $1`, id, parent)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("keine Zeile geändert")
		}
		return err
	}
	if err := move(tx1, *a, *b); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return move(tx, *b, *a) })
	}()
	select {
	case err := <-done:
		t.Fatalf("zweite Änderung wartet nicht auf die Sperre: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.ConstraintName != "device_groups_cycle" {
		t.Errorf("zweite Änderung: %v", err)
	}
}
