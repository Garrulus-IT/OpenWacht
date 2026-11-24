// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/oidc"
	"github.com/garrulus-it/openwacht/internal/verzeichnis"
)

// Anmeldung mit AD-Konto (Etappe 22a). Anbindungen gehören einem Mandanten
// (pflegen dessen Admins), Gruppen werden auf Mandanten im Teilbaum und
// Rollen abgebildet. Das Passwort des Dienstkontos ist verschlüsselt und an
// Anbindung, Mandant, Adresse und Dienstkonto gebunden.

func (s *Server) ldapKey() []byte { return deriveKey(s.boxKey, "openwacht ldap v1") }

func ldapAAD(id, tenant, url, bindDN string) []byte {
	return []byte("openwacht ldap v1|" + id + "|" + tenant + "|" + url + "|" + bindDN)
}

// dirRow: eine Anbindung mit entschlüsseltem Dienstkonto.
type dirRow struct {
	ID, Tenant, URL, BindDN, BaseDN string
	CAPEM                           *string
	PassEnc                         []byte
	Nested                          bool
	Kind                            string // ldap oder oidc (nicht überall gelesen)
	EmailClaim                      string // nur OIDC: Claim mit der Adresse (nicht überall gelesen)
}

func (s *Server) dirConfig(d dirRow) (verzeichnis.Config, error) {
	pass, err := auth.Open(s.ldapKey(), d.PassEnc, ldapAAD(d.ID, d.Tenant, d.URL, d.BindDN))
	if err != nil {
		return verzeichnis.Config{}, errors.New("Passwort des Dienstkontos nicht lesbar")
	}
	c := verzeichnis.Config{URL: d.URL, BindDN: d.BindDN, BindPassword: string(pass), BaseDN: d.BaseDN, NestedGroups: d.Nested,
		Dial: s.ldapDial(d.Tenant)}
	if d.CAPEM != nil {
		c.CAPEM = *d.CAPEM
	}
	return c, nil
}

// ldapDial: Auch der Verzeichnisdienst muss in der Netzfreigabe liegen (global
// und für den Mandanten), sonst könnte ein Mandanten-Admin das Netz abtasten.
func (s *Server) ldapDial(tenant string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.ldapDialOverride != nil {
		return s.ldapDialOverride
	}
	g := s.guardFor(tenant)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := g.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("%w (liegt der Verzeichnisdienst in der Netzfreigabe?)", err)
		}
		return c, nil
	}
}

const dirCols = `d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem, d.bind_pass_enc, d.nested_groups`

func scanDir(row pgx.Row) (dirRow, error) {
	var d dirRow
	err := row.Scan(&d.ID, &d.Tenant, &d.URL, &d.BindDN, &d.BaseDN, &d.CAPEM, &d.PassEnc, &d.Nested)
	return d, err
}

// accountEmail: Adresse des Kontos, nur aus den Domänen der Anbindung.
func (s *Server) accountEmail(ctx context.Context, dirID string, u verzeichnis.User) (string, error) {
	rows, err := s.pool.Query(ctx, `SELECT openwacht.directory_domain_list($1)`, dirID)
	if err != nil {
		return "", err
	}
	doms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", err
	}
	for _, e := range []string{strings.ToLower(u.UPN), strings.ToLower(u.Mail)} {
		at := strings.LastIndexByte(e, '@')
		if at > 0 && len(e) <= 254 && slices.Contains(doms, e[at+1:]) {
			return e, nil
		}
	}
	return "", nil
}

func (s *Server) groupMap(ctx context.Context, dirID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT group_dn FROM openwacht.directory_group_map($1)`, dirID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// errDirectoryDown: Verzeichnis nicht erreichbar (Anmeldung meldet das).
var errDirectoryDown = errors.New("Verzeichnis nicht erreichbar")

// directoryLogin meldet login am passenden Verzeichnis an und gleicht das
// Konto ab. Rückgabe: Konto-ID oder "" (abgelehnt).
func (s *Server) directoryLogin(ctx context.Context, login, password string) (string, error) {
	_, domain, netbios := verzeichnis.SplitLogin(login)
	if domain == "" && netbios == "" {
		return "", nil
	}
	var dom, nb *string
	if domain != "" {
		dom = &domain
	}
	if netbios != "" {
		nb = &netbios
	}
	var kind string
	row := s.pool.QueryRow(ctx, `SELECT d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem,
		d.bind_pass_enc, d.nested_groups, d.kind FROM openwacht.directory_for_login($1, $2) d`, dom, nb)
	var d dirRow
	err := row.Scan(&d.ID, &d.Tenant, &d.URL, &d.BindDN, &d.BaseDN, &d.CAPEM, &d.PassEnc, &d.Nested, &kind)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "ldap") {
		return "", nil // OIDC: Anmeldung nur über die Weiterleitung
	}
	if err != nil {
		return "", err
	}
	cfg, err := s.dirConfig(d)
	if err != nil {
		return "", err
	}
	groups, err := s.groupMap(ctx, d.ID)
	if err != nil {
		return "", err
	}
	u, err := cfg.Authenticate(ctx, login, password, groups)
	switch {
	case errors.Is(err, verzeichnis.ErrBadPassword), errors.Is(err, verzeichnis.ErrNotFound), errors.Is(err, verzeichnis.ErrAmbiguous):
		return "", nil
	case err != nil:
		slog.Warn("Verzeichnis: Anmeldung nicht möglich", "anbindung", d.ID, "fehler", err)
		return "", errDirectoryDown
	}
	email, err := s.accountEmail(ctx, d.ID, u)
	if err != nil {
		return "", err
	}
	if email == "" {
		slog.Warn("Verzeichnis: UPN bzw. mail passt zu keiner Domäne der Anbindung", "dn", u.DN)
		return "", nil
	}
	var id *string
	if err := s.pool.QueryRow(ctx, `SELECT openwacht.directory_user_sync($1, $2, $3, $4, $5, $6)::text`,
		d.ID, u.ID, email, u.Name, u.Groups, !u.Disabled).Scan(&id); err != nil {
		return "", err
	}
	if id == nil || u.Disabled {
		return "", nil
	}
	return *id, nil
}

// SyncDirectories gleicht alle Konten aller Anbindungen mit dem Verzeichnis
// ab (Gruppen, gesperrt, entfernt). Läuft stündlich.
func (s *Server) SyncDirectories(ctx context.Context) {
	rows, err := s.pool.Query(ctx, `SELECT `+dirCols+` FROM openwacht.directory_sync_list() d`)
	if err != nil {
		slog.Warn("Verzeichnis-Abgleich", "fehler", err)
		return
	}
	dirs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (dirRow, error) { return scanDir(r) })
	if err != nil {
		slog.Warn("Verzeichnis-Abgleich", "fehler", err)
		return
	}
	for _, d := range dirs {
		if err := s.syncDirectory(ctx, d); err != nil {
			slog.Warn("Verzeichnis-Abgleich", "anbindung", d.ID, "fehler", err)
		}
	}
}

func (s *Server) syncDirectory(ctx context.Context, d dirRow) error {
	cfg, err := s.dirConfig(d)
	if err != nil {
		return err
	}
	groups, err := s.groupMap(ctx, d.ID)
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `SELECT user_id::text, external_id, email FROM openwacht.directory_users($1)`, d.ID)
	if err != nil {
		return err
	}
	type acc struct{ id, ext, email string }
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (acc, error) {
		var a acc
		err := r.Scan(&a.id, &a.ext, &a.email)
		return a, err
	})
	if err != nil || len(users) == 0 {
		return err
	}
	conn, err := cfg.Session(ctx)
	if err != nil {
		return err // Verzeichnis weg: nichts sperren
	}
	defer conn.Close()
	for _, a := range users {
		u, err := cfg.LookupByID(ctx, conn, a.ext, groups)
		if errors.Is(err, verzeichnis.ErrNotFound) {
			if _, err := s.pool.Exec(ctx, `SELECT openwacht.directory_user_gone($1)`, a.id); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		email, err := s.accountEmail(ctx, d.ID, u)
		if err != nil {
			return err
		}
		if email == "" {
			email = a.email
		}
		if _, err := s.pool.Exec(ctx, `SELECT openwacht.directory_user_sync($1, $2, $3, $4, $5, $6)`,
			d.ID, u.ID, email, u.Name, u.Groups, !u.Disabled); err != nil {
			slog.Warn("Verzeichnis-Abgleich: Konto", "konto", a.email, "fehler", err)
		}
	}
	return nil
}

// RunDirectorySync gleicht alle 60 Minuten ab.
func (s *Server) RunDirectorySync(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SyncDirectories(ctx)
		}
	}
}

// --- API: Anbindungen ----------------------------------------------------------

type dirIn struct {
	Art           string   `json:"art"` // ldap (Standard) oder oidc
	ClientID      string   `json:"client_id"`
	GruppenClaim  string   `json:"gruppen_claim"`
	AdressClaim   string   `json:"adress_claim"` // nur OIDC: email (Standard), upn oder preferred_username
	Mandant       string   `json:"mandant"`
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	CA            string   `json:"ca"`
	BindDN        string   `json:"bind_dn"`
	Passwort      string   `json:"passwort"`
	BaseDN        string   `json:"base_dn"`
	NetBIOS       string   `json:"netbios"`
	Domaenen      []string `json:"domaenen"`
	Verschachtelt *bool    `json:"verschachtelt"`
	ZweiFaktor    bool     `json:"zwei_faktor"`
	Aktiv         *bool    `json:"aktiv"`
	// Höchstdauer der Sitzung in Stunden (1–12), 0 oder fehlend = Standard
	SitzungStunden int    `json:"sitzung_stunden"`
	Code           string `json:"code"`
	Gruppen        []struct {
		Gruppe  string `json:"gruppe"`
		Mandant string `json:"mandant"`
		Rolle   string `json:"rolle"`
	} `json:"gruppen"`
}

var (
	claimRe   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,100}$`)
	netbiosRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
	domainRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

func cleanDN(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) < 3 || len(s) > 1000 || !strings.Contains(s, "=") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", badRequest(what + " bitte als DN angeben, z. B. CN=svc-openwacht,OU=Dienste,DC=firma,DC=de.")
	}
	return s, nil
}

func (in *dirIn) validate() error {
	var err error
	if in.Name, err = cleanName(in.Name); err != nil {
		return err
	}
	in.URL = strings.TrimSpace(in.URL)
	switch in.Art {
	case "", "ldap":
		in.Art = "ldap"
		if strings.TrimSpace(in.AdressClaim) != "" && strings.TrimSpace(in.AdressClaim) != "email" {
			return badRequest("Den Adress-Claim gibt es nur bei OIDC.")
		}
		in.AdressClaim = "email"
		if _, _, _, err := verzeichnis.ValidateURL(in.URL); err != nil {
			return badRequest(err.Error() + ".")
		}
		if in.BindDN, err = cleanDN(in.BindDN, "Dienstkonto"); err != nil {
			return err
		}
		if in.BaseDN, err = cleanDN(in.BaseDN, "Basis-DN"); err != nil {
			return err
		}
	case "oidc":
		if err := oidc.ValidateIssuer(in.URL); err != nil {
			return badRequest(err.Error() + ".")
		}
		in.BindDN = strings.TrimSpace(in.ClientID)
		if in.BindDN == "" || len(in.BindDN) > 200 || strings.ContainsFunc(in.BindDN, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return badRequest("Client-ID fehlt oder ist zu lang.")
		}
		if len(in.BindDN) < 3 {
			return badRequest("Client-ID: mindestens 3 Zeichen.")
		}
		in.BaseDN = strings.TrimSpace(in.GruppenClaim)
		if in.BaseDN == "" {
			in.BaseDN = "groups"
		}
		if !claimRe.MatchString(in.BaseDN) {
			return badRequest("Gruppen-Claim: Buchstaben, Ziffern und _ . : / - (z. B. groups).")
		}
		in.AdressClaim = strings.TrimSpace(in.AdressClaim)
		if in.AdressClaim == "" {
			in.AdressClaim = "email"
		}
		if !oidc.ValidEmailClaim(in.AdressClaim) {
			return badRequest("Adress-Claim: email, upn oder preferred_username.")
		}
		if strings.TrimSpace(in.NetBIOS) != "" {
			return badRequest("NetBIOS-Namen gibt es nur bei LDAP.")
		}
		f := false
		in.Verschachtelt = &f
	default:
		return badRequest("Art: ldap oder oidc.")
	}
	in.NetBIOS = strings.TrimSpace(in.NetBIOS)
	if in.NetBIOS != "" && !netbiosRe.MatchString(in.NetBIOS) {
		return badRequest("NetBIOS-Name: 1 bis 15 Buchstaben, Ziffern oder -.")
	}
	var doms []string
	for _, d := range in.Domaenen {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !domainRe.MatchString(d) || !strings.Contains(d, ".") {
			return badRequest(fmt.Sprintf("Domäne %q ist ungültig.", d))
		}
		if !slices.Contains(doms, d) {
			doms = append(doms, d)
		}
	}
	if len(doms) == 0 && in.NetBIOS == "" {
		return badRequest("Mindestens eine Domäne (UPN-Suffix, z. B. firma.de) oder den NetBIOS-Namen angeben.")
	}
	if len(doms) > 20 {
		return badRequest("Höchstens 20 Domänen.")
	}
	if doms == nil {
		doms = []string{}
	}
	in.Domaenen = doms
	if in.SitzungStunden < 0 || in.SitzungStunden > 12 {
		return badRequest("Höchstdauer der Sitzung: 1 bis 12 Stunden (leer = Standard 12 Stunden).")
	}
	in.CA = strings.TrimSpace(in.CA)
	if len(in.CA) > 65536 {
		return badRequest("CA-Zertifikat zu groß.")
	}
	if len(in.Passwort) > 1000 {
		return badRequest("Passwort zu lang.")
	}
	if len(in.Gruppen) > 200 {
		return badRequest("Höchstens 200 Gruppen.")
	}
	for i := range in.Gruppen {
		g := &in.Gruppen[i]
		if in.Art == "oidc" {
			g.Gruppe = strings.TrimSpace(g.Gruppe)
			if g.Gruppe == "" || len(g.Gruppe) > 1000 || strings.ContainsFunc(g.Gruppe, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return badRequest("Gruppe: Wert aus dem Gruppen-Claim angeben.")
			}
		} else if g.Gruppe, err = cleanDN(g.Gruppe, "Gruppe"); err != nil {
			return err
		}
		if !uuidPattern.MatchString(g.Mandant) {
			return badRequest("Mandant der Gruppe fehlt.")
		}
		if g.Rolle != "admin" && g.Rolle != "operator" && g.Rolle != "leser" {
			return badRequest("Rolle: admin, operator oder leser.")
		}
	}
	return nil
}

func (s *Server) handleDirList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "verzeichnisse", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT d.id::text, d.tenant_id::text, t.name, d.name, d.url, d.ca_pem IS NOT NULL, d.bind_dn, d.base_dn,
			d.netbios, d.nested_groups, d.mfa_required, d.enabled, d.kind, d.email_claim, d.netbios_status, coalesce(d.session_hours, 0),
			coalesce((SELECT array_agg(dd.domain ORDER BY dd.domain) FROM openwacht.directory_domains dd WHERE dd.directory_id = d.id), '{}'),
			coalesce((SELECT jsonb_object_agg(dd.domain, dd.status) FROM openwacht.directory_domains dd WHERE dd.directory_id = d.id), '{}'),
			coalesce((SELECT jsonb_agg(jsonb_build_object('gruppe', g.group_dn, 'mandant', g.target_tenant, 'rolle', g.role) ORDER BY g.group_dn)
			          FROM openwacht.directory_groups g WHERE g.directory_id = d.id), '[]'),
			(SELECT count(*) FROM openwacht.users u WHERE u.directory_id = d.id)
			FROM openwacht.directories d JOIN openwacht.tenants t ON t.id = d.tenant_id ORDER BY t.name, d.name`)
		if err != nil {
			return 0, nil, err
		}
		list := []map[string]any{}
		for rows.Next() {
			var id, tid, tname, name, url, bind, base, kind, emailClaim, nbStatus string
			var hours int
			var domStatus map[string]string
			var nb *string
			var hasCA, nested, mfa, enabled bool
			var doms []string
			var groups []map[string]any
			var users int
			if err := rows.Scan(&id, &tid, &tname, &name, &url, &hasCA, &bind, &base, &nb, &nested, &mfa, &enabled, &kind, &emailClaim, &nbStatus, &hours, &doms, &domStatus, &groups, &users); err != nil {
				return 0, nil, err
			}
			list = append(list, map[string]any{"id": id, "mandant": tid, "mandant_name": tname, "name": name, "url": url,
				"eigene_ca": hasCA, "bind_dn": bind, "base_dn": base, "netbios": nb, "verschachtelt": nested, "zwei_faktor": mfa,
				"aktiv": enabled, "domaenen": doms, "gruppen": groups, "konten": users, "art": kind, "adress_claim": emailClaim,
				// Etappe 30: beantragt, freigegeben oder abgelehnt (Untermandanten brauchen die Freigabe des Betreibers)
				"domaenen_status": domStatus, "netbios_status": nbStatus, "sitzung_stunden": hours})
		}
		return http.StatusOK, map[string]any{"verzeichnisse": list, "sso_rueckkehr": s.ssoRedirect()}, rows.Err()
	})
}

// testDir prüft Verbindung und Dienstkonto, bevor gespeichert wird.
func (s *Server) testDir(ctx context.Context, tenant string, in *dirIn, pass string) error {
	if in.Art == "oidc" {
		c := oidc.Config{Issuer: in.URL, ClientID: in.BindDN, ClientSecret: pass, CAPEM: in.CA, Dial: s.ldapDial(tenant)}
		if _, err := c.Discover(ctx); err != nil {
			return &apiError{http.StatusBadGateway, "Verbindung zum Identity Provider: " + err.Error() + "."}
		}
		return nil
	}
	c := verzeichnis.Config{URL: in.URL, CAPEM: in.CA, BindDN: in.BindDN, BindPassword: pass, BaseDN: in.BaseDN,
		Dial: s.ldapDial(tenant), Timeout: 10 * time.Second}
	if err := c.Test(ctx); err != nil {
		return &apiError{http.StatusBadGateway, "Verbindung zum Verzeichnis: " + err.Error() + "."}
	}
	return nil
}

func (s *Server) saveDirChildren(ctx context.Context, tx pgx.Tx, id, tenant string, in *dirIn) error {
	// Nur entfernte Domänen löschen und neue anlegen: Eine Freigabe durch den
	// Betreiber (Untermandanten, Etappe 30) bleibt beim Ändern erhalten.
	if _, err := tx.Exec(ctx, `DELETE FROM openwacht.directory_domains WHERE directory_id = $1 AND NOT (domain = ANY($2))`, id, in.Domaenen); err != nil {
		return err
	}
	for _, d := range in.Domaenen {
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.directory_domains (domain, directory_id, tenant_id) VALUES ($1, $2, $3)
			ON CONFLICT (domain, directory_id) DO NOTHING`, d, id, tenant); err != nil {
			return err
		}
	}
	if in.Gruppen == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM openwacht.directory_groups WHERE directory_id = $1`, id); err != nil {
		return err
	}
	for _, g := range in.Gruppen {
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.directory_groups (directory_id, tenant_id, group_dn, target_tenant, role)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (directory_id, group_dn, target_tenant) DO UPDATE SET role = EXCLUDED.role`,
			id, tenant, g.Gruppe, g.Mandant, g.Rolle); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleDirCreate(w http.ResponseWriter, r *http.Request) {
	var in dirIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "verzeichnis anlegen", err) }
	if err := in.validate(); err != nil {
		fail(err)
		return
	}
	if !uuidPattern.MatchString(in.Mandant) {
		fail(badRequest("Mandant fehlt."))
		return
	}
	if in.Passwort == "" {
		fail(badRequest("Passwort des Dienstkontos bzw. Client-Secret fehlt."))
		return
	}
	// Erst Rechte (Admin des Mandanten), dann Bestätigung, dann Verbindungstest.
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(r.Context(), `SELECT $1::uuid IN (SELECT openwacht.admin_tenants())`, in.Mandant).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return &apiError{http.StatusForbidden, "Nur Admins des Mandanten richten die Anmeldung ein."}
		}
		return nil
	}); err != nil {
		fail(err)
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	if err := s.testDir(r.Context(), in.Mandant, &in, in.Passwort); err != nil {
		fail(err)
		return
	}
	id, err := newUUID()
	if err != nil {
		fail(err)
		return
	}
	enc, err := auth.Seal(s.ldapKey(), []byte(in.Passwort), ldapAAD(id, in.Mandant, in.URL, in.BindDN))
	if err != nil {
		fail(err)
		return
	}
	nested := in.Verschachtelt == nil || *in.Verschachtelt
	s.handle(w, r, "verzeichnis anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var ca *string
		if in.CA != "" {
			ca = &in.CA
		}
		var nb *string
		if in.NetBIOS != "" {
			nb = &in.NetBIOS
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.directories (id, tenant_id, name, url, ca_pem, bind_dn, bind_pass_enc, base_dn,
			netbios, nested_groups, mfa_required, kind, email_claim, session_hours) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			id, in.Mandant, in.Name, in.URL, ca, in.BindDN, enc, in.BaseDN, nb, nested, in.ZweiFaktor, in.Art, in.AdressClaim, sessionHours(in.SitzungStunden)); err != nil {
			return 0, nil, err
		}
		if err := s.saveDirChildren(ctx, tx, id, in.Mandant, &in); err != nil {
			return 0, nil, err
		}
		tid := in.Mandant
		return http.StatusCreated, map[string]any{"id": id},
			audit(ctx, tx, &tid, "verzeichnis.angelegt", map[string]any{"name": in.Name, "url": in.URL, "domaenen": in.Domaenen})
	})
}

func (s *Server) handleDirUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in dirIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "verzeichnis ändern", err) }
	if err := in.validate(); err != nil {
		fail(err)
		return
	}
	var cur dirRow
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		var err error
		err = tx.QueryRow(r.Context(), `SELECT d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem,
			NULL::bytea, d.nested_groups, d.kind FROM openwacht.directories d WHERE d.id = $1`, id).
			Scan(&cur.ID, &cur.Tenant, &cur.URL, &cur.BindDN, &cur.BaseDN, &cur.CAPEM, &cur.PassEnc, &cur.Nested, &cur.Kind)
		return err
	}); err != nil {
		fail(err)
		return
	}
	if cur.Kind != in.Art {
		fail(badRequest("Die Art der Anbindung lässt sich nicht ändern."))
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	pass := in.Passwort
	if pass == "" {
		curCA := ""
		if cur.CAPEM != nil {
			curCA = *cur.CAPEM
		}
		if in.URL != cur.URL || in.BindDN != cur.BindDN || in.CA != curCA {
			fail(badRequest("Bei neuer Adresse, neuem Dienstkonto oder neuer CA bitte das Passwort neu eingeben."))
			return
		}
		if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(), `SELECT openwacht.directory_secret($1)`, id).Scan(&cur.PassEnc)
		}); err != nil || cur.PassEnc == nil {
			fail(badRequest("Bitte das Passwort des Dienstkontos neu eingeben."))
			return
		}
		c, err := s.dirConfig(cur)
		if err != nil {
			fail(err)
			return
		}
		pass = c.BindPassword
	}
	if err := s.testDir(r.Context(), cur.Tenant, &in, pass); err != nil {
		fail(err)
		return
	}
	enc, err := auth.Seal(s.ldapKey(), []byte(pass), ldapAAD(id, cur.Tenant, in.URL, in.BindDN))
	if err != nil {
		fail(err)
		return
	}
	nested := in.Verschachtelt == nil || *in.Verschachtelt
	enabled := in.Aktiv == nil || *in.Aktiv
	s.handle(w, r, "verzeichnis ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var ca *string
		if in.CA != "" {
			ca = &in.CA
		}
		var nb *string
		if in.NetBIOS != "" {
			nb = &in.NetBIOS
		}
		tag, err := tx.Exec(ctx, `UPDATE openwacht.directories SET name = $2, url = $3, ca_pem = $4, bind_dn = $5, bind_pass_enc = $6,
			base_dn = $7, netbios = $8, nested_groups = $9, mfa_required = $10, enabled = $11, email_claim = $12,
			session_hours = $13, updated_at = now() WHERE id = $1`,
			id, in.Name, in.URL, ca, in.BindDN, enc, in.BaseDN, nb, nested, in.ZweiFaktor, enabled, in.AdressClaim, sessionHours(in.SitzungStunden))
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		if err := s.saveDirChildren(ctx, tx, id, cur.Tenant, &in); err != nil {
			return 0, nil, err
		}
		tid := cur.Tenant
		return http.StatusOK, map[string]any{"id": id},
			audit(ctx, tx, &tid, "verzeichnis.geaendert", map[string]any{"name": in.Name, "url": in.URL, "domaenen": in.Domaenen,
				"gruppen": len(in.Gruppen), "zwei_faktor": in.ZweiFaktor, "aktiv": enabled})
	})
}

func (s *Server) handleDirDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in codeRequest
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		writeDBError(w, "verzeichnis löschen", err)
		return
	}
	s.handle(w, r, "verzeichnis löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM openwacht.directories WHERE id = $1`, id)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() == 0 {
			return 0, nil, errNotFound
		}
		return http.StatusOK, map[string]any{"geloescht": true}, nil
	})
}

// loginDirectory meldet Konten ohne lokales Passwort am Verzeichnis an.
// Rückgabe false: kein passendes Verzeichnis, der lokale Weg antwortet.
func (s *Server) loginDirectory(w http.ResponseWriter, r *http.Request, req loginRequest, knownID *string, src []byte) bool {
	ctx := r.Context()
	_, domain, netbios := verzeichnis.SplitLogin(req.Email)
	if domain == "" && netbios == "" {
		return false
	}
	if knownID != nil {
		if s.loginBlocked(ctx, *knownID, src) {
			writeError(w, http.StatusUnauthorized, msgLoginFailed)
			return true
		}
		// Wartezeit bei vielen Fehlversuchen aus unbekannten Quellen
		if !s.loginGate(w, r, *knownID, src) {
			return true
		}
	}
	id, err := s.directoryLogin(ctx, req.Email, req.Passwort)
	switch {
	case errors.Is(err, errDirectoryDown):
		writeError(w, http.StatusServiceUnavailable, "Der Verzeichnisdienst (AD) ist gerade nicht erreichbar. Bitte später erneut versuchen.")
		return true
	case err != nil:
		internalError(w, "verzeichnis anmeldung", err)
		return true
	case id == "":
		if knownID == nil {
			return false // wie ein unbekanntes Konto behandeln (gleiche Arbeit)
		}
		s.loginFailed(ctx, *knownID, src)
		s.auditAuth(ctx, *knownID, "anmeldung.fehlgeschlagen", map[string]any{"grund": "verzeichnis"}, false)
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return true
	}
	if s.loginBlocked(ctx, id, src) {
		writeError(w, http.StatusUnauthorized, msgLoginFailed)
		return true
	}
	var totp bool
	if err := s.pool.QueryRow(ctx, `SELECT totp_enabled FROM openwacht.auth_state($1)`, id).Scan(&totp); err != nil {
		internalError(w, "auth_state", err)
		return true
	}
	s.continueLogin(w, r, id, totp)
	return true
}

// sessionHours: 0 = Standard (NULL in der Datenbank).
func sessionHours(h int) *int {
	if h == 0 {
		return nil
	}
	return &h
}

// loginBlocked: deaktiviert oder die Quelle ist für dieses Konto gesperrt.
func (s *Server) loginBlocked(ctx context.Context, id string, src []byte) bool {
	var disabled bool
	if err := s.pool.QueryRow(ctx, `SELECT disabled FROM openwacht.auth_state($1)`, id).Scan(&disabled); err != nil {
		return true
	}
	if disabled {
		return true
	}
	if s.sourceLocked(ctx, id, src) {
		s.auditAuth(ctx, id, "anmeldung.gesperrt", nil, false)
		return true
	}
	return false
}

// handleDirTest prüft eine gespeicherte Anbindung (Dienstkonto, optional ein
// Benutzer samt Gruppen, ohne dessen Passwort: nur Suche).
func (s *Server) handleDirTest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var d dirRow
	err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT d.id::text, d.tenant_id::text, d.url, d.bind_dn, d.base_dn, d.ca_pem,
			openwacht.directory_secret(d.id), d.nested_groups, d.kind FROM openwacht.directories d WHERE d.id = $1`, id).
			Scan(&d.ID, &d.Tenant, &d.URL, &d.BindDN, &d.BaseDN, &d.CAPEM, &d.PassEnc, &d.Nested, &d.Kind)
	})
	if err != nil {
		writeDBError(w, "verzeichnis test", err)
		return
	}
	if !s.limiter.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Versuche. Bitte kurz warten.")
		return
	}
	if d.Kind == "oidc" {
		c, err := s.oidcConfig(d)
		if err == nil {
			_, err = c.Discover(r.Context())
		}
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": "Verbindung zum Identity Provider: " + err.Error() + "."})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	cfg, err := s.dirConfig(d)
	if err != nil {
		writeDBError(w, "verzeichnis test", err)
		return
	}
	cfg.Timeout = 10 * time.Second
	if err := cfg.Test(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "fehler": "Verbindung zum Verzeichnis: " + err.Error() + "."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- 2FA-Pflicht ----------------------------------------------------------------

var mfaPolicies = map[string]bool{"admins": true, "alle": true, "freiwillig": true}

func (s *Server) handleMFAPolicyGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "anmeldung", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		var p *string
		if err := tx.QueryRow(ctx, `SELECT mfa_policy FROM openwacht.settings`).Scan(&p); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, err
		}
		v := "admins"
		if p != nil {
			v = *p
		}
		return http.StatusOK, map[string]any{"zwei_faktor": v}, nil
	})
}

func (s *Server) handleMFAPolicyPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ZweiFaktor string `json:"zwei_faktor"`
		Code       string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "anmeldung", err) }
	if !mfaPolicies[in.ZweiFaktor] {
		fail(badRequest("Zwei-Faktor-Pflicht: admins, alle oder freiwillig."))
		return
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	s.handle(w, r, "anmeldung", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE openwacht.settings SET mfa_policy = $1`, in.ZweiFaktor); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"zwei_faktor": in.ZweiFaktor},
			audit(ctx, tx, nil, "einstellungen.zwei_faktor", map[string]any{"pflicht": in.ZweiFaktor})
	})
}
