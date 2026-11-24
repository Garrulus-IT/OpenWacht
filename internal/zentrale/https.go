// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// HTTPS der Oberfläche durch die Zentrale selbst (Etappe 21a). Zertifikat und
// Schlüssel liegen in openwacht.https_material; die privaten Schlüssel sind mit
// einem vom Hauptschlüssel abgeleiteten Schlüssel verschlüsselt.

func httpsKey(master []byte) []byte {
	return deriveKey(deriveKey(master, "openwacht secretbox v1"), "openwacht https v1")
}

var (
	httpsLeafAAD = []byte("openwacht https v1\x00server")
	httpsCAAAD   = []byte("openwacht https v1\x00ca")
)

// httpsRow ist der Inhalt von https_get().
type httpsRow struct {
	kind      string
	certPEM   string
	keyEnc    []byte
	caCertPEM *string
	caKeyEnc  []byte
	names     []string
	updated   time.Time
}

func readHTTPS(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (*httpsRow, error) {
	var r httpsRow
	err := q.QueryRow(ctx, `SELECT kind, cert_pem, key_enc, ca_cert_pem, ca_key_enc, names, updated_at FROM openwacht.https_get()`).
		Scan(&r.kind, &r.certPEM, &r.keyEnc, &r.caCertPEM, &r.caKeyEnc, &r.names, &r.updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// sealedMaterial: Zertifikate und verschlüsselte Schlüssel zum Speichern.
type sealedMaterial struct {
	kind    string
	cert    string
	key     []byte
	caCert  *string
	caKey   []byte
	names   []string
	leaf    *pki.Material
	caCertX *pki.CA
}

func sealMaterial(master []byte, kind string, m pki.Material, ca *pki.CA, names []string) (*sealedMaterial, error) {
	k := httpsKey(master)
	key, err := auth.Seal(k, m.KeyDER, httpsLeafAAD)
	if err != nil {
		return nil, err
	}
	out := &sealedMaterial{kind: kind, cert: string(m.CertPEM), key: key, names: names, leaf: &m, caCertX: ca}
	if ca != nil {
		der, err := ca.KeyDER()
		if err != nil {
			return nil, err
		}
		if out.caKey, err = auth.Seal(k, der, httpsCAAAD); err != nil {
			return nil, err
		}
		p := string(ca.CertPEM())
		out.caCert = &p
	}
	return out, nil
}

// HTTPS hält das wirksame Zertifikat der Oberfläche und tauscht es ohne
// Neustart aus (GetCertificate).
type HTTPS struct {
	pool   *pgxpool.Pool
	master []byte
	now    func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
	row  *httpsRow
	ca   *pki.CA // nur bei eigener CA
}

// LoadHTTPS liest das Zertifikat aus der Datenbank. Fehlt es, ist das ein
// Fehler (die Einrichtung legt es an).
func LoadHTTPS(ctx context.Context, pool *pgxpool.Pool, master []byte) (*HTTPS, error) {
	h := &HTTPS{pool: pool, master: master, now: time.Now}
	if err := h.Reload(ctx); err != nil {
		return nil, err
	}
	return h, nil
}

// Reload liest das Zertifikat neu (nach Einrichtung, Einstellungen, Erneuerung).
func (h *HTTPS) Reload(ctx context.Context) error {
	row, err := readHTTPS(ctx, h.pool)
	if err != nil {
		return err
	}
	if row == nil {
		return errors.New("kein HTTPS-Zertifikat in der Datenbank (Einrichtung nicht abgeschlossen?)")
	}
	k := httpsKey(h.master)
	keyDER, err := auth.Open(k, row.keyEnc, httpsLeafAAD)
	if err != nil {
		return errors.New("HTTPS-Schlüssel nicht lesbar (falscher Hauptschlüssel?)")
	}
	c, err := pki.Material{CertPEM: []byte(row.certPEM), KeyDER: keyDER}.TLS()
	if err != nil {
		return fmt.Errorf("HTTPS-Zertifikat: %w", err)
	}
	var ca *pki.CA
	if row.kind == "eigene-ca" && row.caCertPEM != nil {
		caDER, err := auth.Open(k, row.caKeyEnc, httpsCAAAD)
		if err != nil {
			return errors.New("Schlüssel der HTTPS-CA nicht lesbar")
		}
		if ca, err = pki.LoadCA([]byte(*row.caCertPEM), caDER); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.cert, h.row, h.ca = &c, row, ca
	h.mu.Unlock()
	return nil
}

// TLSConfig für den HTTPS-Port der Oberfläche.
func (h *HTTPS) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			h.mu.RLock()
			defer h.mu.RUnlock()
			return h.cert, nil
		},
	}
}

// Info für Einstellungen und Assistent.
func (h *HTTPS) info() map[string]any {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[string]any{"art": h.row.kind, "namen": h.row.names, "gueltig_bis": h.cert.Leaf.NotAfter,
		"fingerabdruck": pki.SHA256Hex(h.cert.Leaf), "aussteller": h.cert.Leaf.Issuer.CommonName}
	if h.ca != nil {
		out["ca_fingerabdruck"] = pki.SHA256Hex(h.ca.Cert)
		out["ca_gueltig_bis"] = h.ca.Cert.NotAfter
	}
	return out
}

// caPEM: die Wurzel zum Installieren auf PC und Handy (nur eigene CA).
func (h *HTTPS) caPEM() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.ca == nil {
		return nil
	}
	return h.ca.CertPEM()
}

// RenewIfDue stellt bei eigener CA ein neues Serverzertifikat aus, wenn das
// alte in weniger als 30 Tagen abläuft. true = erneuert.
func (h *HTTPS) RenewIfDue(ctx context.Context) (bool, error) {
	h.mu.RLock()
	ca, row, leaf := h.ca, h.row, h.cert.Leaf
	h.mu.RUnlock()
	if ca == nil || leaf.NotAfter.Sub(h.now()) > pki.HTTPSRenewBefore {
		return false, nil
	}
	m, err := ca.HTTPSLeaf(row.names, h.now())
	if err != nil {
		return false, err
	}
	sm, err := sealMaterial(h.master, "eigene-ca", m, nil, row.names)
	if err != nil {
		return false, err
	}
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT openwacht.https_renew($1, $2, $3)`, row.certPEM, sm.cert, sm.key).Scan(&ok); err != nil {
		return false, err
	}
	return ok, h.Reload(ctx)
}

// RunRenewal prüft alle 6 Stunden, ob das Serverzertifikat zu erneuern ist,
// und lädt dabei auch Änderungen aus den Einstellungen neu.
func (h *HTTPS) RunRenewal(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if ok, err := h.RenewIfDue(ctx); err != nil {
			slog.Warn("HTTPS: Erneuerung fehlgeschlagen", "fehler", err)
		} else if ok {
			slog.Info("HTTPS: Serverzertifikat erneuert")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// EnsureSetupCert legt für den Assistenten ein vorläufiges, selbstsigniertes
// Zertifikat an, wenn noch keines gespeichert ist. names: Adressen dieses
// Rechners (HostNames).
func EnsureSetupCert(ctx context.Context, pool *pgxpool.Pool, master []byte, names []string) error {
	row, err := readHTTPS(ctx, pool)
	if err != nil || row != nil {
		return err
	}
	m, err := pki.SelfSigned(names, time.Now())
	if err != nil {
		return err
	}
	sm, err := sealMaterial(master, "einrichtung", m, nil, names)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `SELECT openwacht.https_setup_init($1, $2, $3)`, sm.cert, sm.key, names)
	return err
}

// HostNames: Hostname und Adressen dieses Rechners ohne Loopback, für das
// vorläufige Zertifikat und als Vorschlag im Assistenten.
func HostNames() []string {
	var out []string
	if h, err := os.Hostname(); err == nil && pki.ValidName(h) == nil {
		out = append(out, strings.ToLower(h))
	}
	for _, p := range hostPrefixes() {
		out = append(out, p.Addr().String())
	}
	if len(out) == 0 {
		out = []string{"localhost"}
	}
	if len(out) > pki.MaxNames {
		out = out[:pki.MaxNames]
	}
	return out
}

// interfaceAddrs ist in Tests austauschbar. Unter Linux fragt Go die Adressen
// per Netlink ab; der Dienst braucht dafür AF_NETLINK (openwacht-zentrale.service).
var interfaceAddrs = net.InterfaceAddrs

// hostPrefixes: Adressen der Netzwerkkarten mit Präfix (ohne Loopback,
// Link-Local und Multicast). Nie nil: Lässt sich nichts abfragen, ist die
// Liste leer, damit JSON „[]“ statt „null“ liefert.
func hostPrefixes() []netip.Prefix {
	out := []netip.Prefix{}
	addrs, err := interfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		// Öffentliche IPv6-Adressen (nicht ULA) vergibt meist der Provider
		// per Präfix, und das wechselt. Im Zertifikat und in der Netzfreigabe
		// stünden dann bald fremde Adressen. Wer sie braucht, trägt sie selbst ein.
		if ip.Is6() && !ip.IsPrivate() {
			continue
		}
		bits, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(ip, bits))
	}
	return out
}

// --- Einstellungen → HTTPS ---------------------------------------------------

func (s *Server) handleHTTPSGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen https", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		if s.https == nil {
			return http.StatusOK, map[string]any{"aktiv": false}, nil
		}
		out := s.https.info()
		out["aktiv"] = true
		return http.StatusOK, out, nil
	})
}

type httpsIn struct {
	Art         string `json:"art"` // "erneuern", "eigene-ca", "hochgeladen"
	Zertifikat  string `json:"zertifikat"`
	Schluessel  string `json:"schluessel"`
	Code        string `json:"code"`
	Bestaetigen bool   `json:"bestaetigen"`
}

// handleHTTPSPut: neues Serverzertifikat (erneuern), neue eigene CA oder
// eigenes Zertifikat hochladen. Neue CA und Hochladen nur mit frischem
// 2FA-Code: Ein fremdes Zertifikat würde Mitlesen erlauben.
func (s *Server) handleHTTPSPut(w http.ResponseWriter, r *http.Request) {
	var in httpsIn
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "einstellungen https", err) }
	if s.https == nil {
		writeError(w, http.StatusConflict, "Die Oberfläche läuft nicht mit HTTPS der Zentrale (Startoption oder Reverse Proxy).")
		return
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	s.https.mu.RLock()
	names, ca := s.https.row.names, s.https.ca
	s.https.mu.RUnlock()
	now := s.now()
	var sm *sealedMaterial
	var err error
	switch in.Art {
	case "erneuern":
		if ca == nil {
			fail(badRequest("Erneuern geht nur mit der eigenen OpenWacht-CA."))
			return
		}
		m, err := ca.HTTPSLeaf(names, now)
		if err != nil {
			fail(err)
			return
		}
		sm, err = sealMaterial(s.key, "eigene-ca", m, ca, names)
		if err != nil {
			fail(err)
			return
		}
	case "eigene-ca":
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
		nca, err := pki.NewHTTPSCA(names, now)
		if err != nil {
			fail(err)
			return
		}
		m, err := nca.HTTPSLeaf(names, now)
		if err != nil {
			fail(err)
			return
		}
		if sm, err = sealMaterial(s.key, "eigene-ca", m, nca, names); err != nil {
			fail(err)
			return
		}
	case "hochgeladen":
		m, perr := pki.ParseUploaded([]byte(in.Zertifikat), []byte(in.Schluessel), names, now)
		if perr != nil {
			fail(badRequest(perr.Error() + "."))
			return
		}
		if err := s.confirmCode(r, in.Code); err != nil {
			fail(err)
			return
		}
		if sm, err = sealMaterial(s.key, "hochgeladen", m, nil, names); err != nil {
			fail(err)
			return
		}
	default:
		fail(badRequest("Art: erneuern, eigene-ca oder hochgeladen."))
		return
	}
	s.handle(w, r, "einstellungen https", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `SELECT openwacht.https_put($1, $2, $3, $4, $5, $6)`,
			sm.kind, sm.cert, sm.key, sm.caCert, sm.caKey, sm.names); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"art": sm.kind, "fingerabdruck": pki.SHA256Hex(sm.leaf.Leaf)}, nil
	})
	if err := s.https.Reload(context.WithoutCancel(r.Context())); err != nil {
		slog.Warn("HTTPS: nach dem Speichern nicht neu geladen", "fehler", err)
	}
}

// handleCADownload liefert die Wurzel der eigenen CA (öffentlich, damit
// Handys sie vor der Anmeldung laden können; sie ist kein Geheimnis).
func (s *Server) handleCADownload(w http.ResponseWriter, r *http.Request) {
	var p []byte
	if s.https != nil {
		p = s.https.caPEM()
	}
	if p == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="openwacht-wurzel.crt"`)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(p)
}

// --- Einstellungen der Installation (Adresse, Zeitzone, Sicherung) -------------

// DefaultZoneName: Zeitzone, wenn keine eingestellt ist.
const DefaultZoneName = "Europe/Berlin"

var defaultZone = func() *time.Location {
	if l, err := time.LoadLocation(DefaultZoneName); err == nil {
		return l
	}
	return time.UTC
}()

// Install sind die Felder von runtime_install().
type Install struct {
	BaseURL    *string
	Names      []string
	Timezone   *string
	BackupHour *int16
	BackupDays *int16
}

// ReadInstall liest Adresse, Namen, Zeitzone und Sicherung (App-Rolle).
func ReadInstall(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (Install, error) {
	var in Install
	err := q.QueryRow(ctx, `SELECT base_url, names, timezone, backup_hour, backup_days FROM openwacht.runtime_install()`).
		Scan(&in.BaseURL, &in.Names, &in.Timezone, &in.BackupHour, &in.BackupDays)
	return in, err
}

// Zone: eingestellte Zeitzone oder Europe/Berlin.
func (in Install) Zone() (*time.Location, string) {
	if in.Timezone != nil {
		if l, err := time.LoadLocation(*in.Timezone); err == nil {
			return l, *in.Timezone
		}
	}
	return defaultZone, DefaultZoneName
}

// Backup: Uhrzeit und Aufbewahrung der Sicherung (Standard 0 Uhr, 14 Tage).
func (in Install) Backup() (hour, days int) {
	hour, days = 0, 14
	if in.BackupHour != nil {
		hour = int(*in.BackupHour)
	}
	if in.BackupDays != nil {
		days = int(*in.BackupDays)
	}
	return hour, days
}

func (s *Server) zoneName() string {
	_, n := s.zone()
	return n
}

// --- Einstellungen → Installation (Adresse, Zeitzone, Sicherung) ----------------

func (s *Server) handleInstallGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen installation", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		in, err := ReadInstall(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		h, d := in.Backup()
		_, zn := in.Zone()
		var auditDays *int32
		if err := tx.QueryRow(ctx, `SELECT audit_days FROM openwacht.settings`).Scan(&auditDays); err != nil {
			return 0, nil, err
		}
		out := map[string]any{"adresse": s.cfg.BaseURL.String(), "namen": in.Names, "zeitzone": zn,
			"sicherung": map[string]int{"uhr": h, "tage": d}, "https": map[string]any{"aktiv": false},
			"audit_tage": auditDays}
		if s.https != nil {
			hi := s.https.info()
			hi["aktiv"] = true
			out["https"] = hi
		}
		return http.StatusOK, out, nil
	})
}

func (s *Server) handleInstallPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Zeitzone  string `json:"zeitzone"`
		Sicherung struct {
			Uhr  int `json:"uhr"`
			Tage int `json:"tage"`
		} `json:"sicherung"`
		// Aufbewahrung des Audit-Logs (Etappe 31): fehlt = unverändert,
		// null = unbegrenzt, sonst 365 bis 3650 Tage
		AuditTage json.RawMessage `json:"audit_tage"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var auditDays *int32
	setAudit := len(in.AuditTage) > 0
	if setAudit && string(in.AuditTage) != "null" {
		var d int32
		if err := json.Unmarshal(in.AuditTage, &d); err != nil || d < 365 || d > 3650 {
			writeError(w, http.StatusBadRequest, "Audit-Log: Aufbewahrung 365 bis 3650 Tage oder unbegrenzt.")
			return
		}
		auditDays = &d
	}
	tz := strings.TrimSpace(in.Zeitzone)
	if _, err := time.LoadLocation(tz); err != nil || tz == "" || tz == "Local" {
		writeError(w, http.StatusBadRequest, "Zeitzone bitte als IANA-Namen angeben, z. B. Europe/Berlin.")
		return
	}
	if in.Sicherung.Uhr < 0 || in.Sicherung.Uhr > 23 || in.Sicherung.Tage < 1 || in.Sicherung.Tage > 365 {
		writeError(w, http.StatusBadRequest, "Sicherung: Uhrzeit 0 bis 23, Aufbewahrung 1 bis 365 Tage.")
		return
	}
	s.handle(w, r, "einstellungen installation", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		_, err := tx.Exec(ctx, `UPDATE openwacht.settings SET timezone = $1, backup_hour = $2, backup_days = $3`,
			tz, int16(in.Sicherung.Uhr), int16(in.Sicherung.Tage))
		if err != nil || !setAudit {
			return http.StatusOK, map[string]any{"zeitzone": tz}, err
		}
		var old *int32
		if err := tx.QueryRow(ctx, `SELECT audit_days FROM openwacht.settings`).Scan(&old); err != nil {
			return 0, nil, err
		}
		if (old == nil) != (auditDays == nil) || (old != nil && *old != *auditDays) {
			if _, err := tx.Exec(ctx, `UPDATE openwacht.settings SET audit_days = $1`, auditDays); err != nil {
				return 0, nil, err
			}
			if err := audit(ctx, tx, nil, "audit.aufbewahrung", map[string]any{"alt": old, "neu": auditDays}); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusOK, map[string]any{"zeitzone": tz, "audit_tage": auditDays}, nil
	})
	if err := s.ReloadSettings(context.WithoutCancel(r.Context())); err != nil {
		slog.Warn("Einstellungen: nach dem Speichern nicht neu geladen", "fehler", err)
	}
}

// OwnCA: neue eigene CA mit Serverzertifikat, verschlüsselt zum Speichern
// (für `openwacht-zentrale https-umstieg`).
type OwnCA struct {
	Cert, CACert string
	Key, CAKey   []byte
}

// NewOwnCA erzeugt CA und Serverzertifikat für names; Rückgabe mit dem
// Fingerabdruck der Wurzel.
func NewOwnCA(master []byte, names []string) (OwnCA, string, error) {
	now := time.Now()
	ca, err := pki.NewHTTPSCA(names, now)
	if err != nil {
		return OwnCA{}, "", err
	}
	m, err := ca.HTTPSLeaf(names, now)
	if err != nil {
		return OwnCA{}, "", err
	}
	sm, err := sealMaterial(master, "eigene-ca", m, ca, names)
	if err != nil {
		return OwnCA{}, "", err
	}
	return OwnCA{Cert: sm.cert, Key: sm.key, CACert: *sm.caCert, CAKey: sm.caKey}, pki.SHA256Hex(ca.Cert), nil
}

// BackupCAKey liest den Schlüssel der aktiven Agent-CA aus einer eingespielten
// Sicherung (nil = keine CA). Ab Migration 0039 kann es mehrere CAs geben
// (Agent-CA-Wechsel); ältere Sicherungen haben nur die Zeile mit id 1.
func BackupCAKey(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) ([]byte, error) {
	var multi bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'openwacht' AND table_name = 'agent_ca' AND column_name = 'state')`).Scan(&multi); err != nil {
		return nil, err
	}
	sql := `SELECT key_enc FROM openwacht.agent_ca WHERE id = 1`
	if multi {
		sql = `SELECT key_enc FROM openwacht.agent_ca WHERE state = 'aktiv'`
	}
	var key []byte
	if err := q.QueryRow(ctx, sql).Scan(&key); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return key, nil
}

// CheckAgentCAKey prüft, ob der Hauptschlüssel den Schlüssel der Agent-CA
// (aus einer Sicherung) entschlüsselt. Leer = Sicherung ohne Agent-CA.
func CheckAgentCAKey(master, keyEnc []byte) error {
	if len(keyEnc) == 0 {
		return nil
	}
	k := deriveKey(master, "openwacht agent-ca v1")
	if _, err := auth.Open(k, keyEnc, []byte("agent-ca")); err != nil {
		if errors.Is(err, auth.ErrWrongKey) {
			_, id := auth.BoxKeyID(keyEnc)
			return fmt.Errorf("die Sicherung gehört zu einem anderen Hauptschlüssel (Kennzeichen %x, dieser: %x); "+
				"nach einem Schlüsselwechsel liegt der frühere als <schluessel>.alt-<zeit> daneben",
				id, auth.KeyID(k))
		}
		return errors.New("der Hauptschlüssel passt nicht zur Sicherung (Agent-CA lässt sich nicht entschlüsseln)")
	}
	return nil
}

// --- Einstellungen → Sicherungen, Adresse (Etappe 21b) -------------------------

func (s *Server) handleBackupsGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen sicherungen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT started_at, finished_at, file, size_bytes, ok, message, removed_at FROM openwacht.backup_list(60)`)
		if err != nil {
			return 0, nil, err
		}
		type entry struct {
			Beginn   time.Time  `json:"beginn"`
			Ende     time.Time  `json:"ende"`
			Datei    *string    `json:"datei"`
			Groesse  *int64     `json:"groesse"`
			OK       bool       `json:"ok"`
			Meldung  *string    `json:"meldung"`
			Geloesch *time.Time `json:"geloescht"`
		}
		list := []entry{}
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.Beginn, &e.Ende, &e.Datei, &e.Groesse, &e.OK, &e.Meldung, &e.Geloesch); err != nil {
				return 0, nil, err
			}
			list = append(list, e)
		}
		return http.StatusOK, map[string]any{"sicherungen": list, "verzeichnis": "/var/backups/openwacht"}, rows.Err()
	})
}

// handleAddressPut ändert Adresse und Namen der Zentrale. Mit eigener CA gibt
// es eine neue Wurzel für die neuen Namen; mit eigenem Zertifikat muss eines
// für die neuen Namen mitkommen. Danach startet die Zentrale neu (Basis-URL,
// Agent-Namen und erlaubte Ursprünge gelten ab dem Start).
func (s *Server) handleAddressPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Adressen   []string `json:"adressen"`
		Zertifikat string   `json:"zertifikat"`
		Schluessel string   `json:"schluessel"`
		Code       string   `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	fail := func(err error) { writeDBError(w, "einstellungen adresse", err) }
	if s.https == nil {
		writeError(w, http.StatusConflict, "Die Adresse kommt aus den Startoptionen (-basis-url); hier lässt sie sich nicht ändern.")
		return
	}
	if err := s.withUser(r.Context(), sessionFrom(r.Context()).UserID, func(tx pgx.Tx) error {
		return requireOperator(r.Context(), tx)
	}); err != nil {
		fail(err)
		return
	}
	names, err := pki.NormalizeNames(in.Adressen)
	if err != nil {
		fail(badRequest("Adresse: " + err.Error() + "."))
		return
	}
	s.https.mu.RLock()
	kind := s.https.row.kind
	s.https.mu.RUnlock()
	now := s.now()
	var sm *sealedMaterial
	if kind == "hochgeladen" || in.Zertifikat != "" {
		m, perr := pki.ParseUploaded([]byte(in.Zertifikat), []byte(in.Schluessel), names, now)
		if perr != nil {
			fail(badRequest("Zertifikat für die neue Adresse: " + perr.Error() + "."))
			return
		}
		if sm, err = sealMaterial(s.key, "hochgeladen", m, nil, names); err != nil {
			fail(err)
			return
		}
	} else {
		ca, err := pki.NewHTTPSCA(names, now)
		if err != nil {
			fail(err)
			return
		}
		m, err := ca.HTTPSLeaf(names, now)
		if err != nil {
			fail(err)
			return
		}
		if sm, err = sealMaterial(s.key, "eigene-ca", m, ca, names); err != nil {
			fail(err)
			return
		}
	}
	if err := s.confirmCode(r, in.Code); err != nil {
		fail(err)
		return
	}
	base := "https://" + hostForURL(names[0])
	restart := s.cfg.Restart != nil
	s.handle(w, r, "einstellungen adresse", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if _, err := tx.Exec(ctx, `SELECT openwacht.install_set_address($1, $2, $3, $4, $5, $6, $7)`,
			base, names, sm.kind, sm.cert, sm.key, sm.caCert, sm.caKey); err != nil {
			return 0, nil, err
		}
		out := map[string]any{"adresse": base, "neustart": restart, "https": setupHTTPSInfo(sm)}
		return http.StatusOK, out, nil
	})
	if err := s.https.Reload(context.WithoutCancel(r.Context())); err != nil {
		slog.Warn("HTTPS: nach dem Speichern nicht neu geladen", "fehler", err)
	}
	if restart {
		slog.Info("Adresse geändert, Zentrale startet neu", "adresse", base)
		time.AfterFunc(time.Second, s.cfg.Restart)
	}
}
