// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/fenster"
	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/webui"
)

// Einrichtungsassistent (Etappe 21a). Solange die Einrichtung offen ist,
// läuft statt der Zentrale nur dieser kleine Server: Er liefert die Seite
// /einrichtung und die API /api/v1/einrichtung/…, sonst nichts. Kein
// Agent-Port, keine Checks, keine Alarme.
//
// Zugang nur mit dem Token aus dem Link, den `installieren` ausgibt
// (…/einrichtung#<Token>). Das Token steht im Fragment, kommt also nicht in
// Logs; die Seite tauscht es gegen ein HttpOnly-Cookie und entfernt es aus der
// Adresszeile. In der Datenbank liegt nur sein SHA-256; jede Anfrage prüft es
// dort (setup_check), „Fertig“ (setup_finish) löscht es in derselben
// Transaktion, in der alles angelegt wird.

// SetupTokenTTL: so lange gilt ein Einrichtungslink.
const SetupTokenTTL = 2 * time.Hour

const setupCookie = "ow_einrichtung"

// NewSetupToken erzeugt ein Token und seinen Hash (für die Datenbank).
func NewSetupToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

func setupHash(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// SetupOpen: Ist die Einrichtung noch offen?
func SetupOpen(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var open bool
	err := pool.QueryRow(ctx, `SELECT openwacht.setup_open()`).Scan(&open)
	return open, err
}

// setupSession: Zwischenstand des Assistenten (nur im Speicher; nach einem
// Neustart der Zentrale fängt man bei 2FA und Zertifikat neu an).
type setupSession struct {
	userID  string
	email   string
	totp    []byte
	totpOK  bool
	step    int64
	https   *sealedMaterial
	touched time.Time
}

// Setup ist der Server des Assistenten.
type Setup struct {
	pool    *pgxpool.Pool
	key     []byte
	boxKey  []byte
	params  auth.Params
	now     func() time.Time
	ui      fs.FS
	limiter *ipLimiter
	mailLim perKeyLimit
	mailer  *alarm.Mailer
	issuer  string

	mu       sync.Mutex
	sessions map[string]*setupSession // Hash (hex) → Zwischenstand
	done     chan struct{}
	once     sync.Once
}

// NewSetup erstellt den Server des Assistenten. params: Kosten für den
// Passwort-Hash (nil = Standard).
func NewSetup(pool *pgxpool.Pool, key []byte, params *auth.Params) (*Setup, error) {
	if len(key) != auth.KeySize {
		return nil, errors.New("Hauptschlüssel muss 32 Bytes lang sein")
	}
	p := auth.DefaultParams
	if params != nil {
		p = *params
	}
	s := &Setup{pool: pool, key: key, boxKey: deriveKey(key, "openwacht secretbox v1"), params: p, now: time.Now,
		ui: webui.FS(), limiter: newIPLimiter(30, time.Minute), mailer: alarm.NewMailer("openwacht"), issuer: "OpenWacht",
		sessions: map[string]*setupSession{}, done: make(chan struct{})}
	s.mailLim.every = 10 * time.Second
	return s, nil
}

// Done ist geschlossen, sobald die Einrichtung abgeschlossen ist.
func (s *Setup) Done() <-chan struct{} { return s.done }

// Handler: Seite und API des Assistenten.
func (s *Setup) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/einrichtung/start", s.handleStart)
	mux.Handle("GET /api/v1/einrichtung", s.auth(s.handleState))
	mux.Handle("POST /api/v1/einrichtung/zwei-faktor", s.auth(s.handleTOTP))
	mux.Handle("POST /api/v1/einrichtung/zwei-faktor/pruefen", s.auth(s.handleTOTPCheck))
	mux.Handle("POST /api/v1/einrichtung/https", s.auth(s.handleHTTPS))
	mux.Handle("POST /api/v1/einrichtung/testmail", s.auth(s.handleTestMail))
	mux.Handle("POST /api/v1/einrichtung/fertig", s.auth(s.handleFinish))
	mux.HandleFunc("GET /api/v1/gesund", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "einrichtung": true})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusServiceUnavailable, "Die Einrichtung ist noch nicht abgeschlossen.")
	})
	ui := uiHandler(s.ui)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Nur die Seite des Assistenten und ihre Dateien; alles andere führt dorthin.
		if r.URL.Path != "/einrichtung" && !strings.HasPrefix(r.URL.Path, "/assets/") && r.URL.Path != "/thema.js" &&
			r.URL.Path != "/favicon.svg" {
			http.Redirect(w, r, "/einrichtung", http.StatusFound)
			return
		}
		ui.ServeHTTP(w, r)
	})
	return s.headers(s.origin(mux))
}

func (s *Setup) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// origin: Die Adresse der Installation steht noch nicht fest; verändernde
// Anfragen müssen vom selben Ursprung kommen, unter dem die Seite geladen ist.
func (s *Setup) origin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if o := r.Header.Get("Origin"); o != "" && o != scheme+"://"+r.Host {
				writeError(w, http.StatusForbidden, "Anfrage von fremdem Ursprung abgelehnt.")
				return
			}
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
				writeError(w, http.StatusForbidden, "Anfrage von fremdem Ursprung abgelehnt.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Setup) ip(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// check prüft ein Token gegen die Datenbank (mit Rate Limit je Adresse).
func (s *Setup) check(w http.ResponseWriter, r *http.Request, raw string) (string, bool) {
	select {
	case <-s.done:
		writeError(w, http.StatusGone, "Die Einrichtung ist abgeschlossen. Bitte anmelden.")
		return "", false
	default:
	}
	if !s.limiter.allow(s.ip(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Versuche. Bitte eine Minute warten.")
		return "", false
	}
	if raw == "" || len(raw) > 64 {
		writeError(w, http.StatusForbidden, "Einrichtungslink fehlt oder ist ungültig.")
		return "", false
	}
	h := setupHash(raw)
	var ok bool
	if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.setup_check($1)`, h).Scan(&ok); err != nil {
		internalError(w, "setup check", err)
		return "", false
	}
	if !ok {
		writeError(w, http.StatusForbidden, "Der Einrichtungslink ist ungültig oder abgelaufen. Einen neuen gibt „sudo openwacht-zentrale einrichtungslink“ aus.")
		return "", false
	}
	return hex.EncodeToString(h), true
}

type setupCtxKey struct{}

func (s *Setup) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(setupCookie)
		raw := ""
		if err == nil {
			raw = c.Value
		}
		id, ok := s.check(w, r, raw)
		if !ok {
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), setupCtxKey{}, [2]string{id, raw})))
	})
}

func (s *Setup) session(r *http.Request) (*setupSession, string, string) {
	v := r.Context().Value(setupCtxKey{}).([2]string)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Zwischenstände anderer (alter) Tokens verwerfen: es gibt nur einen Link.
	for k := range s.sessions {
		if k != v[0] {
			delete(s.sessions, k)
		}
	}
	ss := s.sessions[v[0]]
	if ss == nil {
		ss = &setupSession{}
		s.sessions[v[0]] = ss
	}
	ss.touched = s.now()
	return ss, v[0], v[1]
}

func (s *Setup) handleStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if _, ok := s.check(w, r, in.Token); !ok {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: in.Token, Path: "/api/v1/einrichtung",
		MaxAge: int(SetupTokenTTL / time.Second), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, s.proposals(r))
}

func (s *Setup) handleState(w http.ResponseWriter, r *http.Request) {
	ss, _, _ := s.session(r)
	out := s.proposals(r)
	s.mu.Lock()
	if ss.totpOK {
		out["zwei_faktor_fuer"] = ss.email
	}
	if ss.https != nil {
		out["https"] = setupHTTPSInfo(ss.https)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// proposals: Vorschläge für die Felder des Assistenten.
func (s *Setup) proposals(r *http.Request) map[string]any {
	names := HostNames()
	if h, _, err := net.SplitHostPort(r.Host); err == nil || r.Host != "" {
		if err != nil {
			h = r.Host
		}
		h = strings.Trim(h, "[]")
		if n, err := pki.NormalizeNames([]string{h}); err == nil && n[0] != "localhost" {
			names = append([]string{n[0]}, slices.DeleteFunc(names, func(x string) bool { return x == n[0] })...)
		}
	}
	nets := []string{} // nie nil: Der Assistent erwartet eine Liste.
	for _, p := range hostPrefixes() {
		if q := p.Masked().String(); !slices.Contains(nets, q) {
			nets = append(nets, q)
		}
	}
	return map[string]any{"adressen": names, "netze": nets, "zeitzone": systemZone(),
		"sicherung": map[string]int{"uhr": 0, "tage": 14}, "token_gueltig_min": int(SetupTokenTTL / time.Minute)}
}

// systemZone: Zeitzone des Rechners (/etc/localtime), sonst Europe/Berlin.
func systemZone() string {
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(l, "zoneinfo/"); i >= 0 {
			if z := l[i+len("zoneinfo/"):]; z != "" {
				if _, err := fenster.LoadZone(z); err == nil {
					return z
				}
			}
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		if z := strings.TrimSpace(string(b)); z != "" {
			if _, err := fenster.LoadZone(z); err == nil {
				return z
			}
		}
	}
	return DefaultZoneName
}

func (s *Setup) handleTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if err := validEmail(email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		internalError(w, "totp", err)
		return
	}
	ss, _, _ := s.session(r)
	s.mu.Lock()
	if ss.userID == "" {
		id, err := newUUID()
		if err != nil {
			s.mu.Unlock()
			internalError(w, "uuid", err)
			return
		}
		ss.userID = id
	}
	ss.email, ss.totp, ss.totpOK, ss.step = email, secret, false, 0
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"geheimnis": auth.TOTPSecretText(secret), "uri": auth.TOTPURI(s.issuer, email, secret)})
}

func (s *Setup) handleTOTPCheck(w http.ResponseWriter, r *http.Request) {
	var in codeRequest
	if !readJSON(w, r, &in) {
		return
	}
	ss, _, _ := s.session(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss.totp == nil {
		writeError(w, http.StatusConflict, "Erst die Zwei-Faktor-Anmeldung beginnen.")
		return
	}
	step, ok := auth.VerifyTOTP(ss.totp, in.Code, s.now(), ss.step)
	if !ok {
		writeError(w, http.StatusBadRequest, "Der Code ist ungültig. Bitte den aktuellen Code aus der App eingeben.")
		return
	}
	ss.totpOK, ss.step = true, step
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": ss.email})
}

type setupHTTPSIn struct {
	Art        string   `json:"art"` // "eigene-ca" oder "hochgeladen"
	Adressen   []string `json:"adressen"`
	Zertifikat string   `json:"zertifikat"`
	Schluessel string   `json:"schluessel"`
}

func setupHTTPSInfo(m *sealedMaterial) map[string]any {
	out := map[string]any{"art": m.kind, "namen": m.names, "fingerabdruck": pki.SHA256Hex(m.leaf.Leaf),
		"gueltig_bis": m.leaf.Leaf.NotAfter, "aussteller": m.leaf.Leaf.Issuer.CommonName}
	if m.caCertX != nil {
		out["ca_fingerabdruck"] = pki.SHA256Hex(m.caCertX.Cert)
	}
	return out
}

// handleHTTPS: Schritt „HTTPS“. Erzeugt die eigene CA für die Adressen oder
// prüft ein hochgeladenes Zertifikat; gespeichert wird erst mit „Fertig“.
func (s *Setup) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	var in setupHTTPSIn
	if !readJSON(w, r, &in) {
		return
	}
	names, err := pki.NormalizeNames(in.Adressen)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Adresse: "+err.Error()+".")
		return
	}
	now := s.now()
	var sm *sealedMaterial
	switch in.Art {
	case "eigene-ca":
		ca, err := pki.NewHTTPSCA(names, now)
		if err != nil {
			internalError(w, "setup ca", err)
			return
		}
		m, err := ca.HTTPSLeaf(names, now)
		if err != nil {
			internalError(w, "setup leaf", err)
			return
		}
		if sm, err = sealMaterial(s.key, "eigene-ca", m, ca, names); err != nil {
			internalError(w, "setup seal", err)
			return
		}
	case "hochgeladen":
		m, err := pki.ParseUploaded([]byte(in.Zertifikat), []byte(in.Schluessel), names, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error()+".")
			return
		}
		if sm, err = sealMaterial(s.key, "hochgeladen", m, nil, names); err != nil {
			internalError(w, "setup seal", err)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "Art: eigene-ca oder hochgeladen.")
		return
	}
	ss, _, _ := s.session(r)
	s.mu.Lock()
	ss.https = sm
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, setupHTTPSInfo(sm))
}

type setupMailIn struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	TLS      string `json:"tls"`
	Absender string `json:"absender"`
	Benutzer string `json:"benutzer"`
	Passwort string `json:"passwort"`
	CA       string `json:"ca"`
}

func (m *setupMailIn) config() (alarm.SMTPConfig, error) {
	c := alarm.SMTPConfig{Host: strings.TrimSpace(m.Server), Port: m.Port, TLS: m.TLS, From: strings.TrimSpace(m.Absender),
		User: strings.TrimSpace(m.Benutzer), Pass: m.Passwort, CA: strings.TrimSpace(m.CA)}
	if c.User == "" {
		c.Pass = ""
	}
	return c, alarm.ValidateSMTP(c)
}

// handleTestMail: Testmail an die Adresse des ersten Admins, ohne zu speichern.
func (s *Setup) handleTestMail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mail setupMailIn `json:"mail"`
		An   string      `json:"an"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, err := in.Mail.config()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error()+".")
		return
	}
	to := strings.ToLower(strings.TrimSpace(in.An))
	if err := validEmail(to); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.mailLim.allow("setup", s.now()) {
		writeError(w, http.StatusTooManyRequests, "Gerade erst getestet. Bitte einen Moment warten.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := s.mailer.Send(ctx, c, []string{to}, alarm.TestMail("OpenWacht", "Einrichtung")); err != nil {
		writeError(w, http.StatusBadGateway, "Versand fehlgeschlagen: "+err.Error()+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gesendet": true, "an": to})
}

type setupFinishIn struct {
	Mandant string `json:"mandant"`
	Admin   struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Passwort string `json:"passwort"`
	} `json:"admin"`
	Adressen  []string     `json:"adressen"`
	Zeitzone  string       `json:"zeitzone"`
	Netze     []string     `json:"netze"`
	Mail      *setupMailIn `json:"mail"`
	Sicherung struct {
		Uhr  int `json:"uhr"`
		Tage int `json:"tage"`
	} `json:"sicherung"`
}

func validEmail(e string) error {
	at := strings.IndexByte(e, '@')
	if len(e) < 3 || len(e) > 254 || at <= 0 || at == len(e)-1 || strings.Count(e, "@") != 1 ||
		strings.ContainsFunc(e, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("Bitte eine gültige E-Mail-Adresse angeben.")
	}
	return nil
}

func validTenantName(n string) error {
	if l := len([]rune(n)); l < 1 || l > 100 || strings.ContainsFunc(n, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return errors.New("Name des Hauptmandanten: 1 bis 100 Zeichen.")
	}
	return nil
}

// handleFinish: „Fertig“. Prüft alles, legt alles in einer Transaktion an und
// schließt die Einrichtung.
func (s *Setup) handleFinish(w http.ResponseWriter, r *http.Request) {
	var in setupFinishIn
	if !readJSON(w, r, &in) {
		return
	}
	bad := func(msg string) { writeError(w, http.StatusBadRequest, msg) }
	tenant := strings.TrimSpace(in.Mandant)
	if err := validTenantName(tenant); err != nil {
		bad(err.Error())
		return
	}
	name := strings.TrimSpace(in.Admin.Name)
	if l := len([]rune(name)); l < 1 || l > 100 {
		bad("Name des Admins: 1 bis 100 Zeichen.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Admin.Email))
	if err := validEmail(email); err != nil {
		bad(err.Error())
		return
	}
	if err := auth.ValidateNewPassword(in.Admin.Passwort, email); err != nil {
		bad(err.Error())
		return
	}
	names, err := pki.NormalizeNames(in.Adressen)
	if err != nil {
		bad("Adresse: " + err.Error() + ".")
		return
	}
	tz := strings.TrimSpace(in.Zeitzone)
	if tz == "" {
		tz = DefaultZoneName
	}
	if _, err := fenster.LoadZone(tz); err != nil {
		bad(err.Error() + ".")
		return
	}
	nets, err := parseNets(in.Netze)
	if err != nil {
		bad(err.Error())
		return
	}
	if in.Sicherung.Uhr < 0 || in.Sicherung.Uhr > 23 || in.Sicherung.Tage < 1 || in.Sicherung.Tage > 365 {
		bad("Sicherung: Uhrzeit 0 bis 23, Aufbewahrung 1 bis 365 Tage.")
		return
	}
	var smtp *alarm.SMTPConfig
	if in.Mail != nil && strings.TrimSpace(in.Mail.Server) != "" {
		c, err := in.Mail.config()
		if err != nil {
			bad("Mail: " + err.Error() + ".")
			return
		}
		smtp = &c
	}

	ss, id, raw := s.session(r)
	s.mu.Lock()
	userID, secret, totpOK, step, https, totpEmail := ss.userID, ss.totp, ss.totpOK, ss.step, ss.https, ss.email
	s.mu.Unlock()
	if !totpOK || totpEmail != email {
		bad("Bitte zuerst die Zwei-Faktor-Anmeldung für diese E-Mail-Adresse einrichten (Schritt 2).")
		return
	}
	if https == nil || !slices.Equal(https.names, names) {
		bad("Das HTTPS-Zertifikat passt nicht zu den Adressen. Bitte in Schritt 4 neu erzeugen oder hochladen.")
		return
	}
	pwHash, err := auth.HashPassword(in.Admin.Passwort, s.params)
	if err != nil {
		internalError(w, "setup hash", err)
		return
	}
	totpEnc, err := auth.Seal(s.boxKey, secret, []byte(userID))
	if err != nil {
		internalError(w, "setup seal", err)
		return
	}
	var sh, st, sf, su *string
	var sp *int32
	var spass []byte
	if smtp != nil {
		sh, st, sf = &smtp.Host, &smtp.TLS, &smtp.From
		port := int32(smtp.Port)
		sp = &port
		if smtp.User != "" {
			su = &smtp.User
			if smtp.Pass != "" {
				if spass, err = auth.Seal(deriveKey(s.boxKey, "openwacht smtp v1"), []byte(smtp.Pass), smtpAAD(smtp.Host, smtp.User)); err != nil {
					internalError(w, "setup smtp", err)
					return
				}
			}
		}
	}
	baseURL := "https://" + hostForURL(names[0])
	hour, days := int16(in.Sicherung.Uhr), int16(in.Sicherung.Tage)
	_, err = s.pool.Exec(r.Context(), `SELECT openwacht.setup_finish($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		$13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)`,
		setupHash(raw), userID, tenant, email, name, pwHash, totpEnc, step, baseURL, names, tz, nets,
		sh, sp, st, sf, su, spass, hour, days, https.kind, https.cert, https.key, https.caCert, https.caKey)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42501" {
			writeError(w, http.StatusForbidden, "Der Einrichtungslink ist ungültig oder abgelaufen.")
			return
		}
		writeDBError(w, "setup finish", err)
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	slog.Info("Einrichtung abgeschlossen", "mandant", tenant, "adresse", baseURL)
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: "", Path: "/api/v1/einrichtung", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	out := setupHTTPSInfo(https)
	writeJSON(w, http.StatusOK, map[string]any{"fertig": true, "adresse": baseURL, "https": out})
	s.once.Do(func() { close(s.done) })
}

// hostForURL setzt IPv6-Adressen in eckige Klammern.
func hostForURL(n string) string {
	if a, err := netip.ParseAddr(n); err == nil && a.Is6() {
		return "[" + n + "]"
	}
	return n
}
