// SPDX-License-Identifier: AGPL-3.0-only

// Package zentrale enthält den HTTP-Server der Zentrale: API für die
// Web-Oberfläche, Anmeldung, Sitzungen und Sicherheits-Middleware.
package zentrale

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/checks"
	"github.com/garrulus-it/openwacht/internal/pve"
	"github.com/garrulus-it/openwacht/internal/snmp"
	"github.com/garrulus-it/openwacht/internal/tr064"
	"github.com/garrulus-it/openwacht/internal/traps"
	"github.com/garrulus-it/openwacht/internal/version"
	"github.com/garrulus-it/openwacht/internal/webui"
)

// Config sind die Einstellungen des Servers.
type Config struct {
	// BaseURL ist die öffentliche Adresse der Oberfläche, z. B. https://openwacht.example.
	// Daran wird der Origin-Header geprüft.
	BaseURL *url.URL
	// Issuer erscheint in der Authenticator-App.
	Issuer string

	SessionIdle     time.Duration // Leerlauf bis zur Abmeldung
	SessionLifetime time.Duration // absolute Höchstdauer
	PendingLifetime time.Duration // Zeit für die Eingabe des TOTP-Codes

	// TrustedProxies: Nur von diesen Adressen wird X-Forwarded-For übernommen.
	TrustedProxies []netip.Prefix

	// PasswordParams für neue Hashes; nil = auth.DefaultParams.
	PasswordParams *auth.Params
	// MaxConcurrentHashes begrenzt gleichzeitige Argon2-Berechnungen (Speicher).
	MaxConcurrentHashes int
	// LoginsPerMinutePerIP begrenzt Anmeldeversuche je Client-Adresse.
	LoginsPerMinutePerIP int
	// UserRequestsPerMinute begrenzt Anfragen je angemeldetem Benutzer
	// (Sitzung oder API-Token, 1.0.5); 0 = 1200.
	UserRequestsPerMinute int

	// AgentNames: Hostnamen/IPs, unter denen Agents die Zentrale erreichen
	// (stehen im Server-Zertifikat des Agent-Ports).
	AgentNames []string
	// AgentURL: Adresse des Agent-Ports für Installationsbefehle in der
	// Oberfläche, z. B. https://openwacht.example:8444. Leer = Agent-Port aus.
	AgentURL string
	// AgentCertLifetime: Laufzeit der Agent-Zertifikate (Standard 30 Tage).
	AgentCertLifetime time.Duration
	// AgentInterval: gewünschtes Meldeintervall der Agents (Standard 60 s).
	AgentInterval time.Duration
	// UpdateKeys: nur für Tests (Inhalt wie schluessel.pub); sonst die
	// eingebetteten Schlüssel (internal/update)
	UpdateKeys string
	// ZentraleUpdateDir: Ablage für Updates der Zentrale aus der Oberfläche
	// (1.0.4, Debian-Paket: /var/lib/openwacht-update). Leer = aus.
	ZentraleUpdateDir string
	// Authenticode: nur für Tests (Inhalt wie internal/update/authenticode.txt)
	Authenticode string
	// Downloads: Ordner mit Agents, MSI, Desktop-App und Agent-Paketen für
	// die Seite „Downloads“ (1.0.14, Debian-Paket: /usr/share/openwacht/downloads,
	// downloads.go). Leer = Seite ohne Dateien.
	Downloads string
	// AgentRegistrationsPerMinutePerIP begrenzt Registrierungsversuche.
	AgentRegistrationsPerMinutePerIP int

	// CheckNetworks: Netze, die aktive Checks erreichen dürfen. Leer = keine.
	// Loopback und Link-Local nur mit einem Eintrag, der darin liegt.
	CheckNetworks []netip.Prefix
	// CheckConcurrency: gleichzeitig laufende Checks (Standard 32).
	CheckConcurrency int
	// CheckPoll: wie oft der Planer nach fälligen Checks sieht (Standard 2 s).
	CheckPoll time.Duration

	// AlertTargets: freigegebene ntfy-Server (-alarm-ziele). nil = keine.
	AlertTargets *alarm.Targets
	// AlertPoll: wie oft nach zu meldenden Ereignissen gesehen wird (Standard 15 s).
	AlertPoll time.Duration
	// AlertThreshold: Fehlschläge in Folge bis zum Alarm (Standard 3, bis
	// 1.0.5 2); je Sensor änderbar (fail_threshold, 1.0.6).
	AlertThreshold int
	// AlertReminder: Erinnerung bei anhaltendem Fehler (Standard 12 h; negativ = aus).
	AlertReminder time.Duration
	// AlertCollect: so lange sammeln Mail- und SMS-Kanäle mit Schalter „Sammeln“
	// ab dem ersten Ereignis (Standard 1 min; negativ = nie sammeln).
	AlertCollect time.Duration
	// HostSilentAfter: Ab wann ein Agent ohne Meldung als stumm gilt
	// (Standard 3 min, mindestens zwei Meldeintervalle).
	HostSilentAfter time.Duration
	// Schwellen in Prozent für Platten und Arbeitsspeicher (Standard 90/95;
	// negativ = aus). Die Warnschwelle muss unter der kritischen liegen.
	DiskWarn, DiskCrit float64
	MemWarn, MemCrit   float64
	// CPU: Mittel der Auslastung über 15 Minuten (Standard 90/98).
	CPUWarn, CPUCrit float64
	// DiskDays: Warnung, wenn eine Platte laut Prognose in weniger Tagen voll
	// ist (Standard 14; negativ = aus). Keine Startoption, nur Einstellungen.
	DiskDays float64

	// DeadManURL: Ping-Adresse des Totmannschalters (healthchecks.io), leer = aus.
	DeadManURL string

	// Audit-Export (Etappe 31): Datei für JSON-Zeilen (leer = aus) und
	// Syslog über TLS (nil = aus). Nur als Startoption.
	AuditFile   string
	AuditSyslog *AuditSyslog
	// security.txt (Etappe 36): Kontakte des Betreibers (Startoption
	// -sicherheitskontakt), dazu der Hersteller aus dem Build; aus = 404.
	SecurityContacts []string
	SecurityTxtOff   bool
	// SelfWatchDisks: Pfade, deren Platte die Selbstüberwachung prüft
	// (Standard: /, PostgreSQL, Sicherungen, Logs).
	SelfWatchDisks []string
	// DeadManEvery: höchstens ein Ping je Intervall (Standard 60 s).
	DeadManEvery time.Duration

	// SettingsFromDB: Netze, Alarmziele, Totmann und Schwellen kommen aus der
	// Datenbank (Seite Einstellungen), außer sie sind in Pinned (Startoption
	// gesetzt). false (Tests): nur die Werte oben, die Datenbank zählt nicht.
	// Netze und Schwellen je Mandant und Gerät gelten in beiden Fällen.
	SettingsFromDB bool
	// Pinned: per Startoption gesetzte Felder (Namen wie in der API, z. B. "netze").
	Pinned map[string]bool

	// HTTPS: Zertifikat der Oberfläche aus der Datenbank (Etappe 21a); nil =
	// TLS aus Dateien oder Reverse Proxy davor.
	HTTPS *HTTPS
	// Origins: weitere erlaubte Ursprünge neben BaseURL (alle Namen der
	// Zentrale, z. B. https://10.10.0.5), Form "https://host[:port]".
	Origins []string
	// Simulation: nur Klick-Demo, ersetzt Abfragen über das Netz (simulation.go).
	Simulation Simulation
	// Restart: Zentrale neu starten lassen (systemd startet sie wieder), z. B.
	// nach einer neuen Adresse; nil = nicht möglich (ohne systemd).
	Restart func()
}

func (c *Config) setDefaults() {
	if c.Issuer == "" {
		c.Issuer = "OpenWacht"
	}
	if c.SessionIdle == 0 {
		c.SessionIdle = 30 * time.Minute
	}
	if c.SessionLifetime == 0 {
		c.SessionLifetime = 12 * time.Hour
	}
	if c.PendingLifetime == 0 {
		c.PendingLifetime = 5 * time.Minute
	}
	if c.PasswordParams == nil {
		p := auth.DefaultParams
		c.PasswordParams = &p
	}
	if c.MaxConcurrentHashes == 0 {
		c.MaxConcurrentHashes = 4
	}
	if c.UserRequestsPerMinute <= 0 {
		c.UserRequestsPerMinute = userRate
	}
	if c.LoginsPerMinutePerIP == 0 {
		c.LoginsPerMinutePerIP = 20
	}
	if c.AgentCertLifetime == 0 {
		c.AgentCertLifetime = 30 * 24 * time.Hour
	}
	if c.AgentInterval == 0 {
		c.AgentInterval = 60 * time.Second
	}
	if c.AgentRegistrationsPerMinutePerIP == 0 {
		c.AgentRegistrationsPerMinutePerIP = 30
	}
	if c.CheckConcurrency == 0 {
		c.CheckConcurrency = 32
	}
	if c.CheckPoll == 0 {
		c.CheckPoll = 2 * time.Second
	}
	if c.AlertPoll == 0 {
		c.AlertPoll = 15 * time.Second
	}
	if c.AlertThreshold == 0 {
		c.AlertThreshold = 3
	}
	if c.AlertReminder == 0 {
		c.AlertReminder = 12 * time.Hour
	}
	if c.AlertCollect == 0 {
		c.AlertCollect = time.Minute
	}
	if c.HostSilentAfter == 0 {
		c.HostSilentAfter = 3 * time.Minute
	}
	if c.DeadManEvery == 0 {
		c.DeadManEvery = time.Minute
	}
	for _, x := range []struct {
		v   *float64
		def float64
	}{{&c.DiskWarn, 90}, {&c.DiskCrit, 95}, {&c.MemWarn, 90}, {&c.MemCrit, 95},
		{&c.CPUWarn, 90}, {&c.CPUCrit, 98}, {&c.DiskDays, 14}} {
		if *x.v == 0 {
			*x.v = x.def
		}
	}
}

// hostLimits: Schwellen für alarm.EvaluateHost (aus = 0).
func (c *Config) hostLimits() alarm.HostLimits {
	pos := func(v float64) float64 { return max(v, 0) }
	return alarm.HostLimits{SilentAfter: c.HostSilentAfter,
		DiskWarn: pos(c.DiskWarn), DiskCrit: pos(c.DiskCrit), MemWarn: pos(c.MemWarn), MemCrit: pos(c.MemCrit),
		CPUWarn: pos(c.CPUWarn), CPUCrit: pos(c.CPUCrit), DiskDays: pos(c.DiskDays)}
}

func (c *Config) checkHostLimits() error {
	if c.HostSilentAfter < 2*c.AgentInterval {
		return fmt.Errorf("Hosts gelten frühestens nach zwei Meldeintervallen (%s) als stumm", 2*c.AgentInterval)
	}
	for _, p := range []struct {
		name       string
		warn, crit float64
	}{{"Platte", c.DiskWarn, c.DiskCrit}, {"Arbeitsspeicher", c.MemWarn, c.MemCrit}, {"CPU", c.CPUWarn, c.CPUCrit}} {
		if p.warn > 100 || p.crit > 100 || math.IsNaN(p.warn) || math.IsNaN(p.crit) {
			return fmt.Errorf("%s: Schwellen höchstens 100 %%", p.name)
		}
		if p.warn > 0 && p.crit > 0 && p.warn >= p.crit {
			return fmt.Errorf("%s: Die Warnschwelle muss unter der kritischen liegen", p.name)
		}
	}
	return nil
}

// Server ist die Zentrale.
type Server struct {
	cfg       Config
	downloads downloadPruefung // Prüfsummen der Downloads (downloads.go)
	base      string           // Basis-Pfad aus BaseURL, "" für die Wurzel (basis.go)
	collect   collectWindow    // 1.0.1: Sammelfenster je Mail-/SMS-Kanal
	pool      *pgxpool.Pool
	key       []byte // Hauptschlüssel aus der Schlüsseldatei
	csrfKey   []byte // abgeleitet, nur für CSRF-Token
	boxKey    []byte // abgeleitet, nur für Geheimnisse in der Datenbank
	trapKey   []byte // abgeleitet, nur für die Zugangsdaten des Trap-Dienstes
	// abgeleitet (Etappe 30): Quelle einer Anmeldung als HMAC, Wiederherstellungscodes
	sourceKey   []byte
	recoveryKey []byte
	// Wartezeit vor der Prüfung bei vielen Fehlversuchen; in Tests ersetzbar
	loginWait func(ctx context.Context, d time.Duration) error
	hashSem   chan struct{}
	limiter   *ipLimiter
	// Anmeldungen von Wandanzeigen, getrennt von den Benutzeranmeldungen
	displayLimiter *ipLimiter
	dummyHash      string
	now            func() time.Time
	started        time.Time // Start der Zentrale, für die Schonfrist stummer Hosts
	ui             fs.FS     // Web-Oberfläche; Standard: eingebettet
	agent          agentState
	guard          *checks.Guard
	checker        *checks.Runner

	alertTargets   *alarm.Targets
	alertSender    *alarm.Sender
	mailer         *alarm.Mailer
	fullDays       fullDaysCache
	alertTestLimit perKeyLimit
	// abgelehnte Anlagen von Benutzern je Admin (H3)
	userCreateRejects rejectCounter
	smsWatch          smsWatch
	snmp              *snmp.Client
	snmpProbeLimit    perKeyLimit
	// Sammler: Abruf der Geräteliste je Agent, Ergebnisse je Quelle
	collectorListLimit   perKeyLimit
	collectorResultLimit perKeyLimit
	// Sensoren auf dem Agent: Liste und Ergebnisse je Agent
	sensorListLimit   perKeyLimit
	sensorResultLimit perKeyLimit
	// Meldungen, Zertifikatserneuerung und Update-Abrufe je Agent und Minute:
	// Ein Agent darf die Zentrale nicht mit Messwerten oder Signaturen fluten.
	agentReportRate *rateWindow
	agentRenewRate  *rateWindow
	agentUpdateRate *rateWindow
	pve             *pve.Client
	tr064           *tr064.Client
	deadMan         atomic.Pointer[deadMan] // nil = aus
	live            liveSettings
	https           *HTTPS
	apiTokenRate    *rateWindow
	users           *userGate // Grenzen je Benutzer (H4)
	// nur für Tests: Verbindung zum Verzeichnis ohne Netzfreigabe
	ldapDialOverride func(ctx context.Context, network, addr string) (net.Conn, error)
	// Etappe 31: Audit-Export, Lebenszeichen der Hintergrundläufe
	audit auditExporter
	beats beats
}

// New erstellt den Server. key ist der 32-Byte-Hauptschlüssel.
func New(cfg Config, pool *pgxpool.Pool, key []byte) (*Server, error) {
	if len(key) != auth.KeySize {
		return nil, errors.New("Hauptschlüssel muss 32 Bytes lang sein")
	}
	if cfg.BaseURL == nil || (cfg.BaseURL.Scheme != "https" && cfg.BaseURL.Hostname() != "localhost" && cfg.BaseURL.Hostname() != "127.0.0.1") {
		return nil, errors.New("BaseURL muss https sein (http nur für localhost)")
	}
	if cfg.BaseURL.RawQuery != "" || cfg.BaseURL.Fragment != "" || !validBasePath(basePath(cfg.BaseURL)) {
		return nil, errors.New("BaseURL: Pfad nur aus Buchstaben, Ziffern, - und _ (z. B. https://firma.example/openwacht), ohne ? und #")
	}
	cfg.setDefaults()
	if err := cfg.checkHostLimits(); err != nil {
		return nil, err
	}
	// Ein Dummy-Hash mit denselben Kosten, damit unbekannte E-Mail-Adressen
	// nicht an der Antwortzeit erkennbar sind.
	dummy, err := auth.HashPassword("dummy-passwort-fuer-gleiche-laufzeit", *cfg.PasswordParams)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:          cfg,
		base:         basePath(cfg.BaseURL),
		audit:        auditExporter{failSince: map[string]time.Time{}, failMsg: map[string]string{}},
		pool:         pool,
		key:          key,
		csrfKey:      deriveKey(key, "openwacht csrf v1"),
		boxKey:       deriveKey(key, "openwacht secretbox v1"),
		trapKey:      traps.DeriveKey(key),
		sourceKey:    deriveKey(key, "openwacht login-quelle v1"),
		recoveryKey:  deriveKey(key, "openwacht wiederherstellung v1"),
		loginWait:    sleepCtx,
		hashSem:      make(chan struct{}, cfg.MaxConcurrentHashes),
		apiTokenRate: newRateWindow(apiTokenLimit),
		users:        newUserGate(cfg.UserRequestsPerMinute),
		limiter:      newIPLimiter(cfg.LoginsPerMinutePerIP, time.Minute),
		dummyHash:    dummy,
		now:          time.Now,
		started:      time.Now(),
		ui:           webui.FS(),
		https:        cfg.HTTPS,
	}
	s.agent.limiter = newIPLimiter(cfg.AgentRegistrationsPerMinutePerIP, time.Minute)
	s.agentReportRate = newRateWindow(agentReportsPerMinute)
	s.agentRenewRate = newRateWindow(agentRenewalsPerMinute)
	s.agentUpdateRate = newRateWindow(agentUpdateFetchesPerMinute)
	s.agent.download = newIPLimiter(60, time.Minute)
	s.displayLimiter = newIPLimiter(cfg.LoginsPerMinutePerIP, time.Minute)
	s.guard = checks.NewGuard(cfg.CheckNetworks)
	s.checker = &checks.Runner{Guard: s.guard, Now: func() time.Time { return s.now() }}
	s.alertTargets = cfg.AlertTargets
	if s.alertTargets == nil {
		s.alertTargets = alarm.NewTargets()
	}
	s.alertSender = alarm.NewSender(s.alertTargets)
	s.mailer = alarm.NewMailer(cfg.BaseURL.Hostname())
	s.alertTestLimit.every = 10 * time.Second
	s.snmp = &snmp.Client{Guard: s.guard, Now: func() time.Time { return s.now() }}
	s.snmpProbeLimit.every = 3 * time.Second
	s.collectorListLimit.every = 5 * time.Second
	s.collectorResultLimit.every = 10 * time.Second
	s.sensorListLimit.every = 5 * time.Second
	s.sensorResultLimit.every = 4 * time.Second
	s.pve = &pve.Client{Guard: s.guard, Now: func() time.Time { return s.now() }, UserAgent: "openwacht/" + version.Version}
	s.tr064 = &tr064.Client{Guard: s.guard, Now: func() time.Time { return s.now() }, UserAgent: "openwacht/" + version.Version}
	dm, err := newDeadMan(cfg.DeadManURL, cfg.DeadManEvery)
	if err != nil {
		return nil, err
	}
	s.deadMan.Store(dm)
	s.live.limits = cfg.hostLimits()
	s.live.deadURL = cfg.DeadManURL
	return s, nil
}

// deriveKey leitet zweckgebundene Schlüssel ab, damit derselbe Schlüssel nie
// für zwei Zwecke verwendet wird.
func deriveKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}

func (s *Server) csrfToken(tokenHash []byte) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write(tokenHash)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Handler liefert alle Routen mit der Sicherheits-Middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sitzung", s.handleLogin)
	mux.HandleFunc("GET /openwacht-wurzel.crt", s.handleCADownload)
	mux.HandleFunc("GET /.well-known/security.txt", s.handleSecurityTxt)
	// Nach der Einrichtung ist der Assistent tot (auch mit altem Link).
	mux.HandleFunc("/api/v1/einrichtung/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusGone, "Die Einrichtung ist abgeschlossen. Bitte anmelden.")
	})
	mux.HandleFunc("POST /api/v1/sitzung/zweiter-faktor", s.handleSecondFactor)
	mux.HandleFunc("POST /api/v1/sitzung/sso", s.handleSSOStart)
	mux.HandleFunc("GET /api/v1/sitzung/sso/rueckkehr", s.handleSSOReturn)
	mux.Handle("DELETE /api/v1/sitzung", s.requireSession(true, http.HandlerFunc(s.handleLogout)))
	mux.Handle("GET /api/v1/ich", s.requireSession(true, http.HandlerFunc(s.handleMe)))
	mux.Handle("POST /api/v1/zwei-faktor/einrichten", s.requireSession(true, http.HandlerFunc(s.handleTOTPBegin)))
	mux.Handle("POST /api/v1/zwei-faktor/bestaetigen", s.requireSession(true, http.HandlerFunc(s.handleTOTPConfirm)))
	mux.Handle("POST /api/v1/zwei-faktor/codes", s.requireSession(true, http.HandlerFunc(s.handleRecoveryCodes)))
	// Passkeys (Etappe 36): zusätzlich zur App, nur für das eigene Konto.
	mux.HandleFunc("POST /api/v1/sitzung/passkey/optionen", s.handlePasskeyLoginOptions)
	mux.HandleFunc("POST /api/v1/sitzung/passkey", s.handlePasskeyLogin)
	mux.Handle("GET /api/v1/passkeys", s.requireSession(true, http.HandlerFunc(s.handlePasskeyList)))
	mux.Handle("POST /api/v1/passkeys/optionen", s.requireSession(true, http.HandlerFunc(s.handlePasskeyOptions)))
	mux.Handle("POST /api/v1/passkeys", s.requireSession(true, http.HandlerFunc(s.handlePasskeyCreate)))
	mux.Handle("DELETE /api/v1/passkeys/{id}", s.requireSession(true, http.HandlerFunc(s.handlePasskeyDelete)))
	// Verwaltung: nur mit eingerichtetem 2FA, wenn Admin (requireSession(false, ...)).
	protected := func(h http.HandlerFunc) http.Handler { return s.requireSession(false, h) }
	mux.Handle("GET /api/v1/mandanten", protected(s.handleTenantList))
	mux.Handle("POST /api/v1/mandanten", protected(s.handleTenantCreate))
	mux.Handle("PATCH /api/v1/mandanten/{id}", protected(s.handleTenantRename))
	mux.Handle("DELETE /api/v1/mandanten/{id}", protected(s.handleTenantDelete))
	mux.Handle("GET /api/v1/mandanten-antraege", protected(s.handleTenantRequestList))
	mux.Handle("POST /api/v1/mandanten/{id}/antraege", protected(s.handleTenantRequestCreate))
	mux.Handle("POST /api/v1/mandanten-antraege/{id}/freigeben", protected(s.handleTenantRequestDecide(true)))
	mux.Handle("POST /api/v1/mandanten-antraege/{id}/ablehnen", protected(s.handleTenantRequestDecide(false)))
	mux.Handle("GET /api/v1/mandanten/{id}/rezertifizierung", protected(s.handleRecertReport))
	mux.Handle("GET /api/v1/benutzer", protected(s.handleUserList))
	mux.Handle("POST /api/v1/benutzer", protected(s.handleUserCreate))
	mux.Handle("PATCH /api/v1/benutzer/{id}", protected(s.handleUserUpdate))
	mux.Handle("DELETE /api/v1/benutzer/{id}", protected(s.handleUserDelete))
	mux.Handle("PUT /api/v1/benutzer/{id}/passwort", protected(s.handlePasswordSet))
	mux.Handle("PUT /api/v1/benutzer/{id}/rollen/{mandant}", protected(s.handleRoleSet))
	mux.Handle("DELETE /api/v1/benutzer/{id}/rollen/{mandant}", protected(s.handleRoleDelete))
	// Agents: hinzufügen und sperren dürfen Operatoren und Admins (RLS).
	mux.Handle("POST /api/v1/mandanten/{id}/agent-tokens", protected(s.handleTokenCreate))
	mux.Handle("GET /api/v1/mandanten/{id}/agent-tokens", protected(s.handleTokenList))
	mux.Handle("DELETE /api/v1/agent-tokens/{id}", protected(s.handleTokenDelete))
	mux.Handle("GET /api/v1/agents", protected(s.handleAgentList))
	mux.Handle("POST /api/v1/agents/{id}/sperren", protected(s.handleAgentRevoke))
	mux.Handle("DELETE /api/v1/agents/{id}", protected(s.handleAgentDelete))
	mux.Handle("GET /api/v1/agents/{id}/verlauf", protected(s.handleAgentHistory))
	// Wartung: setzen und beenden dürfen Operatoren und Admins (RLS).
	mux.Handle("GET /api/v1/checks", protected(s.handleCheckList))
	mux.Handle("GET /api/v1/geraete", protected(s.handleDeviceList))
	mux.Handle("POST /api/v1/mandanten/{id}/geraete", protected(s.handleDeviceCreate))
	mux.Handle("PUT /api/v1/geraete/{id}", protected(s.handleDeviceUpdate))
	mux.Handle("DELETE /api/v1/geraete/{id}", protected(s.handleDeviceDelete))
	mux.Handle("GET /api/v1/geraete/{id}/loeschen", protected(s.handleDeviceDeletePreview))
	mux.Handle("GET /api/v1/geraete/{id}/schwellen", protected(s.handleDeviceLimitsGet))
	mux.Handle("PUT /api/v1/geraete/{id}/schwellen", protected(s.handleDeviceLimitsPut))
	mux.Handle("GET /api/v1/einstellungen", protected(s.handleSettingsGet))
	mux.Handle("GET /api/v1/einstellungen/anmeldung", protected(s.handleMFAPolicyGet))
	mux.Handle("GET /api/v1/einstellungen/anmeldedomaenen", protected(s.handleLoginClaims))
	mux.Handle("POST /api/v1/einstellungen/anmeldedomaenen", protected(s.handleLoginClaimDecide))
	mux.Handle("PUT /api/v1/einstellungen/anmeldung", protected(s.handleMFAPolicyPut))
	mux.Handle("GET /api/v1/verzeichnisse", protected(s.handleDirList))
	mux.Handle("GET /api/v1/api-tokens", protected(s.handleAPITokenList))
	mux.Handle("GET /api/v1/downloads", protected(s.handleDownloadsList))
	mux.Handle("GET /api/v1/downloads/{os}/{name}", protected(s.handleDownloadFile))
	mux.Handle("GET /api/v1/agent-updates", protected(s.handleAgentUpdatesGet))
	mux.Handle("POST /api/v1/agent-updates", protected(s.handleAgentUpdateUpload))
	mux.Handle("DELETE /api/v1/agent-updates/{id}", protected(s.handleAgentUpdateDelete))
	mux.Handle("PUT /api/v1/agents/{id}/update", protected(s.handleAgentUpdateRelease))
	mux.Handle("DELETE /api/v1/agents/{id}/update", protected(s.handleAgentUpdateRelease))
	mux.Handle("GET /api/v1/agent-updates/automatik", protected(s.handleAutoList))
	mux.Handle("GET /api/v1/zentrale-update", protected(s.handleZentraleUpdateStand))
	mux.Handle("POST /api/v1/zentrale-update", protected(s.handleZentraleUpdateUpload))
	mux.Handle("PUT /api/v1/mandanten/{id}/agent-updates/automatik", protected(s.handleAutoSet))
	mux.Handle("POST /api/v1/api-tokens", protected(s.handleAPITokenCreate))
	mux.Handle("DELETE /api/v1/api-tokens/{id}", protected(s.handleAPITokenRevoke))
	mux.Handle("POST /api/v1/verzeichnisse", protected(s.handleDirCreate))
	mux.Handle("PUT /api/v1/verzeichnisse/{id}", protected(s.handleDirUpdate))
	mux.Handle("DELETE /api/v1/verzeichnisse/{id}", protected(s.handleDirDelete))
	mux.Handle("POST /api/v1/verzeichnisse/{id}/test", protected(s.handleDirTest))
	mux.Handle("PUT /api/v1/einstellungen", protected(s.handleSettingsPut))
	mux.Handle("PUT /api/v1/einstellungen/mandanten/{id}", protected(s.handleTenantSettingsPut))
	mux.Handle("GET /api/v1/einstellungen/aufbewahrung", protected(s.handleRetentionGet))
	mux.Handle("PUT /api/v1/einstellungen/aufbewahrung", protected(s.handleRetentionPut))
	mux.Handle("PUT /api/v1/einstellungen/mandanten/{id}/aufbewahrung", protected(s.handleTenantRetentionPut))
	mux.Handle("GET /api/v1/einstellungen/installation", protected(s.handleInstallGet))
	mux.Handle("PUT /api/v1/einstellungen/installation", protected(s.handleInstallPut))
	mux.Handle("GET /api/v1/einstellungen/sicherungen", protected(s.handleBackupsGet))
	mux.Handle("GET /api/v1/einstellungen/agent-ca", protected(s.handleAgentCAGet))
	mux.Handle("PUT /api/v1/einstellungen/adresse", protected(s.handleAddressPut))
	mux.Handle("GET /api/v1/einstellungen/https", protected(s.handleHTTPSGet))
	mux.Handle("PUT /api/v1/einstellungen/https", protected(s.handleHTTPSPut))
	mux.Handle("GET /api/v1/einstellungen/mail", protected(s.handleMailSettingsGet))
	mux.Handle("PUT /api/v1/einstellungen/mail", protected(s.handleMailSettingsPut))
	mux.Handle("POST /api/v1/einstellungen/mail/test", protected(s.handleMailSettingsTest))
	mux.Handle("PUT /api/v1/ich/alarm-mails", protected(s.handleMyAlertMail))
	mux.Handle("PUT /api/v1/ich/hinweise-ton", protected(s.handleMyAlarmUI))
	mux.Handle("GET /api/v1/ich/alarm-mobilnummer", protected(s.handleMyAlertMobileGet))
	mux.Handle("PUT /api/v1/ich/alarm-mobilnummer", protected(s.handleMyAlertMobilePut))
	mux.Handle("POST /api/v1/geraete/{id}/zusammenfuehren", protected(s.handleDeviceMerge))
	mux.Handle("POST /api/v1/geraete/{id}/verschieben", protected(s.handleDeviceMove))
	mux.Handle("POST /api/v1/geraete/gruppe", protected(s.handleDeviceGroupAssign))
	mux.Handle("GET /api/v1/gruppen", protected(s.handleGroupList))
	mux.Handle("POST /api/v1/mandanten/{id}/gruppen", protected(s.handleGroupCreate))
	mux.Handle("PUT /api/v1/gruppen/{id}", protected(s.handleGroupUpdate))
	mux.Handle("POST /api/v1/gruppen/{id}/position", protected(s.handleGroupPosition))
	mux.Handle("DELETE /api/v1/gruppen/{id}", protected(s.handleGroupDelete))
	mux.Handle("POST /api/v1/geraete/{id}/agent-token", protected(s.handleDeviceToken))
	mux.Handle("PUT /api/v1/geraete/{id}/wartung", protected(s.handleDeviceMaintenanceSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/wartung", protected(s.handleDeviceMaintenanceEnd))
	mux.Handle("GET /api/v1/geraete/{id}/sparklines", protected(s.handleDeviceSparklines))
	mux.Handle("POST /api/v1/geraete/{id}/checks", protected(s.handleCheckCreate))
	mux.Handle("PUT /api/v1/checks/{id}", protected(s.handleCheckUpdate))
	mux.Handle("DELETE /api/v1/checks/{id}", protected(s.handleCheckDelete))
	mux.Handle("POST /api/v1/geraete/{id}/checks/herkunft-loeschen", protected(s.handleCheckDeleteOrigin))
	mux.Handle("POST /api/v1/checks/{id}/jetzt", protected(s.handleCheckNow))
	mux.Handle("GET /api/v1/checks/{id}/verlauf", protected(s.handleCheckHistory))
	mux.Handle("PUT /api/v1/checks/{id}/wartung", protected(s.handleCheckMaintenanceSet))
	mux.Handle("DELETE /api/v1/checks/{id}/wartung", protected(s.handleCheckMaintenanceEnd))
	mux.Handle("GET /api/v1/wartung", protected(s.handleMaintenanceOverview))
	mux.Handle("POST /api/v1/wartungsfenster", protected(s.handleWindowCreate))
	mux.Handle("PUT /api/v1/wartungsfenster/{id}", protected(s.handleWindowUpdate))
	mux.Handle("DELETE /api/v1/wartungsfenster/{id}", protected(s.handleWindowDelete))
	// Alarmkanäle: pflegen nur Admins des Mandanten (RLS).
	mux.Handle("GET /api/v1/sensor-vorlagen", protected(s.handleTemplateList))
	mux.Handle("POST /api/v1/mandanten/{id}/sensor-vorlagen", protected(s.handleTemplateCreate))
	mux.Handle("PUT /api/v1/sensor-vorlagen/{id}", protected(s.handleTemplateUpdate))
	mux.Handle("DELETE /api/v1/sensor-vorlagen/{id}", protected(s.handleTemplateDelete))
	mux.Handle("POST /api/v1/sensor-vorlagen/anwenden", protected(s.handleTemplateApply))
	mux.Handle("POST /api/v1/mandanten/{id}/sensor-vorlagensaetze", protected(s.handleSetCreate))
	mux.Handle("PUT /api/v1/sensor-vorlagensaetze/{id}", protected(s.handleSetUpdate))
	mux.Handle("DELETE /api/v1/sensor-vorlagensaetze/{id}", protected(s.handleSetDelete))
	mux.Handle("GET /api/v1/kennfarben", protected(s.handleKennfarbeList))
	mux.Handle("POST /api/v1/mandanten/{id}/kennfarben", protected(s.handleKennfarbeCreate))
	mux.Handle("PUT /api/v1/kennfarben/{id}", protected(s.handleKennfarbeUpdate))
	mux.Handle("DELETE /api/v1/kennfarben/{id}", protected(s.handleKennfarbeDelete))
	mux.Handle("PUT /api/v1/sensoren/kennfarbe", protected(s.handleSensorKennfarbe))
	mux.Handle("PUT /api/v1/sensoren/herkunft-kennfarbe", protected(s.handleOriginKennfarbe))
	mux.Handle("POST /api/v1/sensoren/ausnehmen", protected(s.handleSensorExclude))
	mux.Handle("POST /api/v1/sensoren/einbeziehen", protected(s.handleSensorInclude))
	mux.Handle("GET /api/v1/snmp/{id}/entfernt", protected(s.handleSensorHiddenList))

	mux.Handle("GET /api/v1/snmp", protected(s.handleSNMPList))
	mux.Handle("GET /api/v1/snmp-profile", protected(s.handleSNMPProfileList))
	mux.Handle("POST /api/v1/mandanten/{id}/snmp-profile", protected(s.handleSNMPProfileCreate))
	mux.Handle("PUT /api/v1/snmp-profile/{id}", protected(s.handleSNMPProfileUpdate))
	mux.Handle("DELETE /api/v1/snmp-profile/{id}", protected(s.handleSNMPProfileDelete))
	mux.Handle("POST /api/v1/mandanten/{id}/geraete/import", protected(s.handleDeviceImport))
	mux.Handle("PUT /api/v1/geraete/{id}/snmp", protected(s.handleSNMPSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/snmp", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/snmp/pruefen", protected(s.handleSNMPProbe))
	mux.Handle("POST /api/v1/snmp/{id}/jetzt", protected(s.handleSNMPNow))
	mux.Handle("PUT /api/v1/geraete/{id}/proxmox", protected(s.handlePVESet))
	mux.Handle("DELETE /api/v1/geraete/{id}/proxmox", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/proxmox/pruefen", protected(s.handlePVEProbe))
	mux.Handle("PUT /api/v1/geraete/{id}/vcenter", protected(s.handleVCSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/vcenter", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/vcenter/pruefen", protected(s.handleVCProbe))
	mux.Handle("PUT /api/v1/geraete/{id}/fritzbox", protected(s.handleFritzSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/fritzbox", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/fritzbox/pruefen", protected(s.handleFritzProbe))
	mux.Handle("PUT /api/v1/geraete/{id}/netapp", protected(s.handleNetAppSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/netapp", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/netapp/pruefen", protected(s.handleNetAppProbe))
	mux.Handle("PUT /api/v1/geraete/{id}/xenserver", protected(s.handleXenSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/xenserver", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/xenserver/pruefen", protected(s.handleXenProbe))
	mux.Handle("PUT /api/v1/geraete/{id}/citrix", protected(s.handleCitrixSet))
	mux.Handle("DELETE /api/v1/geraete/{id}/citrix", protected(s.handleSNMPDelete))
	mux.Handle("POST /api/v1/geraete/{id}/citrix/pruefen", protected(s.handleCitrixProbe))
	mux.Handle("GET /api/v1/snmp/{id}/verlauf", protected(s.handleSNMPHistory))
	mux.Handle("GET /api/v1/snmp/{id}/traps", protected(s.handleTrapLog))
	mux.Handle("POST /api/v1/snmp/{id}/traps/zuruecksetzen", protected(s.handleTrapReset))
	mux.Handle("GET /api/v1/trapregeln", protected(s.handleTrapRuleList))
	mux.Handle("POST /api/v1/trapregeln", protected(s.handleTrapRuleCreate))
	mux.Handle("PUT /api/v1/trapregeln/{id}", protected(s.handleTrapRuleUpdate))
	mux.Handle("DELETE /api/v1/trapregeln/{id}", protected(s.handleTrapRuleDelete))
	mux.Handle("POST /api/v1/mandanten/{id}/trapregeln/reihenfolge", protected(s.handleTrapRuleOrder))
	mux.Handle("POST /api/v1/mandanten/{id}/trapregeln/standard", protected(s.handleTrapRuleDefaults))

	mux.Handle("GET /api/v1/alarm-kanaele", protected(s.handleChannelList))
	mux.Handle("POST /api/v1/mandanten/{id}/alarm-kanaele", protected(s.handleChannelCreate))
	mux.Handle("PUT /api/v1/alarm-kanaele/{id}", protected(s.handleChannelUpdate))
	mux.Handle("DELETE /api/v1/alarm-kanaele/{id}", protected(s.handleChannelDelete))
	mux.Handle("POST /api/v1/alarm-kanaele/{id}/test", protected(s.handleChannelTest))
	mux.Handle("PUT /api/v1/alarm-kanaele/{id}/zustellung", protected(s.handleChannelDelivery))
	mux.Handle("GET /api/v1/berichte", protected(s.handleReport))
	mux.Handle("GET /api/v1/berichte/pdf", protected(s.handleReportPDF))
	mux.Handle("PUT /api/v1/mandanten/{id}/sla", protected(s.handleSLA))
	mux.Handle("GET /api/v1/mandanten/{id}/alarm-empfaenger", protected(s.handleChannelRecipients))
	mux.Handle("POST /api/v1/mandanten/{id}/alarm-kanaele/sms-fingerabdruck", protected(s.handleSMSFingerprint))
	mux.Handle("GET /api/v1/alarme", protected(s.handleAlarmList))
	mux.Handle("POST /api/v1/alarme/{id}/bestaetigen", protected(s.handleAlarmAck))
	mux.Handle("GET /api/v1/sensoren", protected(s.handleSensors))
	mux.Handle("GET /api/v1/prognose/platten", protected(s.handleDiskForecast))
	mux.Handle("GET /api/v1/dashboard/verlauf", protected(s.handleDashboardHistory))
	mux.Handle("GET /api/v1/dashboard/kennzahlen", protected(s.handleDashboardFigures))
	mux.Handle("GET /api/v1/dashboard/layout", protected(s.handleLayoutGet))
	mux.Handle("PUT /api/v1/dashboard/layout", protected(s.handleLayoutPut))
	mux.Handle("DELETE /api/v1/dashboard/layout", protected(s.handleLayoutDelete))
	mux.Handle("GET /api/v1/anzeigen", protected(s.handleDisplayList))
	mux.Handle("POST /api/v1/mandanten/{id}/anzeigen", protected(s.handleDisplayCreate))
	mux.Handle("DELETE /api/v1/anzeigen/{id}", protected(s.handleDisplayDelete))
	mux.Handle("POST /api/v1/anzeigen/{id}/neuer-link", protected(s.handleDisplayNewLink))
	mux.Handle("PUT /api/v1/anzeigen/{id}/ton", protected(s.handleDisplaySound))
	mux.Handle("GET /api/v1/anzeigen/{id}/vorschau", protected(s.handleDisplayPreview))
	// Wandanzeige selbst: ohne Benutzersitzung, nur mit Anzeige-Cookie.
	mux.HandleFunc("POST /api/v1/anzeige/anmelden", s.handleDisplayLogin)
	mux.Handle("GET /api/v1/anzeige/daten", s.requireDisplay(http.HandlerFunc(s.handleDisplayData)))
	mux.HandleFunc("GET /api/v1/gesund", s.handleHealth)
	mux.Handle("GET /api/v1/audit/export", protected(s.handleAuditExport))
	mux.Handle("GET /api/v1/einstellungen/audit", protected(s.handleAuditStatus))
	mux.Handle("GET /api/v1/hinweise", protected(s.handleNotices))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Unbekannter Endpunkt.")
	})
	mux.Handle("/", uiHandler(s.ui, s.base))
	return s.stripBase(s.securityHeaders(s.checkOrigin(mux)))
}

// withUser führt fn in einer Transaktion mit gesetztem Benutzerkontext aus.
// Alles, was mandantenbezogene Daten liest oder schreibt, läuft hierüber.
func (s *Server) withUser(ctx context.Context, userID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// statement_timeout (H4): eine Abfrage eines Benutzers läuft nicht ewig.
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true), set_config('statement_timeout', $2, true)`,
			userID, userStatementTimeout); err != nil {
			return err
		}
		return fn(tx)
	})
}
