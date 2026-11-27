// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Sensor-Vorlagen (Etappe 18): eine Sensorart mit Vorbelegung, anwendbar auf
// Geräte oder eine Gruppe. Entscheidung (Entscheidung, 21.11.2026): Ein Sensor aus
// einer Vorlage ist eine Kopie, gemerkt wird nur der Name der Vorlage
// (checks.origin). Auf eine Gruppe angewandt, gilt das einmalig für die
// Geräte, die jetzt darin sind.
//
// Eingebaute Vorlagen stehen hier im Code; eigene Vorlagen gehören einem
// Mandanten (openwacht.sensor_templates, RLS wie Checks).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/checks"
)

type vorlageOut struct {
	ID        string          `json:"id"`
	MandantID *string         `json:"mandant_id"` // nil = eingebaut
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Notiz     string          `json:"notiz"`
	AmAgent   bool            `json:"am_agent"`
	// Ziel braucht die Adresse des Geräts ({adresse})
	BrauchtAdresse bool       `json:"braucht_adresse"`
	Geaendert      *time.Time `json:"geaendert,omitempty"`
	// 1.0.1: Kennfarbe eines Eintrags im eigenen Vorlagensatz (beim Anwenden übernommen)
	Kennfarbe *string `json:"kennfarbe_id,omitempty"`
	// 1.0.6: Fehlversuche bis zum Alarm (nil = Standard), beim Anwenden übernommen
	Fehlversuche *int `json:"fehlversuche"`
}

// builtinTemplates: die gängigsten Sensoren. IDs mit Präfix „std-“.
var builtinTemplates = func() []vorlageOut {
	list := []struct {
		id, name, kind, target, note string
		interval                     int
	}{
		{"std-ping", "Ping mit Verlust", "ping", `{"host":"{adresse}","anzahl":5,"verlust_warnung":20,"verlust_kritisch":60}`,
			"5 Pakete; Warnung ab 20 %, kritisch ab 60 % Verlust", 60},
		{"std-https", "HTTPS-Seite", "http", `{"url":"https://{adresse}/"}`, "Statuscode 200–399, Antwortzeit", 300},
		{"std-tls", "TLS-Zertifikat", "tls", `{"host":"{adresse}","port":443}`, "Warnung 21 Tage, kritisch 7 Tage vor Ablauf", 3600},
		{"std-ssh", "SSH-Port", "tcp", `{"host":"{adresse}","port":22}`, "Port 22 offen", 300},
		{"std-smb", "SMB-Freigabe (Port 445)", "tcp", `{"host":"{adresse}","port":445}`, "Port 445 offen", 300},
		{"std-rdp", "Remotedesktop (Port 3389)", "tcp", `{"host":"{adresse}","port":3389}`, "Port 3389 offen", 300},
		{"std-dns", "DNS-Name löst auf", "dns", `{"name":"{adresse}"}`, "nur für Geräte mit Namen als Adresse", 300},
		{"std-smtp", "Mailserver (SMTP-Banner)", "tcp_banner", `{"host":"{adresse}","port":25,"enthaelt":"220"}`, "Port 25 meldet sich mit 220", 300},
		{"std-imaps", "IMAPS-Banner (Port 993)", "tcp_banner", `{"host":"{adresse}","port":993,"tls":true,"enthaelt":"OK"}`,
			"direktes TLS, Begrüßung mit OK", 300},
		{"std-ssh-banner", "SSH-Banner", "tcp_banner", `{"host":"{adresse}","port":22,"enthaelt":"SSH-2.0"}`, "Port 22 meldet sich als SSH-2.0", 300},
		{"std-ntp", "Zeitserver (NTP)", "ntp", `{"host":"{adresse}"}`, "Warnung ab 100 ms, Fehler ab 1000 ms Abweichung, Stratum 16", 300},
		{"std-syno-status", "Synology Systemzustand", "snmp_oid", `{"oid":"1.3.6.1.4.1.6574.1.1.0","gleich":"1"}`,
			"systemStatus 1 = Normal; braucht SNMP am Gerät", 60},
		{"std-syno-temp", "Synology Temperatur", "snmp_oid", `{"oid":"1.3.6.1.4.1.6574.1.2.0","warnung_ueber":60,"kritisch_ueber":70}`,
			"Systemtemperatur in °C; braucht SNMP am Gerät", 60},
		{"std-dienst-ssh", "Dienst SSH (Linux)", "dienst", `{"name":"ssh"}`, "systemd-Unit ssh.service läuft (Debian/Ubuntu)", 60},
		{"std-dienst-docker", "Dienst Docker (Linux)", "dienst", `{"name":"docker"}`, "systemd-Unit docker.service läuft", 60},
		{"std-dienst-spooler", "Dienst Druckwarteschlange (Windows)", "dienst", `{"name":"Spooler"}`, "Windows-Dienst Spooler läuft", 60},
		{"std-autodienste", "Automatische Dienste (Windows)", "autodienste",
			`{"ausnahmen":["gupdate","edgeupdate","sppsvc","MapsBroker","RemoteRegistry"]}`,
			"alle Dienste mit Starttyp „Automatisch“ laufen; Ausnahmen anpassen; am Windows-Agent freigeben", 300},
		{"std-docker", "Docker-Container läuft", "docker", `{"name":"container"}`,
			"Name anpassen; am Agent Docker über einen nur-lesenden Socket-Proxy freigeben", 60},
		{"std-hyperv", "Hyper-V-VM läuft", "hyperv", `{"name":"vm"}`,
			"Name anpassen; am Windows-Agent Hyper-V freigeben", 60},
		{"std-vzdump", "Proxmox-Backups (Ordner)", "datei",
			`{"pfad":"/var/lib/vz/dump","ordner":true,"warnung_stunden":26,"kritisch_stunden":50}`,
			"jüngstes Backup: Warnung ab 26 Std., kritisch ab 50 Std.; Ordner am Agent freigeben", 300},
		{"std-backup-datei", "Backup-Datei aktuell", "datei",
			`{"pfad":"/var/backups/backup.tar","warnung_stunden":26,"kritisch_stunden":50,"mindestgroesse":1024}`,
			"Pfad anpassen; Ordner am Agent freigeben", 300},
	}
	out := make([]vorlageOut, len(list))
	for i, t := range list {
		out[i] = vorlageOut{ID: t.id, Name: t.name, Typ: t.kind, Ziel: json.RawMessage(t.target), Intervall: t.interval,
			Notiz: t.note, AmAgent: checks.IsAgentKind(t.kind), BrauchtAdresse: checks.UsesPlaceholder([]byte(t.target))}
	}
	return out
}()

// --- Vorlagensätze (0.44.0) -------------------------------------------------------

// vorlagenSatz: mehrere Sensoren für eine Anwendung auf einmal (Swyx,
// Ferrari OfficeMaster, IQ4docs). Wie bei Vorlagen ist jeder angelegte
// Sensor eine Kopie; gemerkt wird der Name des Satzes (checks.origin).
// Sätze stehen nur im Code, eigene Sätze gibt es (noch) nicht.
type vorlagenSatz struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Notiz    string       `json:"notiz"`
	Sensoren []vorlageOut `json:"sensoren"`
}

type satzEintrag struct {
	name, kind, target, note string
	interval                 int
}

func newSet(id, name, note string, list []satzEintrag) vorlagenSatz {
	out := vorlagenSatz{ID: id, Name: name, Notiz: note}
	for i, t := range list {
		out.Sensoren = append(out.Sensoren, vorlageOut{ID: fmt.Sprintf("%s-%d", id, i+1), Name: t.name, Typ: t.kind,
			Ziel: json.RawMessage(t.target), Intervall: t.interval, Notiz: t.note,
			AmAgent: checks.IsAgentKind(t.kind), BrauchtAdresse: checks.UsesPlaceholder([]byte(t.target))})
	}
	return out
}

// builtinSets: Namen der Dienste, Objekte und Indikatoren aus der Doku der
// Hersteller (Stand 23.11.2026); was dort nicht steht, ist in der Notiz als
// „prüfen“ markiert (Prüfliste Echtbetrieb).
var builtinSets = []vorlagenSatz{
	newSet("satz-swyx", "Swyx", "SwyxWare auf Windows: Dienste und Leistungsindikatoren. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "SwyxServer,SwyxWare Trunk"`, []satzEintrag{
		// Dienstnamen statt Anzeigenamen (an SwyxWare abgelesen, 24.11.2026);
		// die Anzeigenamen SwyxServer usw. fände der Agent auch.
		{"Swyx: Dienst SwyxServer", "dienst", `{"name":"IpPbxSrv"}`, "SwyxServer läuft", 60},
		{"Swyx: Dienst ConfigDataStore", "dienst", `{"name":"IpPbxCDS"}`, "Datenbankzugriff des SwyxServer", 60},
		{"Swyx: Dienst LinkManager", "dienst", `{"name":"LinkMgr"}`, "SIP- und IP-Verbindungen", 60},
		{"Swyx: Server aktiv", "leistungsindikator", `{"objekt":"SwyxServer","indikator":"Server Active","kritisch_unter":1}`,
			"größer 0, wenn der Server aktiv ist", 60},
		{"Swyx: Leitungen angemeldet", "leistungsindikator", `{"objekt":"SwyxServer","indikator":"Trunks","kritisch_unter":1}`,
			"Zahl angemeldeter Leitungen (SwyxGate und SIP/IP); kritisch bei 0", 60},
		{"Swyx: Leitung abgemeldet", "leistungsindikator",
			`{"objekt":"SwyxWare Trunk","indikator":"Trunk registered at server","instanz":"*","zusammenfassung":"minimum","kritisch_unter":1}`,
			"kritisch, sobald eine Leitung nicht angemeldet ist (ohne Namen der Leitungen)", 60},
		{"Swyx: Kanalauslastung", "leistungsindikator",
			`{"objekt":"SwyxServer","indikator":"Active external calls","bezug":"Licensed channels","warnung_ueber":80,"kritisch_ueber":95}`,
			"externe Gespräche in Prozent der lizenzierten Kanäle", 60},
		{"Swyx: Gespräche", "leistungsindikator", `{"objekt":"SwyxServer","indikator":"Active Calls"}`,
			"gleichzeitige Gespräche (nur Anzeige)", 60},
		{"Swyx: Lizenzen Benutzer", "leistungsindikator",
			`{"objekt":"SwyxServer","indikator":"Logged in users","bezug":"Licensed users","warnung_ueber":90,"kritisch_ueber":98}`,
			"angemeldete Benutzer in Prozent der Benutzerlizenzen", 300},
		{"Swyx: SIP-Geräte", "leistungsindikator", `{"objekt":"SwyxServer","indikator":"SIP devices"}`,
			"angemeldete SIP-Geräte (nur Anzeige)", 60},
	}),
	newSet("satz-ferrari", "Ferrari OfficeMaster", "OfficeMaster Suite: Dienste am Agent, Fax-Zähler über SNMP nur auf dem Server selbst "+
		"(Windows-SNMP-Dienst nimmt nur localhost an, der Agent fragt als Sammler 127.0.0.1 ab). Dienst des Messaging Servers "+
		"und weitere OIDs aus der MIB ergänzen. Am Agent freigeben: openwacht-agent sensoren -arten dienst", []satzEintrag{
		{"Ferrari: Windows-SNMP-Dienst", "dienst", `{"name":"SNMP"}`, "liefert die Zähler der Suite", 60},
		{"Ferrari: Webdienst (IIS)", "dienst", `{"name":"W3SVC"}`, "Weboberfläche und Webservice der Suite", 60},
		{"Ferrari: Faxe eingehend aktiv", "snmp_oid", `{"oid":"1.3.6.1.4.1.17524.1.1.1.2.2.15.2.1.20"}`,
			"fmsrvSendRecFaxInActiveJobs (Handbuch 9.3.1); Index mit der MIB am Server prüfen; braucht SNMP am Gerät", 60},
	}),
	newSet("satz-iq4docs", "IQ4docs", "IQ4docs 5 auf Windows: Dienste, IIS-Anwendungspools, Weboberfläche. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren APP_POOL_WAS`, []satzEintrag{
		// Dienstnamen (nicht Anzeigenamen) an einer Installation abgelesen
		// (24.11.2026): Der RabbitMQ-Dienst heißt auch im Anzeigenamen ohne
		// Leerzeichen, „IQ4docs RabbitMQ“ fand der Agent nicht.
		{"IQ4docs: Dienst MongoDB", "dienst", `{"name":"IQ4docsMongoDB"}`, "Datenbank der Microservices", 60},
		{"IQ4docs: Dienst RabbitMQ", "dienst", `{"name":"IQ4docsRabbitMQ"}`, "Nachrichtenwarteschlange der Microservices", 60},
		{"IQ4docs: Dienst Fleet Agent", "dienst", `{"name":"iq4dService"}`, "IQ4docsFleet Agent", 60},
		{"IQ4docs: Dienst Fleet Watchdog", "dienst", `{"name":"iq4dWatchdog"}`, "IQ4docsFleet Watchdog", 60},
		{"IQ4docs: Webserver (IIS)", "dienst", `{"name":"W3SVC"}`, "Webadmin, WebClient und Services", 60},
		{"IQ4docs: Anwendungspool gestoppt", "leistungsindikator",
			`{"objekt":"APP_POOL_WAS","indikator":"Current Application Pool State","instanz":"*","zusammenfassung":"maximum","kritisch_ueber":3}`,
			"3 = läuft; größer 3 heißt, mindestens ein Pool wird gestoppt oder ist aus (ohne Namen)", 60},
		{"IQ4docs: Weboberfläche", "http", `{"url":"https://{adresse}/"}`, "Webadmin bzw. WebClient antwortet", 300},
		{"IQ4docs: Zertifikat", "tls", `{"host":"{adresse}","port":443}`, "Warnung 21 Tage, kritisch 7 Tage vor Ablauf", 3600},
	}),
	// 0.45.0: Exchange Server 2016, 2019 und SE mit DAG (Entscheidung
	// 23.11.2026: DAG gehört in den Satz). Dienste und Indikatoren laut
	// Microsoft-Doku; healthcheck.htm liefert 200, solange Managed
	// Availability den Dienst für gesund hält, sonst 404. Keine Postfach-,
	// Datenbank- oder Warteschlangennamen (Leitprinzip 5).
	newSet("satz-exchange", "Exchange", "Exchange Server mit DAG: Dienste, Mailwarteschlangen, Replikation, Zustand der Webdienste. "+
		"Gerät mit dem DNS-Namen des Zertifikats anlegen. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "MSExchangeTransport Queues,MSExchange Replication"`, []satzEintrag{
		{"Exchange: Dienst Informationsspeicher", "dienst", `{"name":"MSExchangeIS"}`, "Postfachdatenbanken", 60},
		{"Exchange: Dienst Transport", "dienst", `{"name":"MSExchangeTransport"}`, "SMTP und Transport", 60},
		{"Exchange: Dienst Frontend-Transport", "dienst", `{"name":"MSExchangeFrontEndTransport"}`, "SMTP von außen", 60},
		{"Exchange: Dienst Zustellung", "dienst", `{"name":"MSExchangeDelivery"}`, "Postfach-Transport, Zustellung", 60},
		{"Exchange: Dienst Übermittlung", "dienst", `{"name":"MSExchangeSubmission"}`, "Postfach-Transport, Übermittlung", 60},
		{"Exchange: Dienst AD-Topologie", "dienst", `{"name":"MSExchangeADTopology"}`, "Verbindung zum Active Directory", 60},
		{"Exchange: Dienst Replikation", "dienst", `{"name":"MSExchangeRepl"}`, "DAG-Replikation", 60},
		{"Exchange: Webserver (IIS)", "dienst", `{"name":"W3SVC"}`, "OWA, EWS, ActiveSync, MAPI", 60},
		// Exchange 2013 und neuer teilt die Summen in intern und extern; „(All
		// Queues)“ und „Retry Remote Delivery Queue Length“ gibt es dort nicht
		// Namen aus Perflib\009 eines Exchange-Servers ausgelesen (24.11.2026).
		{"Exchange: Warteschlangen intern", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"Internal Aggregate Delivery Queue Length (All Internal Queues)","instanz":"_Total","warnung_ueber":500,"kritisch_ueber":3000}`,
			"Mails in allen internen Zustell-Warteschlangen", 60},
		{"Exchange: Warteschlangen extern", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"External Aggregate Delivery Queue Length (All External Queues)","instanz":"_Total","warnung_ueber":500,"kritisch_ueber":3000}`,
			"Mails in allen Zustell-Warteschlangen nach außen", 60},
		{"Exchange: Wiederholung intern", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"Internal Retry Remote Delivery Queue Length","instanz":"_Total","warnung_ueber":50,"kritisch_ueber":100}`,
			"Mails an andere Exchange-Server, die erneut versucht werden", 60},
		{"Exchange: Wiederholung extern", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"External Retry Remote Delivery Queue Length","instanz":"_Total","warnung_ueber":50,"kritisch_ueber":100}`,
			"Mails nach außen, die erneut versucht werden", 60},
		{"Exchange: Warteschlange unerreichbar", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"Unreachable Queue Length","instanz":"_Total","warnung_ueber":50,"kritisch_ueber":100}`,
			"Mails ohne erreichbares Ziel", 60},
		{"Exchange: Warteschlange Poison", "leistungsindikator",
			`{"objekt":"MSExchangeTransport Queues","indikator":"Poison Queue Length","instanz":"_Total","warnung_ueber":0,"kritisch_ueber":4}`,
			"soll immer 0 sein; ab 5 kritisch", 60},
		{"Exchange: DAG Kopier-Warteschlange", "leistungsindikator",
			`{"objekt":"MSExchange Replication","indikator":"CopyQueueLength","instanz":"*","zusammenfassung":"maximum","warnung_ueber":10,"kritisch_ueber":50}`,
			"höchste Zahl noch nicht kopierter Logdateien einer passiven Kopie (ohne Datenbanknamen)", 60},
		{"Exchange: DAG Wiedergabe-Warteschlange", "leistungsindikator",
			`{"objekt":"MSExchange Replication","indikator":"ReplayQueueLength","instanz":"*","zusammenfassung":"maximum","warnung_ueber":100,"kritisch_ueber":500}`,
			"höchste Zahl noch nicht eingespielter Logdateien; bei verzögerten Kopien Schwellen anheben", 60},
		{"Exchange: OWA", "http", `{"url":"https://{adresse}/owa/healthcheck.htm","erwarte_status":[200]}`, "Outlook im Web laut Managed Availability gesund", 300},
		{"Exchange: ECP", "http", `{"url":"https://{adresse}/ecp/healthcheck.htm","erwarte_status":[200]}`, "Exchange Admin Center", 300},
		{"Exchange: EWS", "http", `{"url":"https://{adresse}/EWS/healthcheck.htm","erwarte_status":[200]}`, "Exchange-Webdienste", 300},
		{"Exchange: ActiveSync", "http", `{"url":"https://{adresse}/Microsoft-Server-ActiveSync/healthcheck.htm","erwarte_status":[200]}`, "Mobilgeräte", 300},
		{"Exchange: MAPI über HTTP", "http", `{"url":"https://{adresse}/mapi/healthcheck.htm","erwarte_status":[200]}`, "Outlook", 300},
		{"Exchange: Autodiscover", "http", `{"url":"https://{adresse}/Autodiscover/healthcheck.htm","erwarte_status":[200]}`, "automatische Einrichtung", 300},
		{"Exchange: SMTP", "tcp_banner", `{"host":"{adresse}","port":25,"enthaelt":"220"}`, "Port 25 meldet sich mit 220", 300},
		{"Exchange: Zertifikat", "tls", `{"host":"{adresse}","port":443}`, "Warnung 21 Tage, kritisch 7 Tage vor Ablauf", 3600},
	}),
	// 0.46.0: Domänencontroller. Dienste laut Microsoft (AD DS), Replikation
	// und LDAP über das Objekt DirectoryServices (Instanz NTDS, ab 2012 R2).
	newSet("satz-dc", "Domänencontroller", "Active Directory: Dienste, Replikation, LDAP, DNS, Kerberos, Zeit, LDAPS-Zertifikat. "+
		"Am Agent freigeben: "+`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren DirectoryServices`, []satzEintrag{
		{"DC: Dienst Active Directory", "dienst", `{"name":"NTDS"}`, "Active Directory Domain Services", 60},
		{"DC: Dienst Netlogon", "dienst", `{"name":"Netlogon"}`, "Anmeldung, DC-Locator", 60},
		{"DC: Dienst Kerberos (KDC)", "dienst", `{"name":"kdc"}`, "Kerberos-Schlüsselverteilung", 60},
		{"DC: Dienst DNS-Server", "dienst", `{"name":"DNS"}`, "nur, wenn der DC auch DNS-Server ist", 60},
		{"DC: Dienst DFS-Replikation", "dienst", `{"name":"DFSR"}`, "SYSVOL-Replikation", 60},
		{"DC: Dienst Zeit", "dienst", `{"name":"W32Time"}`, "Windows-Zeitdienst", 60},
		{"DC: Dienst Standortübergreifend", "dienst", `{"name":"IsmServ"}`, "Intersite Messaging", 60},
		{"DC: Dienst AD-Webdienste", "dienst", `{"name":"ADWS"}`, "für PowerShell und Verwaltungskonsolen", 60},
		{"DC: Replikation ausstehend", "leistungsindikator",
			`{"objekt":"DirectoryServices","indikator":"DRA Pending Replication Synchronizations","instanz":"NTDS","warnung_ueber":10,"kritisch_ueber":50}`,
			"wartende Replikationen; dauerhaft hoch heißt Rückstau", 60},
		{"DC: LDAP-Sitzungen", "leistungsindikator",
			`{"objekt":"DirectoryServices","indikator":"LDAP Client Sessions","instanz":"NTDS"}`, "verbundene LDAP-Clients (nur Anzeige)", 60},
		{"DC: LDAP", "tcp", `{"host":"{adresse}","port":389}`, "Port 389 offen", 300},
		{"DC: LDAPS-Zertifikat", "tls", `{"host":"{adresse}","port":636}`, "LDAPS: Warnung 21 Tage, kritisch 7 Tage vor Ablauf", 3600},
		{"DC: Kerberos", "tcp", `{"host":"{adresse}","port":88}`, "Port 88 offen", 300},
		{"DC: DNS", "tcp", `{"host":"{adresse}","port":53}`, "Port 53 offen (nur DCs mit DNS)", 300},
		{"DC: Zeit (NTP)", "ntp", `{"host":"{adresse}"}`, "Zeitabweichung des DC", 300},
	}),
	// 0.46.0: SQL Server, Standardinstanz (MSSQLSERVER). Für benannte
	// Instanzen heißen Dienste und Objekte anders (MSSQL$NAME,
	// MSSQL$NAME:General Statistics): als eigenen Satz kopieren und anpassen.
	newSet("satz-sql", "SQL Server", "Microsoft SQL Server, Standardinstanz: Dienste, blockierte Prozesse, Deadlocks, Transaktionsprotokoll, "+
		"Speicher. Benannte Instanz: als eigenen Satz kopieren, MSSQL$NAME bzw. SQLAgent$NAME und Objekte MSSQL$NAME:… eintragen. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "SQLServer:General Statistics,SQLServer:Locks,SQLServer:Databases,SQLServer:Memory Manager,SQLServer:Buffer Manager"`,
		[]satzEintrag{
			{"SQL: Dienst Datenbankmodul", "dienst", `{"name":"MSSQLSERVER"}`, "SQL Server (Standardinstanz)", 60},
			{"SQL: Dienst Agent", "dienst", `{"name":"SQLSERVERAGENT"}`, "Aufträge, Sicherungen (nicht in Express)", 60},
			{"SQL: Blockierte Prozesse", "leistungsindikator",
				`{"objekt":"SQLServer:General Statistics","indikator":"Processes blocked","warnung_ueber":5,"kritisch_ueber":20}`,
				"derzeit blockierte Prozesse", 60},
			{"SQL: Verbindungen", "leistungsindikator", `{"objekt":"SQLServer:General Statistics","indikator":"User Connections"}`,
				"verbundene Benutzer (nur Anzeige)", 60},
			{"SQL: Deadlocks", "leistungsindikator",
				`{"objekt":"SQLServer:Locks","indikator":"Number of Deadlocks/sec","instanz":"_Total","warnung_ueber":0.1,"kritisch_ueber":1}`,
				"Deadlocks je Sekunde", 60},
			{"SQL: Transaktionsprotokoll", "leistungsindikator",
				`{"objekt":"SQLServer:Databases","indikator":"Percent Log Used","instanz":"*","zusammenfassung":"maximum","warnung_ueber":80,"kritisch_ueber":95}`,
				"vollstes Protokoll aller Datenbanken in Prozent (ohne Datenbanknamen)", 60},
			{"SQL: Speicher wartet", "leistungsindikator",
				`{"objekt":"SQLServer:Memory Manager","indikator":"Memory Grants Pending","warnung_ueber":0,"kritisch_ueber":5}`,
				"Abfragen, die auf Arbeitsspeicher warten", 60},
			{"SQL: Seitenlebensdauer", "leistungsindikator",
				`{"objekt":"SQLServer:Buffer Manager","indikator":"Page life expectancy","warnung_unter":300}`,
				"Sekunden, die eine Seite im Puffer bleibt; dauerhaft niedrig heißt zu wenig RAM", 60},
			{"SQL: Port 1433", "tcp", `{"host":"{adresse}","port":1433}`, "Standardport der Standardinstanz", 300},
		}),
	newSet("satz-druck", "Druckserver", "Windows-Druckserver: Druckwarteschlange, Aufträge und Fehler aller Warteschlangen zusammengefasst, "+
		"ohne Drucker-, Benutzer- oder Dokumentnamen. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "Print Queue"`,
		[]satzEintrag{
			{"Druck: Dienst Druckwarteschlange", "dienst", `{"name":"Spooler"}`, "Windows-Dienst Spooler läuft", 60},
			{"Druck: Aufträge (vollste Warteschlange)", "leistungsindikator",
				`{"objekt":"Print Queue","indikator":"Jobs","instanz":"*","zusammenfassung":"maximum","warnung_ueber":25,"kritisch_ueber":100}`,
				"Aufträge in der vollsten Warteschlange; viele heißt meist ein hängender Drucker", 60},
			{"Druck: Aufträge gesamt", "leistungsindikator", `{"objekt":"Print Queue","indikator":"Jobs","instanz":"*","zusammenfassung":"summe"}`,
				"Aufträge in allen Warteschlangen (nur Anzeige)", 60},
			{"Druck: Warteschlangen", "leistungsindikator", `{"objekt":"Print Queue","indikator":"Jobs","instanz":"*","zusammenfassung":"anzahl","kritisch_unter":1}`,
				"Zahl der Warteschlangen; kritisch bei 0", 300},
			{"Druck: Auftragsfehler", "leistungsindikator", `{"objekt":"Print Queue","indikator":"Job Errors","instanz":"*","zusammenfassung":"summe"}`,
				"Fehler seit Start des Dienstes, alle Warteschlangen (nur Anzeige)", 300},
			{"Druck: Drucker nicht bereit", "leistungsindikator",
				`{"objekt":"Print Queue","indikator":"Not Ready Errors","instanz":"*","zusammenfassung":"summe"}`,
				"Meldungen „nicht bereit“ seit Start des Dienstes (nur Anzeige)", 300},
			{"Druck: SMB (Port 445)", "tcp", `{"host":"{adresse}","port":445}`, "Freigaben der Drucker erreichbar", 300},
		}),
	newSet("satz-hyperv", "Hyper-V-Host", "Hyper-V-Host: Verwaltungsdienste, VMs in kritischem Zustand, Last des Hypervisors, freier Speicher. "+
		"Einzelne VMs: Vorlage „Hyper-V-VM läuft“. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "Hyper-V Virtual Machine Health Summary,Hyper-V Hypervisor Logical Processor,Memory"`,
		[]satzEintrag{
			{"Hyper-V: Dienst VM-Verwaltung", "dienst", `{"name":"vmms"}`, "Hyper-V-Verwaltung für virtuelle Computer", 60},
			{"Hyper-V: Dienst Host Compute", "dienst", `{"name":"vmcompute"}`, "Hyper-V Host Compute Service (ab Server 2016)", 60},
			{"Hyper-V: VMs kritisch", "leistungsindikator",
				`{"objekt":"Hyper-V Virtual Machine Health Summary","indikator":"Health Critical","kritisch_ueber":0}`,
				"VMs in kritischem Zustand (z. B. Platte voll); kritisch ab 1", 60},
			{"Hyper-V: VMs in Ordnung", "leistungsindikator",
				`{"objekt":"Hyper-V Virtual Machine Health Summary","indikator":"Health Ok"}`, "VMs ohne Probleme (nur Anzeige)", 300},
			{"Hyper-V: Hypervisor-CPU", "leistungsindikator",
				`{"objekt":"Hyper-V Hypervisor Logical Processor","indikator":"% Total Run Time","instanz":"_Total","warnung_ueber":80,"kritisch_ueber":95}`,
				"Auslastung aller logischen Prozessoren in Prozent (auch durch VMs)", 60},
			{"Hyper-V: Freier Speicher", "leistungsindikator",
				`{"objekt":"Memory","indikator":"Available MBytes","warnung_unter":4096,"kritisch_unter":1024}`,
				"freier Arbeitsspeicher des Hosts in MB; Schwellen an die Größe anpassen", 60},
		}),
	newSet("satz-citrix-vda", "Citrix Worker (VDA, Agent)", "Citrix Virtual Apps and Desktops, VDA 2402 LTSR und 2507 LTSR: Dienste, ICA, Sitzungen, "+
		"Latenz ohne Benutzernamen, Neustart verpasst (Laufzeit über 26 Stunden). Ob der VDA am Controller registriert ist, "+
		"zeigt nur indirekt der Desktop Service. Am Agent freigeben: "+
		`openwacht-agent sensoren -arten "dienst,leistungsindikator" -indikatoren "Terminal Services,ICA Session,System"`,
		[]satzEintrag{
			{"Citrix VDA: Desktop Service", "dienst", `{"name":"BrokerAgent"}`, "Citrix Desktop Service, meldet den VDA am Controller an", 60},
			// Dienstnamen statt Anzeigenamen: Diese sind übersetzt („Citrix Desktopdienst“),
			// und einen „Citrix ICA Service“ gibt es auf VDA 2402/2507 nicht (an einem VDA abgelesen).
			{"Citrix VDA: Group Policy Engine", "dienst", `{"name":"CitrixCseEngine"}`, "Citrix-Richtlinien", 60},
			{"Citrix VDA: Remotedesktopdienste", "dienst", `{"name":"TermService"}`, "Remotedesktopdienste (Multi-Session-VDA)", 60},
			{"Citrix VDA: Sitzungen aktiv", "leistungsindikator", `{"objekt":"Terminal Services","indikator":"Active Sessions"}`,
				"aktive Sitzungen (nur Anzeige, ohne Namen)", 60},
			{"Citrix VDA: Latenz (höchste)", "leistungsindikator",
				`{"objekt":"ICA Session","indikator":"Latency - Session Average","instanz":"*","zusammenfassung":"maximum","warnung_ueber":200,"kritisch_ueber":500}`,
				"höchste mittlere Latenz einer Sitzung in ms; Sitzungsnamen werden nicht gemeldet", 60},
			// Worker starten meist nächtlich neu; hängt der Neustart, merkt man es
			// sonst erst an den Benutzern (24.11.2026).
			{"Citrix VDA: Neustart verpasst", "leistungsindikator",
				`{"objekt":"System","indikator":"System Up Time","kritisch_ueber":93600}`,
				"Laufzeit in Sekunden; Fehler über 26 Stunden (93 600 s), an den Neustartplan anpassen", 300},
			{"Citrix VDA: Ping", "ping", `{"host":"{adresse}","anzahl":5,"verlust_warnung":20,"verlust_kritisch":60}`,
				"erreichbar, Paketverlust", 60},
			{"Citrix VDA: ICA (Port 1494)", "tcp", `{"host":"{adresse}","port":1494}`, "ICA ohne Sitzungszuverlässigkeit", 300},
			{"Citrix VDA: CGP (Port 2598)", "tcp", `{"host":"{adresse}","port":2598}`, "Sitzungszuverlässigkeit (Standard)", 300},
		}),
	// Worker ohne Agent (1.0.1, Wunsch eines Citrix-Teams): nur SNMP und
	// Sensoren der Zentrale. Passt zu Workern aus PVS/MCS, weil die
	// SNMP-Einstellung einmal im Master-Image liegt und keine Identität braucht.
	newSet("satz-citrix-vda-snmp", "Citrix Worker (VDA, SNMP)", "Citrix Virtual Apps and Desktops, VDA 2402 LTSR und 2507 LTSR, ohne Agent: "+
		"CPU, Arbeitsspeicher, Platten und erkannte Neustarts liest die SNMP-Abfrage des Geräts selbst (am Gerät „SNMP einrichten“); "+
		"dazu Neustart verpasst über die Laufzeit des Systems, Ping, ICA und Sitzungszuverlässigkeit. Am Worker bzw. im "+
		"Master-Image: Windows-Feature „SNMP-Dienst“, Community nur lesen, nur die Zentrale als Host zulassen (Windows kann nur v1/v2c).",
		[]satzEintrag{
			// hrSystemUptime statt sysUpTime: sysUpTime springt schon beim Neustart des SNMP-Dienstes zurück.
			{"Citrix VDA: Neustart verpasst (SNMP)", "snmp_oid", `{"oid":"1.3.6.1.2.1.25.1.1.0","kritisch_ueber":9360000}`,
				"Laufzeit des Systems in Hundertstelsekunden; Fehler über 26 Stunden (9 360 000), an den Neustartplan anpassen", 300},
			{"Citrix VDA: Ping", "ping", `{"host":"{adresse}","anzahl":5,"verlust_warnung":20,"verlust_kritisch":60}`,
				"erreichbar, Paketverlust", 60},
			{"Citrix VDA: ICA (Port 1494)", "tcp", `{"host":"{adresse}","port":1494}`, "ICA ohne Sitzungszuverlässigkeit", 300},
			{"Citrix VDA: CGP (Port 2598)", "tcp", `{"host":"{adresse}","port":2598}`, "Sitzungszuverlässigkeit (Standard)", 300},
		}),
	newSet("satz-citrix-sf", "Citrix StoreFront", "StoreFront 2402 LTSR und 2507 LTSR: Dienste, IIS, Store-Erkennung über HTTPS, Zertifikat. "+
		"Store heißt hier „Store“; sonst Pfad anpassen. Am Agent freigeben: openwacht-agent sensoren -arten dienst",
		[]satzEintrag{
			{"StoreFront: Credential Wallet", "dienst", `{"name":"CitrixCredentialWallet"}`, "Citrix Credential Wallet", 60},
			{"StoreFront: Default Domain Services", "dienst", `{"name":"CitrixDefaultDomainService"}`, "Anmeldung und Kennwortänderung", 60},
			{"StoreFront: Peer Resolution", "dienst", `{"name":"Citrix Peer Resolution Service"}`, "Anzeigename; Abhängigkeit vieler Dienste", 60},
			{"StoreFront: Subscriptions Store", "dienst", `{"name":"CitrixSubscriptionsStore"}`, "Favoriten der Benutzer", 60},
			{"StoreFront: Configuration Replication", "dienst", `{"name":"CitrixConfigurationReplication"}`, "Abgleich in der Servergruppe", 60},
			{"StoreFront: IIS", "dienst", `{"name":"W3SVC"}`, "WWW-Publishingdienst", 60},
			{"StoreFront: Net.Tcp Port Sharing", "dienst", `{"name":"NetTcpPortSharing"}`, "Voraussetzung für Credential Wallet und Peer Resolution", 60},
			{"StoreFront: Store erreichbar", "http", `{"url":"https://{adresse}/Citrix/Store/discovery"}`,
				"Erkennungsdienst des Stores; Adresse des Geräts muss zum Zertifikat passen", 300},
			{"StoreFront: Zertifikat", "tls", `{"host":"{adresse}","port":443,"warnung_tage":30,"kritisch_tage":14}`,
				"Warnung 30 Tage, kritisch 14 Tage vor Ablauf", 3600},
		}),
	newSet("satz-citrix-ddc", "Citrix Delivery Controller", "Delivery Controller und Lizenzserver, 2402 LTSR und 2507 LTSR: "+
		"Dienste, Ports der Anmeldung der VDAs und der Lizenzen. Lizenzserver auf eigenem Server: Lizenz-Sensoren dort anwenden. "+
		"Am Agent freigeben: openwacht-agent sensoren -arten dienst",
		[]satzEintrag{
			{"Citrix DDC: Broker Service", "dienst", `{"name":"CitrixBrokerService"}`, "vermittelt Sitzungen, nimmt die Anmeldung der VDAs an", 60},
			{"Citrix DDC: Configuration Service", "dienst", `{"name":"Citrix Configuration Service"}`, "Anzeigename", 60},
			{"Citrix DDC: Host Service", "dienst", `{"name":"Citrix Host Service"}`, "Anzeigename; Verbindung zum Hypervisor", 60},
			{"Citrix DDC: Machine Creation Service", "dienst", `{"name":"Citrix Machine Creation Service"}`, "Anzeigename; MCS", 60},
			{"Citrix DDC: Monitor Service", "dienst", `{"name":"Citrix Monitor Service"}`, "Anzeigename; Daten für Director und OData", 60},
			{"Citrix DDC: Delegated Administration", "dienst", `{"name":"Citrix Delegated Administration Service"}`, "Anzeigename; Rechte in Studio", 60},
			{"Citrix DDC: AD Identity Service", "dienst", `{"name":"Citrix AD Identity Service"}`, "Anzeigename; Computerkonten", 60},
			{"Citrix DDC: Broker (Port 80)", "tcp", `{"host":"{adresse}","port":80}`, "Anmeldung der VDAs und XML-Dienst", 300},
			{"Citrix Lizenz: Dienst", "dienst", `{"name":"Citrix Licensing"}`, "Anzeigename; Lizenzserver", 60},
			{"Citrix Lizenz: Port 27000", "tcp", `{"host":"{adresse}","port":27000}`, "License Server Manager", 300},
			{"Citrix Lizenz: Port 7279", "tcp", `{"host":"{adresse}","port":7279}`, "Citrix-Vendor-Daemon (Vergabe der Lizenzen)", 300},
			{"Citrix Lizenz: Web Services (Port 8083)", "tcp", `{"host":"{adresse}","port":8083}`, "Licensing Manager, Studio und Director", 300},
		}),
	// 0.99.2: Citrix Cloud Connector (Citrix DaaS) und Provisioning Services.
	// Dienstnamen an einer Farm abgelesen (24.11.2026), nicht aus der Doku.
	// Dienste, die dort gestoppt waren (Secure Private Access, BOOTP) oder nur
	// mit einer Zusatzfunktion laufen (WEM, ITSM, Metrics), fehlen absichtlich.
	newSet("satz-citrix-cc", "Citrix Cloud Connector", "Cloud Connector für Citrix DaaS: Dienste der Verbindung zu Citrix Cloud, "+
		"Broker-Proxy, Local Host Cache (High Availability), Anmeldung der VDAs auf Port 80. Am Agent freigeben: openwacht-agent sensoren -arten dienst",
		[]satzEintrag{
			{"Cloud Connector: Agent System", "dienst", `{"name":"CitrixWorkspaceCloudAgentSystem"}`, "Grunddienst des Connectors", 60},
			{"Cloud Connector: WatchDog", "dienst", `{"name":"CitrixWorkspaceCloudAgentWatchDog"}`, "überwacht und aktualisiert den Connector", 60},
			{"Cloud Connector: Agent Discovery", "dienst", `{"name":"CitrixWorkspaceCloudAgentDiscovery"}`, "Registrierung bei Citrix Cloud", 60},
			{"Cloud Connector: AD Provider", "dienst", `{"name":"CitrixWorkspaceCloudADProvider"}`, "Zugriff von Citrix Cloud auf das AD", 60},
			{"Cloud Connector: Credential Provider", "dienst", `{"name":"CitrixWorkspaceCloudCredentialProvider"}`, "Anmeldedaten", 60},
			{"Cloud Connector: WebRelay", "dienst", `{"name":"CitrixWorkspaceCloudWebRelayProvider"}`, "Weiterleitung von HTTP-Anfragen aus der Cloud", 60},
			{"Cloud Connector: Message Broker", "dienst", `{"name":"CitrixCloudServicesMessageBroker"}`, "Nachrichten zwischen Cloud und Connector", 60},
			{"Cloud Connector: Remote Broker Provider", "dienst", `{"name":"XaXdCloudProxy"}`, "nimmt die Anmeldung der VDAs an und leitet an den Cloud-Broker weiter", 60},
			{"Cloud Connector: Brokerdienst (STA)", "dienst", `{"name":"CitrixStaService"}`, "Secure Ticket Authority", 60},
			{"Cloud Connector: Config Synchronizer", "dienst", `{"name":"CitrixConfigSyncService"}`, "Abgleich für den Local Host Cache", 60},
			{"Cloud Connector: High Availability", "dienst", `{"name":"CitrixHighAvailabilityService"}`, "Local Host Cache bei Ausfall der Cloud", 60},
			{"Cloud Connector: Remote HCL", "dienst", `{"name":"RemoteHCLServer"}`, "Verbindung zu den Hypervisoren", 60},
			{"Cloud Connector: Cloud Gateway", "dienst", `{"name":"Citrix NetScaler Cloud Gateway"}`, "Gateway-Dienst", 60},
			{"Cloud Connector: Monitor", "dienst", `{"name":"CitrixMonitorService"}`, "Daten für Monitor/Director", 60},
			{"Cloud Connector: VDA-Anmeldung (Port 80)", "tcp", `{"host":"{adresse}","port":80}`, "VDAs melden sich hier an", 300},
		}),
	newSet("satz-citrix-pvs", "Citrix Provisioning", "Citrix Provisioning (PVS): Streaming, SOAP, API, TFTP und PXE. BOOTP ist absichtlich nicht dabei "+
		"(meist aus, wenn DHCP bootet). Am Agent freigeben: openwacht-agent sensoren -arten dienst",
		[]satzEintrag{
			{"PVS: Stream Service", "dienst", `{"name":"StreamService"}`, "liefert die vDisks an die Ziele", 60},
			{"PVS: SOAP Server", "dienst", `{"name":"soapserver"}`, "Verwaltung, Konsole und Abgleich", 60},
			{"PVS: API Service", "dienst", `{"name":"PvsApi"}`, "Programmierschnittstelle", 60},
			{"PVS: TFTP", "dienst", `{"name":"BNTFTP"}`, "Bootdatei für die Ziele", 60},
			{"PVS: PXE", "dienst", `{"name":"BNPXE"}`, "Netzwerkstart der Ziele", 60},
			{"PVS: Two-Stage Boot", "dienst", `{"name":"PVSTSB"}`, "Start über Boot Device Manager", 60},
			{"PVS: SOAP (Port 54321)", "tcp", `{"host":"{adresse}","port":54321}`, "SOAP-Schnittstelle der Konsole", 300},
		}),
	newSet("satz-netscaler", "NetScaler", "NetScaler (ADC) 14.1 und 13.1 über SNMPv3: CPU, Speicher, HA, virtuelle Server, Dienste, "+
		"kürzeste Restlaufzeit aller Zertifikate. Werte über Tabellenspalten, ohne Namen. Braucht eine SNMP-Abfrage am Gerät.",
		[]satzEintrag{
			{"NetScaler: CPU", "snmp_oid", `{"oid":"1.3.6.1.4.1.5951.4.1.1.41.1.0","warnung_ueber":80,"kritisch_ueber":95}`,
				"resCpuUsage in Prozent", 60},
			{"NetScaler: Speicher", "snmp_oid", `{"oid":"1.3.6.1.4.1.5951.4.1.1.41.2.0","warnung_ueber":80,"kritisch_ueber":90}`,
				"resMemUsage in Prozent", 60},
			{"NetScaler: HA-Zustand", "snmp_oid", `{"oid":"1.3.6.1.4.1.5951.4.1.1.23.24.0","gleich":"3"}`,
				"haCurState 3 = UP; nur bei HA-Paar, sonst löschen", 60},
			{"NetScaler: Virtuelle Server down", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.5951.4.1.3.1.1.5","zusammenfassung":"anzahl_gleich","vergleichswert":1,"kritisch_ueber":0}`,
				"vsvrState 1 = DOWN; abgeschaltete (OUT OF SERVICE) zählen nicht", 60},
			{"NetScaler: Dienste down", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.5951.4.1.3.1.1.37","zusammenfassung":"summe","warnung_ueber":0}`,
				"vsvrCurServicesDown, Summe über alle virtuellen Server", 60},
			{"NetScaler: Zertifikate", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.5951.4.1.1.56.1.1.5","zusammenfassung":"minimum","warnung_unter":30,"kritisch_unter":14}`,
				"sslDaysToExpire: Tage bis zum Ablauf des nächsten Zertifikats; Warnung 30, kritisch 14", 3600},
			{"NetScaler: Zahl der Zertifikate", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.5951.4.1.1.56.1.1.5","zusammenfassung":"anzahl"}`, "installierte Zertifikate (nur Anzeige)", 3600},
			{"NetScaler: Verwaltung (HTTPS)", "tls", `{"host":"{adresse}","port":443,"warnung_tage":30,"kritisch_tage":14}`,
				"Zertifikat der Verwaltungsadresse", 3600},
		}),
	// 1.0.8: LANCOM-Switche der Serie GS-3000 (gemessen an einem GS-3628XUP mit LCOS SX 4.30). Temperatur, Lüfter und CPU
	// liefert diese Firmware als Text, deshalb „Zahl aus Text“.
	newSet("satz-lancom-3000", "LANCOM 3000", "LANCOM-Switche der Serie GS-3000 mit LCOS SX 4.x über SNMPv3: Temperaturen, Lüfter, CPU, PoE und LLDP-Nachbarn. "+
		"Die Schwellen der Temperaturen sind eine Vorbelegung; an die eigenen Geräte anpassen. Braucht eine SNMP-Abfrage am Gerät.",
		[]satzEintrag{
			{"LANCOM: Temperatur 1", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.22.0","zahl_aus_text":"erste","einheit":"°C","warnung_ueber":80,"kritisch_ueber":90}`,
				"lcsSystemInfoTemperature1; der wärmste Fühler, im Betrieb um 70 °C", 300},
			{"LANCOM: Temperatur 2", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.23.0","zahl_aus_text":"erste","einheit":"°C","warnung_ueber":60,"kritisch_ueber":70}`,
				"lcsSystemInfoTemperature2", 300},
			{"LANCOM: Temperatur 3", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.34.0","zahl_aus_text":"erste","einheit":"°C","warnung_ueber":60,"kritisch_ueber":70}`,
				"lcsSystemInfoTemperature3", 300},
			{"LANCOM: Lüfter", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.17.0","zahl_aus_text":"erste","einheit":"RPM","kritisch_unter":300}`,
				"lcsSystemInfoFanSpeed („1500RPM“); kritisch, wenn der Lüfter steht; bei lüfterlosen Modellen löschen", 300},
			{"LANCOM: CPU (10 s)", "snmp_oid",
				`{"oid":"1.3.6.1.4.1.2356.14.1.1.1.24.0","zahl_aus_text":"nach","zahl_nach":"10s:","einheit":"%","warnung_ueber":85,"kritisch_ueber":95}`,
				"lcsSystemInfoCPULoad, Mittel über 10 Sekunden", 60},
			{"LANCOM: PoE-Leistung", "snmp_oid", `{"oid":"1.3.6.1.4.1.2356.14.1.1.1.204.0","faktor":0.1,"einheit":"W"}`,
				"abgegebene PoE-Leistung (Wert des Geräts in 0,1 W); nur Anzeige, Schwelle je nach Budget selbst setzen", 300},
			{"LANCOM: PoE-Budget", "snmp_oid", `{"oid":"1.3.6.1.2.1.105.1.3.1.1.2.1","einheit":"W"}`,
				"pethMainPsePower: verfügbare PoE-Leistung (nur Anzeige)", 3600},
			{"LANCOM: PoE-Versorgung", "snmp_oid", `{"oid":"1.3.6.1.2.1.105.1.3.1.1.3.1","gleich":"1"}`,
				"pethMainPseOperStatus 1 = an (2 = aus, 3 = gestört); bei Modellen ohne PoE löschen", 300},
			{"LANCOM: PoE-Ports im Fehler", "snmp_oid",
				`{"oid":"1.3.6.1.2.1.105.1.1.1.6","zusammenfassung":"anzahl_gleich","vergleichswert":4,"warnung_ueber":0}`,
				"pethPsePortDetectionStatus 4 = fault, gezählt über alle Ports", 300},
			{"LANCOM: PoE-Ports mit Strom", "snmp_oid",
				`{"oid":"1.3.6.1.2.1.105.1.1.1.6","zusammenfassung":"anzahl_gleich","vergleichswert":3}`,
				"Ports, die gerade ein Gerät versorgen (nur Anzeige)", 300},
			{"LANCOM: LLDP-Nachbarn", "snmp_oid",
				`{"oid":"1.0.8802.1.1.2.1.4.1.1.4","zusammenfassung":"anzahl","warnung_unter":1}`,
				"lldpRemTable: Zahl der Nachbarn, die sich per LLDP melden; Warnung, wenn keiner mehr da ist. " +
					"Die Schwelle auf die übliche Zahl des Geräts setzen, dann fällt ein fehlender Uplink auf", 300},
		}),
}

func builtinSet(id string) (vorlagenSatz, bool) {
	for _, t := range builtinSets {
		if t.ID == id {
			return t, true
		}
	}
	return vorlagenSatz{}, false
}

func builtinTemplate(id string) (vorlageOut, bool) {
	for _, t := range builtinTemplates {
		if t.ID == id {
			return t, true
		}
	}
	return vorlageOut{}, false
}

type vorlageIn struct {
	Name      string          `json:"name"`
	Typ       string          `json:"typ"`
	Ziel      json.RawMessage `json:"ziel"`
	Intervall int             `json:"intervall_sekunden"`
	Notiz     string          `json:"notiz"`
	Kennfarbe *string         `json:"kennfarbe_id"` // nur in eigenen Vorlagensätzen (1.0.1)
	// 1.0.6: 1 bis 10, 0 oder leer = Standard der Zentrale
	Fehlversuche *int `json:"fehlversuche"`
}

func parseTemplateIn(in vorlageIn) (vorlageIn, []byte, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 60 || strings.ContainsFunc(in.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return in, nil, badRequest("Name: 1 bis 60 Zeichen, keine Steuerzeichen.")
	}
	in.Notiz = strings.TrimSpace(in.Notiz)
	if utf8.RuneCountInString(in.Notiz) > 200 || strings.ContainsFunc(in.Notiz, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return in, nil, badRequest("Notiz: höchstens 200 Zeichen, keine Steuerzeichen.")
	}
	if in.Intervall == 0 {
		in.Intervall = 300
	}
	if in.Intervall < 30 || in.Intervall > 86400 || checks.IsAgentKind(in.Typ) && in.Intervall < 60 {
		return in, nil, badRequest("Intervall: 30 Sekunden bis 1 Tag, auf dem Agent mindestens 60 Sekunden.")
	}
	if len(in.Ziel) == 0 {
		in.Ziel = json.RawMessage("{}")
	}
	target, err := checks.ParseTemplate(in.Typ, in.Ziel)
	if err != nil {
		return in, nil, badRequest(err.Error() + ".")
	}
	if in.Fehlversuche, err = parseThreshold(in.Fehlversuche); err != nil {
		return in, nil, err
	}
	return in, target, nil
}

func (s *Server) handleTemplateList(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "vorlagen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, name, kind, target, interval_s, note, changed_at, fail_threshold
			FROM openwacht.sensor_templates ORDER BY lower(name), id`)
		if err != nil {
			return 0, nil, err
		}
		own, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (vorlageOut, error) {
			var v vorlageOut
			var tid string
			var target []byte
			var changed time.Time
			err := row.Scan(&v.ID, &tid, &v.Name, &v.Typ, &target, &v.Intervall, &v.Notiz, &changed, &v.Fehlversuche)
			v.MandantID, v.Ziel, v.Geaendert = &tid, target, &changed
			v.AmAgent, v.BrauchtAdresse = checks.IsAgentKind(v.Typ), checks.UsesPlaceholder(target)
			return v, err
		})
		if err != nil {
			return 0, nil, err
		}
		if own == nil {
			own = []vorlageOut{}
		}
		sets, err := ownSets(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"eingebaut": builtinTemplates, "eigene": own, "saetze": builtinSets, "eigene_saetze": sets}, nil
	})
}

func (s *Server) handleTemplateCreate(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in vorlageIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vorlage anlegen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, target, err := parseTemplateIn(in)
		if err != nil {
			return 0, nil, err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.sensor_templates (tenant_id, name, kind, target, interval_s, note, fail_threshold)
			VALUES ($1, $2, $3, $4, $5, $6, nullif($7::smallint, 0)) RETURNING id::text`,
			tid, in.Name, in.Typ, target, in.Intervall, in.Notiz, in.Fehlversuche).Scan(&id); err != nil {
			return 0, nil, err // fremder Mandant oder Leser: 42501 → 403
		}
		if err := audit(ctx, tx, &tid, "vorlage.angelegt", map[string]any{"id": id, "name": in.Name, "typ": in.Typ}); err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, map[string]any{"id": id}, nil
	})
}

func (s *Server) handleTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var in vorlageIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vorlage ändern", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		in, target, err := parseTemplateIn(in)
		if err != nil {
			return 0, nil, err
		}
		var tid string
		if err := tx.QueryRow(ctx, `UPDATE openwacht.sensor_templates SET name = $2, kind = $3, target = $4, interval_s = $5, note = $6,
				fail_threshold = CASE WHEN $7::smallint IS NULL THEN fail_threshold ELSE nullif($7::smallint, 0) END
			WHERE id = $1 RETURNING tenant_id::text`, id, in.Name, in.Typ, target, in.Intervall, in.Notiz, in.Fehlversuche).Scan(&tid); err != nil {
			return 0, nil, err // nicht sichtbar oder nur Leser: 404
		}
		if err := audit(ctx, tx, &tid, "vorlage.geaendert", map[string]any{"id": id, "name": in.Name, "typ": in.Typ}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (s *Server) handleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	s.handle(w, r, "vorlage löschen", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var tid, name string
		if err := tx.QueryRow(ctx, `DELETE FROM openwacht.sensor_templates WHERE id = $1 RETURNING tenant_id::text, name`, id).
			Scan(&tid, &name); err != nil {
			return 0, nil, err
		}
		if err := audit(ctx, tx, &tid, "vorlage.geloescht", map[string]any{"id": id, "name": name}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// --- Anwenden ----------------------------------------------------------------------

type anwendenIn struct {
	VorlageID      string   `json:"vorlage_id"`
	SatzID         string   `json:"satz_id"` // statt vorlage_id: ein Vorlagensatz (0.44.0)
	Geraete        []string `json:"geraete"`
	GruppeID       string   `json:"gruppe_id"`
	MitUntergruppe bool     `json:"mit_untergruppen"`
}

type uebersprungen struct {
	GeraetID string `json:"geraet_id"`
	Geraet   string `json:"geraet"`
	Sensor   string `json:"sensor,omitempty"` // bei Sätzen: welcher Sensor
	Grund    string `json:"grund"`
}

const maxApply = 300

// templateSensorName: der Name der Vorlage, wie „Ping“. Seit Etappe 18c sind
// Namen je Gerät eindeutig, der Gerätename steht nicht mehr davor (Alarme und
// Listen zeigen ihn ohnehin). Gibt es am Gerät den Namen schon, wird die
// Vorlage dort übersprungen: Zweimal anwenden legt nichts doppelt an.
func templateSensorName(template string) string {
	n := template
	if utf8.RuneCountInString(n) > 100 {
		n = string([]rune(n)[:100])
	}
	return strings.TrimSpace(n)
}

func (s *Server) loadTemplate(ctx context.Context, tx pgx.Tx, id string) (vorlageOut, error) {
	if t, ok := builtinTemplate(id); ok {
		return t, nil
	}
	if !uuidPattern.MatchString(id) {
		return vorlageOut{}, badRequest("Vorlage: ungültige ID.")
	}
	var v vorlageOut
	var target []byte
	err := tx.QueryRow(ctx, `SELECT id::text, name, kind, target, interval_s, fail_threshold FROM openwacht.sensor_templates WHERE id = $1`, id).
		Scan(&v.ID, &v.Name, &v.Typ, &target, &v.Intervall, &v.Fehlversuche)
	v.Ziel = target
	return v, err
}

// handleTemplateApply legt aus einer Vorlage je Gerät einen Sensor an (eine
// Transaktion). Übersprungen werden Geräte ohne passende Adresse, ohne Agent
// (für Agent-Arten), mit gesperrtem Ziel oder vergebenem Namen; der Rest wird
// angelegt. Rechte und Mandant setzt die Datenbank (RLS, Fremdschlüssel).
func (s *Server) handleTemplateApply(w http.ResponseWriter, r *http.Request) {
	var in anwendenIn
	if !readJSON(w, r, &in) {
		return
	}
	s.handle(w, r, "vorlage anwenden", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		var items []vorlageOut
		origin, isSet := "", false
		switch {
		case in.SatzID != "" && in.VorlageID != "":
			return 0, nil, badRequest("Entweder eine Vorlage oder einen Vorlagensatz angeben.")
		case in.SatzID != "":
			if set, ok := builtinSet(in.SatzID); ok {
				items, origin, isSet = set.Sensoren, set.Name, true
				break
			}
			// eigener Satz (0.46.0): nur sichtbare (RLS), sonst 404
			list, name, err := loadOwnSet(ctx, tx, in.SatzID)
			if err != nil {
				return 0, nil, err
			}
			items, origin, isSet = list, name, true
		default:
			t, err := s.loadTemplate(ctx, tx, in.VorlageID)
			if err != nil {
				return 0, nil, err
			}
			items, origin = []vorlageOut{t}, t.Name
		}
		var err error
		if (len(in.Geraete) > 0) == (in.GruppeID != "") {
			return 0, nil, badRequest("Entweder Geräte oder eine Gruppe angeben.")
		}
		var rows pgx.Rows
		if in.GruppeID != "" {
			if !uuidPattern.MatchString(in.GruppeID) {
				return 0, nil, badRequest("Gruppe: ungültige ID.")
			}
			var x string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM openwacht.device_groups WHERE id = $1`, in.GruppeID).Scan(&x); err != nil {
				return 0, nil, err // nicht sichtbar: 404
			}
			rows, err = tx.Query(ctx, `WITH RECURSIVE g AS (
					SELECT id, 0 AS depth FROM openwacht.device_groups WHERE id = $1
					UNION ALL
					SELECT c.id, g.depth + 1 FROM openwacht.device_groups c JOIN g ON c.parent_id = g.id WHERE $2 AND g.depth < 4)
				SELECT d.id::text, d.tenant_id::text, d.name, coalesce(d.address, ''),
					EXISTS (SELECT 1 FROM openwacht.agents a WHERE a.device_id = d.id AND a.revoked_at IS NULL),
					EXISTS (SELECT 1 FROM openwacht.snmp_sources s WHERE s.device_id = d.id AND s.version IN ('1', '2c', '3'))
				FROM openwacht.devices d WHERE d.group_id IN (SELECT id FROM g) ORDER BY lower(d.name) LIMIT $3`,
				in.GruppeID, in.MitUntergruppe, maxApply+1)
		} else {
			if len(in.Geraete) > maxApply {
				return 0, nil, badRequest("Geräte: höchstens 300 auf einmal.")
			}
			for _, id := range in.Geraete {
				if !uuidPattern.MatchString(id) {
					return 0, nil, badRequest("Geräte: ungültige ID.")
				}
			}
			rows, err = tx.Query(ctx, `SELECT d.id::text, d.tenant_id::text, d.name, coalesce(d.address, ''),
					EXISTS (SELECT 1 FROM openwacht.agents a WHERE a.device_id = d.id AND a.revoked_at IS NULL),
					EXISTS (SELECT 1 FROM openwacht.snmp_sources s WHERE s.device_id = d.id AND s.version IN ('1', '2c', '3'))
				FROM openwacht.devices d WHERE d.id = ANY($1::uuid[]) ORDER BY lower(d.name)`, in.Geraete)
		}
		if err != nil {
			return 0, nil, err
		}
		type dev struct {
			id, tenant, name, addr string
			agent, snmp            bool
		}
		devs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dev, error) {
			var d dev
			err := row.Scan(&d.id, &d.tenant, &d.name, &d.addr, &d.agent, &d.snmp)
			return d, err
		})
		if err != nil {
			return 0, nil, err
		}
		if len(devs) > maxApply {
			return 0, nil, badRequest("Gruppe: mehr als 300 Geräte, bitte eine kleinere Gruppe wählen.")
		}
		if len(devs) == 0 {
			return 0, nil, badRequest("Keine Geräte gefunden.")
		}
		skipped := []uebersprungen{}
		created := map[string][]string{}
		for _, d := range devs {
			for _, t := range items {
				sensor := ""
				if isSet {
					sensor = t.Name
				}
				skip := func(d dev, why string) { skipped = append(skipped, uebersprungen{d.id, d.name, sensor, why}) }
				raw := []byte(t.Ziel)
				if checks.UsesPlaceholder(raw) {
					if d.addr == "" {
						skip(d, "Gerät hat keine Adresse")
						continue
					}
					raw = checks.Substitute(raw, d.addr)
				}
				if checks.IsAgentKind(t.Typ) && !d.agent {
					skip(d, "Gerät hat keinen Agent")
					continue
				}
				if checks.IsSNMPKind(t.Typ) && !d.snmp {
					skip(d, "Gerät hat keine SNMP-Abfrage")
					continue
				}
				spec, err := checks.Parse(t.Typ, raw)
				if err != nil {
					skip(d, "Ziel passt nicht: "+err.Error())
					continue
				}
				blocked := false
				for _, a := range spec.LiteralAddrs() {
					if !s.guard.Allowed(a) {
						skip(d, "Adresse "+a.String()+" ist für Sensoren der Zentrale nicht freigegeben")
						blocked = true
						break
					}
				}
				if blocked {
					continue
				}
				target, err := json.Marshal(spec)
				if err != nil {
					return 0, nil, err
				}
				var id string
				// Kennfarbe aus dem eigenen Satz (1.0.1) nur, wenn sie zum Mandanten des Geräts passt.
				err = tx.QueryRow(ctx, `INSERT INTO openwacht.checks (device_id, name, kind, target, interval_s, enabled, origin, kennfarbe_id,
					fail_threshold)
				VALUES ($1, $2, $3, $4, $5, true, $6,
					CASE WHEN openwacht.kennfarbe_allowed($7::uuid, $8::uuid) THEN $7::uuid END, $9::smallint)
				ON CONFLICT DO NOTHING RETURNING id::text`,
					d.id, templateSensorName(t.Name), t.Typ, target, t.Intervall, origin, t.Kennfarbe, d.tenant, t.Fehlversuche).Scan(&id)
				var pe *pgconn.PgError
				switch {
				case errors.Is(err, pgx.ErrNoRows):
					skip(d, "Name „"+templateSensorName(t.Name)+"“ ist schon vergeben")
					continue
				case errors.As(err, &pe) && pe.Code == "23514" && strings.Contains(pe.Message, "500"):
					return 0, nil, &apiError{http.StatusConflict, "Höchstens 500 Sensoren je Mandant; nichts angelegt."}
				case errors.As(err, &pe) && pe.Code == "23514" && strings.Contains(pe.Message, "32 SNMP"):
					return 0, nil, &apiError{http.StatusConflict, "Höchstens 32 SNMP-Sensoren je Gerät; nichts angelegt."}
				case err != nil:
					return 0, nil, err // Leser: 42501 → 403, nichts angelegt
				}
				created[d.tenant] = append(created[d.tenant], id)
			}
		}
		n := 0
		for tid, ids := range created {
			n += len(ids)
			// Audit-Einträge sind auf 8 KiB begrenzt: höchstens 100 IDs.
			details := map[string]any{"vorlage": origin, "anzahl": len(ids), "checks": ids[:min(len(ids), 100)]}
			if isSet {
				details["satz"] = in.SatzID
			} else {
				details["typ"] = items[0].Typ
			}
			if err := audit(ctx, tx, &tid, "vorlage.angewandt", details); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusOK, map[string]any{"angelegt": n, "uebersprungen": skipped}, nil
	})
}
