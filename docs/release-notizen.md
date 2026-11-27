# Release-Notizen OpenWacht

## 1.0.7

- **Dashboard frei anpassbar:** Jedes Widget hat eine freie Breite (2 bis 12 Spalten) und Höhe (1 bis 6 Reihen), zum
  Ziehen an der Ecke oder über ⚙; dazu eigene Titel, jede Art beliebig oft (bis 60 Widgets), „verdoppeln“ und bis zu
  acht benannte Seiten als Reiter. Neue Widgets: Zertifikate, Wartung, Einzelner Sensor, Uhr und Notiz. Alte Layouts
  bleiben, wie sie sind ([Kapitel 4](handbuch/04-hosts.md#dashboard-und-wandanzeige)).
- **Dashboard passt sich dem Fenster an:** Das Raster richtet sich nach seinem eigenen Platz (12, 6 oder 1 Spalte) statt
  nach festen Bildschirmbreiten. „⤢ An Fenster anpassen“ verteilt die Höhe des Fensters auf die Reihen, das Dashboard
  passt dann ohne Rollen auf den Bildschirm; die Wahl gilt je Browser.
- **Desktop-App mit demselben Dashboard:** Die App zeigt das Layout deines Kontos mit allen Widgets, Seiten und „An
  Fenster anpassen“ und lässt es bearbeiten (Menü „Ändern“ am Widget). Sie ersetzt die feste Ansicht aus Sonne und
  Übersicht; ein Klick auf ein Gerät öffnet weiter die Sonne mit den Sensoren daneben. Mit API-Token zeigt sie das
  Standard-Layout ([Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- **Sonnendiagramm und Wandanzeige kürzen Namen seltener:** Fehlen einem Namen nur wenige Zeichen, wird seine Schrift
  um bis zu ein Fünftel kleiner und der Name bleibt ganz. Bisher stand dort etwa „Garage Feuerwe…“, obwohl die drei
  Punkte so viel Platz brauchen wie die zwei gekürzten Buchstaben. Gilt im Web, auf der Wandanzeige und in der
  Desktop-App.
- Migration 0062 (läuft beim Update von selbst).

## 1.0.6

- **Kalte Zweitinstanz als geführter Ablauf:** `openwacht-zentrale zweitinstanz -einrichten -quelle <Ordner>` auf einem
  zweiten Rechner; ein Timer spielt jede neue Sicherung der Hauptinstanz ein und prüft sie (Hauptschlüssel, Schema-Stand,
  Audit-Kette), `-umschalten` macht die Zweitinstanz mit einem Befehl zur Zentrale. Die Sicherungen kopiert der Betreiber
  selbst in den Ordner; OpenWacht holt nichts über das Netz ([Handbuch Kapitel 16](handbuch/16-betrieb-und-skalierung.md#ausfallkonzept-kalte-zweitinstanz)).
- **SSO: Signatur des ID-Tokens geprüft:** zusätzlich zur geprüften TLS-Verbindung zum Token-Endpunkt gegen die
  Schlüssel des Identity Providers (JWKS), nur RS256 und ES256, mit Zwischenspeicher und Schlüsselwechsel beim IdP.
  **Vor dem Update prüfen:** Ein IdP, der ID-Tokens mit HS256 oder PS256 signiert, wird danach abgelehnt
  ([Kapitel 10](handbuch/10-ad-und-sso.md#firmen-login-per-oidc-keycloak-adfs-entra-id)).
- **Offline-Paket mit Zusatzpaketen:** `paket-bauen.sh -zusatz realmd,sssd,adcli,…` nimmt weitere Debian-Pakete samt
  Abhängigkeiten auf, z. B. für den Beitritt zur Domäne ohne Internet; `installieren.sh` installiert sie mit
  ([Kapitel 14](handbuch/14-betrieb-ohne-internet.md#zusatzpakete-z-b-für-den-beitritt-zur-domäne)).
- **Beschriebene API:** `docs/api/openapi.json` (OpenAPI 3.1) für die 21 lesenden Endpunkte, die ein API-Token mit der
  Rolle Leser nutzen darf; liegt auch im Paket unter `/usr/share/doc/openwacht-zentrale/`. Ein Test prüft die Datei
  gegen den Code ([Kapitel 11](handbuch/11-api-tokens.md#beschreibung-der-api-openapi)).
- **Schnellsuche:** Strg+K (⌘K) bzw. „Suchen“ oben rechts sucht über Geräte, Sensoren, Mandanten und Seiten, mit
  Pfeiltasten und Enter ([Kapitel 4](handbuch/04-hosts.md)).
- **Wandanzeige im Vollbild:** Knopf bzw. Taste F; Ansicht „Alle Namen“ (Taste N, auch als `?ansicht=namen` in der
  Adresse) zeigt nur das Sonnendiagramm mit jedem Gerät beschriftet; Zeiger und Knöpfe verschwinden nach drei Sekunden
  ([Kapitel 4](handbuch/04-hosts.md#dashboard-und-wandanzeige)).
- **Geräte in einen anderen Mandanten verschieben:** im Menü des Geräts, für Admins beider Mandanten. Agent, Abfragen,
  Sensoren, Alarme und Verlauf ziehen mit, der Agent braucht keine neue Registrierung; Gruppe, Abhängigkeiten,
  Wartungsfenster und nicht geltende Kennfarben fallen weg ([Handbuch Kapitel 4](handbuch/04-hosts.md#in-einen-anderen-mandanten-verschieben)).
- **Citrix:** Abfrage des Monitor Service einer Citrix-Site (OData, Windows-Anmeldung, nur HTTPS, nur lesend): nicht
  registrierte VDAs mit Namen und fehlgeschlagene Verbindungen der letzten Stunde je Fehlerart, nie Benutzer
  ([Kapitel 19](handbuch/19-anbindungen.md#citrix-monitor-service-odata)). Bisher nur gegen eine nachgebaute Gegenstelle
  getestet, noch nicht gegen einen echten Delivery Controller.
- **Meldungen bei verdächtigen Anmeldungen:** Mail an das Konto bei einer Anmeldung von einem neuen Rechner; bei Sperren
  nach Fehlversuchen und bei Notfall-Befehlen auf der Zentrale auch an den Betreiber. Braucht den eingerichteten
  Mailversand ([Kapitel 3](handbuch/03-mandanten-und-rollen.md)).
- **Zweiter Faktor kontoweit gebremst:** Zehn falsche Codes binnen 15 Minuten sperren die Anmeldung mit Code für
  15 Minuten, egal von wie vielen Rechnern; Passkeys gehen weiter.
- **Notfall-Befehl `passwort-setzen`:** neues Passwort für ein lokales Konto auf der Zentrale, z. B. wenn das einzige
  Admin-Passwort verloren ist ([Kapitel 3](handbuch/03-mandanten-und-rollen.md)).
- **Automatische Windows-Dienste:** Dienste, deren Einstellungen der Agent nicht lesen darf, werden nicht mehr still
  übersprungen; die Meldung nennt ihre Zahl, steht einer davon, gibt es eine Warnung. Braucht den Agent 1.0.6.
- **Konten löschen:** gesperrte Konten löscht OpenWacht 90 Tage nach dem Sperren, vorher von Hand; das Audit-Log bleibt
  ([Kapitel 3](handbuch/03-mandanten-und-rollen.md#konten-sperren-und-löschen)).
- **Oberfläche aufgeräumt:** Dashboard-Widget „Zustand“ neu (Zahlen je Zustand statt Sechsecke; Probleme bleiben auch
  unter vielen OK-Sensoren sichtbar); Gruppen unter Hosts ab Werk zugeklappt, mit „Alle aufklappen“; Sensor-Vorlagen mit
  Suche, Abschnitten zum Zuklappen und nach Ort und Art geordnet, lange Hinweise gekürzt.
- **Desktop-App mit eigenem Fenster wie die Weboberfläche:** Start der Datei oder Linksklick aufs Symbol öffnet ein
  Fenster ohne Browser, aufgebaut wie die Weboberfläche: Seitenleiste mit Mandantenwahl, „mit Untermandanten“ und den
  Piktogrammen des Webs, Kopf mit Brotkrumen und Suche, Darstellung wie System, hell oder dunkel. Das **Dashboard**
  zeigt dauerhaft das Sonnendiagramm wie im Web (Fugen, Namen entlang des Bogens) und daneben Geräte je Zustand und
  „Aktuell“; ein Klick auf ein Gerät öffnet daneben seine Sensoren. **Kennfarben** färben Sonne, „Aktuell“ und
  Sensorliste wie in der Wandanzeige („Rot gewinnt immer“). **Jeder Punkt der Seitenleiste ist eine Seite der App:**
  Hosts (Baum und Gerät), Topologie, Zertifikate, Alarme, Berichte (mit PDF in den Ordner Downloads), Sensor-Vorlagen
  mit Kennfarben, SNMP-Profile, Wandanzeigen, Wartung sowie Benutzer und Mandanten mit allen Reitern (Benutzer,
  Agent- und API-Tokens, Agent-Updates, Anmeldung über AD und SSO), jeweils mit Anlegen, Ändern und Löschen wie im
  Web. Im Browser bleiben nur Formulare für Wartungsfenster und „hängt ab von“, Alarmwege, Einstellungen und das eigene
  Konto. Mit einem API-Token der Rolle **Operator** lassen sich Geräte und Sensoren anlegen, ändern, löschen,
  pausieren, jetzt abfragen, in Wartung setzen und Alarme bestätigen; mit **Leser** nur ansehen. Angemeldet wird in einem eigenen Fenster statt in der Konsole,
  „Abmelden“ steht unten in der Seitenleiste. **Anmeldung wie im Browser:** mit E-Mail, Passwort und Code aus der
  Authenticator-App führt die App dieselbe Sitzung wie der Browser und darf genau, was das Konto darf, auch als Admin,
  mit frischem Code für heikle Änderungen; die Sitzung lebt nur im Speicher. Das API-Token bleibt als zweiter Weg für
  Rechner, die nur im Infobereich wachen. Die Zentrale ändert sich dafür nicht. Dazu: ein Klick öffnet nicht mehr
  zwei Tabs, „Mit Windows starten“ meldet, ob es geklappt hat, der Autostart startet nur ins Infobereich, und die Datei
  trägt Programmbeschreibung, Version und das Bildzeichen
  ([Kapitel 8](handbuch/08-alarme-und-wartung.md#fenster-wie-die-weboberfläche-ab-106)). Unter Wine getestet, auf
  echtem Windows noch nicht. Die Stückliste führt die eingebetteten Schriften (TTF) mit.
- **Signieren unter Windows vorbereitet:** `tools/signieren/authenticode.ps1` signiert mit dem Zertifikat aus Certum
  SimplySign Agent und Desktop-App, baut die MSI aus den signierten Agents neu, signiert sie, berechnet
  `SHA256SUMS` neu und prüft alles ([Kapitel 15](handbuch/15-signieren-und-verteilen.md)). Die Dateien von 1.0.6
  sind noch unsigniert, bis das Zertifikat ausgestellt ist.
- **Agent-MSI mit Assistent:** Per Doppelklick führt das MSI durch Zentrale, Token, Sensor-Freigaben (Dienste,
  automatische Dienste, Prozesse, Dateien mit Ordnern, Leistungsindikatoren, Hyper-V) und Sammler-Netze, mit Prüfung
  der Eingaben und eigenem Kopf in Nachtblau. Still per GPO/Intune gehen dieselben Freigaben über die neuen
  Eigenschaften `SENSOREN`, `ORDNER`, `INDIKATOREN` und `NETZE`; `paket-einrichten` kennt dafür `-arten`, `-ordner`,
  `-indikatoren` und `-netze`. Ist schon ein Agent installiert, fragt das MSI zuerst: Aktualisieren, Neu einrichten
  (neues Token ersetzt die Registrierung, `paket-einrichten -wahl neu`) oder Entfernen (wahlweise samt Registrierung,
  `paket-entfernen -registrierung 1`). Die Einrichtung schreibt Ausgabe und Fehler in die Ereignisanzeige (Quelle
  `openwacht-agent`), richtet den Dienst vor der Registrierung ein (ein Fehler kostet kein Token), räumt nach einer
  gescheiterten Registrierung auf und benennt die Ursache (Name, Verbindung, TLS, Zertifikat, Antwort). Behoben: Die
  Tabelle ServiceControl startete den Dienst statt ihn vor einem Update anzuhalten. Texte im MSI dürfen jetzt Umlaute
  enthalten (Codepage 1252)
  ([Kapitel 5](handbuch/05-agent.md#msi-unter-windows-doppelklick-gpo-intune)). Unter Wine getestet, auf echtem
  Windows noch nicht.
- **Alarm erst nach 3 Fehlschlägen, je Sensor einstellbar:** Sensoren melden „kritisch“ jetzt nach 3 statt 2
  Fehlschlägen in Folge, damit kurze Aussetzer (Neustart, verlorenes Paket) keinen Alarm auslösen. Am Sensor, in eigenen
  Vorlagen und Vorlagensätzen lässt sich „Alarm nach“ von 1 (sofort) bis 10 setzen, im Web und in der Desktop-App;
  die API kennt dafür `fehlversuche` und zeigt die geltende Zahl als `fehlversuche_gilt`. Warnungen gehen weiter
  sofort raus ([Kapitel 7](handbuch/07-sensoren-und-vorlagen.md#sensoren)).
- **Neustart-Meldung ruhiger:** Ein Neustart wird nur noch gemeldet, wenn das Gerät davor mindestens 27 Stunden lief;
  geplante nächtliche Neustarts (Citrix-Worker, Terminalserver) melden nichts mehr. SNMP liest dafür die Laufzeit des
  Rechners (`hrSystemUptime`) statt nur die des SNMP-Dienstes, so löst ein Neustart allein des SNMP-Dienstes keine
  Meldung mehr aus. Gilt auch für Proxmox, NetApp, XenServer und FRITZ!Box
  ([Kapitel 6](handbuch/06-snmp.md#snmp-an-einem-gerät)). Für die Rechnerlaufzeit über einen Sammler braucht dieser den
  Agent 1.0.6.
- Beim Anlegen eines Benutzers lautet die Meldung für eine vergebene Adresse immer gleich; höchstens 20 solcher
  Ablehnungen je Admin und Stunde.
- Die Warnung beim Start ohne Alarmziele nennt richtig, was gesperrt ist (Mail geht weiter).
- Kennfarben: Der Vorschlag Braun (#8a5a2b) hatte auf dunklem Grund nur 2,9:1 Kontrast und fiel durch die eigene
  Prüfung; jetzt #9a6530 (3,5:1 dunkel, 4,9:1 hell).
- Migrationen 0056 bis 0061 (laufen beim Update von selbst).

## 1.0.5

- **Sensor „Automatische Windows-Dienste“:** ein Sensor prüft alle Dienste mit Starttyp „Automatisch“ und meldet die
  Namen der gestoppten. Dienste mit Auslöser zählen nicht, verzögert startende erst 15 Minuten nach dem Systemstart;
  Ausnahmen je Name oder mit `*`. Braucht den Agent 1.0.5 und die Freigabe `-arten autodienste`
  ([Handbuch Kapitel 7](handbuch/07-sensoren-und-vorlagen.md#automatische-windows-dienste)).
- **Zertifikate:** neue Seite mit allen TLS-Zertifikaten, sortiert nach Ablauf, mit Filtern „bald fällig“ und „mit
  Problem“ ([Kapitel 4](handbuch/04-hosts.md#zertifikate)).
- **Härtung (Hinweise aus dem Pentest):** Grenzen je Benutzer (8 Anfragen gleichzeitig, 1200 je Minute) und
  `statement_timeout` von 60 Sekunden für Abfragen von Benutzern und Wandanzeigen; Meldungen eines Agents auch in der
  Datenbank begrenzt; eine Wandanzeige liest in der Datenbank nur noch offene Alarme
  ([Kapitel 17](handbuch/17-haertung.md)).
- Migrationen 0054 und 0055 (laufen beim Update von selbst). Agents nur für den neuen Sensor aktualisieren.

## 1.0.4

- **Update der Zentrale in der Oberfläche:** Einstellungen → Update der Zentrale (Betreiber, mit Zweitfaktor). Paket,
  `SHA256SUMS` und `SHA256SUMS.sig` hochladen; die Zentrale prüft Signatur, Prüfsumme, Plattform und Version, ein
  getrennter Dienst mit root-Rechten prüft noch einmal und installiert mit apt. Nur bei Installation als
  Debian-Paket; das Update **auf** 1.0.4 selbst noch von Hand ([Handbuch Kapitel 1](handbuch/01-installation.md)).
- **Agent-Updates automatisch:** je Mandant Pilotgruppe, Wartezeit und Zeitfenster; die übrigen Agents folgen nur, wenn
  kein Pilot einen Fehler meldet. Freigaben von Hand gehen vor ([Kapitel 12](handbuch/12-agent-updates.md)).
- **Desktop-App für Windows:** `openwacht-desktop` im Infobereich mit Zustandssymbol und Benachrichtigungen, nur lesend
  mit einem API-Token der Rolle Leser ([Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- Migration 0053 (läuft beim Update von selbst). Agents müssen nicht aktualisiert werden.

## 1.0.3

- **Kürzere Alarm-Mails:** Der Betreff nennt nur noch Zustand, Gerät und Sensor (höchstens 90 Zeichen), die Meldung steht
  groß oben im Text. Sammelmails haben den schlimmsten Zustand vorn im Betreff und getrennte Abschnitte „Probleme“ und
  „Wieder in Ordnung“ ([Handbuch Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- **Topologie:** neue Seite mit den Abhängigkeiten der Geräte als Bäume, Zustand je Gerät, Klick öffnet das Gerät
  ([Kapitel 4](handbuch/04-hosts.md)).
- **Windows-Benachrichtigungen:** neue Alarme, Verschlechterungen und Entwarnungen auf Wunsch zusätzlich als
  Benachrichtigung des Systems, wenn OpenWacht im Hintergrund ist; OpenWacht lässt sich in Edge und Chrome als App
  installieren ([Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- **CSV-Import:** Dateien, in denen Excel jede Zeile in Anführungszeichen gesetzt hat, werden erkannt und gelesen.
- **Handbuch:** neues Kapitel 19 „Anbindungen“ (Proxmox, vCenter, NetApp, XenServer, FRITZ!Box, Hyper-V, Docker, Windows
  ohne Agent) und der Update-Ablauf Schritt für Schritt in Kapitel 1.
- Keine Migration. Agents müssen nicht aktualisiert werden.

## 1.0.2

- **Wandanzeige:** Sonnendiagramm neu gezeichnet, ruhiger und besser lesbar: Geräte mit Problem treten nach außen vor,
  klare Fugen, fette Schrift, Zeichen und Wortmarke in der Mitte.
- **Hinweise am Rand:** kurzer Hinweis unten rechts bei neuen Alarmen, Verschlechterung und Entwarnung, je Benutzer
  abschaltbar (unten in der Leiste „Hinweise und Ton“).
- **Ton:** je Benutzer und je Wandanzeige einstellbar: aus, nur Kritisch oder Warnung und Kritisch, Klang Bling, Gong
  oder Doppelton, Lautstärke, leiser Ton bei Entwarnung. Die Klänge erzeugt der Browser, es werden keine Dateien
  geladen. Die Wandanzeige spielt Ton nach einem Klick auf „Ton einschalten“
  ([Handbuch Kapitel 4](handbuch/04-hosts.md) und [Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- Migration 0052 (läuft beim Update von selbst).

## 1.0.1

- **Sammeln:** Mail- und SMS-Kanäle sammeln Meldungen eine Minute lang und schicken sie gemeinsam, Entwarnungen
  inklusive; ist ein Sensor innerhalb der Minute wieder OK, kommt keine Meldung. Nach einem Fehlschlag (z. B. Grenze
  des Relays, `421`) erst nach einer Minute erneut. Je Kanal unter „Zustellung“ abschaltbar, ab Werk an
  ([Handbuch Kapitel 8](handbuch/08-alarme-und-wartung.md)).
- **Kennfarben für Vorlagensätze:** Kennfarbe je Eintrag im eigenen Vorlagensatz und in einem Schritt für alle Sensoren
  einer Herkunft, an einem Gerät oder auf allen ([Handbuch Kapitel 7](handbuch/07-sensoren-und-vorlagen.md)).
- **Korrektur MSI:** Das MSI des Windows-Agents brach unter Windows mit Fehler 1603 ab (Fehler 2228, Tabelle `Signature`
  fehlte); Installation und Update per MSI gehen wieder.
- **Vorlagensätze für Citrix-Worker:** „Citrix Worker (VDA, Agent)“ (bisher „Citrix Worker (VDA)“) prüft Dienste nach
  festen Dienstnamen statt übersetzter Anzeigenamen; den Dienst „Citrix ICA Service“ gibt es auf aktuellen VDAs nicht,
  der Sensor entfällt. Neu „Citrix Worker (VDA, SNMP)“ für Worker ohne Agent, etwa aus PVS oder MCS: CPU, Arbeitsspeicher
  und Neustarts über SNMP, dazu Neustart verpasst, Ping, ICA und Sitzungszuverlässigkeit.
- **Doku:** Befehl für die Sicherung von Hand vor einem Update ergänzt.
- Migrationen 0050 und 0051 (laufen beim Update von selbst).

## 1.0.0

Erste veröffentlichte Version. OpenWacht überwacht Server, Netzwerkgeräte und Dienste für mehrere Mandanten von einer
Zentrale aus und läuft vollständig im eigenen Netz, auch ohne Internet. Einzelheiten stehen im
[Handbuch](handbuch/README.md).

**Zentrale und Installation**
- Zentrale als Debian-Paket für Debian 13 (amd64, arm64) mit PostgreSQL; das Paket richtet Datenbank, Rollen, Dienste
  und HTTPS selbst ein und gibt einen Link zum Einrichtungsassistenten im Browser aus.
- Offline-Paket mit PostgreSQL und allen Abhängigkeiten für Netze ohne Internet.
- Jeder Build liefert `SHA256SUMS`, mit dem Update-Schlüssel signiert (`SHA256SUMS.sig`), und eine Stückliste
  (CycloneDX).

**Mandanten und Anmeldung**
- Mandantenbaum mit Rollen Admin, Operator und Leser; wer eine Rolle hat, sieht seinen Mandanten und alle darunter,
  nie Geschwister oder Eltern. Die Trennung gilt in der Anwendung und zusätzlich in der Datenbank (Row-Level Security).
- Lokale Konten mit Zwei-Faktor-Anmeldung (TOTP oder Passkey), Wiederherstellungscodes, Sperre nach Fehlversuchen,
  Rezertifizierung der Rollen, Anträge auf Untermandanten.
- Anmeldung über Active Directory (LDAPS, auch verschachtelte Gruppen) und per OIDC (SSO), API-Tokens für Skripte.

**Überwachen**
- Agent für Linux und Windows (als `.deb`, `.rpm` und MSI), weitere Systeme ohne Gewähr. Der Agent sendet nur, öffnet
  keinen Port und nimmt keine Befehle an. Optional fragt er als Sammler SNMP-Geräte in seinem Netz ab.
- Sensoren der Zentrale: Ping, TCP-Port, HTTP(S), TLS-Zertifikat, DNS, HTTP-JSON-Wert, TCP-Banner, Zeitserver.
  Sensoren des Agents: Dienst, Prozess, Datei- oder Ordneralter, Docker-Container, Windows-Leistungsindikatoren,
  Hyper-V.
- SNMP v1, v2c und v3 mit Zugangsprofilen, eigenen OIDs und Tabellenspalten, Traps, CSV-Import von Geräten.
- Abfragequellen, nur lesend: Proxmox VE, VMware vCenter, NetApp ONTAP, XenServer und XCP-ng, Router von AVM (TR-064).
- Sensor-Vorlagen und Vorlagensätze, darunter Exchange mit DAG, Domänencontroller, SQL Server, Druckserver,
  Hyper-V-Host, Citrix, NetScaler, Swyx, Ferrari OfficeMaster und IQ4docs; eigene Vorlagensätze je Mandant.
- Gruppenbaum, Abhängigkeiten, Kennfarben je Sensor, einzelne Werte einer Quelle mit Begründung ausnehmen.
- Dashboard, Wandanzeige als Sonnendiagramm über einen geheimen Link ohne Konto, Monatsberichte als Ansicht, PDF und Mail.

**Alarme**
- Kanäle Mail, signierter Webhook, ntfy, Microsoft Teams und SMS über ein brevis.one-Gateway im eigenen Netz.
- Bereitschaftszeiten, Eskalation, Wartungsfenster, Bestätigen von Alarmen, Totmannschalter und Selbstüberwachung
  der Zentrale.

**Betrieb und Sicherheit**
- Agent-Updates nur mit Signatur des Offline-Schlüssels (Ed25519), mit Reserveschlüssel und Widerruf; ein getrennter
  Installationsdienst tauscht das Programm.
- Tägliche Sicherung und Sicherung vor jedem Update mit Schemaänderung, Wiederherstellung, Wechsel von Hauptschlüssel
  und Agent-CA, Audit-Log mit Prüfung und Export.
- Härtungsleitfaden, `security.txt` mit Meldeweg, Vorlagen für Datenschutz, BSI-Grundschutz und Barrierefreiheit.

**Bekannte Grenzen**
- Programm und MSI für Windows sind nicht Authenticode-signiert; die Echtheit lässt sich über die signierten Prüfsummen
  prüfen ([Handbuch Kapitel 15](handbuch/15-signieren-und-verteilen.md)).
- NetApp ONTAP ist gegen eine Attrappe nach der ONTAP-REST-Referenz getestet.
- XenServer und XCP-ng sind gegen eine Attrappe nach dem XAPI-Datenmodell getestet.
- VMware vCenter ist gegen eine Attrappe getestet.
- Hyper-V ist nur gebaut und statisch geprüft, nicht auf einem echten Hyper-V-Host ausgeführt.
- Router von AVM (TR-064) sind gegen eine Attrappe getestet.
- Docker ist gegen eine Attrappe des Socket-Proxys getestet.
- Das SMS-Gateway von brevis.one ist gegen eine Attrappe nach dessen HTTP-API-Dokumentation getestet.
- Microsoft Teams und Exchange als Mail-Relay sind gegen Attrappen getestet.
- Verschachtelte AD-Gruppen sind gegen OpenLDAP getestet, nicht gegen ein echtes Active Directory.
- Die Vorlagensätze für Windows-Anwendungen (Exchange, Domänencontroller, SQL Server, Druckserver, Hyper-V, Citrix,
  NetScaler, Swyx, Ferrari OfficeMaster, IQ4docs) folgen der Dokumentation der Hersteller.
- Kein Hinweis „neue Version verfügbar“, keine Umleitung von Port 80 auf 443.

## Update allgemein

Ein Update ist immer derselbe Weg:

1. **Sicherung:** Das Paket sichert die Datenbank selbst, aber nur, wenn Migrationen ausstehen. Vor jedem Update
   zusätzlich von Hand sichern ([Handbuch Kapitel 13](handbuch/13-sicherung.md)):

   ```bash
   sudo -u svc_openwacht_db env OPENWACHT_DB_EIGENTUEMER="host=/run/postgresql user=openwacht_owner dbname=openwacht" \
     openwacht-zentrale sichern -verzeichnis /var/backups/openwacht -jetzt
   ```
2. **Paket prüfen:** Signatur von `SHA256SUMS` prüfen, dann die Prüfsumme des Pakets vergleichen
   (`sha256sum -c --ignore-missing SHA256SUMS`, [Handbuch Kapitel 1](handbuch/01-installation.md)).
3. **Installieren:** `sudo apt install ./openwacht-zentrale_<version>_amd64.deb`. Das Paket führt alle fehlenden
   Migrationen der Reihe nach aus und startet die Dienste neu. Ohne Internet: das Offline-Paket mit
   `sudo sh installieren.sh` (siehe [Handbuch, Installation](handbuch/01-installation.md)).
4. **Prüfen:** Die Fußzeile der Oberfläche zeigt die neue Version. `journalctl -u openwacht-migrieren -u openwacht-zentrale -b`
   zeigt die Migrationen.

Mehrere Versionen auf einmal zu überspringen ist erlaubt. Die Migrationen laufen nacheinander in einer Transaktion je
Migration. **Zurück** geht es nur über die Sicherung, weil Migrationen das Schema ändern und nicht umkehrbar sind: die
Sicherung von vor dem Update in eine Datenbank einspielen und das alte Paket installieren. Läuft die Zentrale in einer VM
oder einem Container, ist ein Snapshot von vorher der einfachste Rückweg.

Agents müssen nicht gleichzeitig aktualisiert werden. Alte Agents melden weiter; neue Funktionen auf dem Agent brauchen
aber die neue Agent-Version. Agents lassen sich über signierte Updates aus der Zentrale aktualisieren
([Handbuch Kapitel 12](handbuch/12-agent-updates.md)).
