# Release-Notizen OpenWacht

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
- Beim Anlegen eines Benutzers lautet die Meldung für eine vergebene Adresse immer gleich; höchstens 20 solcher
  Ablehnungen je Admin und Stunde.
- Die Warnung beim Start ohne Alarmziele nennt richtig, was gesperrt ist (Mail geht weiter).
- Migrationen 0056 bis 0060 (laufen beim Update von selbst).

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
