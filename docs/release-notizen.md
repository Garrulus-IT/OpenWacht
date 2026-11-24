# Release-Notizen OpenWacht

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

1. **Sicherung:** Das Paket sichert die Datenbank selbst, bevor es migriert. Wer zusätzlich sichern will:
   `sudo -u svc_openwacht_db openwacht-zentrale sichern -jetzt`.
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
