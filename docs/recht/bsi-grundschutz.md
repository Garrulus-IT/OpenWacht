# Zuordnung zum BSI IT-Grundschutz

Grundlage ist das **IT-Grundschutz-Kompendium Edition 2023** (111 Bausteine), das bis zur vollständigen Einführung von
Grundschutz++ die Grundlage für Zertifizierungen bleibt. Grundschutz++ (Katalog seit 1. Januar 2026, Methodik in der
Pilotierung) ordnet Anforderungen neu und prozessorientiert; diese Zuordnung wird übertragen, sobald der Betreiber
umstellt. Stand der Prüfung: 22.11.2026.

So zu lesen: Die Tabelle nennt die Bausteine, die für den Betrieb von OpenWacht modelliert werden sollten, und was die
Software zu deren Anforderungen beiträgt. „Betreiber“ heißt: Die Software hilft nicht oder nur teilweise, die Anforderung
liegt in der Umgebung oder Organisation. Die Bausteine für Server, Virtualisierung, Netz und Räume modelliert der
Betreiber wie für jede andere Anwendung.

## Anwendung

| Baustein | Beitrag von OpenWacht | Betreiber |
| --- | --- | --- |
| APP.3.1 Webanwendungen und Webservices | Authentisierung mit zweitem Faktor, serverseitige Sitzungen mit kurzer Laufzeit, CSRF-Schutz, Ausgabekodierung, strenge CSP und Sicherheits-Header, Eingabeprüfung, Rate Limits, keine Fehlertexte mit Interna, API-Tokens mit begrenzter Laufzeit und Rolle | TLS-Zertifikat bzw. Wurzel verteilen, Reverse Proxy nach Handbuch Kapitel 17 |
| APP.4.3 Relationale Datenbanken | Anwendung ohne Eigentümerrechte, Row-Level Security, parametrisierte Abfragen, Definer-Funktionen mit festem `search_path`, Geheimnisse für die Anwendung nicht lesbar, Peer-Authentifizierung über Unix-Socket | PostgreSQL aktuell halten, keine Netzfreigabe der Datenbank |
| APP.6 Allgemeine Software | Release-Notizen, signierte Pakete, SBOM, reproduzierbarer Build, Handbuch, Update-Weg mit Sicherung vorher | Freigabeprozess für Updates |
| CON.1 Kryptokonzept | AES-256-GCM, Argon2id, Ed25519, ECDSA P-256, TLS 1.3 für Agents; Schlüsselwechsel für Hauptschlüssel, Agent-CA und Update-Schlüssel dokumentiert | Hauptschlüssel getrennt sichern |
| CON.2 Datenschutz | Datensparsamkeit als Leitprinzip, Vorlagen in `docs/recht/`, Rezertifizierungsbericht | Verzeichnis, Rechtsgrundlage, Beteiligungen |
| CON.3 Datensicherungskonzept | tägliche Sicherung, Sicherung vor Updates, Rücksicherung per Befehl, Hinweis bei fehlgeschlagener Sicherung | Auslagerung, Probe-Rücksicherung, Aufbewahrung des Schlüssels |
| CON.6 Löschen und Vernichten | automatische Fristen für Messwerte, Alarme, Traps, Anmeldequellen; Aufbewahrung des Audit-Logs einstellbar | Löschkonzept festlegen; Konten löschen (Funktion fehlt noch) |
| CON.8 Software-Entwicklung | Code-Review per Pull Request, CI mit Tests, Mutations- und Fuzz-Tests, `govulncheck`, `npm audit`, gepinnte Abhängigkeiten und Actions | – (Hersteller) |
| CON.10 Entwicklung von Webanwendungen | wie APP.3.1, dazu Tests zur Mandantentrennung je Endpunkt | – (Hersteller) |

## Betrieb

| Baustein | Beitrag von OpenWacht | Betreiber |
| --- | --- | --- |
| OPS.1.1.2 Ordnungsgemäße IT-Administration | Betreiber-Rolle getrennt von Admins der Mandanten, frischer Code für heikle Änderungen, Audit jeder Änderung | persönliche Konten, Vier-Augen-Prinzip wo nötig |
| OPS.1.1.3 Patch- und Änderungsmanagement | signierte Agent-Updates per Freigabe je Gerät, Release-Notizen, Zusage für Sicherheitsupdates (`SECURITY.md`) | Updates zeitnah einspielen |
| OPS.1.1.5 Protokollierung | Audit-Log mit Hash-Kette und Prüflauf, Export als JSON-Zeilen oder Syslog über TLS mit Folgenummer und Hash | Export einschalten, zentrale Auswertung |
| OPS.1.1.6 Software-Tests und -Freigaben | – | Testinstallation vor dem Update (Handbuch Kapitel 16) |
| OPS.2.3 Nutzung von Outsourcing | Vorlage Auftragsverarbeitung | wenn Fernwartung durch Dritte |

## Detektion und Reaktion

| Baustein | Beitrag von OpenWacht | Betreiber |
| --- | --- | --- |
| DER.1 Detektion von sicherheitsrelevanten Ereignissen | OpenWacht selbst ist ein Werkzeug für DER.1 (Verfügbarkeit, Zertifikate, Trap-Empfang); Audit-Export an ein SIEM; Hinweise bei Bruch der Audit-Kette und Fehlversuchen | SIEM-Regeln für Audit-Ereignisse (`anmeldung.fehlgeschlagen`, `audit.*`) |
| DER.2.1 Behandlung von Sicherheitsvorfällen | Meldeweg (`security.txt`, `SECURITY.md`), Sperren von Konten und Agents, Widerruf von Update-Schlüsseln | eigener Vorfallprozess |
| DER.4 Notfallmanagement | kalte Zweitinstanz mit Rücksicherung dokumentiert (Handbuch Kapitel 16), externer Totmannschalter | Notfallhandbuch, Übungen |

## Organisation und Systeme

| Baustein | Beitrag von OpenWacht | Betreiber |
| --- | --- | --- |
| ORP.4 Identitäts- und Berechtigungsmanagement | Rollen je Mandant mit Vererbung nach unten, kein Rechteausweiten über den eigenen Teilbaum, AD-Gruppen auf Rollen, Abgleich stündlich, Rezertifizierungsbericht (CSV/PDF) mit letzter Anmeldung, Anträge auf Untermandanten mit Freigabe | Prozess für Ein- und Austritt, Rezertifizierung im Turnus |
| SYS.1.1 Allgemeiner Server, SYS.1.3 Server unter Linux und Unix | systemd-Units mit Härtung (eigene Dienstbenutzer, `PrivateUsers`, `ProtectSystem=strict` u. a.), Debian-Paket | Betriebssystem härten und aktualisieren |
| NET.1.1 Netzarchitektur | eigener Agent-Port, Netzfreigabe für Sensoren und Alarmziele (Schutz gegen SSRF), kein Verkehr nach außen im Betrieb | Segmentierung, Firewall |

## Offene Punkte

- Konto löschen (CON.6, ORP.4): nur sperren in der Oberfläche.
- Benachrichtigung bei verdächtigen Anmeldungen (APP.3.1, DER.1): nicht umgesetzt; Audit-Export an ein SIEM als Ersatz.
- Hochverfügbarkeit (DER.4): nur kalte Zweitinstanz.
- Externer Penetrationstest: [beauftragt am … / Ergebnis …].
