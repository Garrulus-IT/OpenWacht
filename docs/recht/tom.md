# Technische und organisatorische Maßnahmen (Art. 32 DSGVO)

Teil A beschreibt, was OpenWacht 0.35.0 selbst mitbringt. Teil B listet, was der Betreiber in seiner Umgebung
sicherstellen muss; ohne Teil B sind die Maßnahmen aus Teil A nicht vollständig. Details: Handbuch Kapitel 17
(Härtung) und das Sicherheitskonzept.

## Teil A: Maßnahmen der Software

### Vertraulichkeit

| Maßnahme | Umsetzung |
| --- | --- |
| Zugangskontrolle (Anmeldung) | Lokale Konten mit Argon2id-Passwort-Hash; AD/LDAP nur über LDAPS/StartTLS mit Zertifikatsprüfung; Firmen-Login (OIDC) mit PKCE, Nonce und geprüftem TLS |
| Zweiter Faktor | Authenticator-App (TOTP mit Schutz gegen Wiederverwendung), zusätzlich Passkeys (WebAuthn: ES256, Ed25519, RS256); zehn Wiederherstellungscodes (nur als HMAC gespeichert). Pflicht einstellbar: für Admins (Standard), für alle oder freiwillig; der Betreiber braucht immer die App |
| Schutz gegen Rate- und Aussperr-Angriffe | Rate Limit je Adresse (IPv6 je /64), Sperre nur für das Paar Konto + Quelle (1 Min. bis 1 Std.), wachsende Wartezeit für unbekannte Quellen |
| Zugriffskontrolle | Mandantenbaum: Rechte gelten für einen Mandanten und alles darunter, nie für Geschwister oder Eltern; Rollen Admin, Operator, Leser; Durchsetzung in der Anwendung **und** in PostgreSQL (Row-Level Security). Die Anwendung verbindet sich mit einer Rolle ohne Eigentümer-, SUPERUSER- oder BYPASSRLS-Recht |
| Heikle Änderungen | frischer Code aus der App (Netzfreigabe, Alarmziele, HTTPS, Mail-Relay, Passkeys, Kürzen der Aufbewahrung) |
| Sitzungen | serverseitig, Cookie `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`, CSRF-Token, 30 Minuten Leerlauf, höchstens 12 Stunden |
| Trennung der Agents | Agents haben eigene Zertifikate (mTLS, TLS 1.3) und einen eigenen Port; sie nehmen keine Befehle an und öffnen keinen Port |
| Verschlüsselung gespeicherter Geheimnisse | AES-256-GCM mit Zusatzdaten je Geheimnis; Hauptschlüssel als Datei außerhalb der Datenbank (Rechte 0400), Wechsel per Befehl |
| Verschlüsselung der Übertragung | HTTPS für die Oberfläche (eigene, namensbeschränkte Wurzel oder eigenes Zertifikat), TLS 1.3 für Agents, TLS für LDAP, OIDC, SMTP, Syslog |
| Web-Sicherheit | strenge Content-Security-Policy ohne Inline-Skripte, HSTS, `frame-ancestors 'none'`, keine externen Ressourcen, Ausgaben escaped |
| Datensparsamkeit | keine Benutzernamen, Prozesslisten mit Benutzerbezug oder Inhalte von überwachten Rechnern; Anmeldequellen nur als HMAC |

### Integrität

| Maßnahme | Umsetzung |
| --- | --- |
| Audit-Log | nur anhängend, Hash-Kette, täglicher Prüflauf mit Hinweis an den Betreiber, fortlaufender Export (Datei, Syslog über TLS) als Anker außerhalb der Datenbank |
| Eingaben | typisierte API, Längen- und Typprüfung, parametrisierte Datenbankzugriffe; Daten von Agents und Geräten gelten als nicht vertrauenswürdig |
| Software-Updates | Agent-Updates nur mit Ed25519-Signatur eines Offline-Schlüssels, keine Rückstufung; Installationspaket mit signierten Prüfsummen |
| Lieferkette | gepinnte Abhängigkeiten, `govulncheck` und `npm audit` in der CI, SBOM (CycloneDX) zu jedem Build, reproduzierbare Builds |
| Robustheit | Panik-Absicherung in allen Parsern, 17 Fuzz-Ziele in der CI |

### Verfügbarkeit und Belastbarkeit

| Maßnahme | Umsetzung |
| --- | --- |
| Datensicherung | tägliche Sicherung (`pg_dump`), automatisch vor jedem Update, Aufbewahrung einstellbar; Rücksicherung per Befehl |
| Selbstüberwachung | Hinweise bei fehlgeschlagener Sicherung, ablaufenden Zertifikaten, voller Platte, Bruch der Audit-Kette, stummem Trap-Dienst; externer Totmannschalter |
| Grenzen | Lasttest dokumentiert (Handbuch Kapitel 16) |

### Verfahren zur Überprüfung

| Maßnahme | Umsetzung |
| --- | --- |
| Rezertifizierung | Bericht „wer hat welche Rolle, letzte Anmeldung“ je Mandant als CSV und PDF (Verwaltung → Mandanten) |
| Tests | Mandantentrennung je API-Endpunkt (Geschwister, Eltern, Kinder), Negativtests für Anmeldung, Rechte, Signaturen; Mutationstests |
| Meldeweg | `SECURITY.md`, `/.well-known/security.txt` |

## Teil B: Maßnahmen des Betreibers

Ankreuzen und ergänzen:

- [ ] Server in einem geschützten Netz, Firewall nach Handbuch Kapitel 17 (Oberfläche 443, Agent-Port 8444 nur aus den
      Netzen der Agents)
- [ ] Zutrittskontrolle zum Serverraum bzw. Hypervisor: [ ]
- [ ] Hauptschlüssel getrennt von den Sicherungen aufbewahrt: [Ort]
- [ ] Sicherungen außerhalb des Servers, Rücksicherung mindestens jährlich geprobt: [Datum]
- [ ] Audit-Export eingeschaltet und außerhalb der Zentrale aufbewahrt: [Ziel]
- [ ] 2FA-Pflicht nicht auf „freiwillig“ (bei von außen erreichbaren Installationen nie)
- [ ] Updates von OpenWacht, PostgreSQL und Betriebssystem zeitnah eingespielt: [Verfahren]
- [ ] Rezertifizierung der Rollen: [Turnus, z. B. halbjährlich]; zuständig: [ ]
- [ ] Meldeweg des Betreibers in `security.txt` (`-sicherheitskontakt`)
- [ ] Verpflichtung der Administratoren auf Vertraulichkeit: [ ]
- [ ] Notfallverfahren (kalte Zweitinstanz, Handbuch Kapitel 16): [ ]
