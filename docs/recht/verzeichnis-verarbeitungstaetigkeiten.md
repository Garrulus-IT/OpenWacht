# Verzeichnis der Verarbeitungstätigkeiten (Vorlage)

Eintrag für das Verzeichnis nach Art. 30 Abs. 1 DSGVO. Felder in eckigen Klammern füllt der Betreiber aus. Die
Angaben zu Daten und Fristen beschreiben OpenWacht 0.35.0 im Auslieferungszustand.

## 1. Allgemeines

| Feld | Inhalt |
| --- | --- |
| Bezeichnung | Überwachung der IT-Infrastruktur mit OpenWacht |
| Verantwortlicher | [Name und Anschrift der Organisation] |
| Vertretung, Ansprechpartner | [Name, Funktion, Kontakt] |
| Datenschutzbeauftragte(r) | [Name, Kontakt] |
| Fachlich zuständig | [z. B. IT-Betrieb] |
| Eingeführt am / letzte Änderung | [Datum] / [Datum] |
| Version der Software | 0.35.0 (bei Updates prüfen, ob sich Abschnitt 3 ändert) |

## 2. Zwecke und Rechtsgrundlage

Zwecke:

1. Verfügbarkeit und Sicherheit der IT-Infrastruktur sicherstellen: Server, Netzgeräte und Dienste überwachen, Störungen
   melden, Kapazität planen.
2. Zugriff auf die Überwachung steuern: Anmeldung der Administratoren und Bediener, Rechte je Mandant.
3. Nachvollziehbarkeit: Änderungen und Anmeldungen im Audit-Log festhalten (Revisionssicherheit, Aufklärung von
   Sicherheitsvorfällen).

Rechtsgrundlage: [vom Betreiber festzulegen, typischerweise Art. 6 Abs. 1 lit. c und e DSGVO i. V. m. dem eigenen
Landesrecht (Behörden) bzw. Art. 6 Abs. 1 lit. f DSGVO (Unternehmen); für Beschäftigtendaten zusätzlich § 26 BDSG bzw.
das Landesdatenschutzgesetz, ggf. eine Dienstvereinbarung].

## 3. Kategorien betroffener Personen und Daten

| Betroffene | Daten in OpenWacht | Herkunft |
| --- | --- | --- |
| Konten der Administratoren, Bediener und Leser | E-Mail-Adresse, Anzeigename, Heimatmandant, Rollen je Mandant mit Datum, Passwort-Hash (Argon2id), Geheimnis der Authenticator-App (verschlüsselt), Hashes der Wiederherstellungscodes, öffentliche Schlüssel von Passkeys mit selbst gewähltem Namen, Zeitpunkt der letzten Anmeldung, Zähler für Fehlversuche, Sperrzeiten | Eingabe durch Admins, Abgleich mit AD/LDAP oder Firmen-Login (OIDC) |
| dieselben | Anmeldequelle als HMAC (Adresse bzw. IPv6-/64, nicht im Klartext) mit Zeitpunkt der letzten erfolgreichen Anmeldung und Fehlversuchen | Anmeldung |
| dieselben | Sitzungen (nur Hash des Tokens, Beginn, letzte Aktivität, Ablauf) | Anmeldung |
| dieselben | Audit-Log: wer (Konto), wann, was (Aktion, betroffene Objekte); im Export zusätzlich die E-Mail-Adresse der handelnden Person | jede Änderung und Anmeldung |
| dieselben | Empfänger von Alarm-Mails und Berichten (Konto), Abbestellung | Einstellung im Mandanten |
| dieselben | Name der Person, die eine Wartung gesetzt, einen Alarm bestätigt oder einen Untermandanten beantragt bzw. entschieden hat | Bedienung |
| Konten aus dem AD/LDAP | zusätzlich die unveränderliche Kennung im Verzeichnis (objectGUID) und die Zuordnung zur Anbindung | Abgleich stündlich |
| API-Tokens | technisches Konto ohne Person, Name des Tokens, anlegendes Konto, letzte Nutzung | Admin |
| Mittelbar: Personen, deren Name in Gerätenamen steckt | Hostnamen, Gerätenamen, Freitexte (z. B. „pc-mueller“) | Agents, SNMP, Eingaben |

Nicht erhoben werden: Benutzernamen auf den überwachten Rechnern, Prozesslisten mit Benutzerbezug, Dateiinhalte,
Webseiteninhalte (nur „Text vorhanden ja/nein“), `sysContact` von SNMP-Geräten, Inhalte von E-Mails.

Besondere Kategorien (Art. 9 DSGVO): keine.

## 4. Empfänger

| Empfänger | Was | Wann |
| --- | --- | --- |
| Konten mit Rolle im jeweiligen Mandanten | Daten des Mandanten und seiner Untermandanten, nie Geschwister oder Eltern | laufend |
| Betreiber der Installation | Einstellungen, Namen der Mandanten (keine Daten ohne eigene Rolle) | laufend |
| Alarmziele (ntfy, Teams, Webhook, Mail-Relay) | Mandant, Gerät, Sensor, Zustand, Meldung, Link; keine Personennamen außer bei Wartungen | bei Alarmen |
| SIEM/Syslog (falls eingeschaltet) | Audit-Log mit E-Mail-Adresse der handelnden Person | laufend |
| [Dienstleister für Fernwartung] | [nur mit Vertrag nach Art. 28] | [bei Bedarf] |

Übermittlung in Drittländer: keine durch OpenWacht selbst. [Prüfen, falls Alarmziele außerhalb der EU liegen,
z. B. ntfy.sh, Microsoft Teams.]

## 5. Fristen für die Löschung

Siehe [Löschkonzept](loeschkonzept.md). Kurzfassung: Messwerte 2 bis 7 Tage (Rohwerte), 30 bis 400 Tage
(5-Minuten-Werte), 90 Tage bis 5 Jahre (Stundenwerte); beendete Alarme 90 Tage; Anmeldequellen 90 Tage; Audit-Log nach
Einstellung (Standard unbegrenzt); Konten bis zur Löschung durch den Betreiber.

## 6. Technische und organisatorische Maßnahmen

Siehe [TOM](tom.md).

## 7. Datenschutz-Folgenabschätzung

[Einschätzung des Betreibers.] Hinweis: Bei reiner Überwachung von Infrastruktur entstehen personenbezogene Daten fast
nur über die Konten der Administratoren. Eine Überwachung von Arbeitsplatzrechnern ist nicht vorgesehen; würde sie
eingeführt, wäre eine Folgenabschätzung und die Beteiligung der Beschäftigtenvertretung vorher nötig.
