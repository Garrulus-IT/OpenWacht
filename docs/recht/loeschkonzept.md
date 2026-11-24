# Löschkonzept (Vorlage)

Gilt für OpenWacht 0.35.0. Die Spalte „Frist in der Software“ ist im Code festgelegt bzw. einstellbar; die Spalte
„Festlegung Betreiber“ füllt der Betreiber aus (eigene Fristen dürfen nur kürzer sein, wo die Software das erlaubt).
Gelöscht wird, soweit nicht anders angegeben, automatisch durch den Wartungslauf der Zentrale (stündlich) mit
`DELETE` in PostgreSQL. Gelöschte Zeilen bleiben in Sicherungen, bis diese selbst ablaufen (siehe Abschnitt 3).

## 1. Daten mit fester oder einstellbarer Frist

| Datenart | Personenbezug | Frist in der Software | Einstellbar | Festlegung Betreiber |
| --- | --- | --- | --- | --- |
| Messwerte, Rohdaten (CPU, RAM, Platten, Antwortzeiten, SNMP) | nein (mittelbar über Gerätenamen) | 2 Tage | 2–7 Tage (Betreiber, nur global) | [ ] |
| Messwerte, 5-Minuten-Mittel | nein | 30 Tage | 30–400 Tage, global und je Mandant | [ ] |
| Messwerte, Stundenmittel | nein | 365 Tage | 90–1830 Tage, global und je Mandant | [ ] |
| Zustandswechsel der Sensoren | nein | 30 Tage | nein | – |
| Beendete Alarme (Alarmprotokoll, mit Name der bestätigenden Person) | ja | 90 Tage nach Ende | nein | – |
| Protokoll empfangener SNMP-Traps (mit Werten) | selten (Freitexte der Geräte) | 30 Tage | nein | – |
| Hinweise an den Betreiber (Selbstüberwachung) | nein | 30 Tage nach Ende | nein | – |
| Ergebnisse der Prüfläufe der Audit-Kette | nein | 400 Tage | nein | – |
| Anmeldequellen (HMAC der Adresse, Fehlversuche, letzte erfolgreiche Anmeldung) | ja | 90 Tage nach letzter Änderung | nein | – |
| Sitzungen | ja | bei Abmeldung, Ablauf (höchstens 12 Std. bzw. Leerlaufzeit) oder Sperre des Kontos | Leerlauf/Dauer je Anbindung 1–12 Std. | [ ] |
| Challenges für Passkeys | ja | 5 Minuten bzw. bei Verwendung | nein | – |
| Registrierungs-Tokens für Agents | nein | bei Ablauf (höchstens 7 Tage) bzw. Verbrauch unbrauchbar | Laufzeit beim Anlegen | [ ] |
| API-Tokens | technisches Konto | höchstens 1 Jahr gültig; widerrufene und abgelaufene bleiben als Eintrag | Laufzeit beim Anlegen | [ ] |
| Audit-Log | ja (handelnde Konten) | **unbegrenzt** (Standard) | 1–10 Jahre (Betreiber); gelöscht wird nur am Anfang der Kette, nach heiler Prüfung und nie über den Stand des Exports hinaus | [ ] |
| Sicherungen der Datenbank (`pg_dump`) | ja (alles oben) | 14 Tage (Standard) | Einstellungen → Installation | [ ] |
| Anträge auf Untermandanten (mit Antragsteller und Entscheider) | ja | bis zur Löschung des Elternmandanten; in der Oberfläche 90 Tage nach der Entscheidung sichtbar | nein | – |

## 2. Daten ohne automatische Löschung

| Datenart | Wann sie wegfällt | Hinweis |
| --- | --- | --- |
| Konten (E-Mail, Name, Rollen, letzte Anmeldung, 2FA-Daten) | **Nicht automatisch.** In der Oberfläche lassen sich Konten nur sperren; gesperrte Konten bleiben als Bezug für das Audit-Log stehen | Löschen eines Kontos geht heute nur als Eigentümer in der Datenbank. Offener Punkt für eine Folgeversion (Funktion „Konto löschen“ mit Audit) |
| Konten aus AD/LDAP | Werden beim Abgleich gesperrt, wenn sie im AD fehlen, gesperrt sind oder in keiner Gruppe mehr liegen | wie oben, kein automatisches Löschen |
| Passkeys | beim Entfernen durch das Konto selbst, beim Zurücksetzen der App (`zweifaktor-zuruecksetzen`) | – |
| Wiederherstellungscodes | beim Erzeugen neuer Codes, beim Zurücksetzen der App, beim Wechsel des Hauptschlüssels | – |
| Geräte, Sensoren, Agents, Kanäle, Vorlagen | beim Löschen durch Admins oder Operatoren | Messwerte des Geräts verschwinden mit dem Gerät |
| Mandanten | beim Löschen durch einen Admin des Elternknotens; nur ohne Untermandanten, Benutzer und Einträge im Audit-Log | – |

## 3. Sicherungen und Exporte

- Sicherungen enthalten alle Daten zum Zeitpunkt der Sicherung. Eine Löschung in der Datenbank wirkt erst, wenn die
  letzte Sicherung mit dem Datum abgelaufen ist (Standard 14 Tage). Wer Sicherungen zusätzlich auslagert, legt dort eine
  eigene Frist fest: [ ].
- Der Audit-Export (Datei oder Syslog) liegt außerhalb von OpenWacht; seine Frist legt das empfangende System fest: [ ].
- CSV- und PDF-Berichte (Rezertifizierung, Monatsberichte) und Mails verlassen OpenWacht; dort gelten die Regeln des
  Empfängers.

## 4. Löschen auf Antrag (Art. 17 DSGVO)

1. Konto sperren (Benutzer → Konto → Sperren). Damit enden alle Sitzungen.
2. Rollen entziehen. Konten aus dem AD: im AD entfernen; der stündliche Abgleich sperrt.
3. Echte Löschung des Kontos: bis eine Funktion dafür existiert, durch den Betreiber in der Datenbank als Eigentümer,
   wenn keine Aufbewahrungspflicht (z. B. Audit) entgegensteht. Einträge im Audit-Log verweisen dann auf eine gelöschte
   Konto-ID; die E-Mail-Adresse steht nur im Export.
4. Einträge im Audit-Log selbst werden nicht einzeln gelöscht (Hash-Kette). Hier greift die Aufbewahrungsfrist aus
   Abschnitt 1 bzw. eine Einschränkung der Verarbeitung.

## 5. Verantwortlich

| Rolle | Aufgabe |
| --- | --- |
| Betreiber der Installation | Fristen einstellen, Sicherungen und Exporte |
| Admins der Mandanten | Konten sperren, Rollen entziehen, Rezertifizierung (Bericht unter Verwaltung → Mandanten) |
| [Datenschutzbeauftragte(r)] | jährliche Prüfung dieses Konzepts |
