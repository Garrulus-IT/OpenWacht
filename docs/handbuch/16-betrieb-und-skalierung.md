# 16. Betrieb und Skalierung

## Lasttest (22.11.2026, gemessen mit Version 0.34.0)

**Aufbau:** 20 Mandanten (Hauptmandant, 4 Bereiche, 15 Untermandanten darunter), 500 Agents (25 je Mandant,
simuliert mit `tools/simagent`, Meldung alle 60 s, je Standort eine eigene Absenderadresse) und 2000 SNMP-Geräte
(100 je Mandant, Attrappen mit CPU, Speicher, Platte und zwei Schnittstellen, Abfrage alle 60 s, angelegt per
CSV-Import mit Zugangsprofil). Werkzeug: `tools/lasttest` (Go-Test mit Build-Tag `lasttest`, läuft nicht in der CI)
und `tools/lasttest/tag.sql` für das Hochrechnen auf einen Tag.

**Umgebung:** eine Sandbox mit **2 vCPU und 7 GB RAM**, PostgreSQL 16 mit Standardeinstellungen
(`shared_buffers` 128 MB), Zentrale, Datenbank, simulierte Agents und SNMP-Attrappen auf demselben Rechner. Die
Attrappen brauchten selbst mehr Rechenzeit als die Zentrale. Die Werte sind also eher zu hoch als zu niedrig; auf
eigener Hardware ist mehr Luft.

### Ergebnisse unter Last

| Messgröße | Wert |
| --- | --- |
| Rechenzeit Zentrale | ≈ 7 % eines Kerns (Mittel über 15 Minuten), Arbeitsspeicher 60 MB |
| Rechenzeit PostgreSQL | ≈ 9 % eines Kerns |
| Neue Messwerte | ≈ 15 000 Zeilen je Minute (SNMP 11 800, Agents 3 000) |
| Wartung `metrics_maintain()` (alle 5 Min.) | 2–3 s |
| Verdichtung eines ganzen Tages nachholen (z. B. nach Ausfall der Zentrale) | 108 s |
| Aufbau: 20 CSV-Importe mit je 100 Geräten | 11 s |
| Registrierung von 500 Agents | ≈ 1 Minute (25 je Standort; Grenze 30 je Minute und Absenderadresse) |

Antwortzeiten der Oberfläche (Median / 95 %), angemeldet als Admin des Hauptmandanten (sieht alles):

| Abfrage | nach 1 Std. Betrieb | mit vollem Verlauf (7 Tage 5-Min., 30 Tage Stunde) |
| --- | --- | --- |
| Graph eines Hosts oder SNMP-Geräts (24 Std., 7 Tage, 30 Tage) | ≤ 10 ms | ≤ 35 ms |
| Liste Agents / Alarme / SNMP | 9 / 3 / 51 ms | unverändert |
| Liste aller Geräte (2500) | 314 / 394 ms | unverändert |
| Dashboard: Kennzahlen (Verfügbarkeit aller Quellen) | 368 / 454 ms | **über 60 s, bricht ab** |
| Dashboard: Verlauf aller Hosts (höchste 8 Linien) | 150 / 170 ms | **8,5 s (24 Std.) bis 28–54 s (7 Tage)** |

**Grenze (bekannt, offen):** Die beiden Dashboard-Widgets „Kennzahlen“ und „Graph über alle Hosts“ rechnen bei
jedem Aufruf über alle Quellen und den ganzen Zeitraum. Mit 2500 Quellen und vollem Verlauf sind sie zu langsam; die
übrigen Seiten bleiben schnell. Bis das umgebaut ist (vorberechnete Werte je Quelle): in großen Installationen diese
Widgets je Mandant einstellen oder entfernen. Linear hochgerechnet (nicht gemessen) brauchen sie bei 300 Quellen
etwa 1 s (24 Std.) bis 3–6 s (7 Tage).

**Planer:** Er holt für Checks und SNMP neue Aufgaben, sobald Plätze frei sind; im Lasttest kamen alle 2000 Geräte im
60-s-Takt dran (Test `TestPlanerDurchsatz`). Die Grenze ist jetzt die Antwortzeit der Geräte: mit
32 gleichzeitigen Abfragen und 200 ms je Gerät etwa 160 Geräte je Sekunde.

### Platzbedarf

Gemessen je Tag bei 2500 Quellen (500 Agents, 2000 SNMP-Geräte mit je CPU, Speicher, Platte, zwei Schnittstellen):

| Stufe | je Tag | Standard-Aufbewahrung | belegt (Standard) |
| --- | --- | --- | --- |
| Rohwerte | 1,9 GB | 2 Tage (plus laufender Tag) | ≈ 6 GB |
| 5-Minuten-Werte | 0,8 GB | 30 Tage | ≈ 24 GB |
| Stundenwerte | 65 MB | 365 Tage | ≈ 24 GB |
| **zusammen** | | | **≈ 54 GB** |

Je 100 Quellen also gut 2 GB. Die Größe wächst linear mit der Zahl der Quellen und der Reihen je Quelle (eine
Schnittstelle mehr = zwei Reihen mehr). Die Seite **Einstellungen → Aufbewahrung der Messwerte** zeigt den belegten
Platz je Stufe.

### Empfehlungen

| Installation | CPU | RAM | Platte (Datenbank) |
| --- | --- | --- | --- |
| bis 100 Quellen (kleines Büro, ein Standort) | 2 | 4 GB | 20 GB |
| bis 500 Quellen | 2–4 | 4–8 GB | 40 GB |
| bis 2500 Quellen (gemessen) | 4 | 8 GB | 100 GB SSD |

- PostgreSQL bei mehr als 500 Quellen einstellen: `shared_buffers` etwa ein Viertel des RAM,
  `effective_cache_size` etwa die Hälfte, `max_wal_size` 4 GB.
- Platz sparen: 5-Minuten-Werte auf 14 Tage (Graph „7 Tage“ bleibt voll) oder Stundenwerte je Mandant kürzer
  (Einstellungen → Aufbewahrung). Kürzer stellen löscht beim nächsten Wartungslauf, unwiderruflich.
- Sicherungen brauchen zusätzlich Platz (komprimiert). Im Lasttest war die Sicherung nur 430 MB für 9,5 GB, weil sich
  die hochgerechneten Testdaten wiederholen; mit echten Daten mit etwa einem Fünftel der Datenbank je Sicherung
  rechnen (Annahme, nicht gemessen), mal Anzahl der aufbewahrten Sicherungen.
- Viele Agents hinter einer NAT-Adresse: Registrierung höchstens 30 je Minute; ein Rollout von 500 Rechnern durch
  eine Adresse dauert also gut 15 Minuten (der Paketmanager meldet „Zu viele Registrierungsversuche“, erneut
  ausführen genügt).

## Aufbewahrung der Messwerte

| Stufe | Standard | einstellbar global | je Mandant |
| --- | --- | --- | --- |
| Rohwerte (für 1-Std.- und 24-Std.-Graphen, Alarme) | 2 Tage | 2–7 Tage | nein (gemeinsame Tagespartitionen) |
| 5-Minuten-Werte (Graph 7 Tage, Verfügbarkeit) | 30 Tage | 30–400 Tage | ja |
| Stundenwerte (Graph 30 Tage, Berichte, Prognose) | 365 Tage | 90–1830 Tage | ja |

Untermandanten erben den Wert des nächsten Mandanten darüber. Einstellen darf nur der Betreiber, kürzer nur mit
frischem 2FA-Code; jede Änderung steht im Audit-Log (`einstellungen.aufbewahrung`). Zustandswechsel der Sensoren
werden so lange aufbewahrt wie die 5-Minuten-Werte.

## Ausfallkonzept: kalte Zweitinstanz

Echte Hochverfügbarkeit (zwei laufende Zentralen) gibt es nicht. Für einen Ausfall der Zentrale gibt es eine
**kalte Zweitinstanz**: ein zweiter Rechner, auf dem OpenWacht installiert ist, aber nicht läuft. Er spielt jede neue
Sicherung der Hauptinstanz von selbst ein, prüft sie und hält sie als Bereitschaftskopie bereit. Im Ausfall macht ein
Befehl ihn zur Zentrale.

OpenWacht holt die Sicherungen nicht selbst über das Netz. Sie in einen Ordner auf dem Zweitrechner zu kopieren, ist
Sache des Betreibers (rsync über SSH, NFS, zur Not ein USB-Laufwerk). Damit gibt es keinen neuen Netzweg und keine
Zugangsdaten in OpenWacht, und das Verfahren geht auch ohne Internet.

### Einrichten (einmal)

1. Zweiten Rechner (VM oder LXC) mit demselben Betriebssystem auf **anderer Hardware** anlegen und OpenWacht in
   **derselben Version** installieren (`apt install ./openwacht-zentrale_….deb`, Kapitel 1). Den Einrichtungsassistenten
   nicht ausführen.
2. Den **Hauptschlüssel** der Hauptinstanz nach `/etc/openwacht/schluessel` kopieren (ersetzt den dort erzeugten;
   Eigentümer `svc_openwacht`, Rechte 0400) und ebenso `/etc/openwacht/zentrale.env`.
3. Einen Eingangsordner anlegen, z. B. `/var/lib/openwacht-zweitinstanz-eingang` (nicht `/var/backups/openwacht`,
   dort legt der Zweitrechner seine eigenen Sicherungen ab), und die Sicherungen der Hauptinstanz dorthin kopieren
   lassen, siehe unten.
4. Auf dem Zweitrechner:

   ```bash
   sudo openwacht-zentrale zweitinstanz -einrichten -quelle /var/lib/openwacht-zweitinstanz-eingang
   ```

   Das legt die Markierung `/etc/openwacht/zweitinstanz` an, schaltet Zentrale, Trap-Dienst und Sicherung dort ab, den
   Timer `openwacht-zweitinstanz.timer` an und spielt die neueste Sicherung sofort einmal ein. Hat die Datenbank dort
   schon Konten oder läuft dort eine Zentrale, bricht der Befehl ab (Schutz vor Verwechslung der Rechner); `-ersetzen`
   übergeht das.
5. Agents und Browser erreichen die Zentrale über einen **DNS-Namen** mit kurzer TTL (z. B. 300 s), nicht über die
   IP. Dieser Name muss in den Namen der Zentrale stehen (Einstellungen → Installation, Agent-Namen).
6. Bei jedem Update beide Rechner aktualisieren, den Zweitrechner **zuerst**. Das Paket-Update startet auf einem
   markierten Zweitrechner keine Zentrale.

**Kopieren per rsync (Beispiel):** Auf der Hauptinstanz einen Benutzer `openwacht-kopie` anlegen, der die Sicherungen
lesen darf (`setfacl -m u:openwacht-kopie:rx /var/backups/openwacht` und `setfacl -d -m u:openwacht-kopie:r
/var/backups/openwacht`). In seine `authorized_keys` den Schlüssel des Zweitrechners nur für lesendes rsync:

```text
command="rrsync -ro /var/backups/openwacht",restrict ssh-ed25519 AAAA… zweitrechner
```

Auf dem Zweitrechner stündlich (z. B. per systemd-Timer oder cron als root):

```bash
rsync -t --chmod=F600 'openwacht-kopie@zentrale.beispiel.example:openwacht-*.dump' /var/lib/openwacht-zweitinstanz-eingang/
```

`rsync` legt die Datei erst unter einem versteckten Namen an; die Zweitinstanz nimmt nur fertige Dateien
`openwacht-<Zeit>.dump`, die seit einer Minute unverändert sind. Alte Dateien im Eingang löscht sie nicht; dafür z. B.
`find /var/lib/openwacht-zweitinstanz-eingang -name 'openwacht-*.dump' -mtime +14 -delete` in denselben Timer.

### Was der Timer prüft

Stündlich nimmt `zweitinstanz -lauf` die neueste Sicherung aus dem Eingang (nach dem Zeitstempel im Namen). Ist sie neu,
spielt er sie in eine eigene Datenbank `openwacht_neu` ein und prüft:

- Der Hauptschlüssel passt (die Agent-CA der Sicherung lässt sich entschlüsseln).
- Dieses Paket kennt jede Migration der Sicherung. Ist die Sicherung neuer, scheitert der Lauf mit „Zweitinstanz auf die
  Version der Hauptinstanz aktualisieren“. Eine ältere Sicherung ist in Ordnung.
- Die Hash-Kette des Audit-Logs ist heil, es gibt mindestens einen Mandanten.

Erst dann ersetzt sie die bisherige Bereitschaftskopie (die Datenbank `openwacht`); die vorige wird gelöscht. Scheitert
eine Prüfung, bleibt die bisherige Kopie unverändert. Der Lauf scheitert außerdem, wenn die neueste Sicherung im Eingang
**älter als 26 Stunden** ist (kommen keine Sicherungen mehr an?). Ohne Markierung oder wenn auf dem Rechner eine Zentrale
läuft, ändert der Lauf nichts.

```bash
sudo openwacht-zentrale zweitinstanz -status      # Stand: letzte Sicherung, eingespielt, Inhalt, Fehler
journalctl -u openwacht-zweitinstanz              # Verlauf
```

Beim Einspielen braucht der Zweitrechner kurz Platz für zwei Datenbanken.

**Überwachen:** Der Stand liegt in `/var/lib/openwacht-zweitinstanz/` (ohne Geheimnisse, für alle lesbar):
`status.json` nach jedem Lauf, `ok` nur nach einer erfolgreich eingespielten neuen Sicherung. Einen OpenWacht-Agent auf dem
Zweitrechner registrieren (bei der Hauptinstanz), den Ordner freigeben (`openwacht-agent sensoren -arten datei -ordner
/var/lib/openwacht-zweitinstanz`) und einen Sensor „Datei“ auf `/var/lib/openwacht-zweitinstanz/ok` mit höchstem Alter
26 Stunden anlegen (Kapitel 7). So meldet die Hauptinstanz, wenn die Zweitinstanz nicht mehr mitkommt.

### Im Ausfall

| Schritt | Befehl | Dauer |
| --- | --- | --- |
| 1. Entscheidung: Hauptinstanz kommt nicht schnell zurück; sie bleibt aus | | |
| 2. Zweitinstanz wird Zentrale | `sudo openwacht-zentrale zweitinstanz -umschalten` | < 1 Min. |
| 3. DNS-Namen auf die Zweitinstanz umstellen | im DNS | 1 Min. + TTL |
| 4. Prüfen | Oberfläche, `curl -k https://<name>/api/v1/gesund`, Agents „melden sich“ | 2–5 Min. |

`-umschalten` fragt nach (`-ja` ohne Rückfrage), spielt eine noch neuere fertige Sicherung ein, falls eine im Eingang
liegt, führt die Migrationen aus, entfernt die Markierung, schaltet den Timer ab und Zentrale, Trap-Dienst und Sicherung
an. Scheitert das Einspielen der neueren Sicherung, gilt die vorhandene Bereitschaftskopie; der Befehl nennt ihr Datum.

Weil die Kopie schon eingespielt ist, dauert das Umschalten unter einer Minute; die **Wiederanlaufzeit** bestimmt vor
allem der DNS (etwa 5–10 Minuten mit kurzer TTL). Zum Vergleich: Einspielen von Hand (`wiederherstellen`, Kapitel 13)
dauerte im Lasttest (2 vCPU, Datenbank 9,5 GB) rund 4 Minuten, bei 54 GB hochgerechnet etwa 25 Minuten.

Was bleibt: Agents, SNMP-Geräte, Zugangsdaten, Agent-CA und HTTPS-Wurzel kommen aus der Sicherung; Agents verbinden
sich ohne Zutun wieder, sobald der Name auf die Zweitinstanz zeigt. **Was verloren geht:** alles seit der letzten
Sicherung (bis zu 24 Stunden bei täglicher Sicherung): Messwerte, Alarmverlauf, Änderungen an Geräten und Benutzern.
Wer weniger verlieren will, sichert öfter (eigener Timer mit `sichern -jetzt`, z. B. alle 4 Stunden); die Zweitinstanz
nimmt jede neue Sicherung.

**Zurück auf die Hauptinstanz:** Die bisherige Hauptinstanz wird jetzt Zweitinstanz: dort dieselbe Version
installieren, Hauptschlüssel prüfen, `zweitinstanz -einrichten -quelle … -ersetzen` mit den Sicherungen der neuen
Zentrale, nach dem ersten erfolgreichen Lauf in einem ruhigen Moment dort `-umschalten` und den DNS-Namen zurückstellen.
Danach die andere Seite wieder mit `-einrichten -ersetzen` zur Zweitinstanz machen. **Nie beide gleichzeitig laufen
lassen:** Agents melden sich bei der, auf die der DNS-Name zeigt; die andere hielte veraltete Daten und schickte eigene
Alarme.

**Proben:** halbjährlich auf einer Kopie des Zweitrechners (z. B. Snapshot der VM ohne Netz) `-umschalten` ausführen,
anmelden, die Zeit notieren und den Snapshot verwerfen.

Der Totmannschalter (Einstellungen → Totmann) meldet den Ausfall der Zentrale nach außen; ohne ihn merkt niemand,
dass die Überwachung selbst steht.
