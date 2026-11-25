# Betrieb unter Linux (Debian 13)

**Neu installieren:** PostgreSQL installieren, dann das Paket aus dem Release:

```bash
apt install postgresql
apt install ./openwacht-zentrale_1.0.3_amd64.deb
```

`postinst` ruft `openwacht-zentrale installieren` auf: Systembenutzer, `/etc/openwacht` mit Hauptschlüssel,
Trap-Schlüssel, PostgreSQL-Rollen und Datenbank, `pg_hba`/`pg_ident` (Pfade fragt es bei PostgreSQL ab, Sicherung
`*.vor-openwacht`), Migrationen, Units, Dienste. Am Ende steht der **Einrichtungslink**
(`https://<Adresse>/einrichtung#<Token>`, 2 Stunden gültig) mit dem Fingerabdruck des vorläufigen Zertifikats. Der
Assistent im Browser fragt Hauptmandant, ersten Admin mit 2FA, Adresse, HTTPS, Zeitzone, Netzfreigabe, Mail und
Sicherung ab. Neuer Link: `sudo openwacht-zentrale einrichtungslink`.

**Update:** dieselbe Zeile mit dem neuen Paket. Die Migrationen laufen beim Neustart der Zentrale.

**Ohne Internet beim Kunden:** Offline-Paket mit PostgreSQL und allen Abhängigkeiten, siehe `deploy/offline/` und
Handbuch Kapitel 14 (`docs/handbuch/14-betrieb-ohne-internet.md`).

**Ohne Paket:** Binary irgendwohin legen und `sudo ./openwacht-zentrale installieren` ausführen; die Units landen dann
in `/etc/systemd/system` (mit dem Pfad des Binarys).

| Datei | Ziel | Hinweis |
| --- | --- | --- |
| `*.service`, `*.socket`, `*.timer` | `/usr/lib/systemd/system/` (Paket) | auch im Binary eingebettet (`embed.go`) |
| `zentrale.env.beispiel` | nur zum Nachlesen | neu: `installieren` legt `/etc/openwacht/zentrale.env` an |
| `postgresql/*` | nur noch zum Nachlesen | `installieren` legt Rollen und Zeilen selbst an |
| `Caddyfile` | nur noch für ntfy (Port 2587) | die Oberfläche macht TLS selbst |
| `ntfy-server.yml` | `/etc/ntfy/server.yml` | ntfy ist optional, siehe Handbuch Kapitel 8 |

## Grundsätze

- **Keine Datenbankpasswörter.** Zentrale und Migrationen melden sich über den Unix-Socket mit
  Peer-Authentifizierung an. Nur der Systembenutzer `svc_openwacht` wird zur Rolle `openwacht_zentrale`,
  nur `svc_openwacht_db` zu `openwacht_owner`.
- **Migrationen vor jedem Start** als eigener Dienst (`openwacht-migrieren`) mit der Eigentümer-Rolle.
  Die Zentrale selbst bekommt diese Rolle nie und verweigert den Start, wenn sie RLS umgehen könnte.
- **Hauptschlüssel** in `/etc/openwacht/schluessel` (Eigentümer `svc_openwacht`, 0400). Ohne ihn sind
  TOTP-Geheimnisse, Agent-CA und Kanal-Token in der Datenbank unbrauchbar: getrennt sicher aufbewahren.
- **Totmannschalter** (optional, empfohlen): Ping-Adresse von healthchecks.io in `/etc/openwacht/totmann`
  (Eigentümer `svc_openwacht`, 0400), Option `-totmann-datei /etc/openwacht/totmann`. Die Zentrale pingt
  höchstens einmal je Minute nach einem erfolgreichen Alarmdurchlauf, bei gescheiterter Zustellung
  `<adresse>/fail`. Den Check bei healthchecks.io mit Periode 1 Minute und Karenzzeit 5 Minuten anlegen
  und dort per Mail alarmieren lassen, nicht über ntfy: ntfy fällt mit der Zentrale aus. Das eigene Netz verlässt
  nur eine HTTPS-Anfrage ohne Inhalt.
- **HTTPS macht die Zentrale selbst:** Port 443 öffnet systemd (`openwacht-zentrale.socket`, keine
  Capability). Zertifikat und Schlüssel liegen verschlüsselt in der Datenbank: entweder eine eigene OpenWacht-Wurzel,
  die per Name Constraints nur für die eingetragenen Namen gilt (das Serverzertifikat gilt 200 Tage und erneuert sich
  30 Tage vorher selbst), oder ein hochgeladenes Zertifikat (Einstellungen → HTTPS). Die Wurzel gibt es unter
  `/openwacht-wurzel.crt`. Der Agent-Port (8444) läuft wie bisher direkt mit mTLS.
- **Sicherung:** `openwacht-sicherung.timer` stündlich, `openwacht-zentrale sichern` (als `svc_openwacht_db`, Eigentümer-Rolle)
  sichert zur Uhrzeit aus den Einstellungen bzw. nach, wenn die letzte älter als 25 Stunden ist; Aufbewahrung nach
  Einstellung (Standard 14 Tage, die neueste bleibt immer). Sofort sichern: Befehl in Handbuch Kapitel 13 (als `svc_openwacht_db` mit `OPENWACHT_DB_EIGENTUEMER`).
- **Trap-Dienst** (SNMP-Traps und -Informs): eigener Prozess `openwacht-zentrale traps` unter dem
  Systembenutzer `svc_openwacht_traps` mit der Datenbankrolle `openwacht_trapdienst` (Mitglied von
  `openwacht_traps`, darf nur die Funktionen `traps_*`). Port 162/udp öffnet systemd
  (`openwacht-traps.socket`), der Dienst braucht keine Capability. Er bekommt nicht den Hauptschlüssel,
  sondern den davon abgeleiteten Trap-Schlüssel in `/etc/openwacht-traps/schluessel` (Verzeichnis 0750
  root:svc_openwacht_traps, Datei Eigentümer `svc_openwacht_traps`, 0400; eigenes Verzeichnis, weil der Trap-Dienst
  `/etc/openwacht` nicht lesen soll), erzeugt mit `openwacht-zentrale trapschluessel -schluessel /etc/openwacht/schluessel`.
  Angenommen werden nur Traps von Adressen bekannter SNMP-Geräte, bei denen „Traps annehmen“ an ist.
- **Update:** `apt install ./openwacht-zentrale_<neu>_amd64.deb`; das Paket startet Zentrale und Trap-Dienst neu,
  die Migrationen laufen dabei automatisch.
