# 15. Windows-Agent signieren (Authenticode) und Release

Den Windows-Agent gibt es als MSI. Damit Smart App Control (SAC) ihn startet und SmartScreen nicht warnt, müssen
Programm **und** MSI mit einem Authenticode-Zertifikat einer öffentlichen Zertifizierungsstelle signiert sein. Ein
selbst erzeugtes Zertifikat hilft dagegen nicht.

> **Stand 1.0.6: Programme und MSI sind noch nicht Authenticode-signiert.** Ein Certum „Open Source Code Signing in
> the Cloud“ ist beantragt; sobald es ausgestellt ist, signiert der Herausgeber jedes Release mit
> `tools/signieren/authenticode.ps1` (unten). Bis dahin gilt:
>
> - **Echtheit prüfen** über die signierten Prüfsummen: `SHA256SUMS` ist mit dem Update-Schlüssel signiert
>   (`SHA256SUMS.sig`, Kennungen in Kapitel 12); das Offline-Paket prüft das selbst (`installieren.sh -pruefen
>   -abdruck <kennung>`, Kapitel 1). Unter Windows die Prüfsumme der MSI mit
>   `Get-FileHash openwacht-agent_<version>_amd64.msi -Algorithm SHA256` gegen `SHA256SUMS` vergleichen.
> - **Virenschutz und Smart App Control:** SAC (nur Windows 11, nicht auf Servern) blockiert unsignierte Programme,
>   SmartScreen warnt. Blockiert ein Virenschutz den Agent, eine Ausnahme für den Pfad `C:\Program Files\OpenWacht\`
>   anlegen (dort dürfen nur Administratoren schreiben), nicht für einzelne Prüfsummen.
> - **Gruppenrichtlinien:** Wo „Anmelden als Dienst“ per GPO eingeschränkt ist, `NT SERVICE\openwacht-agent` dort
>   aufnehmen.
>
> Der folgende Ablauf beschreibt das Signieren, sobald ein Zertifikat vorhanden ist.

Das ist ein **zweiter** Schlüssel neben dem Update-Schlüssel (Kapitel 12):

| Schlüssel | Wofür | Wo |
| --- | --- | --- |
| Update-Schlüssel (Ed25519) | Agent-Updates, Download von der Zentrale (Linux), `SHA256SUMS` | offline beim Herausgeber |
| Authenticode-Zertifikat | Windows startet den Agent (SAC, SmartScreen), Download unter Windows | Token oder Cloud-HSM der Zertifizierungsstelle |

## Zertifikat beschaffen (einmalig, Herausgeber)

Für eine Privatperson in Deutschland kommt nur ein Zertifikat mit **geprüfter Person** (IV, bei Certum „Standard
Code Signing“) in Frage; Microsofts Artifact Signing nimmt Einzelpersonen nur aus den USA und Kanada an. Seit
27.02.2026 gilt ein Code-Signing-Zertifikat höchstens 459 Tage, der Schlüssel muss auf zertifizierter Hardware oder
in der Cloud-HSM der Zertifizierungsstelle liegen (kein PFX mehr).

Gängige Wege (Preise vor dem Kauf prüfen, sie ändern sich):

- **Certum Standard Code Signing in der Cloud (SimplySign):** für Privatpersonen mit Ausweiskopie, Schlüssel in der
  Cloud, Freigabe per App auf dem Handy. Signiert wird laut Anleitung der Zertifizierungsstelle unter Windows mit deren
  SimplySign-Anwendung und `signtool`. Es gibt die Variante auch als Karte mit Lesegerät.
- **SSL.com IV Code Signing:** mit eSigner (Cloud, Abo) oder YubiKey.
- Weil OpenWacht unter der AGPL steht, gibt es nach der Veröffentlichung des Quellcodes bei Certum ein günstigeres
  „Open Source Code Signing“, dann mit „Open Source Developer“ vor dem Namen.

Nach der Ausstellung:

1. Fingerabdruck (SHA-1, „Thumbprint“, 40 Hexziffern) ablesen: unter Windows in der Zertifikatsanzeige
   (Details → Fingerabdruck) oder `Get-PfxCertificate`/`certutil`; unter Linux
   `openssl x509 -in zert.pem -noout -fingerprint -sha1`.
2. In `internal/update/authenticode.txt` eintragen (eine Zeile, Großbuchstaben ohne Trenner), in einem **eigenen**
   Pull Request mit „Authenticode-Zertifikat“ im Titel (wie bei `schluessel.pub`). Ab dieser Version bietet die
   Zentrale den Windows-Download an und prüft der Befehl genau diese Zertifikate.
3. Den Fingerabdruck zusätzlich hier im Handbuch und bei Kunden veröffentlichen (zweite Quelle für den Vergleich).
4. **Vor dem Ablauf** (spätestens 30 Tage vorher) das Nachfolgezertifikat holen und als zweite Zeile eintragen; das
   alte erst nach der nächsten Version entfernen. Höchstens drei Einträge.

Signierte Dateien bleiben nach Ablauf gültig, wenn beim Signieren ein **Zeitstempel** gesetzt wurde (immer mit
Zeitstempel signieren, siehe unten).

## Aktuelles Zertifikat

| Feld | Wert |
| --- | --- |
| Inhaber | Open Source Developer Philipp Heller |
| Aussteller | Certum Code Signing 2021 CA |
| Seriennummer | `0B40CD58EEC9B7BBACD977DA0830C782` |
| Gültig | 28.11.2026 bis 28.11.2027 |
| Fingerabdruck (SHA-1) | `2AC32559F124E5A3C9FF56A04F17A8897D591669` |
| Fingerabdruck (SHA-256) | `51356A57E8BDB4D0741C0AA990BCDDBF66E98A01B067AE01EAF53FDCFE6D181C` |

Unter Windows zeigt `Get-AuthenticodeSignature <datei>` den Fingerabdruck in `SignerCertificate.Thumbprint`.

## Ablauf je Release unter Windows mit SimplySign (ab 1.0.6)

Certum SimplySign hält den Schlüssel in der Cloud. **SimplySign Desktop** bindet ihn nach der Anmeldung (Code aus der
SimplySign-App auf dem Handy) als virtuelle Karte ein; das Zertifikat steht dann unter „Eigene Zertifikate“, und
`signtool` signiert über den Fingerabdruck. Einmal einrichten: SimplySign Desktop, Windows SDK
(`winget install Microsoft.WindowsSDK.10.0.26100`, enthält `signtool.exe`), Go, Git und Node.js (`winget install
OpenJS.NodeJS.LTS`, für die Oberfläche), das Repository klonen.

Je Release auf dem Windows-PC des Herausgebers, im Wurzelverzeichnis des Repositorys, Stand des Release-Tags:

1. Ausgabeordner `dist` bereitlegen (die Windows-Dateien liegen ab 1.0.13 in `dist\windows`): CI-Artefakt entpacken oder selbst bauen (`go run ./tools/build -ziele alle`;
   der Bau ist reproduzierbar, die Prüfsummen müssen gleich sein).
2. SimplySign Desktop anmelden.
3. `.\tools\signieren\authenticode.ps1 -Fingerabdruck <SHA-1 des Zertifikats>`. Das Skript signiert Agent und
   Desktop-App (amd64, arm64) mit Zeitstempel von Certum, baut die MSI aus den signierten Agents neu
   (`-msi-neu`), signiert die MSI, berechnet `SHA256SUMS` neu (`-summen-neu`) und prüft jede Datei mit
   `Get-AuthenticodeSignature` (gültig, dieses Zertifikat, mit Zeitstempel). Es warnt, wenn der Fingerabdruck nicht in
   `internal/update/authenticode.txt` steht oder das Zertifikat in weniger als 30 Tagen abläuft. Am 28.11.2026 zum ersten
   Mal mit dem echten Zertifikat gelaufen (1.0.12): alle sechs Dateien gültig, mit Zeitstempel.
4. Offline `SHA256SUMS` mit dem Update-Schlüssel signieren (Schritt 6 unten).

Ein Certum-Open-Source-Zertifikat erlaubt laut Certum bis zu 5000 Signaturen im Monat; ein Release braucht sechs
(4 Programme, 2 MSI).

## Ablauf je Release (allgemein, z. B. unter Linux mit osslsigncode)

Reihenfolge ist wichtig: Das MSI enthält das Programm, also erst das Programm signieren, dann das MSI daraus bauen
und signieren, zuletzt die Prüfsummen bilden und offline signieren.

```bash
# 1. bauen (oder CI-Artefakt nehmen und nachbauen: muss gleich sein)
go run ./tools/build -ziele alle

# 2. Windows-Programme mit Authenticode signieren (Beispiel Linux, osslsigncode mit PKCS#11;
#    unter Windows: signtool sign /fd sha256 /tr <Zeitstempeldienst> /td sha256 /sha1 <Fingerabdruck> <datei>)
for a in amd64 arm64; do
  osslsigncode sign -pkcs11module <modul.so> -pkcs11cert 'pkcs11:…' -key 'pkcs11:…' \
    -h sha256 -n "OpenWacht-Agent" -t <Zeitstempeldienst der CA> \
    -in dist/windows/openwacht-agent_windows_$a.exe -out dist/windows/openwacht-agent_windows_$a.exe.signiert &&
  mv dist/windows/openwacht-agent_windows_$a.exe.signiert dist/windows/openwacht-agent_windows_$a.exe
done

# 3. MSI aus den signierten Programmen neu bauen, Prüfsummen neu
go run ./tools/build -msi-neu

# 4. MSI signieren (wie Schritt 2, Dateien dist/windows/openwacht-agent_<version>_<arch>.msi)

# 5. Prüfsummen neu (die MSI haben sich durch die Signatur geändert)
go run ./tools/build -summen-neu

# 6. offline: Update-Signaturen für die Agents und Signatur der Prüfsummen (Kapitel 12 und 14)
go run ./tools/signieren -schluessel ~/openwacht-update.key -version <version> dist/linux/openwacht-agent_linux_* dist/windows/openwacht-agent_windows_*.exe
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen dist/linux/SHA256SUMS
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen dist/windows/SHA256SUMS
```

Prüfen: `osslsigncode verify -in dist/windows/openwacht-agent_<version>_amd64.msi` bzw. unter Windows
`Get-AuthenticodeSignature .\openwacht-agent_<version>_amd64.msi` (Status `Valid`). `-msi-neu` baut das MSI
reproduzierbar: Wer das signierte Programm hat, bekommt dasselbe unsignierte MSI.

`authenticode.ps1` lief am 28.11.2026 zum ersten Mal mit dem echten Zertifikat (SimplySign, 1.0.12) und signierte alle sechs Dateien. Getestet (22.11.2026, Sandbox): `osslsigncode` 2.8 signiert und prüft MSI und Programm mit einem Testzertifikat,
der Inhalt des MSI bleibt dabei gleich. Die signierte MSI ließ sich am 28.11.2026 auf echtem Windows installieren. **Noch nicht geprüft:** Verhalten von SAC
mit dem gekauften Zertifikat. Vor dem Einsatz bei Kunden prüfen: Start des Dienstes, Rechte des Programmverzeichnisses
und die Meldung des Agents in der Oberfläche.

## Was die Signatur leistet und was nicht

- SAC und SmartScreen sehen einen bekannten Herausgeber. Ein neues Zertifikat hat anfangs noch keinen Ruf; SmartScreen
  kann die ersten Wochen trotzdem warnen.
- Der Download-Befehl für Windows (Kapitel 5) vertraut nur den eingetragenen Fingerabdrücken. Wer das Zertifikat bzw.
  den Zugang zur SimplySign-App erbeutet, kann Windows-Programme im Namen des Herausgebers signieren: Zugang wie den
  Update-Schlüssel schützen, bei Verlust sofort bei der Zertifizierungsstelle sperren lassen und den Eintrag aus
  `authenticode.txt` entfernen.
- Agent-Updates prüft der Agent weiter mit dem Ed25519-Schlüssel (Kapitel 12), nicht mit Authenticode.
