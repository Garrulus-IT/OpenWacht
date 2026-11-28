#Requires -Version 5.1
# SPDX-License-Identifier: AGPL-3.0-only
#
# Authenticode-Signatur der Windows-Dateien eines Releases mit dem Zertifikat
# aus Certum SimplySign (Handbuch Kapitel 15). Läuft auf dem Windows-PC des
# Herausgebers im Wurzelverzeichnis des Repositorys, nachdem der Ausgabeordner
# (CI-Artefakt oder eigener Bau) dort liegt. Reihenfolge wie im Handbuch:
# Programme signieren, MSI aus den signierten Agents neu bauen, MSI signieren,
# SHA256SUMS neu, alles prüfen. Die Signatur von SHA256SUMS mit dem
# Update-Schlüssel (tools/signieren) kommt danach offline.
#
# Voraussetzungen: SimplySign Desktop angemeldet (Zertifikat im Speicher
# „Eigene Zertifikate“), Windows SDK (signtool.exe), Go und Git.
#
#   .\tools\signieren\authenticode.ps1 -Fingerabdruck <40 Hexziffern> [-Ordner dist\windows]

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Fingerabdruck,
    [string]$Ordner = "dist\windows",
    # Zeitstempeldienst von Certum (RFC 3161): Signaturen bleiben nach Ablauf des Zertifikats gültig.
    [string]$Zeitstempel = "http://time.certum.pl"
)

$ErrorActionPreference = "Stop"
$fp = $Fingerabdruck.ToUpperInvariant()

if (-not (Test-Path "internal\update\authenticode.txt")) {
    throw "Bitte im Wurzelverzeichnis des Repositorys starten."
}
if (-not (Test-Path (Join-Path $Ordner "SHA256SUMS"))) {
    throw "In $Ordner fehlt SHA256SUMS: erst bauen (go run ./tools/build -ziele alle) oder das CI-Artefakt dorthin entpacken."
}

# signtool aus dem Windows SDK, neueste Version
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) {
    throw "signtool.exe nicht gefunden. Windows SDK installieren, z. B.: winget install Microsoft.WindowsSDK.10.0.26100"
}

# Zertifikat aus SimplySign im Speicher?
$zert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $fp }
if (-not $zert) {
    throw "Zertifikat $fp nicht unter Eigene Zertifikate: SimplySign Desktop starten und mit dem Code aus der App anmelden."
}
if ($zert.NotAfter -lt (Get-Date).AddDays(30)) {
    Write-Warning ("Das Zertifikat läuft am {0:dd.MM.yyyy} ab: Nachfolger beantragen (Handbuch Kapitel 15)." -f $zert.NotAfter)
}

# Steht der Fingerabdruck in authenticode.txt? Sonst bietet die Zentrale den Download nicht an.
$liste = Get-Content "internal\update\authenticode.txt" | ForEach-Object { $_.Trim().ToUpperInvariant() } |
    Where-Object { $_ -and -not $_.StartsWith("#") }
if ($liste -notcontains $fp) {
    Write-Warning "$fp steht nicht in internal\update\authenticode.txt (eigener Pull Request, Handbuch Kapitel 15)."
}

function Signieren([string[]]$Dateien) {
    foreach ($d in $Dateien) {
        Write-Host "Signiere $d"
        & $signtool.FullName sign /sha1 $fp /fd sha256 /tr $Zeitstempel /td sha256 /d "OpenWacht" `
            /du "https://github.com/Garrulus-IT/OpenWacht" $d
        if ($LASTEXITCODE -ne 0) { throw "signtool meldet Fehler $LASTEXITCODE bei $d" }
    }
}

# 1. Programme (Agent und Desktop-App, amd64 und arm64)
$programme = Get-ChildItem $Ordner -Filter "openwacht-*_windows_*.exe" | Select-Object -ExpandProperty FullName
if (-not $programme) { throw "Keine Windows-Programme in $Ordner." }
Signieren $programme

# 2. MSI aus den signierten Agents neu bauen (reproduzierbar)
& go run ./tools/build -out $Ordner -msi-neu
if ($LASTEXITCODE -ne 0) { throw "MSI neu bauen fehlgeschlagen." }

# 3. MSI signieren
$msi = Get-ChildItem $Ordner -Filter "openwacht-agent_*.msi" | Select-Object -ExpandProperty FullName
Signieren $msi

# 4. Prüfsummen neu (die MSI haben sich durch die Signatur geändert)
& go run ./tools/build -out $Ordner -summen-neu
if ($LASTEXITCODE -ne 0) { throw "SHA256SUMS neu berechnen fehlgeschlagen." }

# 5. Prüfen: gültig, richtiges Zertifikat, mit Zeitstempel
$fehler = 0
foreach ($d in @($programme) + @($msi)) {
    $s = Get-AuthenticodeSignature $d
    $ok = $s.Status -eq "Valid" -and $s.SignerCertificate.Thumbprint -eq $fp -and $s.TimeStamperCertificate
    if ($ok) {
        Write-Host ("OK      {0}" -f (Split-Path $d -Leaf))
    } else {
        Write-Host ("FEHLER  {0}: {1} {2}" -f (Split-Path $d -Leaf), $s.Status, $s.StatusMessage)
        $fehler++
    }
}
if ($fehler) { throw "$fehler Datei(en) nicht richtig signiert." }
Write-Host "Fertig. Jetzt offline SHA256SUMS signieren: go run ./tools/signieren -schluessel <datei> -summen $Ordner\SHA256SUMS"
