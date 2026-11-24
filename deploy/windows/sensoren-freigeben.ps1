# SPDX-License-Identifier: AGPL-3.0-only
#
# OpenWacht: Sensoren auf vielen Windows-Servern freigeben (per WinRM).
#
# Der Agent misst Dienste und Leistungsindikatoren nur, wenn sie auf dem
# Rechner selbst freigegeben sind (Leitprinzip 1). Dieses Skript erkennt je
# Server die Rolle an den installierten Diensten bzw. Rollen und gibt genau
# das frei, was die passenden Vorlagensätze brauchen. Vorhandene Freigaben
# (auch Ordner und Docker) bleiben erhalten, es kommt nur etwas dazu.
#
# Aufruf (PowerShell als Administrator, Konto mit Adminrechten auf den Servern):
#   .\sensoren-freigeben.ps1 -Liste .\server.txt              # nur anzeigen
#   .\sensoren-freigeben.ps1 -Liste .\server.txt -Anwenden    # freigeben
#   .\sensoren-freigeben.ps1 -ComputerName ex02,sql01 -Anwenden
#
# Ohne -Anwenden ändert das Skript nichts. Ein Neustart des Dienstes ist nicht
# nötig: Der Agent liest die Freigabe bei jedem Durchlauf.

[CmdletBinding()]
param(
    [string]$Liste,
    [string[]]$ComputerName,
    [switch]$Anwenden
)

$server = @()
if ($Liste) { $server += Get-Content $Liste | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } }
if ($ComputerName) { $server += $ComputerName }
$server = $server | Sort-Object -Unique
if (-not $server) { throw 'Keine Server angegeben (-Liste oder -ComputerName).' }

$block = {
    param([bool]$anwenden)
    $exe = 'C:\Program Files\OpenWacht\openwacht-agent.exe'
    $datei = 'C:\ProgramData\OpenWacht-Agent\sensoren.json'
    $ergebnis = [ordered]@{ Server = $env:COMPUTERNAME; Rollen = ''; Arten = ''; Indikatoren = ''; Status = '' }
    if (-not (Test-Path $exe)) { $ergebnis.Status = 'kein Agent'; return [pscustomobject]$ergebnis }

    $arten = New-Object System.Collections.Generic.List[string]
    $ind = New-Object System.Collections.Generic.List[string]
    $ordner = New-Object System.Collections.Generic.List[string]
    $docker = ''
    function Dazu($liste, $werte) { foreach ($w in $werte) { if ($w -and -not ($liste -contains $w)) { $liste.Add($w) } } }

    # vorhandene Freigabe übernehmen
    if (Test-Path $datei) {
        try {
            $alt = Get-Content $datei -Raw | ConvertFrom-Json
            Dazu $arten $alt.arten
            Dazu $ind $alt.indikatoren
            Dazu $ordner $alt.ordner
            if ($alt.docker) { $docker = $alt.docker }
        } catch { $ergebnis.Status = 'sensoren.json unlesbar, nicht geändert'; return [pscustomobject]$ergebnis }
    }

    function Dienst($n) {
        [bool](Get-Service -Name $n -ErrorAction SilentlyContinue) -or [bool](Get-Service -DisplayName $n -ErrorAction SilentlyContinue)
    }
    function Rolle($n) {
        try { [bool](Get-WindowsFeature -Name $n -ErrorAction Stop).Installed } catch { $false }
    }

    # Rollen wie in den Vorlagensätzen (internal/zentrale/vorlagen.go)
    $rollen = New-Object System.Collections.Generic.List[string]
    Dazu $arten @('dienst')
    if (Dienst 'MSExchangeIS') { $rollen.Add('Exchange'); Dazu $ind @('MSExchangeTransport Queues', 'MSExchange Replication') }
    if (Dienst 'NTDS') { $rollen.Add('DC'); Dazu $ind @('DirectoryServices') }
    # SQL Server: Standardinstanz (SQLServer:…) und benannte Instanzen
    # (MSSQL$NAME:…, braucht Agent ab 0.99.2)
    $sqlTeile = @('General Statistics', 'Locks', 'Databases', 'Memory Manager', 'Buffer Manager')
    if (Dienst 'MSSQLSERVER') { $rollen.Add('SQL'); Dazu $ind ($sqlTeile | ForEach-Object { "SQLServer:$_" }) }
    $ver = [version]'0.0'
    if ("$(& $exe version)" -match ' (\d+\.\d+\.\d+)') { $ver = [version]$Matches[1] }
    foreach ($d in Get-Service -Name 'MSSQL$*' -ErrorAction SilentlyContinue) {
        $inst = $d.Name.Substring(6)
        if ($ver -ge [version]'0.99.2') { $rollen.Add("SQL $inst"); Dazu $ind ($sqlTeile | ForEach-Object { "$($d.Name):$_" }) }
        else { $rollen.Add("SQL $inst (Zähler erst mit Agent 0.99.2)") }
    }
    if (Dienst 'IpPbxSrv') { $rollen.Add('Swyx'); Dazu $ind @('SwyxServer', 'SwyxWare Trunk', 'Swyx Trunk') }
    if (Dienst 'W3SVC') { $rollen.Add('IIS'); Dazu $ind @('APP_POOL_WAS') }
    if (Rolle 'Print-Server') { $rollen.Add('Druck'); Dazu $ind @('Print Queue') }
    if (Dienst 'vmms') {
        $rollen.Add('Hyper-V'); Dazu $ind @('Hyper-V Virtual Machine Health Summary', 'Hyper-V Hypervisor Logical Processor', 'Memory')
    }
    if (Dienst 'BrokerAgent') { $rollen.Add('Citrix VDA'); Dazu $ind @('Terminal Services', 'ICA Session', 'System') }
    if ($ind.Count -gt 0) { Dazu $arten @('leistungsindikator') }

    $ergebnis.Rollen = ($rollen -join ', ')
    $ergebnis.Arten = ($arten -join ',')
    $ergebnis.Indikatoren = ($ind -join ',')
    if (-not $anwenden) { $ergebnis.Status = 'Vorschau'; return [pscustomobject]$ergebnis }

    $a = @('sensoren', '-arten', ($arten -join ','))
    if ($ind.Count) { $a += @('-indikatoren', ($ind -join ',')) }
    if ($ordner.Count) { $a += @('-ordner', ($ordner -join ',')) }
    if ($docker) { $a += @('-docker', $docker) }
    $aus = & $exe @a 2>&1
    $ergebnis.Status = if ($LASTEXITCODE -eq 0) { 'freigegeben' } else { "Fehler: $(($aus | Out-String).Trim())" }
    [pscustomobject]$ergebnis
}

$alle = foreach ($s in $server) {
    try {
        Invoke-Command -ComputerName $s -ScriptBlock $block -ArgumentList ([bool]$Anwenden) -ErrorAction Stop |
            Select-Object Server, Rollen, Arten, Indikatoren, Status
    } catch {
        [pscustomobject]@{ Server = $s; Rollen = ''; Arten = ''; Indikatoren = ''; Status = "nicht erreichbar: $($_.Exception.Message)" }
    }
}
$alle | Export-Csv .\sensoren-freigabe.csv -NoTypeInformation -Encoding UTF8
$alle | Format-Table Server, Rollen, Status -AutoSize
"Ergebnis je Server in sensoren-freigabe.csv"
