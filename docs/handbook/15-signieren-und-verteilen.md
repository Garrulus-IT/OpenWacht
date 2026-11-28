# 15. Signing the Windows agent (Authenticode) and release

The Windows agent is available as an MSI. For Smart App Control (SAC) to start it and for SmartScreen not to warn,
program **and** MSI must be signed with an Authenticode certificate from a public certification authority. A
self-generated certificate does not help.

> **As of 1.0.6: programs and MSI are not yet Authenticode-signed.** A Certum “Open Source Code Signing in the Cloud”
> has been applied for; as soon as it is issued, the publisher signs every release with
> `tools/signieren/authenticode.ps1` (below). Until then:
>
> - **Check authenticity** via the signed checksums: `SHA256SUMS` is signed with the update key (`SHA256SUMS.sig`,
>   identifiers in chapter 12); the offline package checks this itself (`installieren.sh -pruefen -abdruck
>   <identifier>`, chapter 1). On Windows, compare the MSI checksum from
>   `Get-FileHash openwacht-agent_<version>_amd64.msi -Algorithm SHA256` with `SHA256SUMS`.
> - **Antivirus and Smart App Control:** SAC (Windows 11 only, not on servers) blocks unsigned programs, SmartScreen
>   warns. If an antivirus blocks the agent, create an exception for the path `C:\Program Files\OpenWacht\` (only
>   administrators may write there), not for individual checksums.
> - **Group policies:** Where “Log on as a service” is restricted by GPO, add `NT SERVICE\openwacht-agent` there.
>
> The following procedure describes signing once a certificate is available.

This is a **second** key next to the update key (chapter 12):

| Key | For | Where |
| --- | --- | --- |
| Update key (Ed25519) | agent updates, download from the central server (Linux), `SHA256SUMS` | offline at the publisher |
| Authenticode certificate | Windows starts the agent (SAC, SmartScreen), download on Windows | token or cloud HSM of the certification authority |

## Obtaining the certificate (once, publisher)

For a private individual in Germany, only a certificate with a **verified person** (IV, at Certum “Standard Code
Signing”) is possible; Microsoft’s Artifact Signing only accepts individuals from the USA and Canada. Since 27 Feb 2026
a code signing certificate is valid for at most 459 days, and the key must be on certified hardware or in the
certification authority’s cloud HSM (no PFX any more).

Common ways (check prices before buying, they change):

- **Certum Standard Code Signing in the cloud (SimplySign):** for private individuals with a copy of their ID, key in
  the cloud, approval via an app on the phone. According to the certification authority’s instructions, signing is
  done on Windows with its SimplySign application and `signtool`. There is also a variant as a card with reader.
- **SSL.com IV Code Signing:** with eSigner (cloud, subscription) or YubiKey.
- Because OpenWacht is under the AGPL, after the source code is published Certum offers a cheaper “Open Source Code
  Signing”, then with “Open Source Developer” in front of the name.

After issuance:

1. Read the fingerprint (SHA-1, “thumbprint”, 40 hex digits): on Windows in the certificate viewer (Details →
   Thumbprint) or with `Get-PfxCertificate`/`certutil`; on Linux `openssl x509 -in zert.pem -noout -fingerprint -sha1`.
2. Enter it in `internal/update/authenticode.txt` (one line, upper case without separators), in a **separate** pull
   request with “Authenticode-Zertifikat” in the title (as for `schluessel.pub`). From this version on, the central
   server offers the Windows download and the command checks exactly these certificates.
3. Additionally publish the fingerprint here in the handbook and to customers (second source for the comparison).
4. **Before expiry** (at the latest 30 days before), obtain the successor certificate and enter it as a second line;
   remove the old one only after the next version. At most three entries.

Signed files remain valid after expiry if a **timestamp** was set when signing (always sign with a timestamp, see
below).

## Current certificate

| Field | Value |
| --- | --- |
| Holder | Open Source Developer Philipp Heller |
| Issuer | Certum Code Signing 2021 CA |
| Serial number | `0B40CD58EEC9B7BBACD977DA0830C782` |
| Valid | 28.11.2026 to 28.11.2027 |
| Fingerprint (SHA-1) | `2AC32559F124E5A3C9FF56A04F17A8897D591669` |
| Fingerprint (SHA-256) | `51356A57E8BDB4D0741C0AA990BCDDBF66E98A01B067AE01EAF53FDCFE6D181C` |

On Windows, `Get-AuthenticodeSignature <file>` shows the fingerprint in `SignerCertificate.Thumbprint`.

## Procedure per release on Windows with SimplySign (from 1.0.6)

Certum SimplySign keeps the key in the cloud. After sign-in (code from the SimplySign app on the phone), **SimplySign
Desktop** mounts it as a virtual card; the certificate is then under “Personal certificates”, and `signtool` signs via
the fingerprint. Set up once: SimplySign Desktop, Windows SDK (`winget install Microsoft.WindowsSDK.10.0.26100`,
contains `signtool.exe`), Go, Git and Node.js (`winget install OpenJS.NodeJS.LTS`, for the interface), clone the
repository.

Per release on the publisher’s Windows PC, in the root directory of the repository, at the state of the release tag:

1. Prepare the output folder `dist` (from 1.0.13 the Windows files are in `dist\windows`): unpack the CI artefact or build it yourself (`go run ./tools/build -ziele alle`;
   the build is reproducible, the checksums must be identical).
2. Sign in to SimplySign Desktop.
3. `.\tools\signieren\authenticode.ps1 -Fingerabdruck <SHA-1 of the certificate>`. The script signs agent and desktop
   app (amd64, arm64) with a timestamp from Certum, rebuilds the MSI from the signed agents (`-msi-neu`), signs the MSI,
   recomputes `SHA256SUMS` (`-summen-neu`) and checks every file with `Get-AuthenticodeSignature` (valid, this
   certificate, with timestamp). It warns if the fingerprint is not in `internal/update/authenticode.txt` or the
   certificate expires in less than 30 days. First run with the real certificate on 28.11.2026 (1.0.12): all six files
   valid, with timestamp.
4. Sign `SHA256SUMS` offline with the update key (step 6 below).

According to Certum, a Certum open source certificate allows up to 5000 signatures per month; a release needs six
(4 programs, 2 MSI).

## Procedure per release (general, for example on Linux with osslsigncode)

The order matters: the MSI contains the program, so first sign the program, then build the MSI from it and sign it,
finally form the checksums and sign them offline.

```bash
# 1. build (or take the CI artefact and rebuild: must be identical)
go run ./tools/build -ziele alle

# 2. sign the Windows programs with Authenticode (example Linux, osslsigncode with PKCS#11;
#    on Windows: signtool sign /fd sha256 /tr <timestamp service> /td sha256 /sha1 <fingerprint> <file>)
for a in amd64 arm64; do
  osslsigncode sign -pkcs11module <module.so> -pkcs11cert 'pkcs11:…' -key 'pkcs11:…' \
    -h sha256 -n "OpenWacht-Agent" -t <timestamp service of the CA> \
    -in dist/windows/openwacht-agent_windows_$a.exe -out dist/windows/openwacht-agent_windows_$a.exe.signiert &&
  mv dist/windows/openwacht-agent_windows_$a.exe.signiert dist/windows/openwacht-agent_windows_$a.exe
done

# 3. rebuild the MSI from the signed programs, new checksums
go run ./tools/build -msi-neu

# 4. sign the MSI (as step 2, files dist/windows/openwacht-agent_<version>_<arch>.msi)

# 5. new checksums (the MSIs changed through the signature)
go run ./tools/build -summen-neu

# 6. offline: update signatures for the agents and signature of the checksums (chapters 12 and 14)
go run ./tools/signieren -schluessel ~/openwacht-update.key -version <version> dist/linux/openwacht-agent_linux_* dist/windows/openwacht-agent_windows_*.exe
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen dist/linux/SHA256SUMS
go run ./tools/signieren -schluessel ~/openwacht-update.key -summen dist/windows/SHA256SUMS
```

Check: `osslsigncode verify -in dist/windows/openwacht-agent_<version>_amd64.msi` or on Windows
`Get-AuthenticodeSignature .\openwacht-agent_<version>_amd64.msi` (status `Valid`). `-msi-neu` builds the MSI
reproducibly: whoever has the signed program gets the same unsigned MSI.

`authenticode.ps1` first ran with the real certificate on 28 Nov 2026 (SimplySign, 1.0.12) and signed all six files. Tested (22 Nov 2026, sandbox):
`osslsigncode` 2.8 signs and verifies MSI and program with a test certificate; the content of the MSI stays the same.
The signed MSI installed on real Windows on 28 Nov 2026. **Not yet checked:** behaviour of SAC with the purchased
certificate. Before use at customers, check: start of the service, permissions of the program directory and the
agent’s report in the interface.

## What the signature achieves and what not

- SAC and SmartScreen see a known publisher. A new certificate initially has no reputation; SmartScreen may still warn
  during the first weeks.
- The download command for Windows (chapter 5) only trusts the entered fingerprints. Whoever captures the certificate or
  the access to the SimplySign app can sign Windows programs in the publisher’s name: protect the access like the
  update key, have it revoked immediately at the certification authority if lost, and remove the entry from
  `authenticode.txt`.
- The agent continues to check agent updates with the Ed25519 key (chapter 12), not with Authenticode.
