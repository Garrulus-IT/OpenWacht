// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/update"
)

// Download des Agents von der Zentrale (Etappe 34, Entscheidung
// 22.11.2026: nur mit Prüfung der Offline-Signatur auf dem Zielrechner).
//
// Am Agent-Port, mit einem gültigen Registrierungs-Token (Authorization:
// Bearer owa1.…), das dabei nicht verbraucht wird. Geliefert wird das
// neueste Paket der Plattform, dessen Signatur die Zentrale selbst gelten
// lässt (eingebettete Schlüssel, Widerrufe aus der Datenbank). Unter
// Windows zusätzlich nur, wenn Authenticode-Fingerabdrücke eingetragen
// sind, denn dort prüft der Befehl die Authenticode-Signatur.

// Plattformen für den Download (wie die Agent-Updates).
var downloadPlatforms = []string{"linux/amd64", "linux/arm64", "windows/amd64"}

// PathDownload: GET …/download/{os}/{arch} und …/download/{os}/{arch}/signatur.
const PathDownload = "/agent/v1/download/"

// thumbprints: Authenticode-Fingerabdrücke (Tests: cfg.Authenticode).
func (s *Server) thumbprints() []string {
	src := s.cfg.Authenticode
	var (
		list []string
		err  error
	)
	if src != "" {
		list, err = update.ParseThumbprints(src)
	} else {
		list, err = update.Thumbprints()
	}
	if err != nil {
		return nil
	}
	return list
}

// downloadPick: erstes Paket, dessen Signatur gilt und zur Zeile passt.
func downloadPick(k *update.Keyring, goos, arch string, rows pgx.Rows) (update.Signed, bool, error) {
	defer rows.Close()
	for rows.Next() {
		var ver, sum, sig string
		var size int64
		if err := rows.Scan(&ver, &sum, &sig, &size); err != nil {
			return update.Signed{}, false, err
		}
		sg, err := update.ParseSigned([]byte(sig))
		if err != nil || k.VerifySigned(sg) != nil {
			continue
		}
		if sg.Version != ver || sg.OS != goos || sg.Arch != arch || sg.SHA256 != sum || sg.Size != size {
			continue
		}
		return sg, true, nil
	}
	return update.Signed{}, false, rows.Err()
}

// downloadAvailable: Ist der Download für die Plattform eingeschaltet?
func (s *Server) downloadAvailable(goos string) error {
	if !s.updateKey().Usable() {
		return errors.New("Download aus: kein Update-Schlüssel eingetragen")
	}
	if goos == "windows" && len(s.thumbprints()) == 0 {
		return errors.New("Download des Windows-Agents aus: kein Authenticode-Zertifikat eingetragen")
	}
	return nil
}

// downloadRequest prüft zuerst das Token (ohne gültiges Token erfährt
// niemand, ob und was die Zentrale anbietet), dann Plattform und
// Verfügbarkeit. Rückgabe: Hash des Tokens.
func (s *Server) downloadRequest(w http.ResponseWriter, r *http.Request) (goos, arch string, hash []byte, ok bool) {
	if !s.agent.download.allow(s.clientIP(r), s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Downloads. Bitte kurz warten.")
		return
	}
	raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	secret, fp, err := agentproto.ParseToken(strings.TrimSpace(raw))
	if !found || err != nil || fp != s.AgentCAFingerprint() {
		writeError(w, http.StatusUnauthorized, "Registrierungs-Token fehlt oder gehört zu einer anderen Zentrale.")
		return
	}
	h := sha256.Sum256(secret)
	var usable bool
	if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_token_usable($1)`, h[:]).Scan(&usable); err != nil {
		internalError(w, "download token", err)
		return
	}
	if !usable {
		writeError(w, http.StatusUnauthorized, "Das Token ist ungültig, abgelaufen oder schon verbraucht.")
		return
	}
	goos, arch = r.PathValue("os"), r.PathValue("arch")
	platform := goos + "/" + arch
	known := false
	for _, p := range downloadPlatforms {
		known = known || p == platform
	}
	if !known {
		writeError(w, http.StatusNotFound, "Plattform nicht unterstützt.")
		return
	}
	if err := s.downloadAvailable(goos); err != nil {
		writeError(w, http.StatusNotFound, err.Error()+".")
		return
	}
	return goos, arch, h[:], true
}

func tokenRejected(w http.ResponseWriter, err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "28000" {
		writeError(w, http.StatusUnauthorized, "Das Token ist ungültig, abgelaufen oder schon verbraucht.")
		return true
	}
	return false
}

// pickForDownload: Paket für Token und Plattform (ok=false: Antwort geschrieben).
func (s *Server) pickForDownload(w http.ResponseWriter, r *http.Request) (update.Signed, []byte, bool) {
	goos, arch, hash, ok := s.downloadRequest(w, r)
	if !ok {
		return update.Signed{}, nil, false
	}
	ctx := r.Context()
	k, err := s.updateKeys(ctx, s.pool)
	if err != nil || k == nil {
		internalError(w, "download schlüssel", err)
		return update.Signed{}, nil, false
	}
	rows, err := s.pool.Query(ctx, `SELECT version, sha256, signature, size FROM openwacht.agent_download_list($1, $2, $3)`, hash, goos, arch)
	if err != nil {
		internalError(w, "download liste", err)
		return update.Signed{}, nil, false
	}
	sg, found, err := downloadPick(k, goos, arch, rows)
	if tokenRejected(w, err) {
		return update.Signed{}, nil, false
	}
	if err != nil {
		internalError(w, "download liste", err)
		return update.Signed{}, nil, false
	}
	if !found {
		writeError(w, http.StatusNotFound, "Kein signiertes Paket für diese Plattform hochgeladen.")
		return update.Signed{}, nil, false
	}
	return sg, hash, true
}

func (s *Server) handleDownloadSignature(w http.ResponseWriter, r *http.Request) {
	sg, _, ok := s.pickForDownload(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(update.DownloadText(sg)))
}

func (s *Server) handleDownloadBinary(w http.ResponseWriter, r *http.Request) {
	sg, hash, ok := s.pickForDownload(w, r)
	if !ok {
		return
	}
	var data []byte
	err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_download_data($1, $2, $3, $4)`, hash, sg.OS, sg.Arch, sg.Version).Scan(&data)
	if tokenRejected(w, err) {
		return
	}
	if err != nil || int64(len(data)) != sg.Size {
		internalError(w, "download daten", err)
		return
	}
	// Die Zentrale prüft selbst noch einmal, bevor sie etwas ausliefert.
	k, err := s.updateKeys(r.Context(), s.pool)
	if err != nil || k == nil || k.Verify(sg, data) != nil {
		slog.Error("Download: Paket passt nicht zur Signatur", "version", sg.Version, "plattform", sg.OS+"/"+sg.Arch)
		writeError(w, http.StatusInternalServerError, "Paket beschädigt.")
		return
	}
	slog.Info("Agent heruntergeladen", "version", sg.Version, "plattform", sg.OS+"/"+sg.Arch, "von", s.clientIP(r))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-OpenWacht-Version", sg.Version)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// downloadInfo für den Befehl in der Oberfläche: je Plattform Version und
// die Prüfwerte, die im Befehl stehen (Schlüssel bzw. Fingerabdrücke).
type downloadInfo struct {
	Version     string        `json:"version"`
	SHA256      string        `json:"sha256"`
	Keys        []downloadKey `json:"schluessel,omitempty"`
	Thumbprints []string      `json:"fingerabdruecke,omitempty"`
}

type downloadKey struct {
	ID  string `json:"id"`
	PEM string `json:"pem"`
}

func (s *Server) downloadOffers(ctx context.Context, tx pgx.Tx) (map[string]downloadInfo, error) {
	out := map[string]downloadInfo{}
	k, err := s.updateKeys(ctx, tx)
	if err != nil || k == nil {
		return out, err
	}
	for _, p := range downloadPlatforms {
		goos, arch, _ := strings.Cut(p, "/")
		if s.downloadAvailable(goos) != nil {
			continue
		}
		rows, err := tx.Query(ctx, `SELECT version, sha256, signature, size FROM openwacht.agent_download_candidates($1, $2)`, goos, arch)
		if err != nil {
			return out, err
		}
		sg, found, err := downloadPick(k, goos, arch, rows)
		if err != nil {
			return out, err
		}
		if !found {
			continue
		}
		info := downloadInfo{Version: sg.Version, SHA256: sg.SHA256}
		if goos == "windows" {
			info.Thumbprints = s.thumbprints()
		} else {
			for _, key := range k.Keys {
				if !k.IsRevoked(key.ID) {
					info.Keys = append(info.Keys, downloadKey{ID: key.ID, PEM: update.PublicKeyPEM(key.Pub)})
				}
			}
		}
		out[p] = info
	}
	return out, nil
}

// Befehle für den Download. Sie entstehen hier (nicht in der Oberfläche),
// damit Tests sie mit sh und openssl wirklich ausführen können. Alle
// eingesetzten Werte sind vorher geprüft (Adresse aus der Konfiguration,
// Token aus Base64url, Version x.y.z, Schlüssel als PEM, Fingerabdrücke hex).

// linuxVerifyScript lädt Signatur und Binary in ein leeres Verzeichnis und
// prüft beides; danach liegt das geprüfte Binary in der Datei „b“.
func linuxVerifyScript(zentrale, token, caPEM, arch string, info downloadInfo) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("Z='" + zentrale + "'; T='" + token + "'; P=linux/" + arch + "; V='" + info.Version + "'\n")
	b.WriteString(`d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"
# Agent-CA der Zentrale (deren Fingerabdruck steht auch im Token): Das Token geht nur an diese Zentrale.
` + printfLines(caPEM, "ca.pem") + `curl -fsS --proto =https --cacert ca.pem -H "Authorization: Bearer $T" -o s "$Z/agent/v1/download/$P/signatur"
curl -fsS --proto =https --cacert ca.pem -H "Authorization: Bearer $T" -o b "$Z/agent/v1/download/$P"
f() { sed -n "s/^$1 //p" s; }
[ "$(sed -n 1p s)" = '` + update.DownloadHeader + `' ] && [ "$(f os)/$(f arch)" = "$P" ] && [ "$(f version)" = "$V" ] || { echo 'Signaturdatei passt nicht' >&2; exit 1; }
case "$(f schluessel)" in
`)
	for _, k := range info.Keys {
		b.WriteString("  " + k.ID + ") " + strings.TrimSuffix(printfLines(k.PEM, "k.pem"), "\n") + " ;;\n")
	}
	b.WriteString(`  *) echo 'Signatur mit unbekanntem Schlüssel' >&2; exit 1 ;;
esac
[ "$(wc -c < b | tr -d ' ')" = "$(f groesse)" ] && [ "$(sha256sum b | cut -d' ' -f1)" = "$(f sha256)" ] || { echo 'Datei passt nicht zur Signatur' >&2; exit 1; }
if [ -n "$(f widerrufen)" ]; then
  printf 'openwacht-agent-update v2\n%s\n%s\n%s\n%s\n%s\nwiderrufen %s\n' "$(f version)" "$(f os)" "$(f arch)" "$(f sha256)" "$(f groesse)" "$(f widerrufen)" > m
else
  printf 'openwacht-agent-update v1\n%s\n%s\n%s\n%s\n%s\n' "$(f version)" "$(f os)" "$(f arch)" "$(f sha256)" "$(f groesse)" > m
fi
f signatur | base64 -d > g
openssl pkeyutl -verify -pubin -inkey k.pem -rawin -in m -sigfile g >/dev/null || { echo 'Signatur ungültig' >&2; exit 1; }
`)
	return b.String()
}

// printfLines: PEM-Block als printf-Befehl, der die Datei name schreibt
// (PEM enthält nur Base64, Bindestriche und Leerzeichen; sicher in '…').
func printfLines(pemText, name string) string {
	var b strings.Builder
	b.WriteString("printf '%s\\n'")
	for _, l := range strings.Split(strings.TrimSpace(pemText), "\n") {
		b.WriteString(" '" + strings.TrimSpace(l) + "'")
	}
	b.WriteString(" > " + name + "\n")
	return b.String()
}

// linuxDownloadCommand: Block für eine root-Shell (in Klammern, damit ein
// Fehler nur den Block beendet und nicht die Shell).
func linuxDownloadCommand(zentrale, token, caPEM, arch string, info downloadInfo) string {
	return "(\n" + linuxVerifyScript(zentrale, token, caPEM, arch, info) +
		`install -o root -g root -m 0755 b /usr/local/bin/openwacht-agent
/usr/local/bin/openwacht-agent registrieren -zentrale "$Z" -token "$T"
systemctl enable --now openwacht-agent
)
`
}

// windowsDownloadCommand: Block für eine PowerShell als Administrator.
// curl.exe gehört zu Windows (ab 10 1803); der Agent-Port spricht nur TLS 1.3,
// das Windows erst ab 11 bzw. Server 2022 kann.
func windowsDownloadCommand(zentrale, token, caPEM, arch string, info downloadInfo) string {
	quoted := make([]string, len(info.Thumbprints))
	for i, t := range info.Thumbprints {
		quoted[i] = "'" + t + "'"
	}
	return `$ErrorActionPreference = 'Stop'
$Z = '` + zentrale + `'; $T = '` + token + `'; $Erlaubt = @(` + strings.Join(quoted, ", ") + `)
$Ziel = Join-Path $env:ProgramFiles 'OpenWacht'; $Datei = Join-Path $Ziel 'openwacht-agent.exe'
$Tmp = Join-Path $env:TEMP ('openwacht-agent-' + [guid]::NewGuid() + '.exe'); $Ca = "$Tmp.ca.pem"
# Agent-CA der Zentrale: Das Token geht nur an diese Zentrale.
Set-Content -Encoding ascii -Path $Ca -Value @'
` + strings.TrimSpace(caPEM) + `
'@
curl.exe -fsS --proto =https --cacert $Ca -H "Authorization: Bearer $T" -o $Tmp "$Z/agent/v1/download/windows/` + arch + `"
Remove-Item $Ca
if ($LASTEXITCODE -ne 0) { throw 'Download fehlgeschlagen.' }
$Sig = Get-AuthenticodeSignature -FilePath $Tmp
if ($Sig.Status -ne 'Valid' -or $Erlaubt -notcontains $Sig.SignerCertificate.Thumbprint) { Remove-Item $Tmp; throw 'Authenticode-Signatur fehlt oder stammt nicht von OpenWacht.' }
New-Item -ItemType Directory -Force $Ziel | Out-Null
Copy-Item -Force $Tmp $Datei; Remove-Item $Tmp
& $Datei registrieren -zentrale $Z -token $T
if ($LASTEXITCODE -eq 0) { Start-Service openwacht-agent }
`
}

// withCommands ergänzt die Befehle (Token und Adresse kennt nur der Aufrufer).
func withCommands(offers map[string]downloadInfo, zentrale, token, caPEM string) map[string]any {
	out := map[string]any{}
	if zentrale == "" {
		return out
	}
	for p, info := range offers {
		goos, arch, _ := strings.Cut(p, "/")
		cmd := linuxDownloadCommand(zentrale, token, caPEM, arch, info)
		if goos == "windows" {
			cmd = windowsDownloadCommand(zentrale, token, caPEM, arch, info)
		}
		out[p] = map[string]any{"version": info.Version, "sha256": info.SHA256, "schluessel": info.Keys,
			"fingerabdruecke": info.Thumbprints, "befehl": cmd}
	}
	return out
}
