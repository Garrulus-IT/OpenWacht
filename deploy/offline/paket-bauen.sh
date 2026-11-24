#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# OpenWacht: Offline-Installationspaket bauen.
#
# Läuft auf einem Rechner MIT Internet (z. B. ein Arbeitsplatz mit Debian 13 oder
# einem beliebigen Linux mit apt) und packt alles, was eine Zentrale auf
# Debian 13 ohne Internet braucht, in eine einzige Datei:
#
#   - das Paket openwacht-zentrale_<version>_<arch>.deb (aus dist/, geprüft
#     gegen dist/SHA256SUMS),
#   - PostgreSQL und alle Abhängigkeiten als .deb aus dem Debian-Spiegel
#     (vollständige Hülle, auch Grundpakete, damit es auf jedem Debian 13
#     passt; installiert wird später nur, was fehlt),
#   - einen Paketindex (Packages), das Installationsskript installieren.sh,
#     die Stückliste (SBOM) und SHA256SUMS.
#
# apt prüft beim Herunterladen die Signaturen des Debian-Spiegels mit dem
# Schlüsselbund des Systems (debian-archive-keyring). Das Skript benutzt ein
# eigenes, leeres apt-Verzeichnis: Es ändert nichts am Bau-Rechner und braucht
# kein root.
#
# Aufruf (aus dem Repository-Wurzelordner):
#
#   go run ./tools/build -ziele linux/amd64
#   sh deploy/offline/paket-bauen.sh -dist dist
#
# Optionen:
#   -dist <ordner>     Ordner mit dem .deb und SHA256SUMS (Standard: dist)
#   -arch <arch>       amd64 (Standard) oder arm64
#   -aus <ordner>      Ausgabeordner (Standard: wie -dist)
#   -quellen <datei>   eigene sources.list statt des Debian-13-Spiegels
#                      (z. B. ein Spiegel im Firmennetz; zum Testen auch Ubuntu)
#   -ziel <name>       Kennung des Zielsystems, Standard "debian-13"; muss zu
#                      -quellen passen (ID-VERSION_ID aus /etc/os-release)
#
# Ergebnis: <aus>/openwacht-offline_<version>_<ziel>_<arch>.tar und
# dieselbe Datei mit .sha256. Beides zum Kunden bringen, dort auspacken und
# "sudo sh installieren.sh" ausführen (siehe LIESMICH.txt im Paket).
#
# Signieren (Etappe 32): SHA256SUMS aus dem Paket auf den Offline-Rechner
# bringen, dort signieren und die Signatur ins Paket legen:
#
#   tar -xOf <paket>.tar <name>/SHA256SUMS >SHA256SUMS
#   go run ./tools/signieren -schluessel /pfad/update.key -summen SHA256SUMS   (offline)
#   sh deploy/offline/paket-bauen.sh -signatur SHA256SUMS.sig -paket <paket>.tar
#
# Mit -signatur wird nur das fertige Paket um SHA256SUMS.sig ergänzt und neu
# gepackt; sonst ändert sich nichts. Liegt im Ordner -dist ein passendes
# openwacht-zentrale_linux_<arch>, prüft es die Signatur vorher.
set -eu

dist=dist
arch=amd64
aus=
quellen=
ziel=debian-13
signatur=
fertig=

fehler() {
	echo "paket-bauen: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	-dist) dist=${2:?}; shift 2 ;;
	-arch) arch=${2:?}; shift 2 ;;
	-aus) aus=${2:?}; shift 2 ;;
	-quellen) quellen=${2:?}; shift 2 ;;
	-ziel) ziel=${2:?}; shift 2 ;;
	-signatur) signatur=${2:?}; shift 2 ;;
	-paket) fertig=${2:?}; shift 2 ;;
	-h | -hilfe | --help) sed -n '2,50p' "$0"; exit 0 ;;
	*) fehler "unbekannte Option $1" ;;
	esac
done
[ -n "$aus" ] || aus=$dist

# Nur signieren: fertiges Paket um SHA256SUMS.sig ergänzen.
if [ -n "$signatur" ] || [ -n "$fertig" ]; then
	if [ -z "$signatur" ] || [ -z "$fertig" ]; then fehler "-signatur und -paket gehören zusammen"; fi
	[ -f "$fertig" ] || fehler "$fertig fehlt"
	[ "$(sed -n 1p "$signatur")" = "openwacht-sha256sums v1" ] || fehler "$signatur ist keine Signatur von SHA256SUMS"
	name=$(basename "$fertig" .tar)
	arbeit=$(mktemp -d)
	trap 'rm -rf "$arbeit"' EXIT INT TERM
	tar -C "$arbeit" -xf "$fertig"
	[ -f "$arbeit/$name/SHA256SUMS" ] || fehler "$fertig enthält kein $name/SHA256SUMS"
	cp "$signatur" "$arbeit/$name/SHA256SUMS.sig"
	read -r _ a <"$arbeit/$name/ZIEL"
	pruefer=$dist/openwacht-zentrale_linux_$a
	if [ -x "$pruefer" ] && "$pruefer" -version >/dev/null 2>&1; then
		"$pruefer" pruefe-signatur -summen "$arbeit/$name/SHA256SUMS" -signatur "$arbeit/$name/SHA256SUMS.sig" ||
			fehler "Signatur passt nicht zu SHA256SUMS in $fertig"
	else
		echo "Hinweis: $pruefer nicht ausführbar, Signatur nicht vorab geprüft (installieren.sh prüft sie)."
	fi
	tar -C "$arbeit" --sort=name --owner=0 --group=0 --numeric-owner \
		--mode='u+rwX,go+rX,go-w' -cf "$fertig.neu" "$name"
	mv "$fertig.neu" "$fertig"
	(cd "$(dirname "$fertig")" && sha256sum "$name.tar" >"$name.tar.sha256")
	echo "== Signiert: $fertig"
	cat "$fertig.sha256"
	exit 0
fi

case "$arch" in amd64 | arm64) ;; *) fehler "Architektur $arch wird nicht unterstützt (amd64, arm64)" ;; esac
case "$ziel" in *[!a-z0-9.-]* | "") fehler "ungültiges Ziel $ziel" ;; esac

for p in apt-get apt-ftparchive sha256sum tar; do
	command -v "$p" >/dev/null 2>&1 || fehler "$p fehlt (Debian: apt install apt-utils coreutils tar)"
done

# 1. Paket der Zentrale finden und gegen SHA256SUMS aus dem Build prüfen.
[ -f "$dist/SHA256SUMS" ] || fehler "$dist/SHA256SUMS fehlt (erst go run ./tools/build)"
deb=
for f in "$dist"/openwacht-zentrale_*_"$arch".deb; do
	[ -f "$f" ] || continue
	[ -z "$deb" ] || fehler "mehr als ein Paket für $arch in $dist"
	deb=$f
done
[ -n "$deb" ] || fehler "kein openwacht-zentrale_*_$arch.deb in $dist"
debname=$(basename "$deb")
version=${debname#openwacht-zentrale_}
version=${version%_"$arch".deb}
case "$version" in *[!0-9A-Za-z.+~-]* | "") fehler "ungültige Version in $debname" ;; esac
(cd "$dist" && awk -v n="$debname" '$2 == n' SHA256SUMS | sha256sum -c --strict --quiet -) ||
	fehler "Prüfsumme von $debname passt nicht zu $dist/SHA256SUMS"
sbom=$dist/openwacht-$version.cdx.json
if [ -f "$sbom" ]; then
	(cd "$dist" && awk -v n="openwacht-$version.cdx.json" '$2 == n' SHA256SUMS | sha256sum -c --strict --quiet -) ||
		fehler "Prüfsumme der Stückliste passt nicht"
else
	sbom=
fi

name=openwacht-offline_${version}_${ziel}_${arch}
arbeit=$(mktemp -d)
trap 'rm -rf "$arbeit"' EXIT INT TERM
paket=$arbeit/$name
mkdir -p "$paket/pakete"

# 2. Eigenes apt-Verzeichnis mit leerem Paketstand: apt löst dann die
#    vollständige Abhängigkeitshülle auf, unabhängig vom Bau-Rechner.
apt=$arbeit/apt
mkdir -p "$apt/lists/partial" "$apt/cache/archives/partial" "$apt/leer" "$apt/einst"
: >"$apt/status"
if [ -n "$quellen" ]; then
	[ -f "$quellen" ] || fehler "$quellen fehlt"
	cp "$quellen" "$apt/sources.list"
else
	schluessel=/usr/share/keyrings/debian-archive-keyring.gpg
	[ -f "$schluessel" ] || fehler "$schluessel fehlt (apt install debian-archive-keyring)"
	cat >"$apt/sources.list" <<EOF
deb [signed-by=$schluessel] http://deb.debian.org/debian trixie main
deb [signed-by=$schluessel] http://deb.debian.org/debian trixie-updates main
deb [signed-by=$schluessel] http://security.debian.org/debian-security trixie-security main
EOF
fi
benutzer=$(id -un)
set -- -q \
	-o "Dir::State=$apt" -o "Dir::State::status=$apt/status" \
	-o "Dir::State::Lists=$apt/lists" -o "Dir::Cache=$apt/cache" \
	-o "Dir::Etc::SourceList=$apt/sources.list" -o "Dir::Etc::SourceParts=$apt/leer" \
	-o "Dir::Etc::Preferences=$apt/leer/keine" -o "Dir::Etc::PreferencesParts=$apt/leer" \
	-o "APT::Architecture=$arch" -o "APT::Architectures::=$arch" \
	-o "Debug::NoLocking=1" -o "APT::Sandbox::User=$benutzer" \
	-o "Acquire::Languages=none" -o "APT::Install-Recommends=0" \
	-o "Acquire::http::Timeout=60" -o "Acquire::Retries=3"

echo "== Paketlisten laden"
apt-get "$@" update
echo "== PostgreSQL und Abhängigkeiten herunterladen"
# Die Abhängigkeiten von openwacht-zentrale (Depends: postgresql, passwd).
apt-get "$@" -y --download-only install postgresql passwd
n=0
for f in "$apt/cache/archives"/*.deb; do
	[ -f "$f" ] || continue
	cp "$f" "$paket/pakete/"
	n=$((n + 1))
done
[ "$n" -gt 0 ] || fehler "keine Pakete heruntergeladen"
cp "$deb" "$paket/pakete/"

# 3. Paketindex, Skript, Beschreibung, Prüfsummen.
(cd "$paket/pakete" && apt-ftparchive -q packages . >Packages)
grep -q "^Package: postgresql$" "$paket/pakete/Packages" || fehler "postgresql fehlt im Paketindex"
grep -q "^Package: openwacht-zentrale$" "$paket/pakete/Packages" || fehler "openwacht-zentrale fehlt im Paketindex"
cp "$(dirname "$0")/installieren.sh" "$paket/installieren.sh"
# Öffentliche Signaturschlüssel für die erste Installation (installieren.sh
# nimmt nur den, dessen Kennung der Kunde mit -abdruck angibt).
cp "$(dirname "$0")/../../internal/update/schluessel.pub" "$paket/update-schluessel.pub"
[ -z "$sbom" ] || cp "$sbom" "$paket/"
echo "$ziel $arch" >"$paket/ZIEL"
{
	echo "OpenWacht $version – Offline-Installationspaket für $ziel ($arch)"
	echo "gebaut: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo
	echo "Installieren oder aktualisieren (als root, ohne Internet):"
	echo "  sh installieren.sh                      (Update: prüft mit der installierten Zentrale)"
	echo "  sh installieren.sh -abdruck <kennung>   (erste Installation: Kennung des"
	echo "                                           Signaturschlüssels aus dem Handbuch)"
	echo "Nur prüfen, nichts ändern:"
	echo "  sh installieren.sh -pruefen"
	echo
	echo "Enthaltene Pakete:"
	awk '/^Package:/{p=$2} /^Version:/{print "  " p " " $2}' "$paket/pakete/Packages" | sort
} >"$paket/LIESMICH.txt"
(cd "$paket" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum >"$arbeit/SHA256SUMS")
mv "$arbeit/SHA256SUMS" "$paket/SHA256SUMS"

# 4. Ein Archiv, feste Reihenfolge und Eigentümer.
mkdir -p "$aus"
tar -C "$arbeit" --sort=name --owner=0 --group=0 --numeric-owner \
	--mode='u+rwX,go+rX,go-w' -cf "$aus/$name.tar" "$name"
(cd "$aus" && sha256sum "$name.tar" >"$name.tar.sha256")
echo "== Fertig: $aus/$name.tar ($n Pakete aus dem Spiegel + openwacht-zentrale)"
cat "$aus/$name.tar.sha256"
echo "Noch unsigniert. Signieren: tar -xOf $aus/$name.tar $name/SHA256SUMS >SHA256SUMS, offline"
echo "  go run ./tools/signieren -schluessel <datei> -summen SHA256SUMS, dann"
echo "  sh $0 -signatur SHA256SUMS.sig -paket $aus/$name.tar"
