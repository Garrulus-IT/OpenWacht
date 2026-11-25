#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# OpenWacht: Zentrale ohne Internet installieren oder aktualisieren.
#
# Liegt im Offline-Installationspaket (openwacht-offline_<version>_<ziel>_<arch>.tar)
# neben den Paketen. Aufruf als root im ausgepackten Ordner:
#
#   sh installieren.sh            installieren bzw. aktualisieren
#   sh installieren.sh -pruefen   nur Signatur, Prüfsummen und Zielsystem prüfen
#   sh installieren.sh -abdruck <kennung>
#                                 erste Installation: Kennung (16 Hexziffern) des
#                                 Signaturschlüssels aus einer zweiten Quelle
#                                 (Handbuch, Brief, Telefon), nicht aus dem Paket
#   sh installieren.sh -ohne-zusatz
#                                 Zusatzpakete aus dem Paket (Datei ZUSATZ, z. B.
#                                 realmd und sssd für den Domänenbeitritt) nicht
#                                 mitinstallieren
#   sh installieren.sh -unsigniert
#                                 Paket ohne Signatur annehmen (nur solange es
#                                 noch keinen Signaturschlüssel gibt; Restrisiko:
#                                 wer das Paket unterwegs ändert, ändert auch
#                                 SHA256SUMS)
#
# Ablauf:
#   1. Paket in ein Verzeichnis kopieren, das nur root lesen kann. Dort zuerst
#      die Signatur von SHA256SUMS prüfen (SHA256SUMS.sig), dann alle Dateien
#      gegen SHA256SUMS. Geprüft wird mit dem schon installierten
#      openwacht-zentrale (sein eingebetteter Schlüssel stammt aus einer früher
#      geprüften Installation) oder bei der ersten Installation mit openssl
#      gegen den Schlüssel, dessen Kennung -abdruck nennt.
#   2. Prüfen, ob System und Architektur zum Paket passen.
#   3. apt mit einer eigenen Paketliste aufrufen, die NUR dieses Paket kennt.
#      Die normalen Paketquellen des Systems bleiben unberührt und werden nicht
#      gefragt: Es gibt keinen Zugriff ins Netz. apt installiert nur, was fehlt
#      oder älter ist, und stuft nichts zurück.
#   4. Das Paket openwacht-zentrale richtet sich selbst ein und gibt den Link
#      zum Einrichtungsassistenten aus (bei einem Update: Migrationen, Neustart).
#   5. Zusatzpakete aus ZUSATZ (falls vorhanden) aus derselben Quelle.
set -eu

fehler() {
	echo "installieren: $*" >&2
	exit 1
}

nur_pruefen=0
erlaube_anderes=0
abdruck=
unsigniert=0
ohne_zusatz=0
pruefer=
while [ $# -gt 0 ]; do
	case "$1" in
	-pruefen) nur_pruefen=1 ;;
	-abdruck) abdruck=${2:-}; shift ;;
	-unsigniert) unsigniert=1 ;;
	-ohne-zusatz) ohne_zusatz=1 ;;
	# Ein anderswo geprüftes openwacht-zentrale zum Prüfen der Signatur.
	-pruefer) pruefer=${2:-}; shift ;;
	# Nur für Tests: anderes System als im Paket vermerkt zulassen.
	-anderes-system-erlauben) erlaube_anderes=1 ;;
	-h | -hilfe | --help) sed -n '2,40p' "$0"; exit 0 ;;
	*) fehler "unbekannte Option $1" ;;
	esac
	shift
done

[ "$(id -u)" = 0 ] || fehler "bitte als root ausführen (sudo sh installieren.sh)"
for p in apt-get dpkg sha256sum base64; do
	command -v "$p" >/dev/null 2>&1 || fehler "$p fehlt"
done

quelle=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$quelle/SHA256SUMS" ] || [ ! -f "$quelle/ZIEL" ] || [ ! -d "$quelle/pakete" ]; then
	fehler "SHA256SUMS, ZIEL oder pakete/ fehlt; bitte im ausgepackten Ordner aufrufen"
fi

# 1. Kopie nur für root, dort prüfen.
umask 077
arbeit=$(mktemp -d /tmp/openwacht-offline.XXXXXX)
trap 'rm -rf "$arbeit"' EXIT INT TERM
cp -R "$quelle/." "$arbeit/paket"
cd "$arbeit/paket"

# 1a. Signatur von SHA256SUMS, vor allem anderen.
case "$abdruck" in "" | [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
*) fehler "-abdruck: erwartet 16 Hexziffern (Kennung des Schlüssels)" ;;
esac
pruefe_mit_openssl() {
	# Schlüssel aus dem Paket, aber nur der mit der Kennung aus -abdruck.
	[ -n "$abdruck" ] || fehler "erste Installation: Kennung des Signaturschlüssels mit -abdruck angeben (aus dem Handbuch bzw. vom Herausgeber, nicht aus dem Paket)"
	command -v openssl >/dev/null 2>&1 || fehler "openssl fehlt: apt install openssl, oder ein geprüftes openwacht-zentrale mit -pruefer angeben"
	[ -f update-schluessel.pub ] || fehler "update-schluessel.pub fehlt im Paket"
	treffer=
	sed -n 's/^ed25519:\([A-Za-z0-9+/=]*\).*$/\1/p' update-schluessel.pub >"$arbeit/schluessel.b64"
	while read -r b64; do
		id=$(printf %s "$b64" | base64 -d | sha256sum | cut -c1-16)
		if [ "$id" = "$abdruck" ]; then treffer=$b64; fi
	done <"$arbeit/schluessel.b64"
	[ -n "$treffer" ] || fehler "kein Schlüssel mit der Kennung $abdruck im Paket"
	sed -n 's/^schluessel //p' SHA256SUMS.sig | grep -qx "$abdruck" ||
		fehler "SHA256SUMS ist mit einem anderen Schlüssel signiert als $abdruck"
	# Öffentlicher Schlüssel als PEM: fester DER-Kopf für Ed25519 + 32 Byte.
	{
		echo "-----BEGIN PUBLIC KEY-----"
		{ printf '\060\052\060\005\006\003\053\145\160\003\041\000'; printf %s "$treffer" | base64 -d; } | base64 -w0
		echo
		echo "-----END PUBLIC KEY-----"
	} >"$arbeit/schluessel.pem"
	sed -n 's/^signatur //p' SHA256SUMS.sig | base64 -d >"$arbeit/sig.bin"
	{ printf 'openwacht-sha256sums v1\n'; cat SHA256SUMS; } >"$arbeit/nachricht"
	openssl pkeyutl -verify -pubin -inkey "$arbeit/schluessel.pem" -rawin -in "$arbeit/nachricht" \
		-sigfile "$arbeit/sig.bin" >/dev/null 2>&1 || fehler "Signatur von SHA256SUMS ungültig: Paket verändert"
	echo "Signatur in Ordnung (Schlüssel $abdruck, geprüft mit openssl)."
}
if [ -f SHA256SUMS.sig ]; then
	[ "$(sed -n 1p SHA256SUMS.sig)" = "openwacht-sha256sums v1" ] || fehler "SHA256SUMS.sig unlesbar"
	if [ -z "$pruefer" ] && [ -x /usr/bin/openwacht-zentrale ] && [ -z "$abdruck" ]; then
		pruefer=/usr/bin/openwacht-zentrale
	fi
	if [ -n "$pruefer" ]; then
		set +e
		"$pruefer" pruefe-signatur -summen SHA256SUMS -signatur SHA256SUMS.sig
		rc=$?
		set -e
		case "$rc" in
		0) ;;
		# Installierte Version kennt noch keinen Schlüssel: wie bei der ersten Installation.
		3) echo "Hinweis: $pruefer enthält keinen Signaturschlüssel."; pruefe_mit_openssl ;;
		*) fehler "Signatur von SHA256SUMS ungültig oder nicht prüfbar: Paket verändert?" ;;
		esac
	else
		pruefe_mit_openssl
	fi
elif [ "$unsigniert" = 1 ]; then
	echo "WARNUNG: Paket ohne Signatur. Geschützt nur gegen Beschädigung, nicht gegen absichtliche"
	echo "Änderung. Prüfsumme der .tar über einen zweiten Weg vergleichen (z. B. CI-Artefakt)."
else
	fehler "SHA256SUMS.sig fehlt: Paket ist nicht signiert (nur mit -unsigniert annehmen, siehe Handbuch Kapitel 14)"
fi

sha256sum -c --strict --quiet SHA256SUMS || fehler "Prüfsummen stimmen nicht: Paket beschädigt oder verändert"
# Keine Dateien, die nicht in SHA256SUMS stehen (sonst landeten sie ungeprüft bei apt).
find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sig | sed 's|^\./||' | LC_ALL=C sort >"$arbeit/dateien"
awk '{ sub(/^\*/, "", $2); print $2 }' SHA256SUMS | LC_ALL=C sort >"$arbeit/gelistet"
cmp -s "$arbeit/dateien" "$arbeit/gelistet" || fehler "das Paket enthält Dateien, die nicht in SHA256SUMS stehen"
echo "Prüfsummen in Ordnung."

# Zusatzpakete: Liste prüfen (nur Paketnamen, jeder im Paketindex).
zusatz=
if [ -f ZUSATZ ]; then
	while read -r z; do
		case "$z" in
		"" | [!a-z0-9]* | *[!a-z0-9+.-]*) fehler "ZUSATZ: ungültiger Paketname \"$z\"" ;;
		esac
		grep -q "^Package: $z$" pakete/Packages || fehler "ZUSATZ: $z fehlt im Paket"
		zusatz="${zusatz:+$zusatz }$z"
	done <ZUSATZ
	echo "Zusatzpakete im Paket: $zusatz"
fi

# 2. Zielsystem.
read -r ziel arch <ZIEL
system=unbekannt
if [ -r /etc/os-release ]; then
	# shellcheck disable=SC1091
	system=$(. /etc/os-release && echo "${ID:-}-${VERSION_ID:-}")
fi
hier=$(dpkg --print-architecture)
[ "$hier" = "$arch" ] || fehler "Paket ist für $arch, dieses System ist $hier"
if [ "$system" != "$ziel" ]; then
	[ "$erlaube_anderes" = 1 ] || fehler "Paket ist für $ziel, dieses System ist $system"
	echo "Hinweis: Paket für $ziel auf $system (nur für Tests)."
fi
echo "Zielsystem passt ($system, $arch)."
if [ "$nur_pruefen" = 1 ]; then
	echo "Nur geprüft, nichts geändert."
	exit 0
fi

# 3. apt nur mit diesem Paket als Quelle. trusted=yes, weil die Pakete oben
#    gegen SHA256SUMS geprüft wurden und apt die Prüfsummen aus Packages prüft.
mkdir -p "$arbeit/apt/lists/partial" "$arbeit/apt/leer"
echo "deb [trusted=yes] file:$arbeit/paket/pakete ./" >"$arbeit/apt/sources.list"
chmod -R go+rX "$arbeit"
set -- -q \
	-o "Dir::Etc::SourceList=$arbeit/apt/sources.list" -o "Dir::Etc::SourceParts=$arbeit/apt/leer" \
	-o "Dir::State::Lists=$arbeit/apt/lists" -o "Acquire::Languages=none" \
	-o "APT::Sandbox::User=root" -o "APT::Install-Recommends=0" -o "APT::Get::List-Cleanup=0"
apt-get "$@" update
DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-noninteractive} apt-get "$@" -y install openwacht-zentrale
if [ -n "$zusatz" ] && [ "$ohne_zusatz" = 0 ]; then
	echo
	echo "Zusatzpakete installieren: $zusatz"
	set -f
	# shellcheck disable=SC2086
	DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-noninteractive} apt-get "$@" -y install $zusatz
	set +f
elif [ -n "$zusatz" ]; then
	echo "Zusatzpakete nicht installiert (-ohne-zusatz): $zusatz"
fi

echo
echo "OpenWacht ist installiert: $(dpkg-query -W -f '${Version}' openwacht-zentrale)"
echo "Bei einer Neuinstallation steht der Link zum Einrichtungsassistenten oben"
echo "(\"Einrichtung im Browser\"). Neuer Link: sudo openwacht-zentrale installieren"
