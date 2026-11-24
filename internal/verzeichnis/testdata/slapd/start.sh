#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Gegenstelle für die LDAP-Tests (CI und Sandbox): OpenLDAP mit AD-ähnlichem
# Schema, memberOf-Overlay, LDAPS auf 127.0.0.1:16636. Nur Testdaten und
# Testpasswörter. Aufruf als root: start.sh <arbeitsverzeichnis>
# Danach: OPENWACHT_TEST_LDAPS=ldaps://127.0.0.1:16636 OPENWACHT_TEST_LDAP_CA=<dir>/tls/ca.pem
set -eu
src=$(cd "$(dirname "$0")" && pwd)
dir=$1
mkdir -p "$dir/tls" "$dir/db"
cd "$dir/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=Test-CA LDAP" \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=dc1.firma.test" -keyout srv.key -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:dc1.firma.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out srv.pem 2>/dev/null
cp "$src/ad.schema" "$dir/ad.schema"
cat > "$dir/slapd.conf" <<CONF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include $dir/ad.schema
modulepath /usr/lib/ldap
moduleload back_mdb
moduleload memberof
pidfile $dir/slapd.pid
TLSCACertificateFile $dir/tls/ca.pem
TLSCertificateFile $dir/tls/srv.pem
TLSCertificateKeyFile $dir/tls/srv.key
database mdb
suffix "dc=firma,dc=test"
rootdn "cn=admin,dc=firma,dc=test"
rootpw admin-pass-123
directory $dir/db
overlay memberof
access to attrs=userPassword by self auth by anonymous auth by * none
access to * by dn.exact="cn=svc-openwacht,ou=dienst,dc=firma,dc=test" read by self read by * none
CONF
chmod -R a+rX "$dir"
/usr/sbin/slapd -f "$dir/slapd.conf" -h "ldap://127.0.0.1:16389/ ldaps://127.0.0.1:16636/"
for i in $(seq 1 20); do
  ldapwhoami -x -H ldap://127.0.0.1:16389 -D cn=admin,dc=firma,dc=test -w admin-pass-123 >/dev/null 2>&1 && break
  sleep 0.5
done
# online einspielen, damit das memberOf-Overlay die Rückverweise setzt
ldapadd -x -H ldap://127.0.0.1:16389 -D cn=admin,dc=firma,dc=test -w admin-pass-123 -f "$src/data.ldif" >/dev/null
ldapadd -x -H ldap://127.0.0.1:16389 -D cn=admin,dc=firma,dc=test -w admin-pass-123 -f "$src/groups.ldif" >/dev/null
echo "slapd bereit: ldaps://127.0.0.1:16636, CA $dir/tls/ca.pem"
