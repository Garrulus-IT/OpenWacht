#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Rollen und Datenbank für OpenWacht, beim ersten Start des Containers
# postgres (wie deploy/linux/postgresql/rollen.sql, mit Passwörtern statt
# Anmeldung über den Socket). Die Passwörter kommen aus compose.yaml (.env).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
	-v eigentuemer="$OPENWACHT_PG_EIGENTUEMER" -v zentrale="$OPENWACHT_PG_ZENTRALE" <<'SQL'
CREATE ROLE openwacht_app NOLOGIN;
CREATE ROLE openwacht_owner LOGIN PASSWORD :'eigentuemer';
CREATE ROLE openwacht_zentrale LOGIN PASSWORD :'zentrale' IN ROLE openwacht_app;
CREATE ROLE openwacht_traps NOLOGIN;
CREATE DATABASE openwacht OWNER openwacht_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE openwacht FROM PUBLIC;
GRANT CONNECT ON DATABASE openwacht TO openwacht_owner, openwacht_zentrale;
SQL
