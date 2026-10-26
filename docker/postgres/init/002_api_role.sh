#!/bin/sh
# The API connects as a role that can only read and write rows: no DDL, no
# superuser, no access to other databases. Tables and their grants come from
# the migrations (scripts/migrate.sh), which run as the owner.
set -eu
psql -v ON_ERROR_STOP=1 -v api_password="$API_DB_PASSWORD" \
	--username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE api LOGIN PASSWORD :'api_password';
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO api;
SQL
