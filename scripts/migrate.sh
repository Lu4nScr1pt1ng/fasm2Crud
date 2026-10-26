#!/bin/sh
# Apply the schema migrations in docker/postgres/migrations, in order, each
# in its own transaction together with its row in schema_migrations. A
# session advisory lock serializes concurrent runs, and every migration is
# checked again under it, so two migrators never apply one twice.
#
# Runs where psql is (the postgres image: the compose "migrate" service),
# as the database owner: PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE.
# MIGRATIONS is the directory (default: next to this script's repository).
set -eu
dir="${MIGRATIONS:-$(dirname "$0")/../docker/postgres/migrations}"
script="$(mktemp)"
trap 'rm -f "$script"' EXIT
{
	echo '\set ON_ERROR_STOP on'
	echo 'SET client_min_messages = warning;'
	echo 'SELECT pg_advisory_lock(7364591) AS locked \gset'
	echo 'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());'
	# A database made by the old init script already has the first schema.
	echo "INSERT INTO schema_migrations (version) SELECT '0001_schema' WHERE to_regclass('public.users') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM schema_migrations);"
	for f in "$dir"/*.sql; do
		v="$(basename "$f" .sql)"
		echo "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '$v') AS done \\gset"
		echo '\if :done'
		echo '\else'
		echo "\\echo applying $v"
		echo 'BEGIN;'
		echo "\\i $f"
		echo "INSERT INTO schema_migrations (version) VALUES ('$v');"
		echo 'COMMIT;'
		echo '\endif'
	done
	echo 'SELECT pg_advisory_unlock(7364591) AS unlocked \gset'
} > "$script"
psql -X -q -t -f "$script"
echo "migrations up to date: $(psql -X -q -t -A -c 'SELECT max(version) FROM schema_migrations')"
