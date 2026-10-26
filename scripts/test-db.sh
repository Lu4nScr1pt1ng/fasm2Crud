#!/bin/sh
# A throwaway database for the integration tests, on the compose PostgreSQL:
#   test-db.sh create NAME   create it and apply the migrations
#   test-db.sh drop NAME     drop it, disconnecting whoever is still on it
# Tests never touch the development database (POSTGRES_DB).
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] && . ./.env
user="${POSTGRES_USER:-fasm2crud}"
name="$2"
case "$name" in
	fasm2crud_test_*) ;;
	*) echo "test-db.sh: refusing to touch '$name' (not fasm2crud_test_*)" >&2; exit 2 ;;
esac
sql() { docker compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U "$user" -d postgres -c "$1"; }
case "$1" in
	create)
		sql "CREATE DATABASE $name"
		docker compose run --rm -q -e PGDATABASE="$name" migrate >/dev/null
		;;
	drop)
		sql "DROP DATABASE IF EXISTS $name WITH (FORCE)"
		;;
	*)
		echo "usage: test-db.sh create|drop fasm2crud_test_NAME" >&2
		exit 2
		;;
esac
