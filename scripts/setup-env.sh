#!/bin/sh
# Make .env on the first `make up`, so a fresh checkout runs with secrets of
# its own instead of the examples:
#   API_TOKEN_KEY  always generated (tokens then survive restarts)
#   passwords      generated only when the database volume does not exist
#                  yet: an existing volume keeps the passwords it was made
#                  with, and the API could no longer log in otherwise
# An existing .env is never touched.
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] && exit 0
rand() { head -c "$1" /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }
cp .env.example .env
key="$(rand 32)"
sed -i "s|^API_TOKEN_KEY=.*|API_TOKEN_KEY=$key|" .env
if ! docker volume inspect fasm2crud_pgdata >/dev/null 2>&1; then
	sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand 24)|; s|^API_DB_PASSWORD=.*|API_DB_PASSWORD=$(rand 24)|" .env
	echo "setup-env: wrote .env with new passwords and a token key"
else
	echo "setup-env: wrote .env with a token key (the existing database keeps its passwords)"
fi
chmod 600 .env
