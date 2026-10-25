#!/usr/bin/env sh
# Integration checks against the compose PostgreSQL (make up first):
# SCRAM login and a pipelined round trip, a wrong password failing fast,
# the account endpoints, and recovery after the database restarts.
set -eu
cd "$(dirname "$0")/.."

HOST="${API_DB_HOST:-10.231.0.10}"
PASS="${API_DB_PASSWORD:-change-me-too}"
status=0
check() {
	if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected $2, got $3"; status=1; fi
}
code() { curl -q -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/readyz"; }
wait_ready() {
	for _ in $(seq 100); do [ "$(code "$1")" = 200 ] && return 0; sleep 0.1; done
	return 1
}

# A known signing key, so tests/auth_api.py can check tokens independently.
KEY="$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
API_TOKEN_KEY="$KEY" API_PORT=18090 API_WORKERS=2 API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>/dev/null &
good=$!
API_PORT=18091 API_WORKERS=1 API_DB_HOST="$HOST" API_DB_PASSWORD=wrong ./build/fasm2crud 2>/dev/null &
bad=$!
trap 'kill $good $bad 2>/dev/null || true' EXIT

wait_ready 18090 || true
check "readyz through SCRAM and the query pipeline" 200 "$(code 18090)"
check "wrong password answers 503" 503 "$(code 18091)"
python3 -I tests/auth_api.py 18090 "$KEY" || status=1

docker compose restart postgres >/dev/null 2>&1
if wait_ready 18090; then r=200; else r="$(code 18090)"; fi
check "recovers after a database restart" 200 "$r"
exit $status
