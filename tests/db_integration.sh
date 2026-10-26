#!/usr/bin/env sh
# Integration checks against the compose PostgreSQL (make up first):
# SCRAM login and a pipelined round trip, a wrong password failing fast,
# the account and notes endpoints, memory that comes back, rate limits,
# metrics, and recovery after the database restarts.
#
# Everything runs in a throwaway database (scripts/test-db.sh), created
# with the migrations and dropped at the end: the development database is
# never touched.
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] && . ./.env

HOST="${API_DB_HOST:-10.231.0.10}"
PASS="${API_DB_PASSWORD:-change-me-too}"
API_DB_NAME="fasm2crud_test_$$"
export API_DB_NAME
./scripts/test-db.sh create "$API_DB_NAME"
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
API_TOKEN_KEY="$KEY" API_AUTH_RATE=100000 API_AUTH_BURST=100000 API_PORT=18090 API_WORKERS=2 API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>/dev/null &
good=$!
API_PORT=18091 API_WORKERS=1 API_DB_HOST="$HOST" API_DB_PASSWORD=wrong ./build/fasm2crud 2>/dev/null &
bad=$!
trap 'kill $good $bad ${mem:-} ${rl:-} ${met:-} 2>/dev/null || true; ./scripts/test-db.sh drop "$API_DB_NAME"' EXIT

wait_ready 18090 || true
check "readyz through SCRAM and the query pipeline" 200 "$(code 18090)"
check "wrong password answers 503" 503 "$(code 18091)"
psql_test() { docker compose exec -T postgres psql -X -q -t -A -U "${POSTGRES_USER:-fasm2crud}" -d "$API_DB_NAME" -c "$1"; }
# Expired refresh tokens are purged (worker 0, every 10 s); live ones stay.
psql_test "WITH u AS (INSERT INTO users (email, password_hash) VALUES ('purge@example.com', 'x') RETURNING id)
	INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at)
	SELECT sha256(g::text::bytea), u.id, uuidv7(), now() + CASE WHEN g <= 300 THEN interval '-1 day' ELSE interval '1 day' END
	FROM u, generate_series(1, 310) g" >/dev/null
sleep 11
check "expired refresh tokens are purged, live ones kept" "10" "$(psql_test "SELECT count(*) FROM refresh_tokens")"
python3 -I tests/auth_api.py 18090 "$KEY" || status=1
python3 -I tests/notes_api.py 18090 || status=1

# Memory follows the load and goes back; the large buffer pool is bounded.
API_PORT=18092 API_WORKERS=1 API_TRIM_IDLE=2 API_LARGE_BUFFERS=4 API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>/dev/null &
mem=$!
wait_ready 18092 || true
python3 -I tests/memory_api.py 18092 || status=1
kill $mem 2>/dev/null || true

# Per-address limits on the account endpoints.
API_PORT=18093 API_WORKERS=1 API_AUTH_RATE=6 API_AUTH_BURST=3 API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>/dev/null &
rl=$!
wait_ready 18093 || true
python3 -I tests/ratelimit_api.py 18093 || status=1
kill $rl 2>/dev/null || true

# /metrics adds up every worker and survives a worker restart.
API_PORT=18094 API_WORKERS=4 ./build/fasm2crud 2>/dev/null &
met=$!
sleep 0.5
python3 -I tests/metrics_api.py 18094 || status=1
kill $met 2>/dev/null || true

# A short network fuzzing round (make fuzz runs longer ones).
NET_FUZZ_CONNS=3000 ./tests/fuzz/net_fuzz.sh || status=1

docker compose restart postgres >/dev/null 2>&1
if wait_ready 18090; then r=200; else r="$(code 18090)"; fi
check "recovers after a database restart" 200 "$r"
exit $status
