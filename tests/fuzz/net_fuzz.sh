#!/usr/bin/env sh
# Network fuzzing against a fresh server and the compose PostgreSQL (make up first).
set -eu
cd "$(dirname "$0")/../.."
[ -f .env ] && . ./.env
HOST="${API_DB_HOST:-10.231.0.10}"
PASS="${API_DB_PASSWORD:-change-me-too}"
# Run inside the caller's test database, or a throwaway one of our own.
own_db=""
if [ -z "${API_DB_NAME:-}" ]; then
	API_DB_NAME="fasm2crud_test_fuzz_$$"
	own_db="$API_DB_NAME"
	./scripts/test-db.sh create "$API_DB_NAME"
fi
export API_DB_NAME
API_PORT=18097 API_WORKERS=2 API_AUTH_RATE=100000 API_AUTH_BURST=100000 API_RATE=0 API_LARGE_BUFFERS=16 \
	API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>build/net_fuzz.log &
pid=$!
trap 'kill $pid 2>/dev/null || true; [ -n "$own_db" ] && ./scripts/test-db.sh drop "$own_db"; true' EXIT
for _ in $(seq 100); do
	curl -q -s -o /dev/null http://127.0.0.1:18097/healthz && break
	sleep 0.1
done
sleep 1
status=0
python3 -I tests/fuzz/net_fuzz.py 18097 "${NET_FUZZ_CONNS:-3000}" || status=1
if grep -q 'seccomp refused\|killed by signal\|exited with status' build/net_fuzz.log; then
	echo "FAIL server log:"
	grep 'seccomp refused\|killed by signal\|exited with status' build/net_fuzz.log | head
	status=1
fi
exit $status
