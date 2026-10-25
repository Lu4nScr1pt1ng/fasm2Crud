#!/usr/bin/env sh
# Network fuzzing against a fresh server and the compose PostgreSQL (make up first).
set -eu
cd "$(dirname "$0")/../.."
HOST="${API_DB_HOST:-10.231.0.10}"
PASS="${API_DB_PASSWORD:-change-me-too}"
API_PORT=18097 API_WORKERS=2 API_AUTH_RATE=100000 API_AUTH_BURST=100000 API_LARGE_BUFFERS=16 \
	API_DB_HOST="$HOST" API_DB_PASSWORD="$PASS" ./build/fasm2crud 2>build/net_fuzz.log &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
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
