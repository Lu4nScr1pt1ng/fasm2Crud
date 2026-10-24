#!/usr/bin/env sh
# Start the freshly built binary on a spare port, run the conformance suite,
# then check that SIGTERM drains and exits cleanly.
set -eu
cd "$(dirname "$0")/.."

PORT="${TEST_PORT:-18080}"
LOG="$(mktemp)"
API_PORT="$PORT" API_WORKERS=2 ./build/fasm2crud 2>"$LOG" &
PID=$!
trap 'kill -9 $PID 2>/dev/null || true; rm -f "$LOG"' EXIT

for _ in $(seq 50); do
	API_PORT="$PORT" ./build/fasm2crud healthcheck && break
	sleep 0.1
done

status=0
python3 -I tests/http_conformance.py "$PORT" || status=1

kill -TERM "$PID"
if wait "$PID"; then
	echo "ok   graceful shutdown"
else
	echo "FAIL graceful shutdown (exit $?)"
	status=1
fi
cat "$LOG"
exit $status
