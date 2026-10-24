#!/usr/bin/env sh
# Load test against the API container on its bridge IP, which skips the
# userland docker-proxy that sits behind published ports on loopback.
#
#   ./tests/bench.sh [path] [connections] [seconds]
#
# BENCH_CPUS pins the load generator away from the API and database CPUs
# (see API_CPUS / PG_CPUS in .env).
set -eu

PATH_="${1:-/healthz}"
CONNS="${2:-512}"
SECS="${3:-10}"
CPUS="${BENCH_CPUS:-12-15}"

IP="$(docker inspect fasm2crud-api-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
URL="http://$IP:8080$PATH_"
echo "wrk2 is preferable for latency (it corrects coordinated omission);"
echo "this runs wrk and oha when installed. Target: $URL"

if command -v wrk >/dev/null; then
	taskset -c "$CPUS" wrk -t4 -c"$CONNS" -d"${SECS}s" --latency "$URL"
fi
if command -v oha >/dev/null; then
	taskset -c "$CPUS" oha --no-tui -c "$CONNS" -z "${SECS}s" "$URL"
fi
