#!/usr/bin/env python3
"""GET /metrics: one view of the whole service, counters that never go back.

usage: metrics_api.py port
The server must run with API_WORKERS=4.
"""
import os
import signal
import socket
import sys
import time

PORT = int(sys.argv[1])
failed = 0


def check(name, expected, got):
    global failed
    if expected == got:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}: expected {expected!r}, got {got!r}")
        failed += 1


def get(path, method="GET"):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(5)
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), head.decode(), body.decode()


def metrics():
    st, head, body = get("/metrics")
    values = {}
    for line in body.split("\n"):
        if line and not line.startswith("#"):
            name, _, value = line.rpartition(" ")
            values[name] = float(value)
    return st, head, values


def workers():
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().strip() != "fasm2crud-w":
                    continue
            with open(f"/proc/{pid}/environ", "rb") as f:
                if f"API_PORT={PORT}".encode() in f.read().split(b"\0"):
                    out.append(int(pid))
        except OSError:
            pass
    return out


st, head, before = metrics()
check("/metrics", 200, st)
check("Prometheus text format", True, "Content-Type: text/plain; version=0.0.4" in head)
check("every worker is counted", 4.0, before.get("fasm2crud_workers"))

# 400 requests over new connections land on every worker; all are counted,
# whichever worker answers /metrics.
for _ in range(400):
    get("/healthz")
time.sleep(1.1)
_, _, after = metrics()
ok_key = 'fasm2crud_http_responses_total{code="200"}'
check("responses from all workers add up", True, after[ok_key] - before[ok_key] >= 400)
check("the histogram counts them", True,
      after["fasm2crud_http_request_duration_seconds_count"] - before["fasm2crud_http_request_duration_seconds_count"] >= 400)
check("histogram buckets are cumulative", True,
      after['fasm2crud_http_request_duration_seconds_bucket{le="+Inf"}'] == after["fasm2crud_http_request_duration_seconds_count"])
check("POST /metrics", 405, get("/metrics", "POST")[0])

# A worker dies: its counters stay, and the restart is counted.
os.kill(workers()[0], signal.SIGKILL)
time.sleep(1.5)
_, _, later = metrics()
check("counters never go back after a worker restart", True, later[ok_key] >= after[ok_key])
check("the restart is counted", 1.0, later.get("fasm2crud_worker_restarts_total"))
check("four workers again", 4, len(workers()))

sys.exit(1 if failed else 0)
