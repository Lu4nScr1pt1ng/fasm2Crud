#!/usr/bin/env python3
"""Per-address rate limits on the account endpoints.

usage: ratelimit_api.py port
The server must run with API_WORKERS=1, API_AUTH_RATE=6, API_AUTH_BURST=3.
"""
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


BODY = b'{"refresh_token":"abc"}'


def request(path=b"/v1/auth/refresh", body=BODY):
    return (b"POST " + path + b" HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def exchange(raw, count, source="127.0.0.1"):
    s = socket.socket()
    s.bind((source, 0))
    s.connect(("127.0.0.1", PORT))
    s.settimeout(5)
    s.sendall(raw)
    data, out = b"", []
    while len(out) < count:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        while b"\r\n\r\n" in data:
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            headers = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
            length = int(headers.get("content-length", 0))
            if len(rest) < length:
                break
            out.append((int(lines[0].split()[1]), headers.get("retry-after")))
            data = rest[length:]
    s.close()
    return out


codes = [exchange(request(), 1)[0] for _ in range(4)]
check("a burst of 3, then 429", [401, 401, 401, 429], [c for c, _ in codes])
check("Retry-After says when the next token comes (6 a minute)", "10", codes[3][1])
check("another address has its own bucket", 401, exchange(request(), 1, "127.0.0.2")[0][0])
check("logout is not limited (a malformed token is 401, never 429)", [401] * 6, [exchange(request(b"/v1/auth/logout"), 1)[0][0] for _ in range(6)])
check("other routes are not limited", 200, exchange(b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n", 1)[0][0])

# Pipelined on one connection: the address is looked up once, every
# request is counted.
time.sleep(10.5)
got = exchange(request() * 5, 5, "127.0.0.3")
check("pipelined requests are each counted", [401, 401, 401, 429, 429], [c for c, _ in got])
check("the bucket refills with time", 401, exchange(request(), 1)[0][0])

s = socket.create_connection(("127.0.0.1", PORT))
s.sendall(b"GET /metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
text = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    text += chunk
line = [l for l in text.decode().split("\n") if l.startswith("fasm2crud_rate_limited_total ")]
check("refusals are counted in /metrics", "fasm2crud_rate_limited_total 3", line[0] if line else None)

sys.exit(1 if failed else 0)
