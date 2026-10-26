#!/usr/bin/env python3
"""Rate limits per client, for the whole service.

usage: ratelimit_api.py port
The server must run with API_WORKERS=2, API_AUTH_RATE=6, API_AUTH_BURST=3,
API_RATE=60, API_BURST=8, API_TRUSTED_PROXY=127.0.0.1.
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


def request(path=b"/v1/auth/refresh", body=BODY, method=b"POST", xff=None):
    head = method + b" " + path + b" HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
    head += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    if xff:
        head += b"X-Forwarded-For: " + xff + b"\r\n"
    return head + b"\r\n" + body


def exchange(raw, count=1, source="127.0.0.1"):
    family = socket.AF_INET6 if ":" in source else socket.AF_INET
    s = socket.socket(family)
    s.bind((source, 0))
    s.connect(("::1" if family == socket.AF_INET6 else "127.0.0.1", PORT))
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


def codes(n, **kw):
    """n requests, each on a new connection (so spread over the workers)."""
    return [exchange(request(**{k: v for k, v in kw.items() if k != "source"}), 1, kw.get("source", "127.0.0.1"))[0][0]
            for _ in range(n)]


# The auth class: 3 at once, 6 a minute, for the whole service.
got = [exchange(request(), 1, "127.0.0.2")[0] for _ in range(4)]
check("a burst of 3 across both workers, then 429", [401, 401, 401, 429], [c for c, _ in got])
check("Retry-After says when the next token comes (6 a minute)", "10", got[3][1])
check("another IPv4 address has its own bucket", 401, codes(1, source="127.0.0.3")[0])
check("an IPv6 client has its own bucket", [401, 401, 401, 429], codes(4, source="::1"))
check("logout is not in the auth class", [401] * 5, codes(5, path=b"/v1/auth/logout", source="127.0.0.4"))

# Behind the trusted proxy (127.0.0.1): the last X-Forwarded-For entry.
check("each forwarded client has its own bucket", ([401] * 3 + [429], [401] * 3),
      (codes(4, xff=b"203.0.113.7"), codes(3, xff=b"198.51.100.1, 203.0.113.9")))
check("one IPv6 /64 shares a bucket", [401, 401, 401, 429],
      codes(2, xff=b"2001:db8:1:2::1") + codes(2, xff=b"2001:db8:1:2:ffff::9"))
check("the next /64 is someone else", 401, codes(1, xff=b"2001:db8:1:3::1")[0])
check("from anyone but the proxy the header is ignored", [401, 401, 401, 429],
      codes(4, xff=b"192.0.2.55", source="127.0.0.5"))
check("a forwarded client the proxy could not name counts as the proxy", 401,
      codes(1, xff=b"not an address")[0])

# The general class: every /v1/ request, 8 at once, 60 a minute.
check("the general limit covers every /v1/ route", [401] * 8 + [429],
      codes(9, path=b"/v1/notes", method=b"GET", body=b"", source="127.0.0.6"))
check("health checks are not limited", [200] * 12,
      [exchange(b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n", 1, "127.0.0.6")[0][0] for _ in range(12)])

# Pipelined on one connection: the address is looked up once, every
# request is counted. Then the bucket refills.
got = exchange(request() * 5, 5, "127.0.0.7")
check("pipelined requests are each counted", [401, 401, 401, 429, 429], [c for c, _ in got])
time.sleep(10.5)
check("the bucket refills with time", 401, codes(1, source="127.0.0.2")[0])

s = socket.create_connection(("127.0.0.1", PORT))
s.sendall(b"GET /metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
text = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    text += chunk
line = [l for l in text.decode().split("\n") if l.startswith("fasm2crud_rate_limited_total ")]
check("refusals are counted in /metrics", "fasm2crud_rate_limited_total 8", line[0] if line else None)

sys.exit(1 if failed else 0)
