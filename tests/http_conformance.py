#!/usr/bin/env python3
"""HTTP/1.1 conformance and robustness checks against a running server.

usage: http_conformance.py [port]
"""
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def exchange(raw, chunk=None, timeout=3.0):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(timeout)
    if chunk:
        for i in range(0, len(raw), chunk):
            s.sendall(raw[i:i + chunk])
            time.sleep(0.001)
    else:
        s.sendall(raw)
    out = b""
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            out += data
    except socket.timeout:
        out += b"<timeout>"
    s.close()
    return out


def statuses(response):
    """Status codes of consecutive responses, framed by Content-Length."""
    codes = []
    while response.startswith(b"HTTP/1.1 "):
        head, sep, rest = response.partition(b"\r\n\r\n")
        if not sep:
            break
        lines = head.split(b"\r\n")
        codes.append(int(lines[0].split()[1]))
        length = 0
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            if name.lower() == b"content-length":
                length = int(value)
        response = rest[length:]
    return codes


H = b"Host: t\r\n"
CLOSE = b"Connection: close\r\n"
CASES = [
    ("health", b"GET /healthz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [200]),
    ("ready", b"GET /readyz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [200]),
    ("pipelined", (b"GET /healthz HTTP/1.1\r\n" + H + b"\r\n") * 3
     + b"GET /readyz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [200] * 4),
    ("one byte per write", b"GET /healthz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [200], 1),
    ("query string", b"GET /healthz?x=1 HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [200]),
    ("case-insensitive names", b"GET /healthz HTTP/1.1\r\nhOsT: t\r\ncOnNeCtIoN: Close\r\n\r\n", [200]),
    ("http/1.0 closes", b"GET /healthz HTTP/1.0\r\n\r\n", [200]),
    ("unknown path", b"GET /nope HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [404]),
    ("wrong method", b"DELETE /healthz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [405]),
    ("body is skipped", b"POST /healthz HTTP/1.1\r\n" + H + b"Content-Length: 5\r\n\r\nhello"
     + b"GET /healthz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [405, 200]),
    ("unknown method", b"BREW /healthz HTTP/1.1\r\n" + H + CLOSE + b"\r\n", [501]),
    ("missing host", b"GET /healthz HTTP/1.1\r\n\r\n", [400]),
    ("two hosts", b"GET /healthz HTTP/1.1\r\n" + H + H + b"\r\n", [400]),
    ("bare LF", b"GET /healthz HTTP/1.1\nHost: t\n\n", [400]),
    ("space before colon", b"GET /healthz HTTP/1.1\r\nHost : t\r\n\r\n", [400]),
    ("control byte in value", b"GET /healthz HTTP/1.1\r\nHost: t\x01\r\n\r\n", [400]),
    ("transfer-encoding", b"POST /healthz HTTP/1.1\r\n" + H
     + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", [501]),
    ("duplicate content-length", b"POST /healthz HTTP/1.1\r\n" + H
     + b"Content-Length: 1\r\nContent-Length: 1\r\n\r\na", [400]),
    ("signed content-length", b"POST /healthz HTTP/1.1\r\n" + H + b"Content-Length: +1\r\n\r\na", [400]),
    ("absolute-form target", b"GET http://t/healthz HTTP/1.1\r\n" + H + b"\r\n", [400]),
    ("fragment in target", b"GET /healthz#x HTTP/1.1\r\n" + H + b"\r\n", [400]),
    ("http/2 preface", b"GET /healthz HTTP/2.0\r\n" + H + b"\r\n", [505]),
    ("body too large", b"POST /healthz HTTP/1.1\r\n" + H + b"Content-Length: 100000\r\n\r\n", [413]),
    ("headers too large", b"GET /healthz HTTP/1.1\r\n" + H + b"X: " + b"a" * 9000 + b"\r\n\r\n", [431]),
    ("too many headers", b"GET /healthz HTTP/1.1\r\n" + H + b"X: y\r\n" * 70 + b"\r\n", [431]),
]


def main():
    failed = 0
    for case in CASES:
        name, raw, expected = case[0], case[1], case[2]
        chunk = case[3] if len(case) > 3 else None
        got = statuses(exchange(raw, chunk))
        ok = got == expected
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: expected {expected}, got {got}")
    print(f"{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
