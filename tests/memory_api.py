#!/usr/bin/env python3
"""Memory goes up with load and comes back; the large buffer pool is bounded.

usage: memory_api.py port
The server must run with API_WORKERS=1, API_TRIM_IDLE=2, API_LARGE_BUFFERS=4.
"""
import os
import json
import resource
import secrets
import socket
import sys
import time

PORT = int(sys.argv[1])
failed = 0


def check(name, ok, detail=""):
    global failed
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")
    failed += 0 if ok else 1


def children(pid):
    with open(f"/proc/{pid}/task/{pid}/children") as f:
        return [int(p) for p in f.read().split()]


def rss_kib(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def call(method, path, body=None, token=None):
    raw = b"" if body is None else json.dumps(body).encode()
    head = f"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: {len(raw)}\r\n"
    if body is not None:
        head += "Content-Type: application/json\r\n"
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(10)
    s.sendall(head.encode() + b"\r\n" + raw)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, rest = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), head.decode(), json.loads(rest) if rest else None


def settle(pid, seconds):
    time.sleep(seconds)
    return rss_kib(pid)


def find_worker(port):
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().strip() != "fasm2crud-w":
                    continue
            with open(f"/proc/{pid}/environ", "rb") as f:
                if f"API_PORT={port}".encode() in f.read().split(b"\0"):
                    return int(pid)
        except OSError:
            pass
    sys.exit(f"no worker on port {port}")


worker = find_worker(PORT)
hasher = children(worker)[0]
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))

base = settle(worker, 3)
print(f"     worker RSS at rest: {base} KiB")

# 1500 connections, each with a 6 KB request (input pages) and a response
# (output pages), all open at once.
req = b"GET /healthz HTTP/1.1\r\nHost: t\r\nX-Pad: " + b"p" * 6000 + b"\r\n\r\n"
conns = []
for _ in range(1500):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(req)
    conns.append(s)
for s in conns:
    s.settimeout(5)
    s.recv(4096)
peak = rss_kib(worker)
for s in conns:
    s.close()
print(f"     worker RSS with 1500 connections: {peak} KiB")
check("connection memory grows with load", peak > base + 10000, f"{base} -> {peak} KiB")

# Large requests and responses: notes at the schema's limits.
cred = {"email": f"mem-{secrets.token_hex(5)}@example.com", "password": "long enough password"}
call("POST", "/v1/auth/register", cred)
login = call("POST", "/v1/auth/login", cred)
if login[0] != 200:
    sys.exit(f"login failed: {login}")
token = login[2]["access_token"]
hashed = rss_kib(hasher)
title = "".join(chr(1 + i % 31) for i in range(200))
body = "😀" * 4000
for _ in range(20):
    call("POST", "/v1/notes", {"title": title, "body": body}, token)
st, _, page = call("GET", "/v1/notes?limit=50", token=token)
check("large notes through 4 large buffers", st == 200 and len(page["items"]) == 20)
print(f"     hasher RSS after a login: {hashed} KiB")
check("the hasher holds its Argon2 memory after a hash", hashed > 18000, f"{hashed} KiB")

# The pool is bounded: 4 clients each hold a large input buffer (a large
# request sent halfway); a fifth large request gets 503 with Retry-After.
half = (b"POST /v1/notes HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
        b"Authorization: Bearer " + token.encode() + b"\r\nContent-Length: 40000\r\n\r\n" + b"{" + b" " * 9000)
holders = []
for _ in range(4):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(half)
    holders.append(s)
time.sleep(0.3)
s = socket.create_connection(("127.0.0.1", PORT))
s.settimeout(5)
s.sendall(half)
reply = s.recv(4096)
s.close()
check("an exhausted pool answers 503 with Retry-After",
      reply.startswith(b"HTTP/1.1 503") and b"Retry-After: 1" in reply, reply.split(b"\r\n")[0].decode(errors="replace"))
check("small requests still work meanwhile", call("GET", "/healthz")[0] == 200)

# A client that keeps making progress, one byte a second, still loses its
# large buffer at the deadline (REQUEST_TIMEOUT, 10 s).
trickler = holders[0]
started = time.time()
closed_after = None
while time.time() - started < 15:
    try:
        trickler.sendall(b" ")
        trickler.settimeout(1)
        if trickler.recv(4096) == b"":
            closed_after = time.time() - started
            break
    except socket.timeout:
        continue
    except OSError:
        closed_after = time.time() - started
        break
check("a trickling client loses its large buffer at the deadline",
      closed_after is not None and closed_after < 13, f"closed after {closed_after and round(closed_after, 1)} s")
for s in holders:
    s.close()

# Idle: everything goes back (API_TRIM_IDLE=2, one tick of margin).
after = settle(worker, 5)
idle_hasher = rss_kib(hasher)
print(f"     worker RSS idle again: {after} KiB, hasher {idle_hasher} KiB")
check("connection and large buffer memory goes back", after < base + 3000, f"{base} -> {peak} -> {after} KiB")
check("the idle hasher gives its Argon2 memory back", idle_hasher < 4000, f"{hashed} -> {idle_hasher} KiB")

# And comes again when needed.
check("a login after the trim", call("POST", "/v1/auth/login", cred)[0] == 200)
check("a large page after the trim", call("GET", "/v1/notes?limit=50", token=token)[0] == 200)

sys.exit(1 if failed else 0)
