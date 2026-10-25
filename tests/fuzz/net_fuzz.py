#!/usr/bin/env python3
"""Network fuzzing of the running server: the whole connection state machine.

usage: net_fuzz.py port [connections] [seed]

Mutated and well-formed requests (account and notes endpoints included,
some with a valid access token) go over many concurrent connections, cut
into random pieces, pipelined, with clients that stop reading or vanish
mid-request. Afterwards the server must still answer, no worker may have
been restarted, and every connection slot and large buffer must be back.
"""
import importlib.util
import json
import os
import random
import secrets
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
spec = importlib.util.spec_from_file_location("fz", os.path.join(HERE, "fuzz.py"))
fz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fz)

PORT = int(args[0])
CONNS = int(args[1]) if len(args) > 1 else 3000
SEED = int(args[2]) if len(args) > 2 else random.randrange(1 << 30)
rng = random.Random(SEED)
fz.rng = rng


def call(method, path, body=None, token=None):
    raw = json.dumps(body).encode() if body is not None else b""
    head = f"{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: {len(raw)}\r\n"
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
    return data


def metrics():
    text = call("GET", "/metrics").partition(b"\r\n\r\n")[2].decode()
    return {l.rpartition(" ")[0]: float(l.rpartition(" ")[2]) for l in text.split("\n") if l and l[0] != "#"}


cred = {"email": f"fuzz-{secrets.token_hex(5)}@example.com", "password": "long enough password"}
call("POST", "/v1/auth/register", cred)
reply = call("POST", "/v1/auth/login", cred).partition(b"\r\n\r\n")[2]
TOKEN = json.loads(reply).get("access_token", "x") if reply.startswith(b"{") else "x"
NOTE = json.loads(call("POST", "/v1/notes", {"title": "fuzz"}, TOKEN).partition(b"\r\n\r\n")[2] or b"{}").get("id", "0")

PATHS = [b"/healthz", b"/readyz", b"/metrics", b"/v1/auth/login", b"/v1/auth/register", b"/v1/auth/refresh",
         b"/v1/auth/logout", b"/v1/notes", b"/v1/notes?limit=2", b"/v1/notes/" + NOTE.encode(), b"/nope"]


def api_request():
    method = rng.choice([b"GET", b"POST", b"PATCH", b"DELETE", b"PUT"])
    body = rng.choice([b"", b"{}", b'{"title":"t"}', b'{"email":"a@b.co","password":"long enough"}',
                       b'{"refresh_token":"' + b"A" * 43 + b'"}', b'{"title":"' + b"\\u0001" * 200 + b'"}',
                       json.dumps({"title": "x", "body": "😀" * 4000}).encode(), fz.gen_json()])
    head = [method + b" " + rng.choice(PATHS) + b" HTTP/1.1", b"Host: t",
            b"Content-Length: " + str(len(body)).encode()]
    if rng.random() < 0.8:
        head.append(b"Content-Type: application/json")
    if rng.random() < 0.7:
        head.append(b"Authorization: Bearer " + rng.choice([TOKEN.encode(), b"x" * 78, b""]))
    if rng.random() < 0.3:
        head.append(b'If-Match: "' + rng.choice([b"1", b"2", b"x"]) + b'"')
    rng.shuffle(head[1:])
    return b"\r\n".join(head) + b"\r\n\r\n" + body


def client(cid):
    r = random.Random(SEED * 7919 + cid)
    try:
        s = socket.create_connection(("127.0.0.1", PORT))
        s.settimeout(3)
        stream = b"".join(api_request() if r.random() < 0.6 else fz.mutate(api_request()) if r.random() < 0.5
                          else fz.gen_http() for _ in range(r.choice([1, 1, 2, 5, 20])))
        mode = r.randrange(4)
        if mode == 3:
            stream = stream[:r.randrange(len(stream) + 1)]       # vanish mid-request
        pos = 0
        while pos < len(stream):
            n = r.choice([1, 7, 64, 1500, 65536])
            s.sendall(stream[pos:pos + n])
            pos += n
            if r.random() < 0.05:
                time.sleep(0.01)
        if mode == 0:
            s.shutdown(socket.SHUT_WR)
        if mode != 2:                                            # mode 2: never read
            while s.recv(65536):
                pass
    except OSError:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


start = metrics()
threads = []
for cid in range(CONNS):
    t = threading.Thread(target=client, args=(cid,))
    t.start()
    threads.append(t)
    if len(threads) >= 200:
        threads.pop(0).join()
for t in threads:
    t.join()

# Connections wind down within the timeouts (10 s), large buffers with them.
deadline = time.time() + 25
while time.time() < deadline:
    m = metrics()
    if m.get("fasm2crud_connections_active", 99) <= 1 and m.get("fasm2crud_large_buffers_in_use", 99) == 0:
        break
    time.sleep(1)
m = metrics()
failed = 0
for name, ok, detail in (
        ("server still answers", call("GET", "/healthz").startswith(b"HTTP/1.1 200"), ""),
        ("no worker crashed", m.get("fasm2crud_worker_restarts_total", -1) == start.get("fasm2crud_worker_restarts_total", -1),
         f"{m.get('fasm2crud_worker_restarts_total')}"),
        ("every connection slot is back", m.get("fasm2crud_connections_active", 99) <= 1,
         f"{m.get('fasm2crud_connections_active')} active"),
        ("every large buffer is back", m.get("fasm2crud_large_buffers_in_use", 99) == 0,
         f"{m.get('fasm2crud_large_buffers_in_use')} in use"),
        ("no hasher crashed", m.get("fasm2crud_hasher_restarts_total", -1) == start.get("fasm2crud_hasher_restarts_total", -1), "")):
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")
    failed += 0 if ok else 1
served = sum(v for k, v in m.items() if k.startswith("fasm2crud_http_responses_total")) - \
    sum(v for k, v in start.items() if k.startswith("fasm2crud_http_responses_total"))
print(f"     {CONNS} connections, {int(served)} responses, seed {SEED}")
sys.exit(1 if failed else 0)
