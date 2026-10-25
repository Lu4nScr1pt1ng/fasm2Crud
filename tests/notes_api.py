#!/usr/bin/env python3
"""Notes endpoints against a running server with a database.

usage: notes_api.py port
"""
import json
import secrets
import socket
import sys
import threading
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


def request(method, path, body=None, token=None, headers=(), ctype="application/json", ascii=False):
    raw = b"" if body is None else body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=ascii).encode()
    head = f"{method} {path} HTTP/1.1\r\nHost: t\r\n"
    if body is not None:
        head += f"Content-Type: {ctype}\r\n"
    head += f"Content-Length: {len(raw)}\r\n"
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    for h in headers:
        head += h + "\r\n"
    return head.encode() + b"\r\n" + raw


def read_responses(s, count):
    """Parse count responses (Content-Length framed) from socket s."""
    data = b""
    out = []
    while len(out) < count:
        while b"\r\n\r\n" not in data:
            chunk = s.recv(65536)
            if not chunk:
                return out
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        headers = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
        length = int(headers.get("content-length", 0))
        while len(rest) < length:
            chunk = s.recv(65536)
            if not chunk:
                return out
            rest += chunk
        body = rest[:length]
        data = rest[length:]
        out.append((int(lines[0].split()[1]), headers, json.loads(body) if body else None))
    return out


def call(method, path, body=None, token=None, headers=(), ctype="application/json", ascii=False):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(5)
    s.sendall(request(method, path, body, token, headers, ctype, ascii))
    r = read_responses(s, 1)
    s.close()
    return r[0] if r else (0, {}, None)


def account():
    cred = {"email": f"notes-{secrets.token_hex(6)}@example.com", "password": "long enough password"}
    call("POST", "/v1/auth/register", cred)
    return call("POST", "/v1/auth/login", cred)[2]["access_token"]


alice, bob = account(), account()

# Authentication.
st, h, _ = call("GET", "/v1/notes")
check("no token", (401, "Bearer"), (st, h.get("www-authenticate")))
check("garbage token", 401, call("GET", "/v1/notes", token="x" * 78)[0])
check("tampered token", 401, call("GET", "/v1/notes", token=alice[:-2] + ("A" if alice[-2] != "A" else "B") + alice[-1])[0])

# Validation.
check("create without title", 422, call("POST", "/v1/notes", {"body": "x"}, alice)[0])
check("create with empty title", 422, call("POST", "/v1/notes", {"title": ""}, alice)[0])
check("title of 201 characters", 422, call("POST", "/v1/notes", {"title": "t" * 201}, alice)[0])
check("title of 201 emoji", 422, call("POST", "/v1/notes", {"title": "😀" * 201}, alice)[0])
check("body of 4001 characters", 422, call("POST", "/v1/notes", {"title": "t", "body": "é" * 4001}, alice)[0])
check("unknown member", 422, call("POST", "/v1/notes", {"title": "t", "tags": "x"}, alice)[0])
check("wrong content type", 415, call("POST", "/v1/notes", {"title": "t"}, alice, ctype="text/plain")[0])
check("malformed JSON", 400, call("POST", "/v1/notes", b'{"title":', alice)[0])
check("PUT on the collection", (405, "GET, POST"), (lambda r: (r[0], r[1].get("allow")))(call("PUT", "/v1/notes", {"title": "t"}, alice)))
check("PUT on a note", 405, call("PUT", "/v1/notes/" + "0" * 8 + "-0000-0000-0000-" + "0" * 12, {"title": "t"}, alice)[0])
check("malformed id", 404, call("GET", "/v1/notes/not-a-uuid-at-all-not-a-uuid-at-all-xx", token=alice)[0])

# The schema's limits in characters, whatever their encoding: 200 emoji
# (800 bytes) and 4000 of them, sent the way json.dumps sends by default
# (every one escaped as a surrogate pair: a ~50 KB request).
st, _, big = call("POST", "/v1/notes", {"title": "😀" * 200, "body": "😀" * 4000}, alice, ascii=True)
check("200 + 4000 emoji, ASCII-escaped request", (201, "😀" * 200, "😀" * 4000),
      (st, (big or {}).get("title"), (big or {}).get("body")))

# The largest response: every character a control character, escaped as
# \u00XX (6 bytes each, ~25 KB of JSON).
title = "".join(chr(1 + i % 31) for i in range(200))
body = "".join(chr(1 + i % 31) for i in range(4000))
st, h, note = call("POST", "/v1/notes", {"title": title, "body": body}, alice)
check("create the largest note", 201, st)
note = note or {}
nid = note.get("id", "")
check("Location", f"/v1/notes/{nid}", h.get("location"))
check("ETag of a new note", '"1"', h.get("etag"))
check("control characters round trip", (title, body), (note.get("title"), note.get("body")))
check("timestamps are RFC 3339 UTC", True, note.get("created_at", "").endswith("Z") and "T" in note.get("created_at", ""))
st, h, got = call("GET", f"/v1/notes/{nid}", token=alice)
check("get", (200, '"1"', note), (st, h.get("etag"), got))
mixed = 'aé"\\😀\n\t\u2028\u007f'
st, _, m = call("POST", "/v1/notes", {"title": mixed, "body": mixed * 400}, alice)
check("mixed text round trip", (201, mixed, mixed * 400), (st, (m or {}).get("title"), (m or {}).get("body")))

# Several of the largest responses pipelined on one connection, between
# small ones: none may be cut or reordered.
s = socket.create_connection(("127.0.0.1", PORT))
s.settimeout(5)
s.sendall((request("GET", f"/v1/notes/{nid}", token=alice) + request("GET", "/healthz")) * 6)
got = read_responses(s, 12)
s.close()
check("12 pipelined responses, 6 of them large", [200] * 12, [r[0] for r in got])
check("pipelined bodies are whole and in order", True,
      all(r[2] == note for r in got[0::2]) and all(r[2] == {"status": "ok"} for r in got[1::2]))

# Other users see nothing.
check("another user's note (GET)", 404, call("GET", f"/v1/notes/{nid}", token=bob)[0])
check("another user's note (PATCH)", 404, call("PATCH", f"/v1/notes/{nid}", {"title": "x"}, bob, ['If-Match: "1"'])[0])
check("another user's note (DELETE)", 404, call("DELETE", f"/v1/notes/{nid}", token=bob, headers=['If-Match: "1"'])[0])
check("another user's list", [], call("GET", "/v1/notes", token=bob)[2]["items"])

# Conditional writes.
check("PATCH without If-Match", 428, call("PATCH", f"/v1/notes/{nid}", {"title": "x"}, alice)[0])
check("PATCH with a weak tag", 412, call("PATCH", f"/v1/notes/{nid}", {"title": "x"}, alice, ['If-Match: W/"1"'])[0])
check("PATCH with a leading zero", 412, call("PATCH", f"/v1/notes/{nid}", {"title": "x"}, alice, ['If-Match: "01"'])[0])
st, h, _ = call("PATCH", f"/v1/notes/{nid}", {"title": "x"}, alice, ['If-Match: "9"'])
check("PATCH with a stale tag", (412, '"1"'), (st, h.get("etag")))
check("PATCH with nothing to change", 422, call("PATCH", f"/v1/notes/{nid}", {}, alice, ['If-Match: "1"'])[0])
st, h, patched = call("PATCH", f"/v1/notes/{nid}", {"body": "only the body"}, alice, ['If-Match: "1"'])
check("PATCH the body only", (200, '"2"', title, "only the body", 2),
      (st, h.get("etag"), (patched or {}).get("title"), (patched or {}).get("body"), (patched or {}).get("version")))

results = []
def racer(text):
    results.append(call("PATCH", f"/v1/notes/{nid}", {"title": text}, alice, ['If-Match: "2"'])[0])
threads = [threading.Thread(target=racer, args=(f"racer {i}",)) for i in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
check("8 concurrent PATCHes of version 2: one wins", [200] + [412] * 7, sorted(results))

check("DELETE without If-Match", 428, call("DELETE", f"/v1/notes/{nid}", token=alice)[0])
check("DELETE with a stale tag", 412, call("DELETE", f"/v1/notes/{nid}", token=alice, headers=['If-Match: "2"'])[0])
st, h, _ = call("DELETE", f"/v1/notes/{nid}", token=alice, headers=['If-Match: "3"'])
check("DELETE", (204, None), (st, h.get("content-length")))
check("GET after DELETE", 404, call("GET", f"/v1/notes/{nid}", token=alice)[0])
check("DELETE twice", 404, call("DELETE", f"/v1/notes/{nid}", token=alice, headers=['If-Match: "3"'])[0])

# Keyset pages, newest first.
dave = account()
ids = [call("POST", "/v1/notes", {"title": f"n{i}"}, dave)[2]["id"] for i in range(25)]
seen, sizes, cursor = [], [], None
while True:
    path = "/v1/notes?limit=10" + (f"&cursor={cursor}" if cursor else "")
    st, _, page = call("GET", path, token=dave)
    if st != 200:
        break
    sizes.append(len(page["items"]))
    seen += [n["id"] for n in page["items"]]
    cursor = page["next_cursor"]
    if not cursor:
        break
check("pages of 10", [10, 10, 5], sizes)
check("every note once, newest first", list(reversed(ids)), seen)
check("default page size", 20, len(call("GET", "/v1/notes", token=dave)[2]["items"]))
check("limit 0", 400, call("GET", "/v1/notes?limit=0", token=alice)[0])
check("limit 51", 400, call("GET", "/v1/notes?limit=51", token=alice)[0])
check("unknown parameter", 400, call("GET", "/v1/notes?sort=asc", token=alice)[0])
check("limit twice", 400, call("GET", "/v1/notes?limit=1&limit=2", token=alice)[0])
check("malformed cursor", 400, call("GET", "/v1/notes?cursor=abc", token=alice)[0])

# The largest page: 50 notes whose titles are 200 control characters
# (~67 KB of JSON). It comes whole, in one page.
carol = account()
wide = [call("POST", "/v1/notes", {"title": title}, carol)[2]["id"] for _ in range(51)]
st, _, page = call("GET", "/v1/notes?limit=50", token=carol)
page = page or {"items": []}
check("the largest page is whole", (200, 50, list(reversed(wide))[:50], wide[0]),
      (st, len(page["items"]), [n["id"] for n in page["items"]], page.get("next_cursor") and
       call("GET", f"/v1/notes?limit=50&cursor={page['next_cursor']}", token=carol)[2]["items"][0]["id"]))
check("its titles round trip", True, all(n["title"] == title for n in page["items"]))

# Clients that leave before the database answers: their replies are
# dropped, and nothing that belongs to other requests is touched (a
# /readyz reply once carried a garbage auth context and crashed a worker).
import os
def workers():
    out = set()
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().strip() != "fasm2crud-w":
                    continue
            with open(f"/proc/{pid}/environ", "rb") as f:
                if f"API_PORT={PORT}".encode() in f.read().split(b"\0"):
                    out.add(int(pid))
        except OSError:
            pass
    return out
import struct
before = workers()
for path in ["/readyz", "/v1/notes", f"/v1/notes/{ids[0]}"] * 70:
    # A response first, so the server writes, fails on the reset and closes
    # the connection while the query is still out.
    s = socket.create_connection(("127.0.0.1", PORT))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.sendall(request("GET", "/healthz") + request("GET", path, token=dave))
    s.close()
time.sleep(1)
check("clients leaving mid-query crash nothing", (True, before), (call("GET", "/healthz")[0] == 200, workers()))

sys.exit(1 if failed else 0)
