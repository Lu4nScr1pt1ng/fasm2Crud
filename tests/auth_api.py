#!/usr/bin/env python3
"""Account endpoints against a running server with a database.

usage: auth_api.py port
"""
import json
import secrets
import socket
import sys

PORT = int(sys.argv[1])


def call(path, body, ctype="application/json", method="POST", close=False):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    head = (f"{method} {path} HTTP/1.1\r\nHost: t\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(raw)}\r\n")
    if close:
        head += "Connection: close\r\n"
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(5)
    s.sendall(head.encode() + b"\r\n" + raw)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1]) if lines[0] else 0
    headers = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
    length = int(headers.get("content-length", 0))
    while len(rest) < length:
        chunk = s.recv(65536)
        if not chunk:
            break
        rest += chunk
    s.close()
    return status, headers, json.loads(rest) if rest else None


failed = 0


def check(name, expected, got):
    global failed
    if expected == got:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}: expected {expected}, got {got}")
        failed += 1


email = f"user-{secrets.token_hex(6)}@Example.COM"
cred = {"email": email, "password": "correct horse battery"}

st, _, body = call("/v1/auth/register", cred)
check("register", 201, st)
check("register returns the lowercased address", email.lower(), (body or {}).get("email"))
check("register returns a UUID", 36, len((body or {}).get("id", "")))
check("register an address twice", 409, call("/v1/auth/register", {**cred, "email": email.lower()})[0])
check("register a short password", 422, call("/v1/auth/register", {"email": "a@b.co", "password": "short"})[0])
check("register a bad address", 422, call("/v1/auth/register", {"email": "a@@b.co", "password": "long enough"})[0])
check("register an unknown member", 422, call("/v1/auth/register", {**cred, "admin": "yes"})[0])
check("malformed JSON", 400, call("/v1/auth/register", b'{"email":')[0])
check("wrong content type", 415, call("/v1/auth/register", cred, ctype="text/plain")[0])
check("content type with charset", 409, call("/v1/auth/register", cred, ctype="application/json; charset=utf-8")[0])
st, h, _ = call("/v1/auth/login", b"", method="GET")
check("GET on an auth endpoint", (405, "POST"), (st, h.get("allow")))
check("unknown auth endpoint", 404, call("/v1/auth/whoami", cred)[0])

check("login with a wrong password", 401, call("/v1/auth/login", {**cred, "password": "wrong password"})[0])
check("login with an unknown address", 401, call("/v1/auth/login", {"email": "nobody-" + email, "password": "x" * 12})[0])
st, h, tokens = call("/v1/auth/login", cred, close=True)
check("login (Connection: close)", 200, st)
check("login is not cached", "no-store", h.get("cache-control"))
tokens = tokens or {}
check("token type", "Bearer", tokens.get("token_type"))
check("access token lifetime", 900, tokens.get("expires_in"))
check("refresh token is 256 bits", 43, len(tokens.get("refresh_token", "")))
first = tokens.get("refresh_token", "")

st, _, rotated = call("/v1/auth/refresh", {"refresh_token": first})
check("refresh", 200, st)
second = (rotated or {}).get("refresh_token", "")
check("refresh rotates the token", True, bool(second) and second != first)
st, _, rotated = call("/v1/auth/refresh", {"refresh_token": second})
check("refresh the rotated token", 200, st)
third = (rotated or {}).get("refresh_token", "")
check("reuse of a spent token", 401, call("/v1/auth/refresh", {"refresh_token": first})[0])
check("reuse revoked the whole login", 401, call("/v1/auth/refresh", {"refresh_token": third})[0])
check("malformed refresh token", 401, call("/v1/auth/refresh", {"refresh_token": "abc"})[0])
check("unknown refresh token", 401, call("/v1/auth/refresh", {"refresh_token": secrets.token_urlsafe(32)})[0])

other = call("/v1/auth/login", cred)[2] or {}
st, h, _ = call("/v1/auth/logout", {"refresh_token": other.get("refresh_token", "")})
check("logout", (204, None), (st, h.get("content-length")))
check("refresh after logout", 401, call("/v1/auth/refresh", {"refresh_token": other.get("refresh_token", "")})[0])
check("logout twice", 204, call("/v1/auth/logout", {"refresh_token": other.get("refresh_token", "")})[0])

sys.exit(1 if failed else 0)
