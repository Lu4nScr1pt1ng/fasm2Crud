#!/usr/bin/env python3
"""Differential tests for request input handling in build/kat:
the strict JSON parser (against Python's json), e-mail normalization
(against the rules written out below) and PHC strings."""
import base64
import json
import os
import random
import subprocess
import sys

KAT = os.path.join(os.path.dirname(__file__), "..", "..", "build", "kat")
FIELDS = {"email": 254, "password": 128}
OK, SYNTAX, SCHEMA = 0, 1, 2


def run(mode, data):
    out = subprocess.run([KAT, mode], input=data, capture_output=True)
    return out.stderr.decode().strip() if out.returncode == 0 else f"exit {out.returncode}"


def bad_string(s):
    return "\x00" in s or any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def walk(value):
    """Yield every string (keys included) in a parsed document."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, tuple):
        for k, v in value[1]:
            yield k
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)


def reference_json(body):
    try:
        text = body.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=lambda p: ("obj", p),
                         parse_constant=lambda c: 1 / 0)
    except Exception:
        return SYNTAX, None
    if any(bad_string(s) for s in walk(doc)):
        return SYNTAX, None
    if not isinstance(doc, tuple):
        return SCHEMA, None
    seen = {}
    for key, value in doc[1]:
        if key not in FIELDS or key in seen or not isinstance(value, str) \
                or len(value.encode()) > FIELDS[key]:
            return SCHEMA, None
        seen[key] = value.encode()
    return OK, seen


def encode_result(code, values):
    out = bytes([code])
    for name in FIELDS:
        v = (values or {}).get(name)
        out += (bytes([1]) + len(v).to_bytes(2, "little") + v) if v is not None else b"\0\0\0"
    return out.hex()


def random_string(rng):
    pool = ["a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "é", "ß", "中", "😀", " ", "\x7f", "\x01"]
    return "".join(rng.choice(pool) for _ in range(rng.randrange(0, 12)))


def random_value(rng, depth=0):
    kind = rng.randrange(8 if depth < 4 else 5)
    if kind < 3:
        return random_string(rng)
    if kind == 3:
        return rng.choice([0, -1, 3.5, 1e300, -0.0, 12345678901234567890])
    if kind == 4:
        return rng.choice([True, False, None])
    if kind == 5:
        return [random_value(rng, depth + 1) for _ in range(rng.randrange(3))]
    return {rng.choice(["a", "email", "b"]): random_value(rng, depth + 1) for _ in range(rng.randrange(3))}


def random_document(rng):
    if rng.random() < 0.1:
        return json.dumps(random_value(rng)).encode()
    members = []
    for _ in range(rng.randrange(0, 4)):
        key = rng.choice(["email", "password", "email", "password", "other", "émail", ""])
        value = random_string(rng) if rng.random() < 0.85 else random_value(rng)
        if rng.random() < 0.05:
            value = "x" * 300
        members.append((key, value))
    ascii_only = rng.random() < 0.5
    ws = rng.choice(["", " ", "\n", "\t ", "\r\n"])
    body = "{" + ws + ("," + ws).join(
        json.dumps(k, ensure_ascii=ascii_only) + ws + ":" + ws + json.dumps(v, ensure_ascii=ascii_only)
        for k, v in members) + ws + "}"
    body = body.encode()
    r = rng.random()
    if r < 0.08:
        body = body.replace(b"\\\\", b"\\ud800", 1) if b"\\\\" in body else body + b"\\"
    elif r < 0.14:
        body += rng.choice([b"x", b"}", b" ", b"\x00", b"{}"])
    elif r < 0.30 and body:
        i = rng.randrange(len(body))
        body = body[:i] + bytes([rng.randrange(256)]) + body[i + 1:]
    elif r < 0.36:
        body = body[:rng.randrange(len(body) + 1)]
    return body


def reference_email(raw):
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    atext = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.")
    if not 3 <= len(s) <= 254 or s.count("@") != 1:
        return None
    local, domain = s.split("@")
    if any(c not in atext for c in local + domain) or not 1 <= len(local) <= 64 or "." not in domain:
        return None
    for part in (local, domain):
        if not part or part[0] == "." or part[-1] == "." or ".." in part:
            return None
    return s.lower()


def main():
    rng = random.Random(7)
    failures = checks = 0
    for _ in range(4000):
        body = random_document(rng)
        code, values = reference_json(body)
        checks += 1
        if run("json", body) != encode_result(code, values):
            failures += 1
            if failures <= 10:
                print(f"FAIL json {body!r}: expected {encode_result(code, values)}, got {run('json', body)}")
    deep = b"[" * 40 + b"]" * 40
    checks += 1
    if run("json", b'{"x":' + deep + b"}")[:2] != "01":
        failures += 1
        print("FAIL json: nesting deeper than the limit must be rejected")

    samples = ["a@b.co", "A.B+tag@Example.COM", "a@b", "@b.co", "a@", "a@@b.co", "a..b@c.de", ".a@b.co",
               "a.@b.co", "a@b..co", "a@.b.co", "a@b.co.", "a b@c.de", "a\"b@c.de", "x" * 65 + "@b.co",
               "é@b.co", "a@b.co" + "m" * 250, "user@sub.domain.example", "a@b-c.d"]
    for _ in range(1500):
        samples.append("".join(rng.choice("aZ.@-+_!x0é ") for _ in range(rng.randrange(1, 14))))
    for s in samples:
        raw = s.encode()
        want = reference_email(raw)
        expect = ("01" + want.encode().hex()) if want is not None else "00"
        checks += 1
        got = run("email", raw)
        if got != expect:
            failures += 1
            if failures <= 20:
                print(f"FAIL email {s!r}: expected {expect}, got {got}")

    nopad = lambda b: base64.b64encode(b).rstrip(b"=")
    for _ in range(200):
        salt, digest = rng.randbytes(16), rng.randbytes(32)
        want = b"$argon2id$v=19$m=19456,t=2,p=1$" + nopad(salt) + b"$" + nopad(digest)
        checks += 1
        if run("phc", b"e" + salt + digest) != want.hex():
            failures += 1
            print("FAIL phc encode")
        decoded = run("phc", b"d" + want)
        expect = ((19456).to_bytes(4, "little") + (2).to_bytes(4, "little") + (1).to_bytes(4, "little")
                  + (16).to_bytes(4, "little") + salt + bytes(48) + digest).hex()
        checks += 1
        if decoded != expect:
            failures += 1
            print("FAIL phc decode")
    good = b"$argon2id$v=19$m=19456,t=2,p=1$" + nopad(b"s" * 16) + b"$" + nopad(b"h" * 32)
    for bad in [good.replace(b"argon2id", b"argon2i"), good.replace(b"v=19", b"v=16"),
                good.replace(b"p=1", b"p=2"), good.replace(b"m=19456", b"m=99999999"),
                good.replace(b"t=2", b"t=0"), good.replace(b"m=19456", b"m=019456"),
                good[:-1], good + b"A", good.replace(b",t=", b",x="), b"", good.replace(b"$", b"", 1)]:
        checks += 1
        if run("phc", b"d" + bad) != "exit 5":
            failures += 1
            print(f"FAIL phc accepted {bad!r}")
    print(f"{checks - failures}/{checks} input checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
