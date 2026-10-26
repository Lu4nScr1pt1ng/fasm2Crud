#!/usr/bin/env python3
"""Differential fuzzing of the request parser and the JSON parser.

usage: fuzz.py [cases per parser] [seed]

build/fuzz runs the assembly parsers on inputs that end at a PROT_NONE
page; every result is compared with the reference implementations below
(the HTTP one written from the rules in src/http/parser.inc, the JSON one
from tests/kat/differential_input.py, which is checked against Python's
json). A mismatch or a crash prints the input and fails.
"""
import importlib.util
import ipaddress
import json
import os
import random
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FUZZ = os.path.join(HERE, "..", "..", "build", "fuzz")
spec = importlib.util.spec_from_file_location("diff", os.path.join(HERE, "..", "kat", "differential_input.py"))
diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diff)

CASES = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else random.randrange(1 << 30)
rng = random.Random(SEED)

# ------------------------------------------------------------ reference HTTP

TCHAR = set(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
METHODS = {b"GET": 1, b"HEAD": 2, b"POST": 3, b"PUT": 4, b"PATCH": 5, b"DELETE": 6, b"OPTIONS": 7}
MAX_HEADERS = 64


def fold(b):
    return bytes(c | 0x20 for c in b)


def find_end(d):
    for i, c in enumerate(d):
        if c == 10:
            if i == 0 or d[i - 1] != 13:
                return -1
            if i >= 3 and d[i - 3:i + 1] == b"\r\n\r\n":
                return i + 1
    return 0


def ctl(c):
    return (c <= 0x1F and c != 9) or c == 0x7F


def parse(d):
    """Status (0 when valid) and the fields build/fuzz reports."""
    n = len(d)
    i = 0
    while i < n and d[i] in TCHAR:
        i += 1
    if i >= n or d[i] != 32 or i == 0:
        return 400, None
    method = METHODS.get(d[:i], 0)
    i += 1
    if d[i] != ord("/"):
        return 400, None
    start, q = i, None
    while True:
        c = d[i]
        if c == 32:
            break
        if not 0x21 <= c <= 0x7E or c == ord("#"):
            return 400, None
        if c == ord("?") and q is None:
            q = i + 1
        i += 1
        if i >= n:
            return 400, None
    path = (start, (q - 1 if q else i) - start)
    query = (q, i - q) if q else (-1, 0)
    i += 1
    if i + 10 > n:
        return 400, None
    v = d[i:i + 8]
    if v == b"HTTP/1.1":
        version = 11
    elif v == b"HTTP/1.0":
        version = 10
    elif v[:5] == b"HTTP/":
        return 505, None
    else:
        return 400, None
    if d[i + 8:i + 10] != b"\r\n":
        return 400, None
    i += 10
    hosts = headers = length = flags = 0
    found = {"ctype": (-1, 0), "auth": (-1, 0), "ifmatch": (-1, 0)}
    while d[i:i + 2] != b"\r\n":
        headers += 1
        if headers > MAX_HEADERS:
            return 431, None
        ns = i
        while d[i] in TCHAR:
            i += 1
            if i >= n:
                return 400, None
        if d[i] != ord(":") or i == ns:
            return 400, None
        name = fold(d[ns:i])
        i += 1
        while d[i] in (32, 9):
            i += 1
        vs = j = i
        while j < n and not ctl(d[j]):
            j += 1
        if j >= n or d[j:j + 2] != b"\r\n":
            return 400, None
        ve = j
        while ve > vs and d[ve - 1] in (32, 9):
            ve -= 1
        value = d[vs:ve]
        i = j + 2
        if len(name) == 4 and name == b"host":
            hosts += 1
            if hosts > 1:
                return 400, None
        elif len(name) == 8 and name == b"if-match":
            found["ifmatch"] = (vs, len(value))
        elif len(name) == 10 and name == b"connection":
            for tok in value.replace(b"\t", b",").replace(b" ", b",").split(b","):
                if len(tok) == 5 and fold(tok) == b"close":
                    flags |= 1
                elif len(tok) == 10 and fold(tok) == b"keep-alive":
                    flags |= 2
        elif len(name) == 12 and name == b"content-type":
            found["ctype"] = (vs, len(value))
        elif len(name) == 13 and name == b"authorization":
            found["auth"] = (vs, len(value))
        elif len(name) == 14 and name == b"content-length":
            if flags & 4:
                return 400, None
            flags |= 4
            if not value:
                return 400, None
            if len(value) > 9:
                return 413, None
            if not all(48 <= c <= 57 for c in value):
                return 400, None
            length = int(value)
        elif len(name) == 17 and name == b"transfer-encoding":
            return 501, None
    if version == 11 and hosts != 1:
        return 400, None
    return 0, (method, version, flags, hosts, headers, length, path, query,
               found["ctype"], found["auth"], found["ifmatch"])


def expected_http(data):
    end = find_end(data)
    if end <= 0:
        return (end, 0, None)
    status, fields = parse(data[:end])
    return (end, status, fields)


def read_http(out, pos):
    end, status = struct.unpack_from("<iI", out, pos)
    pos += 8
    if end <= 0 or status:
        return (end, status, None), pos
    m, v, f, h, hd, ln = struct.unpack_from("<6I", out, pos)
    pos += 24
    pairs = []
    for _ in range(5):
        off, length = struct.unpack_from("<iI", out, pos)
        pos += 8
        pairs.append((off, length))
    return (end, 0, (m, v, f, h, hd, ln, *pairs)), pos


def read_json(out, pos):
    code = out[pos]
    pos += 1
    values = {}
    for name in diff.FIELDS:
        present, length = out[pos], struct.unpack_from("<H", out, pos + 1)[0]
        pos += 3
        if present:
            values[name] = out[pos:pos + length]
            pos += length
    return (code, values if code == 0 else None), pos


def expected_json(body):
    code, values = diff.reference_json(body)
    return (code, values if code == 0 else None)


# ------------------------------------------------------------ reference IP

def expected_ipv4(data):
    # Four decimal octets of 1 to 3 digits, each at most 255 (leading zeros
    # allowed, unlike Python's parser, which is otherwise the reference).
    parts = data.split(b".")
    if len(parts) != 4 or not all(1 <= len(p) <= 3 and p.isdigit() and p.isascii() for p in parts):
        return (0, None)
    vals = [int(p) for p in parts]
    if any(v > 255 for v in vals):
        return (0, None)
    return (1, bytes(vals))


def expected_ipv6(data):
    # Python's ipaddress, without the forms the server does not take
    # (embedded IPv4, zones).
    if b"." in data or b"%" in data:
        return (0, None)
    try:
        return (1, ipaddress.IPv6Address(data.decode("ascii")).packed)
    except (ValueError, UnicodeDecodeError):
        return (0, None)


def read_ip(size):
    def read(out, pos):
        if out[pos] == 0:
            return (0, None), pos + 1
        return (1, bytes(out[pos + 1:pos + 1 + size])), pos + 1 + size
    return read


TRICKY_V6 = [b"::", b"::1", b"1::", b"1:2:3:4:5:6:7:8", b"1:2:3:4:5:6:7:8::", b"::1:2:3:4:5:6:7:8",
             b"1:2:3:4:5:6:7::", b"::2:3:4:5:6:7:8", b"1::8", b"1:::8", b"1::2::3", b":1", b"1:", b"1:2:3:4:5:6:7:8:9",
             b"12345::", b"fffff::", b"::ffff:1.2.3.4", b"fe80::1%eth0", b"", b":"]


def gen_ip(v6):
    r = rng.random()
    if v6 and r < 0.05:
        return rng.choice(TRICKY_V6)
    if v6:
        if r < 0.5:
            a = ipaddress.IPv6Address(rng.getrandbits(128) & rng.choice([(1 << 128) - 1, ((1 << 64) - 1) << 64, 0xFFFF << 112, 1]))
            text = rng.choice([a.compressed, a.exploded]).encode()
        else:
            text = b":".join(rng.choice([b"", b"0", b"ffff", b"12345", b"g", b"1", b"db8", b":"]) for _ in range(rng.randrange(1, 10)))
    else:
        if r < 0.5:
            text = ".".join(str(rng.randrange(256)) for _ in range(4)).encode()
        else:
            text = b".".join(rng.choice([b"", b"0", b"00", b"255", b"256", b"1234", b"a", b"001"]) for _ in range(rng.randrange(1, 6)))
    return mutate(text) if rng.random() < 0.3 else text


# ------------------------------------------------------------ generators

TARGETS = [b"/", b"/healthz", b"/v1/notes", b"/v1/notes?limit=5&cursor=x", b"/a?b?c", b"/%20", b"/a#b",
           b"*", b"http://x/", b"/\x7f", b"/\xc3\xa9", b"//", b"/?"]
NAMES = [b"Host", b"host", b"HOST", b"Content-Length", b"content-length", b"Transfer-Encoding",
         b"Connection", b"Content-Type", b"Authorization", b"If-Match", b"X-Pad", b"Hos t", b"Ho:st",
         b"", b"Content-Length ", b"\x00", b"Cookie", b"Te", b"Expect"]
VALUES = [b"", b"t", b" t ", b"\tt\t", b"5", b"05", b"-1", b"999999999", b"1234567890", b"close",
          b"Keep-Alive", b"close, keep-alive", b"chunked", b"application/json", b"Bearer abc",
          b"\"1\"", b"a\x01b", b"a\x7fb", b"a\rb", b"a\nb", b"\xff\xfe", b"x" * 300]
SEPS = [b"\r\n", b"\r\n", b"\r\n", b"\n", b"\r", b"\r\r\n", b" \r\n"]


GOOD_NAMES = [b"Connection", b"connection",
              b"Content-Type", b"Authorization", b"If-Match", b"X-Pad", b"Cookie", b"Accept",
              b"x-a!#$%&'*+-.^_`|~1"]
GOOD_VALUES = [b"", b"t", b" t ", b"\tt\t", b"5", b"0", b"999999999", b"close", b"Keep-Alive",
               b"close, keep-alive", b"keep-alive,close", b"x , close\t", b"application/json",
               b"Bearer abc", b'"1"', b"\x80\xff\xfe", b"a b\tc", b"x" * 300]


def gen_request():
    """A well-formed request, then at most a couple of targeted defects."""
    method = rng.choice([b"GET", b"POST", b"PATCH", b"DELETE", b"OPTIONS", b"HEAD", b"PUT",
                         b"BREW", b"get", b"M-SEARCH"])
    target = rng.choice(TARGETS[:6] + [b"/" + bytes(rng.randrange(0x21, 0x7F) for _ in range(rng.randrange(20)))])
    version = rng.choice([b"HTTP/1.1"] * 6 + [b"HTTP/1.0", b"HTTP/2.0", b"HTTP/1.2"])
    headers = []
    if version == b"HTTP/1.1" and rng.random() < 0.9:
        headers.append((rng.choice([b"Host", b"host", b"HOST"]), rng.choice([b"t", b"", b"a:b"])))
    if rng.random() < 0.4:
        headers.append((rng.choice([b"Content-Length", b"content-length"]),
                        str(rng.choice([0, 1, 17, 999999999, rng.randrange(10 ** 9)])).encode()))
    for _ in range(rng.choice([0, 1, 2, 3, 5, 8, 20, 63, 64, 65])):
        headers.append((rng.choice(GOOD_NAMES), rng.choice(GOOD_VALUES)))
    rng.shuffle(headers)
    lines = [method + b" " + target + b" " + version]
    for name, value in headers:
        lines.append(name + b":" + rng.choice([b"", b" ", b"\t", b"  "]) + value + rng.choice([b"", b" ", b"\t"]))
    data = b"\r\n".join(lines) + b"\r\n\r\n"
    for _ in range(rng.choice([0, 0, 0, 1, 1, 2])):
        data = defect(data)
    if rng.random() < 0.2:
        data += b"body" * rng.randrange(4)
    return data


def defect(data):
    """One targeted violation of the grammar."""
    d = rng.randrange(12)
    lines = data.split(b"\r\n")
    k = rng.randrange(len(lines))
    if d == 0:
        lines[k] = lines[k] + b"\n" + b"X: y"           # bare LF
    elif d == 1:
        lines[k] = lines[k].replace(b":", b" :", 1)      # space before colon
    elif d == 2:
        lines.insert(1, b"Transfer-Encoding: chunked")
    elif d == 3:
        lines.insert(1, b"Content-Length: 1")
        lines.insert(1, b"Content-Length: 1")
    elif d == 4:
        lines.insert(1, rng.choice([b"Content-Length: -1", b"Content-Length: 1x", b"Content-Length:",
                                    b"Content-Length: 1234567890", b"Content-Length: 1 2"]))
    elif d == 5:
        lines.insert(1, b"Host: other")                  # a second Host
    elif d == 6:
        lines[k] = lines[k] + bytes([rng.choice([0, 1, 8, 11, 12, 13, 27, 0x7F])])
    elif d == 7:
        lines.insert(rng.randrange(1, len(lines) + 1), b" folded")  # obs-fold
    elif d == 8:
        lines[0] = lines[0].replace(b" ", rng.choice([b"  ", b"\t", b""]), 1)
    elif d == 9:
        lines[0] = lines[0].replace(b"/", rng.choice([b"*", b"http://h/", b"/#f", b"/a b"]), 1)
    elif d == 10:
        lines.insert(1, rng.choice([b":x", b"Na me: x", b"N\x80: x", b"N@: x"]))
    else:
        data = data[:rng.randrange(len(data) + 1)]       # truncated
        return data
    return b"\r\n".join(lines)


def mutate(data):
    data = bytearray(data)
    for _ in range(rng.randrange(1, 6)):
        op = rng.randrange(6)
        p = rng.randrange(len(data) + 1)
        if op == 0 and data:
            data[min(p, len(data) - 1)] ^= 1 << rng.randrange(8)
        elif op == 1:
            data[p:p] = bytes([rng.choice([0, 9, 10, 13, 32, 58, 0x7F, 0xFF, rng.randrange(256)])])
        elif op == 2 and data:
            del data[p:p + rng.randrange(1, 8)]
        elif op == 3 and data:
            q = rng.randrange(len(data))
            data[p:p] = data[q:q + rng.randrange(1, 32)]
        elif op == 4:
            data[p:p] = rng.choice([b"\r\n", b"\r\n\r\n", b"\n", b'"', b"\\", b"\\u", b"{", b"}", b":"])
        else:
            data = data[:p]
    return bytes(data)


def gen_http():
    r = rng.random()
    if r < 0.75:
        data = gen_request()
    elif r < 0.97:
        data = mutate(gen_request())
    else:
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(64)))
    return data[:60000]


def gen_json():
    r = rng.random()
    if r < 0.4:
        doc = {}
        for name in rng.sample(["email", "password", "other", "e"], rng.randrange(4)):
            doc[name] = diff.random_value(rng)
        data = json.dumps(doc, ensure_ascii=rng.random() < 0.5).encode()
    elif r < 0.9:
        doc = {"email": diff.random_string(rng), "password": diff.random_string(rng)}
        data = mutate(json.dumps(doc, ensure_ascii=rng.random() < 0.5).encode())
    else:
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(48)))
    return data[:60000]


# ------------------------------------------------------------ driver

def run(cases):
    stream = b"".join(struct.pack("<BI", kind, len(data)) + data for kind, data in cases)
    p = subprocess.run([FUZZ], input=stream, capture_output=True)
    return p.returncode, p.stdout


def results(out, cases):
    pos, got = 0, []
    for kind, _ in cases:
        if pos >= len(out):
            break
        r, pos = (read_http, read_json, read_ip(4), read_ip(16))[kind](out, pos)
        got.append(r)
    return got


def find_crash(cases):
    lo, hi = 0, len(cases)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if run(cases[lo:mid])[0] != 0:
            hi = mid
        else:
            lo = mid
    return cases[lo]


def main():
    print(f"fuzz: {CASES} cases each of HTTP, JSON, IPv4 and IPv6, seed {SEED}")
    failures = 0
    batch = 4000
    for kind, gen, expect in ((0, gen_http, expected_http), (1, gen_json, expected_json),
                              (2, lambda: gen_ip(False), expected_ipv4), (3, lambda: gen_ip(True), expected_ipv6)):
        done = 0
        while done < CASES:
            cases = [(kind, gen()) for _ in range(min(batch, CASES - done))]
            code, out = run(cases)
            if code != 0:
                bad = find_crash(cases)
                print(f"CRASH (exit {code}) on {('HTTP', 'JSON', 'IPv4', 'IPv6')[kind]} input {bad[1]!r}")
                return 1
            for (k, data), got in zip(cases, results(out, cases)):
                want = expect(data)
                if got != want:
                    failures += 1
                    if failures <= 10:
                        print(f"MISMATCH {('HTTP', 'JSON', 'IPv4', 'IPv6')[k]} {data!r}\n  asm  {got}\n  ref  {want}")
            done += len(cases)
    if failures:
        print(f"{failures} mismatches (seed {SEED})")
        return 1
    print(f"{4 * CASES} fuzz cases agree with the reference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
