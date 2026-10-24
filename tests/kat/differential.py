#!/usr/bin/env python3
"""Compare build/kat against reference implementations on many inputs:
hashlib/hmac for SHA-256, HMAC and BLAKE2b (every block-boundary length),
and the system libargon2 for Argon2d/i/id over random parameters."""
import hashlib
import hmac
import os
import random
import subprocess
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import argon2_ref  # noqa: E402
import base64  # noqa: E402

KAT = os.path.join(os.path.dirname(__file__), "..", "..", "build", "kat")


def run(mode, data):
    out = subprocess.run([KAT, mode], input=data, capture_output=True)
    return out.stderr.decode().strip() if out.returncode == 0 else None


def main():
    rng = random.Random(1)
    sizes = list(range(0, 600)) + [rng.randrange(600, 1_000_000) for _ in range(40)]
    failures = 0
    for n in sizes:
        data = rng.randbytes(n)
        if run("sha256", data) != hashlib.sha256(data).hexdigest():
            print(f"FAIL sha256 length {n}")
            failures += 1
    for _ in range(300):
        key = rng.randbytes(rng.choice([0, 1, 31, 32, 63, 64, 65, 127, 128, 200, rng.randrange(300)]))
        msg = rng.randbytes(rng.randrange(400))
        raw = len(key).to_bytes(2, "little") + key + msg
        if run("hmac", raw) != hmac.new(key, msg, "sha256").hexdigest():
            print(f"FAIL hmac key {len(key)} msg {len(msg)}")
            failures += 1
    checks = len(sizes) + 300
    for n in list(range(0, 400)) + [rng.randrange(400, 1_000_000) for _ in range(20)]:
        outlen = rng.randrange(1, 65)
        data = rng.randbytes(n)
        checks += 1
        if run("blake2b", bytes([outlen]) + data) != hashlib.blake2b(data, digest_size=outlen).hexdigest():
            print(f"FAIL blake2b length {n} digest {outlen}")
            failures += 1
    for _ in range(150):
        kind = rng.randrange(3)
        t = rng.randrange(1, 5)
        p = rng.randrange(1, 5)
        m = rng.randrange(8 * p, 300)
        outlen = rng.choice([4, 16, 32, 64, 65, 100, 128, rng.randrange(4, 513)])
        fields = [rng.randbytes(rng.randrange(0, 80)), rng.randbytes(rng.randrange(8, 40)),
                  rng.randbytes(rng.choice([0, 0, 8, 32])), rng.randbytes(rng.choice([0, 0, 12]))]
        raw = struct.pack("<5I", kind, t, m, p, outlen)
        for f in fields:
            raw += struct.pack("<I", len(f)) + f
        want = argon2_ref.argon2(kind, t, m, p, outlen, *fields).hex()
        checks += 1
        if run("argon2", raw) != want:
            print(f"FAIL argon2 type {kind} t={t} m={m} p={p} tag {outlen}")
            failures += 1
    for n in range(0, 300):
        data = rng.randbytes(n)
        expect = [base64.b64encode(data), base64.urlsafe_b64encode(data).rstrip(b"=")]
        for mode in (0, 1):
            checks += 1
            if run("base64", bytes([mode]) + data) != expect[mode].hex():
                print(f"FAIL base64 encode mode {mode} length {n}")
                failures += 1
        for mode in (2, 3):
            checks += 1
            if run("base64", bytes([mode]) + expect[mode - 2]) != data.hex():
                print(f"FAIL base64 decode mode {mode} length {n}")
                failures += 1
    total = checks
    print(f"{total - failures}/{total} differential checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
