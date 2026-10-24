#!/usr/bin/env python3
"""Compare build/kat against Python's hashlib/hmac on many input sizes,
covering every block-boundary case of the streaming code."""
import hashlib
import hmac
import os
import random
import subprocess
import sys

KAT = os.path.join(os.path.dirname(__file__), "..", "..", "build", "kat")


def run(mode, data):
    out = subprocess.run([KAT, mode], input=data, capture_output=True, check=True)
    return out.stderr.decode().strip()


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
    total = len(sizes) + 300
    print(f"{total - failures}/{total} differential checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
