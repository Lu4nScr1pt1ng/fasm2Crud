# fasm2crud

An HTTP/1.1 JSON API written in pure x86-64 assembly (fasm2), with no libc.
It uses io_uring, runs one shared-nothing worker per CPU, allocates nothing
after startup, and stores data in PostgreSQL 18.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and roadmap.

## Requirements

* Linux 6.6+ on an x86-64-v3 CPU (AVX2, BMI2)
* Docker with Compose v2, for the full stack
* `git`, `make`, and `python3` for the tests

## Build and run

```sh
make            # fetches the pinned fasm2 into .toolchain/ and assembles build/fasm2crud
make test       # starts the binary on port 18080 and runs the HTTP conformance suite
./build/fasm2crud
```

With Docker:

```sh
cp .env.example .env    # change the passwords
make up                 # api + postgres
curl -i http://127.0.0.1:8080/healthz
make bench              # wrk/oha against the container
make down
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `API_PORT` | `8080` | listening port |
| `API_WORKERS` | CPUs available to the process | worker processes |
| `API_MAX_CONNS` | `8192` | connections per worker |

## Endpoints

| Method | Path | |
|---|---|---|
| GET | `/healthz` | liveness |
| GET | `/readyz` | readiness (will include the database) |

## Layout

```
src/main.asm            entry point and segment layout
src/sys/                kernel ABI: syscalls, io_uring
src/core/               supervisor, worker loop, ring, connections, helpers
src/http/               parser, responses, status table, Date header
src/app/                routes
src/tools/              healthcheck subcommand
docker/                 seccomp profile, PostgreSQL config and schema
tests/                  conformance suite, smoke test, benchmark
```
