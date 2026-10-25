# Architecture

fasm2crud is an HTTP/1.1 JSON API written in x86-64 assembly (fasm2) for
Linux. This document records how it is built and why.

## Process model

```
supervisor (PID 1 in the container)
 ├─ owns one SO_REUSEPORT listening socket per worker
 ├─ worker 0  ── pinned to CPU 0 ── io_uring ── its own memory, sockets, DB connections
 ├─ worker 1  ── pinned to CPU 1 ── ...
 └─ worker N-1
```

* **Shared-nothing.** Workers are processes, not threads. There is no lock,
  no atomic and no shared cache line between them on the request path.
* **Fault isolation.** A worker that crashes takes only its own connections
  with it. The supervisor reaps it through a signalfd and forks a
  replacement. Crash loops are slowed to one restart every 250 ms. A worker
  that cannot start at all (exit code 3: no io_uring, no memory) shuts the
  whole service down instead of restarting forever.
* **No lost accept queue.** The supervisor creates all listening sockets
  before forking and keeps them open. Connections the kernel routed to a
  crashed worker's socket wait in its queue for the replacement. Measured:
  three workers killed with SIGKILL during a 6M-request run cost 235 requests.
* **Graceful shutdown.** On SIGTERM a worker stops accepting, closes idle
  connections and answers in-flight requests with `Connection: close`.
  After `DRAIN_TIMEOUT` it closes whatever is left. A second SIGTERM to the
  supervisor kills the workers outright.
* Workers die with the supervisor (`PR_SET_PDEATHSIG`).

## I/O: io_uring

Each worker owns one ring, set up with:

| Flag | Why |
|---|---|
| `SINGLE_ISSUER`, `DEFER_TASKRUN` | completions run on our thread, only when we ask: no IPIs, better cache locality |
| `SUBMIT_ALL` | one failing SQE does not hold back the rest of the batch |
| `NO_SQARRAY` | the SQ tail indexes SQEs directly; one less indirection |
| `CQSIZE` (4x SQ) | headroom for multishot completions |

* **Multishot accept** into **direct descriptors**
  (`IORING_FILE_INDEX_ALLOC`). Sockets never enter the process fd table,
  which saves `fdget`/`fdput` on every operation.
* One `io_uring_enter` per loop iteration submits all queued SQEs and waits
  for completions. After `REAP_BUDGET` completions the loop flushes
  submissions early to keep latency bounded under load.
* The ring fd is registered (`IORING_REGISTER_RING_FDS`), so
  `io_uring_enter` skips the fd lookup.
* Optional adaptive busy polling (`API_BUSY_POLL_US`): after a completion
  the worker keeps polling the ring for that long before blocking, which
  avoids a sleep and wakeup per request at moderate load. Time is measured
  with the TSC, calibrated at startup.
* A multishot 1 s timeout drives connection timeouts and the cached `Date`
  header.
* Signals arrive as reads on a signalfd, through the same ring.

### Single-shot recv into the connection buffer

We use single-shot `RECV` into each connection's own input buffer, not
multishot recv with a provided-buffer ring. Provided buffers are copied
whenever a request spans two buffers, and they make backpressure awkward
because the kernel keeps filling them. With one recv in flight per
connection, reading is zero-copy. Backpressure is also natural: while the
output buffer is full we do not post a recv, so TCP flow control slows the
client down. A client that pipelines without reading its responses costs us
a fixed 16 KiB, measured at 632 KB of RSS for the whole worker under such a
flood.

## Memory

No `malloc`, no `free`, no growth after startup.

* All connection memory is reserved with one `mmap` at startup, with
  `PROT_NONE` guard pages at both ends. A connection slot is 16 KiB:
  a 256-byte header, about 8 KiB of input and 8 KiB of output.
* Slots come from a LIFO free list. The most recently freed slot, still hot
  in cache and already faulted in, is reused first, so resident memory
  follows the number of concurrent connections, not `API_MAX_CONNS`. Idle
  workers use about 1 MB.
* Requests are parsed in place. Responses are written in place.
* Every limit is explicit (see `src/core/config.inc`): request size, header
  count, response reserve, connection count. When one is reached, the
  server answers 413, 431 or 503 or applies backpressure. It never
  allocates more.
* SIMD scans read at most 31 bytes past the data. The connection layout
  guarantees that memory is mapped.

## HTTP

Strict RFC 9112 parsing. Anything ambiguous is rejected and the connection
is closed:

* bare LF, whitespace before `:`, control bytes in field values;
* duplicate or non-numeric `Content-Length`;
* `Transfer-Encoding` of any kind (501). Accepting no chunked bodies removes
  CL/TE request smuggling by construction;
* a missing or repeated `Host` in HTTP/1.1;
* absolute-form, asterisk-form and fragments in the target.

The header terminator search and the field-value validation use AVX2
(32 bytes per step). The terminator search resumes where it stopped, so a
client trickling one byte at a time costs linear time, not quadratic.

Keep-alive and pipelining are supported. Responses for pipelined requests
are batched into one send.

Timeouts: 60 s for an idle keep-alive connection, and 10 s for a partial
request or an undrained response (slowloris). Closes are lingering: we send
FIN and discard input for up to 2 s, so the last response is not destroyed
by an RST.

The listener sets `TCP_DEFER_ACCEPT`, so connections that never send a byte
never reach the server.

## Database: PostgreSQL 18

PostgreSQL 18 runs with `io_method = io_uring`, UUIDv7 keys (time ordered,
so B-tree inserts stay on the right edge) and `synchronous_commit = on`: a
2xx response means the write survives a crash.

The API connects as the `api` role. It can read and write rows and nothing
else (no DDL, no superuser).

### Client (`src/db/`)

The frontend/backend protocol v3 is spoken directly from assembly, over
the same io_uring as the HTTP traffic. Each worker keeps `API_DB_CONNS`
connections:

```
IDLE -> CONNECTING -> AUTH -> PREPARING -> READY
             \_________\__________\________\__> BROKEN -> IDLE (backoff)
```

* **Authentication:** SCRAM-SHA-256 only. Cleartext and MD5 requests are
  refused. The server's final signature is verified, so whoever answers
  must know the password. The nonce comes from getrandom.
* **Prepared statements:** every statement in the table (`pg_statement`)
  is parsed once per connection, right after login.
* **Pipelining:** a query is Bind + Execute + Sync, appended to the
  connection's transmit buffer. One send in flight carries every query
  queued since the previous one, and up to 128 queries wait per
  connection. Replies arrive in order and a FIFO matches each
  ReadyForQuery to its HTTP request. With Sync per query, an error aborts
  only that query.
* **Text format** for parameters and results: rows go straight into JSON.
  Parameters travel separately from the SQL text, so SQL injection is
  impossible by construction.
* **Waiting requests:** the HTTP connection stops reading (F_WAIT_DB) until
  its reply arrives, so pipelined requests are answered in order and a
  slow database pushes back through TCP. A generation counter per slot
  drops replies for clients that disconnected meanwhile.
* **Failures:** a broken connection answers every waiting request with 503
  at once and reconnects after an exponential backoff, from 100 ms doubling
  to 5 s with jitter. When no connection is ready, requests get 503
  immediately (a circuit breaker by construction). Deadlines: 3 s to
  connect, 5 s for the handshake, 15 s without a reply while queries wait,
  `statement_timeout` 5 s on the server, TCP keepalive and
  `TCP_USER_TIMEOUT` 10 s.
* **Addressing:** there is no DNS resolver. Compose gives the database a
  fixed address (10.231.0.10) and `API_DB_HOST` points at it.

Measured (API on 4 cores, PostgreSQL on 2, `GET /readyz` = one `SELECT 1`
per request): 32 us p50 for a single client, about 280-300k queries/s
under load, and zero non-2xx responses. During a database restart under
traffic, clients only saw 200 or 503 (never a hang or a reset), and 200
was back 0.4 s after PostgreSQL. One connection per worker gives the most
throughput, because more queries share each packet; two (the default)
give a better tail and survive the loss of one.

## Authentication

| Piece | Choice | Why |
|---|---|---|
| Password hashing | Argon2id (RFC 9106), BLAKE2b in AVX2 | memory-hard; hash functions keep their security against quantum attackers |
| Access token | stateless, 15 min, HMAC-SHA-256 with SHA-NI and a 256-bit key | Grover's algorithm leaves 128-bit security; verifying costs nanoseconds and no database access |
| Refresh token | 256 random bits, stored as SHA-256, rotated on every use; reuse revokes the whole family | real revocation |
| Signatures (ML-DSA) | not used for tokens | only useful when third parties verify tokens; 2.4 KB signatures for no gain here |
| Transport | TLS 1.3 with X25519MLKEM768, terminated at the edge | protects against harvest-now-decrypt-later |

### Endpoints (`src/app/auth.inc`)

| Endpoint | Body | Answer |
|---|---|---|
| `POST /v1/auth/register` | `email`, `password` | 201 `{"id","email"}`, 409 when taken |
| `POST /v1/auth/login` | `email`, `password` | 200 tokens, 401 |
| `POST /v1/auth/refresh` | `refresh_token` | 200 new tokens, 401; the old token is spent |
| `POST /v1/auth/logout` | `refresh_token` | 204; ends that login (the whole family) |

Bodies are strict JSON (`application/json`, else 415): malformed is 400,
a wrong shape or an unacceptable address or password is 422. Addresses
are lowercased. A wrong password and an unknown address get the same 401
after the same work: unknown addresses are hashed against a dummy salt.
Reusing a spent refresh token revokes its family, and a family with any
revoked token never rotates again, which also covers two refreshes racing
for the same token and a logout racing a refresh. `API_TOKEN_KEY` (32
bytes, base64url) signs access tokens; without it the supervisor makes a
random key, shared by the workers, that dies with the process.

A request keeps its state in an auth context (a fixed pool of 128 per
worker, wiped on release) across its hasher and database round trips;
while it waits, its HTTP connection stops reading, exactly as for a query.

### The hasher process

Argon2id is expensive on purpose (11 ms and 19 MiB per hash), so it never
runs on the event loop. Each worker forks a hasher and talks to it over a
`SOCK_SEQPACKET` socketpair: one message per job, one per reply, and the
replies are read through the worker's ring. The hasher:

* runs at nice 10 on any CPU of the service, so a worker with requests to
  serve wins its CPU back;
* keeps only its socket, cannot be dumped or traced (`PR_SET_DUMPABLE` 0),
  and installs a seccomp filter before its first job: from then on it can
  read, write and exit, and any other system call kills it. Memory is
  reserved before that. Strict mode would allow the same set, but it cannot
  be entered under an existing filter such as Docker's, while filters
  stack. A hasher that cannot install the filter exits instead of serving;
* dies with its worker. If it dies first, its jobs are answered with 503
  at once and a new hasher starts on the next tick.

At most 16 jobs wait per worker; beyond that, auth requests get 503 with
`Retry-After: 1`. Measured with one worker and 100 concurrent logins: 16
accepted, 84 refused with 503, and `GET /healthz` on the same worker kept a
0.08 ms median (0.25 ms max) while the hashes ran.

## Notes (`src/app/notes.inc`)

| Endpoint | Body | Answer |
|---|---|---|
| `GET /v1/notes?limit=&cursor=` | | 200 `{"items":[summary],"next_cursor"}` |
| `POST /v1/notes` | `title`, `body`? | 201 note, `Location`, `ETag` |
| `GET /v1/notes/{id}` | | 200 note, `ETag` |
| `PATCH /v1/notes/{id}` | `title`?, `body`? | 200 note, `ETag`; needs `If-Match` |
| `DELETE /v1/notes/{id}` | | 204; needs `If-Match` |

Every request needs `Authorization: Bearer <access token>` (401 with
`WWW-Authenticate: Bearer` otherwise), checked in the worker with no
database access. Notes of other users are 404, never 403.

* **Optimistic concurrency.** The ETag is the version. PATCH and DELETE
  need `If-Match: "<version>"`: 428 without it, 412 with the current ETag
  when it is stale. The version check and the write are one statement,
  and the row lock makes a concurrent writer re-check the version after
  the first commits: of 8 concurrent PATCHes of one version, exactly one
  succeeds.
* **Keyset pagination**, newest first, over the `(user_id, id DESC)` index:
  `cursor` is the last id seen, so a page costs the same however deep it
  is and concurrent inserts never shift it. `limit` is 1..50 (default 20);
  the query asks for one row more to know whether another page follows.
* **Sizes follow from the memory model.** A response is written in place
  into the connection's 8 KiB output buffer, so a note must always fit:
  title 1..200 bytes and body up to 3000 bytes of UTF-8, with no control
  characters but tab, LF and CR (each escapes to at most two bytes). A
  notes request waits, unparsed, until the output buffer has room for the
  largest note (`route_output_need`), so pipelined requests are delayed,
  never cut. A page of summaries stops early when the buffer is full and
  sets `next_cursor` there; following the cursors still returns every note
  exactly once.
* Times come from the database as RFC 3339 in UTC with microseconds.

Measured (the reference split: API on 4 cores, PostgreSQL on 2, wrk with
32 connections): `GET /v1/notes/{id}` 73k req/s (p50 0.34 ms), a page of
20 summaries 48k req/s (p50 0.52 ms), against 385k req/s for `/healthz`
on the same run. Token checks and JSON cost little next to the query.



All primitives live in `src/crypto/` and are checked by `build/kat`
(published test vectors) and `tests/kat/differential.py` (random inputs
compared with hashlib and the system libargon2, the RFC 9106 reference
implementation), both part of `make test`.

| Primitive | Implementation | Speed (Zen 3, one core) |
|---|---|---|
| SHA-256 | SHA-NI, Intel reference structure | 2.25 GB/s, same as OpenSSL |
| HMAC-SHA-256, PBKDF2 | key schedule expanded once per key | |
| BLAKE2b | scalar, 12 rounds unrolled at assembly time | only used inside Argon2 |
| Argon2d/i/id v1.3 | compression G in AVX2 (four 64-bit lanes per register) | 11 ms for m=19 MiB, t=2, p=1 (libargon2: 14 ms) |

Secrets are compared in constant time, and buffers that held them (hash
contexts, the Argon2 memory and its stack frame) are wiped before return.

## Docker

* The build stage fetches fasm2 at a pinned commit and verifies the
  assembler's SHA-256.
* The runtime image is `FROM scratch`: the 11 KB binary, running as nobody
  on a read-only root with all capabilities dropped.
* The healthcheck is `fasm2crud healthcheck`, since the image has no shell
  or curl.
* `docker/seccomp.json` is Docker's default profile (moby/profiles) plus
  `io_uring_setup`, `io_uring_enter` and `io_uring_register`. The default
  profile blocks io_uring. PostgreSQL uses the same profile for its own
  io_uring.

## Benchmarking honestly

* Pin the API, the database and the load generator to separate physical
  cores (`API_CPUS`, `PG_CPUS`, `BENCH_CPUS`; the defaults split a 5700G
  4/2/2). Otherwise they compete for the same cores and the numbers mean
  little.
* Target the container's bridge IP (`tests/bench.sh`). Published ports on
  loopback go through the userland docker-proxy: 295k req/s through it
  against 755k req/s direct, on the same build.
* Use wrk2 for latency percentiles (it corrects coordinated omission). Plain
  wrk understates tail latency under load.

* On this machine CPUs N and N+8 are SMT siblings (`lscpu -e`). Splitting
  0-7 / 8-15 puts the server and the client on the same physical cores.

### Where the time goes

Under load, 95% of the workers' CPU time is in the kernel (TCP, loopback,
io_uring) and 5% in our code. Faster user code can win at most that 5%;
what moves latency is how the server waits for work and how load spreads
over workers.

### Reference numbers

Ryzen 7 5700G. API with 8 workers on physical cores 0-3 and their SMT
siblings (8-11), wrk on 4-7 and 12-15. `GET /healthz`, closed loop, wrk 4.2:

| connections | busy poll off | busy poll 50 us |
|---|---|---|
| 1 | 57k req/s, p50 16 us, p99 27 us | 65k req/s, p50 14 us, p99 23 us |
| 8 | 330k req/s, p50 21 us, p99 265 us | 362k req/s, p50 18 us, p99 31 us |
| 16 | 516k req/s, p50 24 us, p99 393 us | 532k req/s, p50 25 us, p99 1.08 ms |
| 64 | 691k req/s, p50 58 us, p99 1.05 ms | 652k req/s, p50 51 us, p99 2.41 ms |

Throughput levels off at about 650-700k req/s from roughly 24 connections
on. Past that point, extra concurrency only adds queueing (Little's law: 512
requests in flight at 700k req/s is 0.7 ms of wait), so millisecond
percentiles at 64 or 512 connections describe a saturated machine, not
the server's service time. The rare millisecond p99 at 16-48 connections
comes from scheduling noise, with client, server and loopback softirqs
sharing four physical cores, and from SO_REUSEPORT hashing a few
connections unevenly over workers. A real NIC with RSS and a separate
client machine remove both. Fixed-rate (open-loop) latency curves need
wrk2; oha's own overhead (p50 152 us at 50k req/s) hides the server.

Measured and rejected: one accept queue shared by all workers (4x lower
throughput, see `supervisor.inc`).

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | layout, pinned toolchain, Docker, compose, PostgreSQL, schema | done |
| 1 | supervisor, workers, io_uring, HTTP/1.1, health endpoints | done |
| 2 | memory pools, limits, timeouts, graceful shutdown | done |
| 3 | crypto with known-answer tests: SHA-256 (SHA-NI), HMAC, PBKDF2, BLAKE2b, Argon2id, getrandom | done |
| 4 | PostgreSQL client: startup, SCRAM, prepared statements, pipelining, reconnect with backoff, circuit breaker | done |
| 5 | auth: register, login, refresh, logout, isolated hasher process | done |
| 6 | notes CRUD, JSON, keyset pagination, If-Match | done |
| 7 | seccomp filter inside the binary, rate limiting, fuzzing, `/metrics` | next |
| 8 | stress tests, `perf`, tuning | |
| 9 (optional) | TLS 1.3 with ML-KEM in assembly | |
