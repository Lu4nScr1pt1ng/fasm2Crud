; fasm2crud: HTTP/1.1 JSON API in x86-64 assembly for Linux.
;
; Static ELF, no libc, raw syscalls. A supervisor process forks one worker
; per CPU; each worker runs its own io_uring event loop over its own
; SO_REUSEPORT socket and its own preallocated memory (shared-nothing).

format ELF64 executable 3
entry start

include 'core/sections.inc'
include 'sys/linux.inc'
include 'sys/uring.inc'
include 'core/config.inc'
include 'http/status.inc'

segment readable executable

include 'core/util.inc'
include 'core/start.inc'
include 'core/supervisor.inc'
include 'core/worker.inc'
include 'core/ring.inc'
include 'core/conn.inc'
include 'core/base64.inc'
include 'core/hex.inc'
include 'crypto/ct.inc'
include 'crypto/sha256.inc'
include 'crypto/hmac.inc'
include 'crypto/blake2b.inc'
include 'crypto/argon2.inc'
include 'crypto/phc.inc'
include 'db/scram.inc'
include 'db/pg.inc'
include 'http/date.inc'
include 'http/parser.inc'
include 'http/json.inc'
include 'http/handler.inc'
include 'app/validate.inc'
include 'auth/ctx.inc'
include 'auth/password.inc'
include 'auth/token.inc'
include 'app/router.inc'
include 'app/auth.inc'
include 'app/notes.inc'
include 'tools/healthcheck.inc'

segment readable
	rodata_emit

segment readable writeable
	bss_emit

segment gnustack
