; Compile-time limits. Every buffer and table in the server is sized from
; these numbers at startup; nothing grows at runtime.

DEFAULT_PORT		= 8080
DEFAULT_MAX_CONNS	= 8192		; per worker
MIN_MAX_CONNS		= 16
MAX_MAX_CONNS		= 65536
MAX_WORKERS		= 256
LISTEN_BACKLOG		= 4096

RING_ENTRIES		= 4096		; submission queue
CQ_ENTRIES		= 16384		; completion queue
REAP_BUDGET		= 1024		; completions handled before flushing submissions

; Connection block: header, input buffer and output buffer in one slot.
CONN_SHIFT		= 14
CONN_BLOCK		= 1 shl CONN_SHIFT
IN_OFF			= 256
IN_CAP			= 8192 - IN_OFF	; largest request (headers + body)
OUT_OFF			= 8192
OUT_CAP			= 8192
RESP_RESERVE		= 1024		; room a handler may need for one response

MAX_HEADERS		= 64

DEFAULT_BUSY_POLL_US	= 0

; Timeouts in timer ticks (one tick per second).
IDLE_TIMEOUT		= 60		; keep-alive connection with nothing in flight
REQUEST_TIMEOUT		= 10		; partial request or response not yet drained
LINGER_TIMEOUT		= 2		; lingering close after the last response
DRAIN_TIMEOUT		= 10		; graceful shutdown
LINGER_MAX_BYTES	= 65536

; Process exit codes.
EXIT_OK			= 0
EXIT_FAILURE		= 1
EXIT_CONFIG		= 2
EXIT_FATAL		= 3		; worker could not start: supervisor gives up
