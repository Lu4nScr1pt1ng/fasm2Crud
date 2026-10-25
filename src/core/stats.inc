; Counters each process keeps for /metrics (src/app/metrics.inc): the
; block layout and the macros the rest of the code counts with. g_metrics
; is this process's block; it is valid from the start (a private block
; until the supervisor maps the shared region).

M_STRIDE	= 1024		; per worker, cache-line aligned
M_RESP		= 0		; u64 per ST_xxx (at most 32)
M_HIST		= 256		; u64 per latency bucket (not cumulative)
M_HIST_SUM	= 384		; microseconds
M_HIST_COUNT	= 392
M_ACCEPTED	= 400
M_ACTIVE	= 408		; gauge
M_DB_QUERIES	= 416
M_DB_ERRORS	= 424
M_DB_UNAVAILABLE = 432
M_DB_READY	= 440		; gauge
M_HASH_JOBS	= 448
M_HASH_BUSY	= 456
M_HASH_RESTARTS	= 464
M_HASH_QUEUE	= 472		; gauge
M_LARGE_INUSE	= 480		; gauge
M_LARGE_EXHAUSTED = 488
M_RETURNED	= 496		; bytes given back to the kernel
M_RATE_LIMITED	= 504
M_RESTARTS	= 512		; supervisor block only: worker restarts
M_GAUGES_END	= 520

bss
	align 8
	g_metrics	dq ?
end bss

; Count one event.
macro metric_inc field*
	push	rax
	mov	rax,[g_metrics]
	inc	qword [rax+field]
	pop	rax
end macro

; Add a register to a counter.
macro metric_add field*, reg*
	push	rax
	mov	rax,[g_metrics]
	add	qword [rax+field],reg
	pop	rax
end macro
