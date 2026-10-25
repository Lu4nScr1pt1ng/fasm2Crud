; Metrics, in the Prometheus text format at GET /metrics.
;
; Workers share nothing on the request path, so each one counts into its
; own block of a MAP_SHARED region the supervisor maps before forking:
; plain increments on cache lines no other process writes, no atomics.
; /metrics, answered by whichever worker gets it, adds up every block, so
; any worker reports the whole service. Blocks outlive their worker:
; counters stay monotonic across restarts, and a new worker resets only
; its gauges, which it republishes every tick. Aligned 64-bit loads are
; atomic on x86-64, so a sum may be a moment old but never torn.
;
; API_METRICS=off answers 404 there instead.

HIST_BUCKETS	= 15		; plus +Inf
assert STATUS.count <= 32

rodata
	align 8
	; Bucket upper bounds in microseconds, and as text in seconds.
	hist_us		dq 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000
			dq 100000, 250000, 500000, 1000000, 2500000
	hist_le:
	db 7, '0.00005'
	db 6, '0.0001'
	db 7, '0.00025'
	db 6, '0.0005'
	db 5, '0.001'
	db 6, '0.0025'
	db 5, '0.005'
	db 4, '0.01'
	db 5, '0.025'
	db 4, '0.05'
	db 3, '0.1'
	db 4, '0.25'
	db 3, '0.5'
	db 1, '1'
	db 3, '2.5'
end rodata

bss
	align 8
	g_metrics_base	dq ?		; shared: (workers + 1) blocks
	g_metrics_on	dd ?
	align 8
	g_hist_cycles	rq HIST_BUCKETS
end bss

cstring env_metrics, 'API_METRICS='
cstring str_off, 'off'

; Supervisor, before forking. Without the region (mmap failing) metrics
; are off and the counters go to a private block.
metrics_init:
	mov	dword [g_metrics_on],1
	lea	rdi,[env_metrics]
	mov	esi,env_metrics.len
	call	getenv
	test	rax,rax
	jz	@f
	cmp	dword [rax],'off'		; "off" and its NUL
	jne	@f
	mov	dword [g_metrics_on],0
@@:
	mov	esi,[g_workers]
	inc	esi
	shl	esi,10				; M_STRIDE
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jb	@f
	lea	rax,[g_metrics_private]
	mov	dword [g_metrics_on],0
@@:
	mov	[g_metrics_base],rax
	mov	[g_metrics],rax
	ret

bss
	align 64
	g_metrics_private: rb 2 * M_STRIDE
end bss

; Worker start: its block, gauges reset, bucket bounds in TSC cycles.
metrics_worker:
	mov	eax,[g_worker_id]
	cmp	dword [g_metrics_on],0
	jne	@f
	xor	eax,eax				; private: one block
@@:
	shl	rax,10
	add	rax,[g_metrics_base]
	mov	[g_metrics],rax
	mov	qword [rax+M_ACTIVE],0
	mov	qword [rax+M_DB_READY],0
	mov	qword [rax+M_HASH_QUEUE],0
	mov	qword [rax+M_LARGE_INUSE],0
	xor	ecx,ecx
@@:
	mov	rax,[hist_us+rcx*8]
	imul	rax,[g_tsc_per_us]
	mov	[g_hist_cycles+rcx*8],rax
	inc	ecx
	cmp	ecx,HIST_BUCKETS
	jb	@b
	ret

; Supervisor: a worker had to be restarted.
metrics_restart:
	mov	eax,[g_workers]
	shl	rax,10
	add	rax,[g_metrics_base]
	inc	qword [rax+M_RESTARTS]
	ret

; Once per tick: publish the gauges.
metrics_tick:
	mov	rdx,[g_metrics]
	mov	eax,[g_active_count]
	mov	[rdx+M_ACTIVE],rax
	call	db_ready_count
	mov	rdx,[g_metrics]
	mov	[rdx+M_DB_READY],rax
	mov	eax,[g_hasher_jobs]
	mov	[rdx+M_HASH_QUEUE],rax
	mov	eax,[g_large_pool+P_COUNT]
	sub	eax,[g_large_pool+P_TOP]
	mov	[rdx+M_LARGE_INUSE],rax
	ret

; A response with status esi is being written: count it, and if its
; request was timed (C_T0), add the time to the histogram. r12 = conn.
; Preserves everything but rax, rcx, rdx, r8.
metrics_response:
	mov	r8,[g_metrics]
	mov	eax,esi
	inc	qword [r8+M_RESP+rax*8]
	mov	rcx,[r12+C_T0]
	test	rcx,rcx
	jz	.done
	mov	qword [r12+C_T0],0
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,rcx				; cycles
	xor	ecx,ecx
.bucket:
	cmp	rax,[g_hist_cycles+rcx*8]
	jbe	.found
	inc	ecx
	cmp	ecx,HIST_BUCKETS
	jb	.bucket
.found:
	inc	qword [r8+M_HIST+rcx*8]
	inc	qword [r8+M_HIST_COUNT]
	mov	rcx,[g_tsc_per_us]
	xor	edx,edx
	div	rcx
	add	[r8+M_HIST_SUM],rax
.done:
	ret

; ---------------------------------------------------------------- /metrics

cstring ct_metrics, 'Content-Type: text/plain; version=0.0.4',13,10

; Sum of a u64 field over every worker block. eax = offset. rax = sum.
metrics_sum:
	mov	ecx,[g_workers]
	cmp	dword [g_metrics_on],0
	jne	@f
	mov	ecx,1
@@:
	mov	rdx,[g_metrics_base]
	add	rdx,rax
	xor	eax,eax
.each:
	add	rax,[rdx]
	add	rdx,M_STRIDE
	dec	ecx
	jnz	.each
	ret

; One "name value" line: rsi = name text, ecx = length (written as is,
; labels included), rax = value. rdi is advanced.
metrics_line:
	push	rax
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	pop	rax
	call	write_u64
	mov	byte [rdi],10
	inc	rdi
	ret

; "# TYPE name kind" then "name value" for a plain metric summed over
; workers. Used as: metrics_scalar 'name', 'counter', M_xxx.
macro metrics_scalar name*, kind*, field*
	local n
	put_lit '# TYPE ', name, ' ', kind, 10
	mov	eax,field
	call	metrics_sum
	cstring n, name
	lea	rsi,[n]
	mov	ecx,n.len
	call	metrics_line
end macro

; Everything, into rdi. rdi is advanced.
metrics_write:
	push	rbx
	push	r13
	push	r14
	put_lit '# HELP fasm2crud_http_responses_total HTTP responses by status code.',10
	put_lit '# TYPE fasm2crud_http_responses_total counter',10
	xor	ebx,ebx
.status:
	put_lit 'fasm2crud_http_responses_total{code="'
	mov	eax,ebx
	shl	eax,5
	mov	rsi,[status_tbl+rax]
	add	rsi,9				; "HTTP/1.1 " then three digits
	mov	ecx,3
	rep	movsb
	put_lit '"} '
	mov	eax,ebx
	shl	eax,3
	call	metrics_sum
	call	write_u64
	mov	byte [rdi],10
	inc	rdi
	inc	ebx
	cmp	ebx,STATUS.count
	jb	.status

	put_lit '# HELP fasm2crud_http_request_duration_seconds Time from a parsed request to its response.',10
	put_lit '# TYPE fasm2crud_http_request_duration_seconds histogram',10
	xor	ebx,ebx
	xor	r13d,r13d			; cumulative
	lea	r14,[hist_le]
.bucket:
	mov	eax,ebx
	shl	eax,3
	add	eax,M_HIST
	call	metrics_sum
	add	r13,rax
	put_lit 'fasm2crud_http_request_duration_seconds_bucket{le="'
	cmp	ebx,HIST_BUCKETS
	jae	.inf
	movzx	ecx,byte [r14]
	lea	rsi,[r14+1]
	lea	r14,[r14+rcx+1]
	rep	movsb
	jmp	.le
.inf:
	put_lit '+Inf'
.le:
	put_lit '"} '
	mov	rax,r13
	call	write_u64
	mov	byte [rdi],10
	inc	rdi
	inc	ebx
	cmp	ebx,HIST_BUCKETS
	jbe	.bucket
	; _sum in seconds: microseconds with six decimals.
	put_lit 'fasm2crud_http_request_duration_seconds_sum '
	mov	eax,M_HIST_SUM
	call	metrics_sum
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	push	rdx
	call	write_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	add	rax,1000000			; leading zeros: write 1xxxxxx, drop the 1
	call	write_u64
	mov	ecx,6
	lea	rsi,[rdi-6]
	lea	rdi,[rdi-7]
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	mov	eax,M_HIST_COUNT
	call	metrics_sum
	lea	rsi,[hist_count_name]
	mov	ecx,hist_count_name.len
	call	metrics_line

	metrics_scalar 'fasm2crud_connections_accepted_total', 'counter', M_ACCEPTED
	metrics_scalar 'fasm2crud_connections_active', 'gauge', M_ACTIVE
	metrics_scalar 'fasm2crud_db_queries_total', 'counter', M_DB_QUERIES
	metrics_scalar 'fasm2crud_db_query_errors_total', 'counter', M_DB_ERRORS
	metrics_scalar 'fasm2crud_db_unavailable_total', 'counter', M_DB_UNAVAILABLE
	metrics_scalar 'fasm2crud_db_connections_ready', 'gauge', M_DB_READY
	metrics_scalar 'fasm2crud_hasher_jobs_total', 'counter', M_HASH_JOBS
	metrics_scalar 'fasm2crud_hasher_rejected_total', 'counter', M_HASH_BUSY
	metrics_scalar 'fasm2crud_hasher_restarts_total', 'counter', M_HASH_RESTARTS
	metrics_scalar 'fasm2crud_hasher_queue', 'gauge', M_HASH_QUEUE
	metrics_scalar 'fasm2crud_large_buffers_in_use', 'gauge', M_LARGE_INUSE
	metrics_scalar 'fasm2crud_large_buffers_exhausted_total', 'counter', M_LARGE_EXHAUSTED
	metrics_scalar 'fasm2crud_memory_returned_bytes_total', 'counter', M_RETURNED
	metrics_scalar 'fasm2crud_rate_limited_total', 'counter', M_RATE_LIMITED

	put_lit '# TYPE fasm2crud_worker_restarts_total counter',10
	mov	eax,[g_workers]
	shl	rax,10
	add	rax,[g_metrics_base]
	mov	rax,[rax+M_RESTARTS]
	cmp	dword [g_metrics_on],0
	jne	@f
	xor	eax,eax
@@:
	lea	rsi,[restarts_name]
	mov	ecx,restarts_name.len
	call	metrics_line
	put_lit '# TYPE fasm2crud_workers gauge',10
	mov	eax,[g_workers]
	lea	rsi,[workers_name]
	mov	ecx,workers_name.len
	call	metrics_line
	pop	r14
	pop	r13
	pop	rbx
	ret

cstring hist_count_name, 'fasm2crud_http_request_duration_seconds_count'
cstring restarts_name, 'fasm2crud_worker_restarts_total'
cstring workers_name, 'fasm2crud_workers'

METRICS_MAX	= 6144		; the text above, with every counter at 20 digits

; GET /metrics. Measured by writing it into the response buffer itself:
; respond_reserve with the bound, then the real length to respond_built.
metrics_route:
	cmp	dword [g_metrics_on],0
	je	.off
	cmp	dword [req_method],M_GET
	jne	.get_only
	mov	edx,METRICS_MAX
	call	respond_reserve
	jc	.done
	push	rax
	mov	rdi,rax
	call	metrics_write
	pop	rax
	mov	rdx,rdi
	sub	rdx,rax
	mov	edi,ST_200
	xor	ecx,ecx
	xor	r8d,r8d
	lea	r9,[ct_metrics]
	mov	r10d,ct_metrics.len
	jmp	respond_built_typed
.off:
	mov	edi,ST_404
	jmp	respond_status
.get_only:
	jmp	route_get_only
.done:
	ret
