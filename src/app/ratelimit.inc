; Per-address rate limiting for the account endpoints that cost real work
; (register, login, refresh: a password hash or a database write).
;
; Token buckets, one per client IPv4 address, in a fixed table per worker:
; API_AUTH_BURST requests at once, refilled at API_AUTH_RATE per minute.
; Over the limit: 429 with Retry-After set to when the next token comes.
; Workers share nothing, so the limit is per worker: a client spreading
; connections over every worker gets up to workers x the rate, which the
; defaults (10 at once, 30 a minute) allow for.
;
; The table has RL_SLOTS entries; an address probes RL_PROBE of them. An
; entry whose bucket has refilled carries no information and is reused
; first; failing that, the fullest bucket in the window is evicted, so the
; addresses being limited are the ones that stay.
;
; The address: accepted sockets are io_uring direct descriptors, outside
; the fd table, so getpeername cannot see them. The ring asks instead
; (IORING_OP_URING_CMD, getsockopt SO_PEERNAME), once per connection and
; only when a limited endpoint is first requested; the request waits for
; it like for the database (http_handle returns HTTP_WAIT_PEER).

RL_SLOTS	= 8192		; power of two
RL_PROBE	= 8
RL_SCALE	= 60		; tokens are kept in 1/60ths: a minute's rate per second
DEFAULT_AUTH_RATE  = 30		; per minute
DEFAULT_AUTH_BURST = 10

; Entry (16 bytes).
RLE_ADDR	= 0		; IPv4, network order; 0 = never used
RLE_TOKENS	= 4		; in 1/RL_SCALE
RLE_TICK	= 8		; tick + 1 of the last refill; 0 = never used

PEER_UNKNOWN	= 0
PEER_PENDING	= 1
PEER_KNOWN	= 2

SOCKET_URING_OP_GETSOCKOPT = 2
SO_PEERNAME	= 28

cstring env_auth_rate, 'API_AUTH_RATE='
cstring env_auth_burst, 'API_AUTH_BURST='
cstring hdr_retry_prefix, 'Retry-After: '

bss
	align 16
	g_rl:		rb RL_SLOTS * 16
	g_auth_rate	dd ?		; per minute
	g_auth_burst	dd ?
	g_rl_hdr:	rb 32
end bss

rate_config:
	lea	rdi,[env_auth_rate]
	mov	esi,env_auth_rate.len
	mov	edx,DEFAULT_AUTH_RATE
	mov	ecx,1
	mov	r8d,100000
	call	env_uint
	mov	[g_auth_rate],eax
	lea	rdi,[env_auth_burst]
	mov	esi,env_auth_burst.len
	mov	edx,DEFAULT_AUTH_BURST
	mov	ecx,1
	mov	r8d,100000
	call	env_uint
	mov	[g_auth_burst],eax
	ret

; Does the current request need the client address (a limited endpoint),
; and is it still unknown? eax = 1 when the request has to wait for it.
; Starts the lookup if nobody has. r12 = connection, rbx = slot.
route_needs_peer:
	xor	eax,eax
	cmp	dword [r12+C_PEER_STATE],PEER_KNOWN
	je	.done
	cmp	dword [req_path_len],9
	jbe	.done
	mov	rdx,[req_path]
	mov	rcx,'/v1/auth'
	cmp	[rdx],rcx
	jne	.done
	cmp	byte [rdx+8],'/'
	jne	.done
	cmp	dword [r12+C_PEER_STATE],PEER_PENDING
	je	.wait
	call	peer_lookup
.wait:
	mov	eax,1
.done:
	ret

; getsockopt(SOL_SOCKET, SO_PEERNAME) through the ring into C_PEER_ADDR.
peer_lookup:
	mov	dword [r12+C_PEER_STATE],PEER_PENDING
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[r12+C_FIDX]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OFF],SOCKET_URING_OP_GETSOCKOPT	; cmd_op
	mov	dword [rax+SQE_ADDR],SOL_SOCKET			; level
	mov	dword [rax+SQE_ADDR+4],SO_PEERNAME		; optname
	mov	dword [rax+SQE_FILE_INDEX],16			; optlen
	lea	rcx,[r12+C_PEER_ADDR]
	mov	[rax+SQE_ADDR3],rcx				; optval
	mov	rcx,OP_PEER shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r12+C_PENDING]
	ret

cstring msg_no_peer, 'cannot read client addresses (errno '

; The address arrived (r14 = optlen, or -errno). Without one (a kernel
; without socket uring commands) the client counts as address 0.0.0.0,
; which every such client then shares; that is logged once.
on_peer:
	conn_ptr r12,rbx
	dec	dword [r12+C_PENDING]
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	release_if_idle
	mov	dword [r12+C_PEER_STATE],PEER_KNOWN
	test	r14d,r14d
	jns	.resume
	mov	dword [r12+C_PEER_ADDR+4],0
	cmp	dword [g_peer_warned],0
	jne	.resume
	mov	dword [g_peer_warned],1
	call	log_begin
	lea	rsi,[msg_no_peer]
	mov	edx,msg_no_peer.len
	call	log_str
	mov	eax,r14d
	neg	eax
	call	log_u64
	log_lit '); rate limits apply to all clients together'
	call	log_end
.resume:
	and	dword [r12+C_FLAGS],not F_WAIT_PEER
	jmp	http_resume

bss
	g_peer_warned	dd ?
end bss

; Take a token for the current request's client. CF when there is none:
; 429 has been answered. r12 = connection.
rate_take:
	push	rbx
	push	r13
	mov	r8d,[r12+C_PEER_ADDR+4]		; sin_addr
	; Hash into the table (Fibonacci hashing), then probe a window.
	mov	eax,0x9E3779B1
	imul	eax,r8d
	shr	eax,32 - 13			; log2 RL_SLOTS
	xor	r9,r9				; victim
	xor	r10d,r10d			; its tokens
	mov	r11d,RL_PROBE
.probe:
	mov	ecx,eax
	shl	ecx,4
	lea	rbx,[g_rl+rcx]
	call	.refill
	cmp	[rbx+RLE_ADDR],r8d
	jne	.other
	test	r8d,r8d
	jnz	.found
	cmp	dword [rbx+RLE_TICK],0		; address 0 in use, not a free entry
	jne	.found
.other:
	; Candidate for reuse: full buckets carry nothing, else the fullest.
	mov	ecx,[rbx+RLE_TOKENS]
	cmp	dword [rbx+RLE_TICK],0
	jne	@f
	mov	ecx,-1				; never used: best of all
@@:
	cmp	r9,0
	je	.take
	cmp	ecx,r10d
	jbe	.next
.take:
	mov	r9,rbx
	mov	r10d,ecx
.next:
	inc	eax
	and	eax,RL_SLOTS - 1
	dec	r11d
	jnz	.probe
	; Not found: a new bucket, full, in the victim's place.
	mov	rbx,r9
	mov	[rbx+RLE_ADDR],r8d
	mov	eax,[g_auth_burst]
	imul	eax,eax,RL_SCALE
	mov	[rbx+RLE_TOKENS],eax
	mov	eax,[g_tick]
	inc	eax
	mov	[rbx+RLE_TICK],eax
.found:
	cmp	dword [rbx+RLE_TOKENS],RL_SCALE
	jb	.limited
	sub	dword [rbx+RLE_TOKENS],RL_SCALE
	clc
	jmp	.done
.limited:
	metric_inc M_RATE_LIMITED
	; Seconds until a whole token: (RL_SCALE - tokens) / rate, rounded up.
	mov	eax,RL_SCALE
	sub	eax,[rbx+RLE_TOKENS]
	add	eax,[g_auth_rate]
	dec	eax
	xor	edx,edx
	div	dword [g_auth_rate]
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	lea	rdi,[g_rl_hdr]
	lea	rsi,[hdr_retry_prefix]
	mov	ecx,hdr_retry_prefix.len
	rep	movsb
	call	write_u32
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rcx,[g_rl_hdr]
	mov	r8,rdi
	sub	r8,rcx
	mov	eax,ST_429
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_429
	call	respond
	stc
.done:
	pop	r13
	pop	rbx
	ret

; Refill the bucket at rbx up to the burst. Clobbers ecx, edx.
.refill:
	mov	ecx,[rbx+RLE_TICK]
	test	ecx,ecx
	jz	.refilled
	mov	edx,[g_tick]
	inc	edx
	sub	edx,ecx
	jz	.refilled
	imul	edx,[g_auth_rate]		; per second, in 1/60ths
	add	edx,[rbx+RLE_TOKENS]
	mov	ecx,[g_auth_burst]
	imul	ecx,ecx,RL_SCALE
	cmp	edx,ecx
	cmova	edx,ecx
	mov	[rbx+RLE_TOKENS],edx
	mov	edx,[g_tick]
	inc	edx
	mov	[rbx+RLE_TICK],edx
.refilled:
	ret
