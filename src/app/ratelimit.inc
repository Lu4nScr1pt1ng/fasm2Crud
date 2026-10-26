; Rate limits per client (src/core/inet.inc: an IPv4 address, an IPv6 /64,
; or the client a trusted proxy names), for the whole service.
;
; Two classes, each a token bucket per client:
;   auth     register, login, refresh, password, account: each costs a
;            password hash or a database write. API_AUTH_BURST at once
;            (default 10), refilled at API_AUTH_RATE a minute (30).
;   general  every /v1/ request: API_BURST (500) and API_RATE a minute
;            (6000); API_RATE=0 turns it off.
; Over a limit: 429 with Retry-After set to when the next token comes.
;
; The buckets are one table shared by every worker (MAP_SHARED, mapped
; before the fork), so a client gets its limit once however its
; connections spread. An entry is 16 bytes, {key, tokens and stamp}, and
; changes as a whole with lock cmpxchg16b: no locks, and two workers
; racing on one client simply retry. Stamps are Unix seconds, the clock
; every worker shares. A client probes RL_PROBE entries; a free entry is
; taken first, else the fullest bucket in the window is evicted, so the
; clients being limited are the ones that stay.

RL_SLOTS	= 16384		; power of two; 256 KiB
RL_PROBE	= 8
RL_RETRIES	= 8		; then the request passes: never block on contention
RL_SCALE	= 60		; tokens in 1/60ths: a minute's rate per second
DEFAULT_AUTH_RATE  = 30
DEFAULT_AUTH_BURST = 10
DEFAULT_RATE	= 6000
DEFAULT_BURST	= 500

RL_AUTH		= 0
RL_GENERAL	= 1

PEER_UNKNOWN	= 0
PEER_PENDING	= 1
PEER_KNOWN	= 2

SOCKET_URING_OP_GETSOCKOPT = 2
SO_PEERNAME	= 28

cstring env_auth_rate, 'API_AUTH_RATE='
cstring env_auth_burst, 'API_AUTH_BURST='
cstring env_rate, 'API_RATE='
cstring env_burst, 'API_BURST='
cstring hdr_retry_prefix, 'Retry-After: '

bss
	align 8
	g_rl		dq ?		; the shared table
	g_rl_rate	rd 2		; per class: per minute (0: off)
	g_rl_cap	rd 2		; burst * RL_SCALE
	g_rl_hdr:	rb 32
	g_peer_warned	dd ?
end bss

rate_config:
	lea	rdi,[env_auth_rate]
	mov	esi,env_auth_rate.len
	mov	edx,DEFAULT_AUTH_RATE
	mov	ecx,1
	mov	r8d,1000000
	call	env_uint
	mov	[g_rl_rate+RL_AUTH*4],eax
	lea	rdi,[env_auth_burst]
	mov	esi,env_auth_burst.len
	mov	edx,DEFAULT_AUTH_BURST
	mov	ecx,1
	mov	r8d,1000000
	call	env_uint
	imul	eax,eax,RL_SCALE
	mov	[g_rl_cap+RL_AUTH*4],eax
	lea	rdi,[env_rate]
	mov	esi,env_rate.len
	mov	edx,DEFAULT_RATE
	xor	ecx,ecx
	mov	r8d,1000000
	call	env_uint
	mov	[g_rl_rate+RL_GENERAL*4],eax
	lea	rdi,[env_burst]
	mov	esi,env_burst.len
	mov	edx,DEFAULT_BURST
	mov	ecx,1
	mov	r8d,1000000
	call	env_uint
	imul	eax,eax,RL_SCALE
	mov	[g_rl_cap+RL_GENERAL*4],eax
	; The table, shared by the workers forked later.
	xor	edi,edi
	mov	esi,RL_SLOTS * 16
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.no_memory
	mov	[g_rl],rax
	ret
.no_memory:
	call	log_begin
	log_lit 'cannot map the rate limit table'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; Does the current request need the client address, still unknown?
; eax = 1 when it has to wait for it (the lookup is started if nobody
; has). /v1/auth/ always needs it; every /v1/ route when the general limit
; is on. r12 = connection, rbx = slot.
route_needs_peer:
	xor	eax,eax
	cmp	dword [r12+C_PEER_STATE],PEER_KNOWN
	je	.done
	cmp	dword [req_path_len],4
	jb	.done
	mov	rdx,[req_path]
	cmp	dword [rdx],'/v1/'
	jne	.done
	cmp	dword [g_rl_rate+RL_GENERAL*4],0
	jne	.needed
	cmp	dword [req_path_len],9
	jbe	.done
	mov	rcx,'/v1/auth'
	cmp	[rdx],rcx
	jne	.done
	cmp	byte [rdx+8],'/'
	jne	.done
.needed:
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
	mov	dword [rax+SQE_FILE_INDEX],C_PEER_ADDR_SIZE	; optlen
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
	mov	qword [r12+C_PEER_ADDR],0
	mov	qword [r12+C_PEER_ADDR+8],0
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

; Take a token of class RL_AUTH. CF when there is none: 429 answered.
rate_take:
	mov	edi,RL_AUTH
	jmp	rate_take_class

; The general class, for every /v1/ request (no-op when it is off).
rate_take_general:
	cmp	dword [g_rl_rate+RL_GENERAL*4],0
	jne	@f
	clc
	ret
@@:
	mov	edi,RL_GENERAL
	; fall through

; cas_note: the entry address goes through rdi because fasm2 encodes
; cmpxchg16b [r8..r15] with two REX prefixes (48 41); only the last one
; counts, which silently turns it into cmpxchg8b.

; edi = class. CF when the client has no token left (429 answered).
; r12 = connection.
rate_take_class:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebp,edi
	call	client_key
	mov	rcx,0x9E3779B97F4A7C15
	imul	rcx,rbp
	xor	rax,rcx				; the class is part of the key
	or	rax,1
	mov	r13,rax				; key
	mov	r14d,RL_RETRIES
.again:
	mov	rax,r13
	shr	rax,64 - 14			; log2 RL_SLOTS
	mov	r12d,eax			; start of the window
	xor	r15d,r15d			; victim entry, 0 = none
	xor	r9d,r9d				; its tokens (+1, so 0 = none)
	mov	r11d,RL_PROBE
.probe:
	mov	eax,r12d
	and	eax,RL_SLOTS - 1
	shl	rax,4
	add	rax,[g_rl]
	mov	r10,rax
	mov	rax,[r10]
	cmp	rax,r13
	je	.found
	; Candidate: free beats everything, else the fullest bucket.
	mov	ecx,-1
	test	rax,rax
	jz	@f
	mov	rdx,[r10+8]
	call	.refill
	inc	ecx
@@:
	cmp	ecx,r9d
	jbe	.next
	mov	r9d,ecx
	mov	r15,r10
.next:
	inc	r12d
	dec	r11d
	jnz	.probe
	; Not there: a full bucket for this client in the victim's place.
	mov	r10,r15
	mov	rax,[r10]
	mov	rdx,[r10+8]
	mov	rbx,r13
	mov	ecx,[g_rl_cap+rbp*4]
	sub	ecx,RL_SCALE
	mov	r8d,dword [g_unix_now]
	shl	r8,32
	or	rcx,r8
	mov	rdi,r10			; see cas_note
	lock cmpxchg16b [rdi]
	jz	.allowed
	jmp	.retry
.found:
	mov	rdx,[r10+8]
	call	.refill				; ecx = tokens now
	cmp	ecx,RL_SCALE
	jb	.limited
	sub	ecx,RL_SCALE
	mov	r8d,dword [g_unix_now]
	shl	r8,32
	or	rcx,r8
	mov	rbx,r13
	mov	rax,r13
	mov	rdi,r10			; see cas_note
	lock cmpxchg16b [rdi]
	jz	.allowed
.retry:
	dec	r14d
	jnz	.again
.allowed:
	clc
	jmp	.done
.limited:
	mov	r12,[rsp+24]			; the connection again
	metric_inc M_RATE_LIMITED
	; Seconds until a whole token: (RL_SCALE - tokens) / rate, rounded up.
	mov	eax,RL_SCALE
	sub	eax,ecx
	mov	ecx,[g_rl_rate+rbp*4]
	add	eax,ecx
	dec	eax
	xor	edx,edx
	div	ecx
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
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdx = state (tokens | stamp << 32), ebp = class. ecx = tokens now,
; refilled up to the cap. Clobbers r8.
.refill:
	mov	ecx,edx				; tokens
	mov	r8,rdx
	shr	r8,32				; stamp
	push	rax
	mov	eax,dword [g_unix_now]
	sub	eax,r8d
	jbe	.refilled			; same second (or a clock step back)
	imul	eax,[g_rl_rate+rbp*4]
	jo	.full
	add	ecx,eax
	jc	.full
	cmp	ecx,[g_rl_cap+rbp*4]
	jbe	.refilled
.full:
	mov	ecx,[g_rl_cap+rbp*4]
.refilled:
	pop	rax
	ret
