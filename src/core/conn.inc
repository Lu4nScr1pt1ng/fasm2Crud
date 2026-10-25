; Connections.
;
; Every connection owns one CONN_BLOCK slot:
;   [0, 256)          header (fields below)
;   [256, 8192)       input buffer: requests are parsed in place
;   [8192, 16384)     output buffer: responses are written in place
; Slots come from a pool (src/core/pool.inc): the most recently used,
; cache-hot slot is reused first, so resident memory tracks the number of
; concurrent connections, and slots left idle give all their pages back.
; The generation counter of each slot (which tells late database and
; hasher replies from a new connection's) lives apart, in g_conn_gens,
; and is copied into the header on accept.
;
; A request or a response that does not fit its buffer (a large note)
; borrows a large buffer from a second pool for as long as it needs it:
; C_IN_BUF / C_OUT_BUF then point there instead of into the slot. A large
; input buffer goes back once the input is consumed, a large output buffer
; once its bytes are sent; holding one has a total deadline as well, so
; slow clients cannot keep the pool.
;
; At most one recv and one send are in flight per connection. While output
; is backed up (F_WAIT_OUT) we stop reading, so a client that sends faster
; than it reads is throttled by TCP itself instead of by our memory.

C_STATE		= 0
C_PENDING	= 4		; operations in flight that reference this slot
C_IN_LEN	= 8
C_OUT_LEN	= 12
C_OUT_SENT	= 16
C_LAST		= 20		; tick of the last progress
C_FLAGS		= 24
C_ACTIVE_POS	= 28		; index in g_active_list
C_SCAN		= 32		; where the header terminator search resumes
C_FIDX		= 36		; direct descriptor index
C_LINGER	= 40		; bytes discarded during lingering close
C_AUX		= 44		; a value the current request keeps for its continuation
C_GEN		= 64		; copy of g_conn_gens[slot]; 0 in a free (trimmed) slot
; Set on accept (outside the zeroed header too):
C_IN_BUF	= 72		; dq: input buffer, in the slot or a large buffer
C_OUT_BUF	= 80		; dq: output buffer
C_IN_CAP	= 88
C_OUT_CAP	= 92
C_IN_LARGE	= 96		; large buffer index + 1, or 0
C_OUT_LARGE	= 100
C_IN_SINCE	= 104		; tick the large buffers were taken
C_OUT_SINCE	= 108
C_T0		= 112		; dq: TSC when the current request was parsed (0: none)
C_PEER_STATE	= 120		; PEER_xxx (src/app/ratelimit.inc)
C_PEER_ADDR	= 128		; sockaddr_in of the client, once known

CONN_KEEP	= 0		; the whole slot can go back
CONN_WARM	= 64		; free slots always kept resident

LARGE_SHIFT	= 17
LARGE_SIZE	= 1 shl LARGE_SHIFT	; 128 KiB
LARGE_CAP	= LARGE_SIZE - 64	; SIMD scans may read 31 bytes past the data
LARGE_WARM	= 2
LARGE_HOLD	= 60		; ticks a connection may keep a large output buffer
DEFAULT_LARGE_BUFFERS = 64	; per worker

CS_FREE		= 0
CS_OPEN		= 1
CS_CLOSING	= 2

F_RECV		= 1 shl 0
F_SEND		= 1 shl 1
F_WAIT_OUT	= 1 shl 2
F_CLOSE_AFTER	= 1 shl 3
F_LINGER	= 1 shl 4
F_WAIT_DB	= 1 shl 5	; a database or hasher reply will answer the current request
F_WAIT_PEER	= 1 shl 6	; the current request needs the client address first

macro conn_ptr reg*, slot*
	mov	reg,slot
	shl	reg,CONN_SHIFT
	add	reg,[g_conn_base]
end macro

bss
	align 8
	g_conn_base	dq ?
	g_active_list	dq ?
	g_conn_gens	dq ?		; u32 per slot, never trimmed
	g_active_count	dd ?
	g_large_count	dd ?
	g_conn_pool:	rb P_SIZE
	g_large_pool:	rb P_SIZE
	g_accept_armed	dd ?
	g_accept_paused	dd ?
end bss

; Reserve all connection memory up front, with a guard page at each end.
; eax = 0 or -errno.
conn_pool_init:
	push	rbx
	mov	eax,[g_max_conns]
	shl	rax,CONN_SHIFT
	mov	rbx,rax
	xor	edi,edi
	lea	rsi,[rax+2*PAGE_SIZE]
	mov	edx,PROT_NONE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	lea	rdi,[rax+PAGE_SIZE]
	mov	[g_conn_base],rdi
	mov	rsi,rbx
	mov	edx,PROT_READ or PROT_WRITE
	mov	eax,SYS_mprotect
	syscall
	test	eax,eax
	js	.done

	mov	rax,[g_conn_base]
	mov	[g_conn_pool+P_BASE],rax
	mov	dword [g_conn_pool+P_SHIFT],CONN_SHIFT
	mov	dword [g_conn_pool+P_KEEP],CONN_KEEP
	mov	eax,[g_max_conns]
	mov	[g_conn_pool+P_COUNT],eax
	mov	dword [g_conn_pool+P_WARM],CONN_WARM
	lea	rdi,[g_conn_pool]
	call	pool_init
	test	eax,eax
	js	.done

	; Active list and generations: max_conns u32 each.
	xor	edi,edi
	mov	esi,[g_max_conns]
	shl	esi,3
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[g_active_list],rax
	mov	ecx,[g_max_conns]
	lea	rax,[rax+rcx*4]
	mov	[g_conn_gens],rax

	; Large buffers: address space only, until a request needs one.
	mov	eax,[g_large_count]
	shl	rax,LARGE_SHIFT
	xor	edi,edi
	mov	rsi,rax
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[g_large_pool+P_BASE],rax
	mov	dword [g_large_pool+P_SHIFT],LARGE_SHIFT
	mov	dword [g_large_pool+P_KEEP],0
	mov	eax,[g_large_count]
	mov	[g_large_pool+P_COUNT],eax
	mov	dword [g_large_pool+P_WARM],LARGE_WARM
	lea	rdi,[g_large_pool]
	call	pool_init
.done:
	pop	rbx
	ret

; Once per tick: give back the memory of idle slots and buffers.
conn_trim:
	lea	rdi,[g_conn_pool]
	call	pool_trim
	lea	rdi,[g_large_pool]
	jmp	pool_trim

; Move the input to a large buffer (the request is at its start).
; CF when none is free.
conn_large_input:
	lea	rdi,[g_large_pool]
	call	pool_take
	jc	.done
	lea	ecx,[rax+1]
	mov	[r12+C_IN_LARGE],ecx
	mov	esi,eax
	lea	rdi,[g_large_pool]
	call	pool_ptr
	mov	rdi,rax
	mov	rsi,[r12+C_IN_BUF]
	mov	[r12+C_IN_BUF],rax
	mov	dword [r12+C_IN_CAP],LARGE_CAP
	mov	ecx,[r12+C_IN_LEN]
	rep	movsb
	mov	eax,[g_tick]
	mov	[r12+C_IN_SINCE],eax
	clc
.done:
	ret

; Back to the slot's input buffer. Requires C_IN_LEN = 0 and no recv in
; flight.
conn_inline_input:
	mov	esi,[r12+C_IN_LARGE]
	test	esi,esi
	jz	.done
	dec	esi
	mov	dword [r12+C_IN_LARGE],0
	lea	rax,[r12+IN_OFF]
	mov	[r12+C_IN_BUF],rax
	mov	dword [r12+C_IN_CAP],IN_CAP
	lea	rdi,[g_large_pool]
	jmp	pool_put
.done:
	ret

; Switch the (empty) output to a large buffer. CF when none is free.
conn_large_output:
	lea	rdi,[g_large_pool]
	call	pool_take
	jc	.done
	lea	ecx,[rax+1]
	mov	[r12+C_OUT_LARGE],ecx
	mov	esi,eax
	lea	rdi,[g_large_pool]
	call	pool_ptr
	mov	[r12+C_OUT_BUF],rax
	mov	dword [r12+C_OUT_CAP],LARGE_CAP
	mov	eax,[g_tick]
	mov	[r12+C_OUT_SINCE],eax
	clc
.done:
	ret

; Back to the slot's output buffer. Requires everything sent.
conn_inline_output:
	mov	esi,[r12+C_OUT_LARGE]
	test	esi,esi
	jz	.done
	dec	esi
	mov	dword [r12+C_OUT_LARGE],0
	lea	rax,[r12+OUT_OFF]
	mov	[r12+C_OUT_BUF],rax
	mov	dword [r12+C_OUT_CAP],OUT_CAP
	lea	rdi,[g_large_pool]
	jmp	pool_put
.done:
	ret

arm_accept:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ACCEPT
	mov	word [rax+SQE_IOPRIO],IORING_ACCEPT_MULTISHOT
	mov	ecx,[g_listen]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_FILE_INDEX],IORING_FILE_INDEX_ALLOC
	mov	rcx,OP_ACCEPT shl 32
	mov	[rax+SQE_USER_DATA],rcx
	mov	dword [g_accept_armed],1
	ret

; r14 = direct descriptor or -errno, r15d = cqe flags.
on_accept:
	test	r15d,IORING_CQE_F_MORE
	jnz	@f
	mov	dword [g_accept_armed],0
@@:
	test	r14d,r14d
	js	.failed
	lea	rdi,[g_conn_pool]
	call	pool_take
	jc	.no_slot
	mov	ebx,eax
	conn_ptr r12,rbx
	vpxor	xmm0,xmm0,xmm0
	vmovdqu	[r12],xmm0
	vmovdqu	[r12+16],xmm0
	vmovdqu	[r12+32],xmm0
	vmovdqu	[r12+48],xmm0
	lea	rax,[r12+IN_OFF]
	mov	[r12+C_IN_BUF],rax
	lea	rax,[r12+OUT_OFF]
	mov	[r12+C_OUT_BUF],rax
	mov	dword [r12+C_IN_CAP],IN_CAP
	mov	dword [r12+C_OUT_CAP],OUT_CAP
	mov	qword [r12+C_IN_LARGE],0	; and C_OUT_LARGE
	mov	qword [r12+C_T0],0
	mov	dword [r12+C_PEER_STATE],PEER_UNKNOWN
	metric_inc M_ACCEPTED
	mov	[r12+C_FIDX],r14d
	mov	rcx,[g_conn_gens]
	mov	eax,[rcx+rbx*4]
	inc	eax
	jnz	@f
	inc	eax				; 0 never names a connection
@@:
	mov	[rcx+rbx*4],eax
	mov	[r12+C_GEN],eax
	mov	dword [r12+C_STATE],CS_OPEN
	mov	eax,[g_tick]
	mov	[r12+C_LAST],eax
	mov	eax,[g_active_count]
	mov	rcx,[g_active_list]
	mov	[rcx+rax*4],ebx
	mov	[r12+C_ACTIVE_POS],eax
	inc	dword [g_active_count]
	cmp	dword [g_draining],0
	jne	.refuse
	call	arm_recv
	jmp	.rearm
.refuse:
	call	close_conn
.rearm:
	cmp	dword [g_accept_armed],0
	jne	.done
	cmp	dword [g_draining],0
	jne	.done
	jmp	arm_accept
.done:
	ret
.no_slot:
	; Cannot happen while the file table and the slot pool have the same
	; size; never leak the descriptor if it ever does.
	mov	edi,r14d
	call	close_direct
	jmp	.rearm
.failed:
	; Usually ENFILE: every slot is taken. Retry on the next tick rather
	; than spinning on an accept that keeps failing.
	cmp	dword [g_accept_armed],0
	jne	.done
	mov	dword [g_accept_paused],1
	ret

; edi = direct descriptor index.
close_direct:
	push	rdi
	call	ring_get_sqe
	pop	rcx
	inc	ecx
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	byte [rax+SQE_FLAGS],IOSQE_CQE_SKIP_SUCCESS
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx
	ret

; rbx = slot, r12 = connection.
arm_recv:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[r12+C_FIDX]
	mov	[rax+SQE_FD],ecx
	mov	rcx,[r12+C_IN_BUF]
	mov	edx,[r12+C_IN_CAP]
	test	dword [r12+C_FLAGS],F_LINGER
	jnz	@f				; lingering: overwrite, we only discard
	mov	esi,[r12+C_IN_LEN]
	add	rcx,rsi
	sub	edx,esi
@@:
	mov	[rax+SQE_ADDR],rcx
	mov	[rax+SQE_LEN],edx
	mov	rcx,OP_RECV shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r12+C_PENDING]
	or	dword [r12+C_FLAGS],F_RECV
	ret

arm_send:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[r12+C_FIDX]
	mov	[rax+SQE_FD],ecx
	mov	ecx,[r12+C_OUT_SENT]
	mov	rdx,[r12+C_OUT_BUF]
	add	rdx,rcx
	mov	[rax+SQE_ADDR],rdx
	mov	edx,[r12+C_OUT_LEN]
	sub	edx,ecx
	mov	[rax+SQE_LEN],edx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	mov	rcx,OP_SEND shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r12+C_PENDING]
	or	dword [r12+C_FLAGS],F_SEND
	ret

on_recv:
	conn_ptr r12,rbx
	dec	dword [r12+C_PENDING]
	and	dword [r12+C_FLAGS],not F_RECV
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	release_if_idle
	test	dword [r12+C_FLAGS],F_LINGER
	jnz	.linger
	test	r14d,r14d
	js	close_conn
	jz	.eof
	add	[r12+C_IN_LEN],r14d
	mov	eax,[g_tick]
	mov	[r12+C_LAST],eax
	call	process_input
	jmp	conn_flush
.eof:
	; The client stopped sending; finish what we owe it, then close.
	mov	eax,[r12+C_OUT_LEN]
	cmp	eax,[r12+C_OUT_SENT]
	jbe	close_conn
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
	jmp	conn_flush
.linger:
	test	r14d,r14d
	jle	close_conn
	add	[r12+C_LINGER],r14d
	cmp	dword [r12+C_LINGER],LINGER_MAX_BYTES
	jae	close_conn
	jmp	arm_recv

on_send:
	conn_ptr r12,rbx
	dec	dword [r12+C_PENDING]
	and	dword [r12+C_FLAGS],not F_SEND
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	release_if_idle
	test	r14d,r14d
	jle	close_conn
	add	[r12+C_OUT_SENT],r14d
	mov	eax,[g_tick]
	mov	[r12+C_LAST],eax
	mov	eax,[r12+C_OUT_SENT]
	cmp	eax,[r12+C_OUT_LEN]
	jb	conn_flush			; short send: the rest goes next
	xor	eax,eax
	mov	[r12+C_OUT_LEN],eax
	mov	[r12+C_OUT_SENT],eax
	call	conn_inline_output
	test	dword [r12+C_FLAGS],F_WAIT_OUT
	jz	conn_flush
	and	dword [r12+C_FLAGS],not F_WAIT_OUT
	call	process_input
	jmp	conn_flush

; Decide the next I/O for an open connection after its state changed.
conn_flush:
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.done
	mov	eax,[r12+C_OUT_LEN]
	cmp	eax,[r12+C_OUT_SENT]
	jbe	.sent
	test	dword [r12+C_FLAGS],F_SEND
	jnz	.sent
	call	arm_send
.sent:
	mov	eax,[r12+C_FLAGS]
	test	eax,F_CLOSE_AFTER
	jz	.read_more
	; The last response may still be owed by the database or the hasher.
	test	eax,F_SEND or F_LINGER or F_WAIT_DB or F_WAIT_PEER
	jnz	.done
	jmp	start_linger
.read_more:
	; Waiting on output or on the database: stop reading, so TCP pushes
	; back on the client instead of our buffers filling up.
	test	eax,F_RECV or F_WAIT_OUT or F_WAIT_DB or F_WAIT_PEER
	jnz	.done
	jmp	arm_recv
.done:
	ret

; Lingering close: send FIN, then read and discard until the client closes
; (or LINGER_TIMEOUT). Closing straight away while request bytes are still
; unread makes the kernel send RST, which can destroy the response we just
; sent before the client reads it.
start_linger:
	or	dword [r12+C_FLAGS],F_LINGER
	mov	dword [r12+C_LINGER],0
	mov	eax,[g_tick]
	mov	[r12+C_LAST],eax
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SHUTDOWN
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_CQE_SKIP_SUCCESS
	mov	ecx,[r12+C_FIDX]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_LEN],SHUT_WR
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx
	test	dword [r12+C_FLAGS],F_RECV
	jnz	.done
	jmp	arm_recv
.done:
	ret

; Stop all I/O on the connection and release it once nothing references it.
close_conn:
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.done
	mov	dword [r12+C_STATE],CS_CLOSING
	cmp	dword [r12+C_PENDING],0
	je	conn_release
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	byte [rax+SQE_FLAGS],IOSQE_CQE_SKIP_SUCCESS
	mov	ecx,[r12+C_FIDX]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_ALL or IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx
.done:
	ret

release_if_idle:
	cmp	dword [r12+C_PENDING],0
	je	conn_release
	ret

; Close the descriptor and return the slot. Requires C_PENDING = 0.
conn_release:
	mov	edi,[r12+C_FIDX]
	call	close_direct
	mov	dword [r12+C_STATE],CS_FREE
	; Swap-remove from the active list.
	mov	rcx,[g_active_list]
	mov	eax,[g_active_count]
	dec	eax
	mov	[g_active_count],eax
	mov	edx,[rcx+rax*4]			; slot of the last entry
	mov	esi,[r12+C_ACTIVE_POS]
	mov	[rcx+rsi*4],edx
	conn_ptr rdi,rdx
	mov	[rdi+C_ACTIVE_POS],esi
	; Nothing references the buffers any more.
	call	conn_inline_input
	call	conn_inline_output
	lea	rdi,[g_conn_pool]
	mov	esi,ebx
	jmp	pool_put

; A database or hasher reply was handled (F_WAIT_DB is clear unless the
; request waits again): carry on with the input.
http_resume:
	call	process_input
	jmp	conn_flush

; Parse and answer every complete request in the input buffer (pipelining),
; then move any partial request to the front of the buffer.
process_input:
	push	r13
	xor	r13d,r13d			; bytes consumed
.next:
	mov	esi,[r12+C_IN_LEN]
	sub	esi,r13d
	jz	.compact
	test	dword [r12+C_FLAGS],F_CLOSE_AFTER
	jnz	.discard
	test	dword [r12+C_FLAGS],F_WAIT_DB or F_WAIT_PEER
	jnz	.compact			; answer in order: wait for the reply
	mov	eax,[r12+C_OUT_CAP]
	sub	eax,[r12+C_OUT_LEN]
	cmp	eax,RESP_RESERVE
	jb	.wait_out
	mov	rdi,[r12+C_IN_BUF]
	add	rdi,r13
	call	http_handle
	test	eax,eax
	jz	.incomplete
	cmp	eax,HTTP_LARGE_INPUT
	je	.large
	cmp	eax,HTTP_WAIT_OUTPUT
	je	.wait_out			; after the pending output is sent
	cmp	eax,HTTP_WAIT_PEER
	je	.wait_peer
	add	r13d,eax
	jmp	.next
.large:
	; The request is larger than the slot's buffer: move it to the front,
	; then to a large buffer, and read the rest there.
	call	.shift
	call	conn_large_input
	jnc	.next
	metric_inc M_LARGE_EXHAUSTED
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
	call	respond_busy
	jmp	.discard
.incomplete:
	test	r13d,r13d
	jnz	.compact
	mov	eax,[r12+C_IN_CAP]
	cmp	[r12+C_IN_LEN],eax
	jb	.compact
	; A full buffer without a complete header block.
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
	mov	edi,ST_431
	call	respond_status
.discard:
	mov	r13d,[r12+C_IN_LEN]
	jmp	.compact
.wait_peer:
	or	dword [r12+C_FLAGS],F_WAIT_PEER
	jmp	.compact
.wait_out:
	or	dword [r12+C_FLAGS],F_WAIT_OUT
.compact:
	call	.shift
	; All input consumed and nothing being read: a large input buffer is
	; no longer needed.
	cmp	dword [r12+C_IN_LEN],0
	jne	.done
	test	dword [r12+C_FLAGS],F_RECV
	jnz	.done
	call	conn_inline_input
.done:
	pop	r13
	ret

; Drop the r13d consumed bytes from the front of the input.
.shift:
	test	r13d,r13d
	jz	.shifted
	mov	ecx,[r12+C_IN_LEN]
	sub	ecx,r13d
	mov	[r12+C_IN_LEN],ecx
	mov	rdi,[r12+C_IN_BUF]
	lea	rsi,[rdi+r13]
	xor	r13d,r13d
	rep	movsb
.shifted:
	ret
