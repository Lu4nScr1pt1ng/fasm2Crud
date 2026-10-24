; Connections.
;
; Every connection owns one CONN_BLOCK slot:
;   [0, 256)          header (fields below)
;   [256, 8192)       input buffer: requests are parsed in place
;   [8192, 16384)     output buffer: responses are written in place
; Slots come from a LIFO free list, so the most recently used (cache-hot,
; already faulted-in) memory is reused first and resident memory tracks the
; number of concurrent connections, not the configured maximum.
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
C_GEN		= 64		; bumped per accept; outside the zeroed header

CS_FREE		= 0
CS_OPEN		= 1
CS_CLOSING	= 2

F_RECV		= 1 shl 0
F_SEND		= 1 shl 1
F_WAIT_OUT	= 1 shl 2
F_CLOSE_AFTER	= 1 shl 3
F_LINGER	= 1 shl 4
F_WAIT_DB	= 1 shl 5	; a database or hasher reply will answer the current request

macro conn_ptr reg*, slot*
	mov	reg,slot
	shl	reg,CONN_SHIFT
	add	reg,[g_conn_base]
end macro

bss
	align 8
	g_conn_base	dq ?
	g_active_list	dq ?
	g_free_list	dq ?
	g_free_top	dd ?
	g_active_count	dd ?
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

	; Active list and free list: max_conns u32 each.
	xor	edi,edi
	mov	esi,[g_max_conns]
	shl	esi,3
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_POPULATE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[g_active_list],rax
	mov	ecx,[g_max_conns]
	lea	rdx,[rax+rcx*4]
	mov	[g_free_list],rdx
	mov	[g_free_top],ecx
	; free_list[i] = max - 1 - i, so slot 0 is popped first.
	xor	eax,eax
@@:
	dec	ecx
	mov	[rdx+rax*4],ecx
	inc	eax
	test	ecx,ecx
	jnz	@b
	xor	eax,eax
.done:
	pop	rbx
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
	mov	eax,[g_free_top]
	test	eax,eax
	jz	.no_slot
	dec	eax
	mov	[g_free_top],eax
	mov	rcx,[g_free_list]
	mov	ebx,[rcx+rax*4]
	conn_ptr r12,rbx
	vpxor	xmm0,xmm0,xmm0
	vmovdqu	[r12],xmm0
	vmovdqu	[r12+16],xmm0
	vmovdqu	[r12+32],xmm0
	vmovdqu	[r12+48],xmm0
	mov	[r12+C_FIDX],r14d
	inc	dword [r12+C_GEN]
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
	lea	rcx,[r12+IN_OFF]
	mov	edx,IN_CAP
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
	lea	rdx,[r12+OUT_OFF+rcx]
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
	test	eax,F_SEND or F_LINGER or F_WAIT_DB
	jnz	.done
	jmp	start_linger
.read_more:
	; Waiting on output or on the database: stop reading, so TCP pushes
	; back on the client instead of our buffers filling up.
	test	eax,F_RECV or F_WAIT_OUT or F_WAIT_DB
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
	; Push the slot on the free list.
	mov	rcx,[g_free_list]
	mov	eax,[g_free_top]
	mov	[rcx+rax*4],ebx
	inc	eax
	mov	[g_free_top],eax
	ret

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
	test	dword [r12+C_FLAGS],F_WAIT_DB
	jnz	.compact			; answer in order: wait for the reply
	mov	eax,OUT_CAP
	sub	eax,[r12+C_OUT_LEN]
	cmp	eax,RESP_RESERVE
	jb	.wait_out
	lea	rdi,[r12+IN_OFF+r13]
	call	http_handle
	test	eax,eax
	jz	.incomplete
	add	r13d,eax
	jmp	.next
.incomplete:
	test	r13d,r13d
	jnz	.compact
	cmp	dword [r12+C_IN_LEN],IN_CAP
	jb	.compact
	; A full buffer without a complete header block.
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
	mov	edi,ST_431
	call	respond_status
.discard:
	mov	r13d,[r12+C_IN_LEN]
	jmp	.compact
.wait_out:
	or	dword [r12+C_FLAGS],F_WAIT_OUT
.compact:
	test	r13d,r13d
	jz	.done
	mov	ecx,[r12+C_IN_LEN]
	sub	ecx,r13d
	mov	[r12+C_IN_LEN],ecx
	jz	.done
	lea	rsi,[r12+IN_OFF+r13]
	lea	rdi,[r12+IN_OFF]
	rep	movsb
.done:
	pop	r13
	ret
