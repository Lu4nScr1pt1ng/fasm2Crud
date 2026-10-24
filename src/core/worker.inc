; Worker process: one per CPU, shared-nothing, single-threaded event loop.

bss
	g_listen	dd ?
	g_sigfd		dd ?
	g_tick		dd ?
	g_draining	dd ?
	g_drain_deadline dd ?
	g_sig_buf:	rb SIGINFO_SIZE
	g_cpu_mask:	rb 128
end bss

rodata
	align 8
	ts_tick		dq 1, 0			; __kernel_timespec: one second
	worker_name	db 'fasm2crud-w',0
end rodata

; edi = worker index. Never returns.
worker_main:
	mov	[g_worker_id],edi
	mov	dword [g_is_worker],1
	mov	ebx,edi

	; Die with the supervisor, and never outlive a supervisor we lost the
	; race with.
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	mov	edi,EXIT_OK
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[worker_name]
	mov	eax,SYS_prctl
	syscall

	mov	edi,ebx
	call	pin_to_cpu
	mov	eax,[g_listen_fd+rbx*4]
	mov	[g_listen],eax

	; SIGTERM/SIGINT stay blocked (inherited) and arrive through a signalfd
	; read on the ring. It is a blocking fd on purpose: io_uring then waits
	; for it with an internal poll instead of failing with EAGAIN.
	mov	qword [g_sigmask],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1))
	mov	edi,-1
	lea	rsi,[g_sigmask]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.no_signalfd
	mov	[g_sigfd],eax

	call	conn_pool_init
	test	eax,eax
	js	.no_memory
	call	ring_init
	test	eax,eax
	js	.no_ring
	call	ring_register_files
	test	eax,eax
	js	.no_files

	call	date_init
	call	arm_accept
	call	arm_timer
	call	arm_signal

.loop:
	cmp	dword [g_draining],0
	je	.wait
	cmp	dword [g_active_count],0
	je	.drained
.wait:
	mov	edi,1
	call	ring_enter
	call	ring_reap
	jmp	.loop

.drained:
	mov	edi,EXIT_OK
	jmp	exit_process

.no_signalfd:
	push	rax
	call	log_begin
	log_lit 'signalfd failed (errno '
	jmp	.fatal
.no_memory:
	push	rax
	call	log_begin
	log_lit 'cannot reserve connection memory (errno '
	jmp	.fatal
.no_ring:
	push	rax
	call	log_begin
	log_lit 'io_uring_setup failed (errno '
	pop	rax
	neg	rax
	call	log_u64
	log_lit '); in Docker, run with docker/seccomp.json'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
.no_files:
	push	rax
	call	log_begin
	log_lit 'cannot register the file table (errno '
.fatal:
	pop	rax
	neg	rax
	call	log_u64
	log_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; edi = worker index: pin to the (index mod cpus)-th CPU we may run on.
pin_to_cpu:
	mov	eax,edi
	xor	edx,edx
	div	dword [g_cpu_count]
	xor	ecx,ecx
.scan:
	bt	[g_affinity],ecx
	jnc	.skip
	test	edx,edx
	jz	.found
	dec	edx
.skip:
	inc	ecx
	cmp	ecx,1024
	jb	.scan
	ret
.found:
	lea	rdi,[g_cpu_mask]
	xor	eax,eax
	push	rcx
	mov	ecx,128/8
	rep	stosq
	pop	rcx
	bts	[g_cpu_mask],ecx
	xor	edi,edi
	mov	esi,128
	lea	rdx,[g_cpu_mask]
	mov	eax,SYS_sched_setaffinity
	syscall
	ret

; One tick per second drives timeouts and the cached Date header.
arm_timer:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[ts_tick]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],IORING_TIMEOUT_MULTISHOT
	mov	rcx,OP_TIMER shl 32
	mov	[rax+SQE_USER_DATA],rcx
	ret

arm_signal:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	ecx,[g_sigfd]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_sig_buf]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],SIGINFO_SIZE
	mov	rcx,OP_SIGNAL shl 32
	mov	[rax+SQE_USER_DATA],rcx
	ret

on_timer:
	test	r15d,IORING_CQE_F_MORE
	jnz	@f
	call	arm_timer
@@:
	inc	dword [g_tick]
	call	date_update

	cmp	dword [g_accept_paused],0
	je	.sweep_start
	mov	dword [g_accept_paused],0
	cmp	dword [g_draining],0
	jne	.sweep_start
	cmp	dword [g_accept_armed],0
	jne	.sweep_start
	call	arm_accept

.sweep_start:
	; Walk the active list backwards: conn_release swap-removes, which only
	; moves entries we have already visited.
	mov	r13d,[g_active_count]
.sweep:
	dec	r13d
	js	.done
	mov	rax,[g_active_list]
	mov	ebx,[rax+r13*4]
	conn_ptr r12,rbx
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.sweep
	cmp	dword [g_draining],0
	je	.deadline
	mov	eax,[g_tick]
	cmp	eax,[g_drain_deadline]
	jae	.expire
.deadline:
	mov	ecx,IDLE_TIMEOUT
	mov	eax,[r12+C_FLAGS]
	test	eax,F_LINGER
	jz	@f
	mov	ecx,LINGER_TIMEOUT
	jmp	.check
@@:
	test	eax,F_SEND
	jnz	.busy
	cmp	dword [r12+C_IN_LEN],0
	je	.check
.busy:
	mov	ecx,REQUEST_TIMEOUT
.check:
	mov	eax,[g_tick]
	sub	eax,[r12+C_LAST]
	cmp	eax,ecx
	jb	.sweep
.expire:
	call	close_conn
	jmp	.sweep
.done:
	ret

; SIGTERM/SIGINT: stop accepting, close idle connections, let the busy ones
; finish their current response (sent with "Connection: close").
on_signal:
	test	r14d,r14d
	jg	.drain
	jmp	arm_signal
.drain:
	cmp	dword [g_draining],0
	jne	.done
	mov	dword [g_draining],1
	mov	eax,[g_tick]
	add	eax,DRAIN_TIMEOUT
	mov	[g_drain_deadline],eax

	cmp	dword [g_accept_armed],0
	je	.idle
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	byte [rax+SQE_FLAGS],IOSQE_CQE_SKIP_SUCCESS
	mov	rcx,OP_ACCEPT shl 32
	mov	[rax+SQE_ADDR],rcx		; cancel by user_data
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx

.idle:
	mov	r13d,[g_active_count]
.each:
	dec	r13d
	js	.done
	mov	rax,[g_active_list]
	mov	ebx,[rax+r13*4]
	conn_ptr r12,rbx
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.each
	cmp	dword [r12+C_IN_LEN],0
	jne	.each
	test	dword [r12+C_FLAGS],F_SEND or F_LINGER
	jnz	.each
	call	close_conn
	jmp	.each
.done:
	ret
