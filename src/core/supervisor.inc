; Supervisor: owns the listening sockets, forks one worker per CPU and keeps
; them alive.
;
; Each worker gets its own SO_REUSEPORT socket, created here before any fork.
; Because the supervisor keeps every socket open, a worker that crashes does
; not take its accept queue with it: connections the kernel already routed to
; that socket wait there until the replacement worker picks them up.

bss
	g_sup_pid	dd ?
	g_sup_sigfd	dd ?
	g_alive		dd ?
	g_shutdown	dd ?
	g_exit_code	dd ?
	g_sigmask	dq ?
	g_listen_fd	rd MAX_WORKERS
	g_worker_pid	rd MAX_WORKERS
	g_worker_born	rq MAX_WORKERS
	g_siginfo:	rb SIGINFO_SIZE
end bss

rodata
	align 8
	sigact_ignore	dq SIG_IGN, 0, 0, 0	; handler, flags, restorer, mask
	ts_respawn_delay dq 0, 250000000	; 250 ms
	one_int		dd 1
	defer_accept_secs dd 5
end rodata

supervisor_main:
	call	raise_nofile_limit

	; Writes to closed sockets must return EPIPE, never kill the process.
	mov	edi,SIGPIPE
	lea	rsi,[sigact_ignore]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall

	; TERM, INT and CHLD are consumed through a signalfd. Blocking them here
	; also makes workers inherit the blocked mask, so they can do the same.
	mov	qword [g_sigmask],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1)) or (1 shl (SIGCHLD-1))
	mov	edi,SIG_BLOCK
	lea	rsi,[g_sigmask]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigprocmask
	syscall
	mov	edi,-1
	lea	rsi,[g_sigmask]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.no_signalfd
	mov	[g_sup_sigfd],eax

	mov	eax,SYS_getpid
	syscall
	mov	[g_sup_pid],eax

	; One SO_REUSEPORT socket per worker. A single socket drained by every
	; worker's multishot accept was measured at 4x lower throughput: the
	; kernel kept handing all connections to the same worker.
	xor	ebx,ebx
.open_listeners:
	call	listener_open
	mov	[g_listen_fd+rbx*4],eax
	inc	ebx
	cmp	ebx,[g_workers]
	jb	.open_listeners

	call	log_begin
	log_lit 'listening on port '
	mov	eax,[g_port]
	call	log_u64
	log_lit ' with '
	mov	eax,[g_workers]
	call	log_u64
	log_lit ' workers, '
	mov	eax,[g_max_conns]
	call	log_u64
	log_lit ' connections each'
	call	log_end

	call	metrics_init
	; From here on the supervisor and everything it forks are confined.
	call	seccomp_supervisor

	xor	ebx,ebx
.spawn_all:
	mov	edi,ebx
	call	spawn_worker
	inc	ebx
	cmp	ebx,[g_workers]
	jb	.spawn_all

.wait_signal:
	mov	edi,[g_sup_sigfd]
	lea	rsi,[g_siginfo]
	mov	edx,SIGINFO_SIZE
	mov	eax,SYS_read
	syscall
	cmp	rax,-EINTR
	je	.wait_signal
	test	rax,rax
	js	.no_signalfd
	mov	eax,[g_siginfo]			; ssi_signo
	cmp	eax,SIGCHLD
	je	.child
	call	begin_shutdown
	jmp	.wait_signal
.child:
	call	reap_workers
	jmp	.wait_signal

.no_signalfd:
	call	log_begin
	log_lit 'signalfd failed'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; Socket for worker ebx. Exits on failure: without it the service cannot run.
listener_open:
	push	r12
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.failed
	mov	r12d,eax

	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	call	.setsockopt
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEPORT
	lea	r10,[one_int]
	call	.setsockopt
	; Accepted sockets inherit TCP_NODELAY from the listener.
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	lea	r10,[one_int]
	call	.setsockopt
	; Only hand over connections that already sent data; idle connects are
	; dropped by the kernel without ever costing us a slot.
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_DEFER_ACCEPT
	lea	r10,[defer_accept_secs]
	call	.setsockopt

	; struct sockaddr_in { family, port (big endian), 0.0.0.0, zero[8] }
	sub	rsp,16
	mov	eax,[g_port]
	xchg	al,ah
	shl	eax,16
	or	eax,AF_INET
	mov	qword [rsp],rax
	mov	qword [rsp+8],0
	mov	edi,r12d
	mov	rsi,rsp
	mov	edx,16
	mov	eax,SYS_bind
	syscall
	add	rsp,16
	test	eax,eax
	js	.failed
	mov	edi,r12d
	mov	esi,LISTEN_BACKLOG
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.failed
	mov	eax,r12d
	pop	r12
	ret

.setsockopt:
	mov	edi,r12d
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	js	.failed_pop
	ret
.failed_pop:
	add	rsp,8
.failed:
	push	rax
	call	log_begin
	log_lit 'cannot listen on port '
	mov	eax,[g_port]
	call	log_u64
	log_lit ' (errno '
	pop	rax
	neg	rax
	call	log_u64
	log_lit ')'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; edi = worker index.
spawn_worker:
	push	rbx
	mov	ebx,edi
	call	monotonic_seconds
	mov	[g_worker_born+rbx*8],rax
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.child
	js	.failed
	mov	[g_worker_pid+rbx*4],eax
	inc	dword [g_alive]
	pop	rbx
	ret
.child:
	mov	edi,ebx
	jmp	worker_main
.failed:
	call	log_begin
	log_lit 'fork failed, shutting down'
	call	log_end
	mov	dword [g_exit_code],EXIT_FAILURE
	call	begin_shutdown
	pop	rbx
	ret

; Collect every exited worker and replace it, unless we are shutting down.
reap_workers:
	push	rbx
	push	r12
.next:
	lea	rdi,[g_siginfo]
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,P_ALL
	xor	esi,esi
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	test	rax,rax
	js	.done
	mov	r12d,[g_siginfo+SI_PID]
	test	r12d,r12d
	jz	.done

	xor	ebx,ebx
.find:
	cmp	ebx,[g_workers]
	jae	.next
	cmp	[g_worker_pid+rbx*4],r12d
	je	.found
	inc	ebx
	jmp	.find
.found:
	mov	dword [g_worker_pid+rbx*4],0
	dec	dword [g_alive]
	cmp	dword [g_shutdown],0
	jne	.stopping

	cmp	dword [g_siginfo+SI_CODE],CLD_EXITED
	jne	.crashed
	cmp	dword [g_siginfo+SI_STATUS],EXIT_FATAL
	jne	.crashed
	call	log_begin
	log_lit 'worker '
	mov	eax,ebx
	call	log_u64
	log_lit ' could not start, shutting down'
	call	log_end
	mov	dword [g_exit_code],EXIT_FAILURE
	call	begin_shutdown
	jmp	.next

.crashed:
	call	log_begin
	log_lit 'worker '
	mov	eax,ebx
	call	log_u64
	log_lit ' (pid '
	mov	eax,r12d
	call	log_u64
	cmp	dword [g_siginfo+SI_CODE],CLD_EXITED
	jne	.by_signal
	log_lit ') exited with status '
	jmp	.status
.by_signal:
	log_lit ') killed by signal '
.status:
	mov	eax,[g_siginfo+SI_STATUS]
	call	log_u64
	log_lit ', restarting'
	call	log_end

	call	metrics_restart
	; A worker that dies right after starting is crash-looping; slow the
	; restarts down so the supervisor does not spin.
	call	monotonic_seconds
	sub	rax,[g_worker_born+rbx*8]
	cmp	rax,1
	jae	.respawn
	lea	rdi,[ts_respawn_delay]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
.respawn:
	mov	edi,ebx
	call	spawn_worker
	jmp	.next

.stopping:
	cmp	dword [g_alive],0
	jne	.next
	call	log_begin
	log_lit 'all workers stopped'
	call	log_end
	mov	edi,[g_exit_code]
	jmp	exit_process

.done:
	pop	r12
	pop	rbx
	ret

; First TERM/INT: ask workers to drain. A second one forces them down.
begin_shutdown:
	push	rbx
	push	r12
	mov	r12d,SIGTERM
	cmp	dword [g_shutdown],0
	je	.first
	mov	r12d,SIGKILL
	jmp	.signal
.first:
	mov	dword [g_shutdown],1
	call	log_begin
	log_lit 'shutting down'
	call	log_end
	cmp	dword [g_alive],0
	jne	.signal
	mov	edi,[g_exit_code]
	jmp	exit_process
.signal:
	xor	ebx,ebx
.each:
	cmp	ebx,[g_workers]
	jae	.done
	mov	edi,[g_worker_pid+rbx*4]
	test	edi,edi
	jz	.skip
	mov	esi,r12d
	mov	eax,SYS_kill
	syscall
.skip:
	inc	ebx
	jmp	.each
.done:
	pop	r12
	pop	rbx
	ret

; Lift the soft open-file limit to the hard limit: the registered file table
; of every worker is bounded by RLIMIT_NOFILE.
raise_nofile_limit:
	sub	rsp,24
	xor	edi,edi
	mov	esi,RLIMIT_NOFILE
	xor	edx,edx
	mov	r10,rsp
	mov	eax,SYS_prlimit64
	syscall
	test	rax,rax
	js	.done
	mov	rax,[rsp+8]
	mov	[rsp],rax
	xor	edi,edi
	mov	esi,RLIMIT_NOFILE
	mov	rdx,rsp
	xor	r10d,r10d
	mov	eax,SYS_prlimit64
	syscall
	mov	eax,[g_max_conns]
	add	eax,64
	cmp	[rsp],rax
	jae	.done
	call	log_begin
	log_lit 'RLIMIT_NOFILE is lower than API_MAX_CONNS + 64'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.done:
	add	rsp,24
	ret
