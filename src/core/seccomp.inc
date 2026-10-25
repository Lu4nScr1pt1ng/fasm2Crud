; Seccomp filters for the whole binary.
;
; Filters are inherited across fork and can only get stricter, so they are
; layered:
;   supervisor  before the first fork: what it needs from then on, plus
;               what a worker and a hasher need to start
;   worker      once it is set up: what it needs while serving, plus what a
;               replacement hasher needs to start
;   hasher      its own, tightest (src/auth/password.inc)
; Everything else is refused: no execve, no open or openat (the server
; never opens a file), no ptrace, no clone/clone3/vfork (fork only), no
; executable mappings (mmap and mprotect without PROT_EXEC), sockets of
; the two families in use only, prctl with the options in use only.
;
; A refused call raises SIGSYS; the handler logs which call it was and
; exits, and the supervisor restarts the worker like after any crash. A
; foreign architecture (x32, i386) kills the process outright.
;
; io_uring operations do not go through seccomp: the ring is locked down
; separately with IORING_REGISTER_RESTRICTIONS (src/core/ring.inc).

SECCOMP_RET_TRAP = 0x00030000
SA_SIGINFO	= 4
SA_RESTORER	= 0x04000000
SIGSYS		= 31
SI_SYSCALL	= 24		; siginfo_t, SIGSYS: si_syscall

; BPF over struct seccomp_data: nr at 0, arch at 4, args[i] at 16 + 8 * i.
macro bpf_ld off*
	dw 0x20
	db 0, 0
	dd off
end macro

macro bpf_ret k*
	dw 0x06
	db 0, 0
	dd k
end macro

; Conditional jumps to labels further down.
macro bpf_jeq k*, t*, f*
	local here
	here:
	dw 0x15
	db (t - here) / 8 - 1, (f - here) / 8 - 1
	dd k
end macro

macro bpf_jset k*, t*, f*
	local here
	here:
	dw 0x45
	db (t - here) / 8 - 1, (f - here) / 8 - 1
	dd k
end macro

; A filter: sc_begin name, then sc_allow / sc_check lines, sc_end name,
; then the argument checks the sc_check lines jump to.
macro sc_begin f*
	align 8
	f:
	bpf_ld 4
	bpf_jeq AUDIT_ARCH_X86_64, f#.nr, f#.kill
	f#.nr:
	bpf_ld 0
end macro

macro sc_allow f*, nr*
	local next
	bpf_jeq nr, f#.allow, next
	next:
end macro

macro sc_check f*, nr*, block*
	local next
	bpf_jeq nr, f#.#block, next
	next:
end macro

macro sc_end f*
	; Argument checks (BPF only jumps forward: the returns come last).
	f#.no_exec:				; mmap, mprotect: prot is args[2]
	bpf_ld 32
	bpf_jset PROT_EXEC, f#.trap, f#.allow
	f#.prctl:
	bpf_ld 16
	bpf_jeq PR_SET_PDEATHSIG, f#.allow, f#.p1
	f#.p1:
	bpf_jeq PR_SET_NAME, f#.allow, f#.p2
	f#.p2:
	bpf_jeq PR_SET_DUMPABLE, f#.allow, f#.p3
	f#.p3:
	bpf_jeq PR_SET_NO_NEW_PRIVS, f#.allow, f#.p4
	f#.p4:
	bpf_jeq PR_SET_SECCOMP, f#.allow, f#.trap
	f#.socket:
	bpf_ld 16
	bpf_jeq AF_INET, f#.allow, f#.s1
	f#.s1:
	bpf_jeq AF_UNIX, f#.allow, f#.trap
	f#.socketpair:
	bpf_ld 16
	bpf_jeq AF_UNIX, f#.allow, f#.trap
	f#.trap:
	bpf_ret SECCOMP_RET_TRAP
	f#.kill:
	bpf_ret SECCOMP_RET_KILL_PROCESS
	f#.allow:
	bpf_ret SECCOMP_RET_ALLOW
	f#.end:
	f#.len = (f#.end - f) / 8
	assert f#.len <= 256			; jump offsets are 8 bits
end macro

; What a worker needs while serving, and a new hasher to start.
macro sc_serving f*
	sc_allow f, SYS_io_uring_enter
	sc_allow f, SYS_write
	sc_allow f, SYS_read
	sc_allow f, SYS_close
	sc_allow f, SYS_clock_gettime
	sc_allow f, SYS_madvise
	sc_allow f, SYS_getrandom
	sc_allow f, SYS_sendto
	sc_allow f, SYS_setsockopt
	sc_check f, SYS_socket, socket
	sc_check f, SYS_socketpair, socketpair
	sc_check f, SYS_mmap, no_exec
	sc_check f, SYS_prctl, prctl
	sc_allow f, SYS_fork
	sc_allow f, SYS_getpid
	sc_allow f, SYS_getppid
	sc_allow f, SYS_kill
	sc_allow f, SYS_sched_setaffinity
	sc_allow f, SYS_setpriority
	sc_allow f, SYS_dup3
	sc_allow f, SYS_close_range
	sc_allow f, SYS_rt_sigreturn
	sc_allow f, SYS_exit
	sc_allow f, SYS_exit_group
end macro

rodata
	sc_begin filter_supervisor
	sc_serving filter_supervisor
	; The supervisor itself.
	sc_allow filter_supervisor, SYS_waitid
	sc_allow filter_supervisor, SYS_nanosleep
	; A worker starting.
	sc_allow filter_supervisor, SYS_signalfd4
	sc_allow filter_supervisor, SYS_rt_sigaction
	sc_check filter_supervisor, SYS_mprotect, no_exec
	sc_allow filter_supervisor, SYS_io_uring_setup
	sc_allow filter_supervisor, SYS_io_uring_register
	bpf_jeq 0, filter_supervisor.trap, filter_supervisor.trap	; anything else
	sc_end filter_supervisor

	sc_begin filter_worker
	sc_serving filter_worker
	bpf_jeq 0, filter_worker.trap, filter_worker.trap
	sc_end filter_worker

	align 8
	sigact_sigsys	dq on_sigsys, SA_SIGINFO or SA_RESTORER, sigsys_restorer, 0
end rodata

; edx = filter length, rsi = filter. Exits when it cannot be installed: a
; process that was meant to be confined must not run unconfined.
seccomp_install:
	sub	rsp,16
	mov	word [rsp],dx
	mov	[rsp+8],rsi
	mov	edi,PR_SET_NO_NEW_PRIVS
	mov	esi,1
	xor	edx,edx
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.failed
	mov	edi,PR_SET_SECCOMP
	mov	esi,SECCOMP_MODE_FILTER
	mov	rdx,rsp
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.failed
	add	rsp,16
	ret
.failed:
	push	rax
	call	log_begin
	log_lit 'cannot install the seccomp filter (errno '
	pop	rax
	neg	rax
	call	log_u64
	log_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; Supervisor, before the first fork: the SIGSYS handler (inherited by
; every process) and the outer filter.
seccomp_supervisor:
	mov	edi,SIGSYS
	lea	rsi,[sigact_sigsys]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall
	lea	rsi,[filter_supervisor]
	mov	edx,filter_supervisor.len
	jmp	seccomp_install

; Worker, once it is set up.
seccomp_worker:
	lea	rsi,[filter_worker]
	mov	edx,filter_worker.len
	jmp	seccomp_install

; SIGSYS: rsi = siginfo_t. Log the call and exit.
on_sigsys:
	mov	ebx,[rsi+SI_SYSCALL]
	call	log_begin
	log_lit 'seccomp refused system call '
	mov	eax,ebx
	call	log_u64
	log_lit ', exiting'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

sigsys_restorer:
	mov	eax,SYS_rt_sigreturn
	syscall
