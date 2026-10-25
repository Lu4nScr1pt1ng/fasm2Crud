; Password hashing in an isolated process.
;
; Argon2id with the OWASP parameters costs about 11 ms of CPU and 19 MiB of
; memory. On the event loop that would stall every connection of the
; worker, so each worker forks a hasher: a process that does nothing but
; compute Argon2id tags. They talk over a SOCK_SEQPACKET socketpair, one
; message per job and one per reply; the worker reads replies through its
; ring and keeps serving requests meanwhile.
;
; The hasher
;   * runs at nice 10 on any CPU of the process, so the worker wins its own
;     CPU back whenever it has work;
;   * keeps only its socket open, cannot be traced or dumped, and installs
;     a seccomp filter before the first job: from then on the kernel lets
;     it read, write, exit and give its Argon2 memory back (madvise on that
;     one range), and kills it for any other system call.
;     (Strict mode would say the same, but it cannot be entered under a
;     filter that is already there, such as Docker's; filters stack.)
;   * dies with its worker (PR_SET_PDEATHSIG). If it dies first, its jobs
;     are answered with 503 and a new hasher starts on the next tick;
;   * gives its memory back after API_TRIM_IDLE seconds without a job,
;     when the worker asks (a job with id 0).
;
; At most HASH_QUEUE_MAX jobs wait per worker; beyond that, auth requests
; get 503 with Retry-After. Logins for unknown addresses hash too, so they
; cost the same and take the same time.

HASH_QUEUE_MAX	= 16
HASH_NICE	= 10

; Job (worker -> hasher).
HJ_ID		= 0		; auth context id + 1
HJ_PW_LEN	= 4
HJ_SALT_LEN	= 8
HJ_M		= 12		; KiB
HJ_T		= 16
HJ_SALT		= 20		; 64
HJ_PW		= 84		; PASSWORD_MAX
HJ_SIZE		= HJ_PW + PASSWORD_MAX

; Reply (hasher -> worker).
HR_ID		= 0
HR_STATUS	= 4		; HASH_xxx
HR_TAG		= 8		; PW_HASH_LEN
HR_SIZE		= HR_TAG + PW_HASH_LEN

HASH_OK		= 0
HASH_INVALID	= -1		; parameters refused
HASH_UNAVAILABLE = -2		; the hasher went away

bss
	align 8
	g_pw_mem	dq ?
	g_hasher_fd	dd ?
	g_hasher_pid	dd ?
	g_hasher_up	dd ?
	g_hasher_jobs	dd ?
	g_hasher_parent	dd ?
	align 16
	g_hjob:		rb 256
	g_hreply:	rb 64
	align 8
	g_a2job:	rb ARGON2_SIZE
	g_hasher_filter: rb HASHER_FILTER_LEN * 8
	g_hasher_fprog	dq ?, ?
	g_hasher_last	dd ?		; tick of the last reply
	g_hasher_dirty	dd ?		; hashed since the last trim
end bss

rodata
	align 16
	pw_dummy_salt	db PW_SALT_LEN dup 0
	hasher_name	db 'fasm2crud-h',0
	; Seccomp filter: read, write and exit; madvise only to give back the
	; Argon2 memory (address patched in at startup, size and advice fixed);
	; anything else, or another architecture, kills the process.
	macro bpf code*, jt*, jf*, k*
		dw code
		db jt, jf
		dd k
	end macro
	BPF_LD_ABS	= 0x20
	BPF_JEQ		= 0x15
	BPF_RET		= 0x06
	hasher_filter_tpl:
	bpf BPF_LD_ABS, 0, 0, 4				; 0: arch
	bpf BPF_JEQ, 1, 0, AUDIT_ARCH_X86_64
	bpf BPF_RET, 0, 0, SECCOMP_RET_KILL_PROCESS
	bpf BPF_LD_ABS, 0, 0, 0				; 3: nr
	bpf BPF_JEQ, 15, 0, SYS_read
	bpf BPF_JEQ, 14, 0, SYS_write
	bpf BPF_JEQ, 13, 0, SYS_exit
	bpf BPF_JEQ, 12, 0, SYS_exit_group
	bpf BPF_JEQ, 0, 10, SYS_madvise
	bpf BPF_LD_ABS, 0, 0, 16			; 9: address, low half
	bpf BPF_JEQ, 0, 8, 0				; 10: patched
	bpf BPF_LD_ABS, 0, 0, 20			; high half
	bpf BPF_JEQ, 0, 6, 0				; 12: patched
	bpf BPF_LD_ABS, 0, 0, 24			; length
	bpf BPF_JEQ, 0, 4, PW_MAX_M_KIB * 1024
	bpf BPF_LD_ABS, 0, 0, 28
	bpf BPF_JEQ, 0, 2, 0
	bpf BPF_LD_ABS, 0, 0, 32			; advice
	bpf BPF_JEQ, 1, 0, MADV_DONTNEED
	bpf BPF_RET, 0, 0, SECCOMP_RET_KILL_PROCESS	; 19
	bpf BPF_RET, 0, 0, SECCOMP_RET_ALLOW		; 20
	HASHER_FILTER_LEN = ($ - hasher_filter_tpl) / 8
end rodata

; ---------------------------------------------------------------- worker side

; Fork a hasher. eax = 0 or -errno.
hasher_start:
	sub	rsp,8
	mov	edi,AF_UNIX
	mov	esi,SOCK_SEQPACKET or SOCK_CLOEXEC
	xor	edx,edx
	mov	r10,rsp
	mov	eax,SYS_socketpair
	syscall
	test	eax,eax
	js	.done
	mov	eax,SYS_getpid
	syscall
	mov	[g_hasher_parent],eax
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.child
	js	.no_fork
	mov	[g_hasher_pid],eax
	mov	edi,[rsp+4]
	mov	eax,SYS_close
	syscall
	mov	eax,[rsp]
	mov	[g_hasher_fd],eax
	mov	dword [g_hasher_up],1
	call	hasher_arm_recv
	xor	eax,eax
	jmp	.done
.child:
	mov	edi,[rsp+4]
	jmp	hasher_main
.no_fork:
	push	rax
	mov	edi,[rsp+8]
	mov	eax,SYS_close
	syscall
	mov	edi,[rsp+12]
	mov	eax,SYS_close
	syscall
	pop	rax
.done:
	add	rsp,8
	ret

hasher_arm_recv:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	ecx,[g_hasher_fd]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_hreply]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],64
	mov	rcx,OP_HASHER shl 32
	mov	[rax+SQE_USER_DATA],rcx
	ret

; Once per tick: replace a hasher that went away, and let an idle one give
; its memory back (up to PW_MAX_M_KIB, 19 MiB with the default
; parameters): a job with id 0 asks for that.
hasher_tick:
	cmp	dword [g_hasher_up],0
	jne	.idle
	cmp	dword [g_draining],0
	jne	.done
	call	hasher_start
	test	eax,eax
	jns	.done
	push	rax
	call	log_begin
	log_lit 'cannot start the password hasher (errno '
	pop	rax
	neg	rax
	call	log_u64
	log_lit ')'
	call	log_end
.done:
	ret
.idle:
	cmp	dword [g_hasher_dirty],0
	je	.done
	cmp	dword [g_hasher_jobs],0
	jne	.done
	mov	eax,[g_tick]
	sub	eax,[g_hasher_last]
	cmp	eax,[g_trim_idle]
	jb	.done
	lea	rdi,[g_hjob]
	mov	ecx,HJ_SIZE
	call	secure_zero			; id 0: trim
	mov	edi,[g_hasher_fd]
	lea	rsi,[g_hjob]
	mov	edx,HJ_SIZE
	mov	r10d,MSG_DONTWAIT or MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	cmp	rax,HJ_SIZE
	jne	.done
	mov	dword [g_hasher_dirty],0
	ret

; Queue a hash for the current request.
; rbx = HTTP slot, r12 = HTTP connection, edi = context (id + 1),
; rsi = salt (<= 64 bytes), edx = salt length, ecx = m (KiB), r8d = t,
; r9d = HCONT_xxx. The password is the context's AC_PW.
; eax = 0 when queued (the connection waits, F_WAIT_DB), -1 when the
; hasher cannot take it now (answer 503).
hasher_submit:
	cmp	dword [g_hasher_up],0
	je	.busy
	cmp	dword [g_hasher_jobs],HASH_QUEUE_MAX
	jae	.busy
	push	r13
	push	r14
	push	r15
	mov	r14d,edi
	mov	r13d,r9d
	lea	rdi,[g_hjob]
	mov	[rdi+HJ_ID],r14d
	mov	[rdi+HJ_SALT_LEN],edx
	mov	[rdi+HJ_M],ecx
	mov	[rdi+HJ_T],r8d
	add	rdi,HJ_SALT
	mov	ecx,edx
	rep	movsb
	mov	edi,r14d
	call	auth_ctx_ptr
	mov	r15,rax
	mov	ecx,[r15+AC_PW_LEN]
	mov	[g_hjob+HJ_PW_LEN],ecx
	lea	rsi,[r15+AC_PW]
	lea	rdi,[g_hjob+HJ_PW]
	rep	movsb
	; The socket buffer holds far more than HASH_QUEUE_MAX jobs, so this
	; never blocks; MSG_DONTWAIT makes sure of it.
	mov	edi,[g_hasher_fd]
	lea	rsi,[g_hjob]
	mov	edx,HJ_SIZE
	mov	r10d,MSG_DONTWAIT or MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	push	rax
	lea	rdi,[g_hjob]
	mov	ecx,HJ_SIZE
	call	secure_zero
	pop	rax
	cmp	rax,HJ_SIZE
	jne	.not_sent
	mov	[r15+AC_SLOT],ebx
	mov	eax,[r12+C_GEN]
	mov	[r15+AC_GEN],eax
	mov	[r15+AC_HCONT],r13d
	or	dword [r15+AC_FLAGS],ACF_HASHING
	inc	dword [g_hasher_jobs]
	mov	dword [g_hasher_dirty],1
	or	dword [r12+C_FLAGS],F_WAIT_DB
	xor	eax,eax
	pop	r15
	pop	r14
	pop	r13
	ret
.not_sent:
	; A dead hasher shows up as EOF on the receive side.
	pop	r15
	pop	r14
	pop	r13
.busy:
	mov	eax,-1
	ret

cstring msg_hasher_gone, 'password hasher exited, restarting'

; A reply, or the end of the hasher. r14 = bytes received or -errno.
on_hasher:
	test	r14d,r14d
	jle	hasher_down
	cmp	r14d,HR_SIZE
	jne	hasher_down
	mov	edi,[g_hreply+HR_ID]
	lea	eax,[rdi-1]
	cmp	eax,AUTH_CTX_MAX
	jae	hasher_down
	call	auth_ctx_ptr
	test	dword [rax+AC_FLAGS],ACF_HASHING
	jz	hasher_down
	mov	edi,[g_hreply+HR_ID]
	mov	esi,[g_hreply+HR_STATUS]
	call	hasher_deliver
	lea	rdi,[g_hreply]
	mov	ecx,64
	call	secure_zero
	jmp	hasher_arm_recv

; The hasher closed its end, died or broke the protocol: answer its jobs
; with 503; hasher_tick starts a new one.
hasher_down:
	call	log_begin
	lea	rsi,[msg_hasher_gone]
	mov	edx,msg_hasher_gone.len
	call	log_str
	call	log_end
	mov	dword [g_hasher_up],0
	mov	edi,[g_hasher_fd]
	mov	eax,SYS_close
	syscall
	mov	edi,[g_hasher_pid]
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
	mov	r13d,1
.each:
	mov	edi,r13d
	call	auth_ctx_ptr
	test	dword [rax+AC_FLAGS],ACF_HASHING
	jz	.next
	mov	edi,r13d
	mov	esi,HASH_UNAVAILABLE
	call	hasher_deliver
.next:
	inc	r13d
	cmp	r13d,AUTH_CTX_MAX
	jbe	.each
	ret

; Hand a finished job to its continuation. edi = context (id + 1),
; esi = HASH_xxx; the tag is at g_hreply+HR_TAG.
; The continuation runs with rbx = HTTP slot, r12 = HTTP connection,
; eax = status, ecx = context, rsi = tag; afterwards the HTTP connection
; resumes parsing. Jobs for connections that went away are dropped.
hasher_deliver:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r13d,edi
	mov	r14d,esi
	call	auth_ctx_ptr
	and	dword [rax+AC_FLAGS],not ACF_HASHING
	dec	dword [g_hasher_jobs]
	mov	ecx,[g_tick]
	mov	[g_hasher_last],ecx
	mov	ebx,[rax+AC_SLOT]
	conn_ptr r12,rbx
	mov	ecx,[rax+AC_GEN]
	cmp	[r12+C_GEN],ecx
	jne	.dropped
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.dropped
	test	dword [r12+C_FLAGS],F_WAIT_DB
	jz	.dropped
	and	dword [r12+C_FLAGS],not F_WAIT_DB
	mov	r8d,[rax+AC_HCONT]
	mov	eax,r14d
	mov	ecx,r13d
	lea	rsi,[g_hreply+HR_TAG]
	call	qword [hash_cont_tbl+r8*8]
	call	http_resume
	jmp	.done
.dropped:
	mov	edi,r13d
	call	auth_ctx_free
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- hasher side

; edi = our end of the socketpair. Never returns.
hasher_main:
	mov	ebx,edi
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_hasher_parent]
	jne	.exit
	mov	edi,PR_SET_NAME
	lea	rsi,[hasher_name]
	mov	eax,SYS_prctl
	syscall
	; Passwords pass through this process: no core dumps, no ptrace by
	; other processes of the same user.
	mov	edi,PR_SET_DUMPABLE
	xor	esi,esi
	mov	eax,SYS_prctl
	syscall
	; Any CPU the service may use, at a lower priority than the workers.
	xor	edi,edi
	mov	esi,128
	lea	rdx,[g_affinity]
	mov	eax,SYS_sched_setaffinity
	syscall
	mov	edi,PRIO_PROCESS
	xor	esi,esi
	mov	edx,HASH_NICE
	mov	eax,SYS_setpriority
	syscall

	; Keep stdio and the socket (as fd 3); close everything inherited from
	; the worker: listeners, the ring, database sockets.
	cmp	ebx,3
	je	@f
	mov	edi,ebx
	mov	esi,3
	xor	edx,edx
	mov	eax,SYS_dup3
	syscall
	test	eax,eax
	js	.exit
@@:
	mov	edi,4
	mov	esi,-1
	xor	edx,edx
	mov	eax,SYS_close_range
	syscall

	xor	edi,edi
	mov	esi,PW_MAX_M_KIB * 1024
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.no_memory
	mov	[g_pw_mem],rax

	; Without the filter the hasher does not serve: the worker answers
	; 503 for auth and retries every tick, and the log says why.
	mov	edi,PR_SET_NO_NEW_PRIVS
	mov	esi,1
	xor	edx,edx
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.no_filter
	; The filter, with the address of the memory it may give back.
	lea	rsi,[hasher_filter_tpl]
	lea	rdi,[g_hasher_filter]
	mov	ecx,HASHER_FILTER_LEN * 8
	rep	movsb
	mov	rax,[g_pw_mem]
	mov	[g_hasher_filter+10*8+4],eax
	shr	rax,32
	mov	[g_hasher_filter+12*8+4],eax
	mov	word [g_hasher_fprog],HASHER_FILTER_LEN
	lea	rax,[g_hasher_filter]
	mov	[g_hasher_fprog+8],rax
	mov	edi,PR_SET_SECCOMP
	mov	esi,SECCOMP_MODE_FILTER
	lea	rdx,[g_hasher_fprog]
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.no_filter

.serve:
	mov	edi,3
	lea	rsi,[g_hjob]
	mov	edx,256
	mov	eax,SYS_read
	syscall
	cmp	rax,-EINTR
	je	.serve
	cmp	rax,HJ_SIZE
	jne	.exit				; EOF (the worker is gone) or garbage
	cmp	dword [g_hjob+HJ_ID],0
	je	.trim
	call	hasher_job
	mov	edi,3
	lea	rsi,[g_hreply]
	mov	edx,HR_SIZE
	mov	eax,SYS_write
	syscall
	push	rax
	lea	rdi,[g_hjob]
	mov	ecx,256
	call	secure_zero
	lea	rdi,[g_hreply]
	mov	ecx,64
	call	secure_zero
	pop	rax
	cmp	rax,HR_SIZE
	je	.serve
.trim:
	; The worker saw us idle: give the Argon2 memory back. No reply.
	mov	rdi,[g_pw_mem]
	mov	esi,PW_MAX_M_KIB * 1024
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	jmp	.serve
.exit:
	; exit is enough for a single-threaded process, and the filter allows it.
	xor	edi,edi
	mov	eax,SYS_exit
	syscall
	hlt
.no_memory:
	call	log_begin
	log_lit 'password hasher: cannot reserve its memory'
	call	log_end
	jmp	.exit
.no_filter:
	push	rax
	call	log_begin
	log_lit 'password hasher: cannot install its seccomp filter (errno '
	pop	rax
	neg	rax
	call	log_u64
	log_lit ')'
	call	log_end
	jmp	.exit

; g_hjob -> g_hreply. The worker is trusted, but the limits are checked
; again so a bad job can never run past the buffers or the memory.
hasher_job:
	lea	rbx,[g_hjob]
	mov	eax,[rbx+HJ_ID]
	mov	[g_hreply+HR_ID],eax
	mov	dword [g_hreply+HR_STATUS],HASH_INVALID
	mov	edx,[rbx+HJ_PW_LEN]
	cmp	edx,PASSWORD_MAX
	ja	.done
	mov	r8d,[rbx+HJ_SALT_LEN]
	cmp	r8d,8
	jb	.done
	cmp	r8d,64
	ja	.done
	mov	r9d,[rbx+HJ_M]
	cmp	r9d,8
	jb	.done
	cmp	r9d,PW_MAX_M_KIB
	ja	.done
	mov	eax,[rbx+HJ_T]
	test	eax,eax
	jz	.done
	cmp	eax,PW_MAX_T
	ja	.done
	push	rax
	lea	rdi,[g_hreply+HR_TAG]
	lea	rsi,[rbx+HJ_PW]
	lea	rcx,[rbx+HJ_SALT]
	call	argon2id_tag
	add	rsp,8
	mov	[g_hreply+HR_STATUS],eax
.done:
	ret

; Argon2id tag. rdi = tag[32], rsi = password, edx = its length,
; rcx = salt, r8d = salt length, r9d = m (KiB), [rsp+8] = t.
; eax = 0, or -1 for invalid parameters.
argon2id_tag:
	lea	rax,[g_a2job]
	mov	[rax+A2_OUT],rdi
	mov	dword [rax+A2_OUTLEN],PW_HASH_LEN
	mov	[rax+A2_PWD],rsi
	mov	[rax+A2_PWDLEN],edx
	mov	[rax+A2_SALT],rcx
	mov	[rax+A2_SALTLEN],r8d
	mov	qword [rax+A2_SECRET],0
	mov	dword [rax+A2_SECRETLEN],0
	mov	qword [rax+A2_AD],0
	mov	dword [rax+A2_ADLEN],0
	mov	[rax+A2_M],r9d
	mov	ecx,[rsp+8]
	mov	[rax+A2_T],ecx
	mov	dword [rax+A2_P],PW_P
	mov	dword [rax+A2_TYPE],ARGON2_ID
	mov	rcx,[g_pw_mem]
	mov	[rax+A2_MEM],rcx
	mov	rdi,rax
	jmp	argon2_hash
