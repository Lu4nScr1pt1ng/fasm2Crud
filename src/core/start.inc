; Process entry and runtime configuration.

bss
	g_port		dd ?
	g_workers	dd ?
	g_max_conns	dd ?
	g_busy_poll_us	dd ?
	g_cpu_count	dd ?
	g_affinity:	rb 128		; cpu_set_t of the process at startup (1024 CPUs)
end bss

cstring str_arg_healthcheck, 'healthcheck',0
cstring env_port, 'API_PORT='
cstring env_workers, 'API_WORKERS='
cstring env_max_conns, 'API_MAX_CONNS='
cstring env_busy_poll, 'API_BUSY_POLL_US='

start:
	; At entry: [rsp] = argc, then argv[], NULL, envp[], NULL.
	mov	rax,[rsp]
	mov	[g_argc],rax
	lea	rcx,[rsp+8]
	mov	[g_argv],rcx
	lea	rcx,[rcx+rax*8+8]
	mov	[g_envp],rcx
	and	rsp,-16

	call	cpu_require
	call	config_load

	cmp	qword [g_argc],2
	jb	supervisor_main
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_arg_healthcheck]
	call	cstr_eq
	test	eax,eax
	jnz	healthcheck_main
	call	log_begin
	log_lit 'usage: fasm2crud [healthcheck]'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; Settings come from the environment so the same image runs anywhere:
;   API_PORT       listening port (default 8080)
;   API_WORKERS    worker processes (default: CPUs this process may run on)
;   API_MAX_CONNS  connections per worker (default 8192)
;   API_BUSY_POLL_US  spin this long for new completions before sleeping
config_load:
	; CPUs available to us, honouring cgroup cpusets and taskset.
	xor	edi,edi
	mov	esi,128
	lea	rdx,[g_affinity]
	mov	eax,SYS_sched_getaffinity
	syscall
	xor	ecx,ecx
	test	rax,rax
	jle	.counted
	xor	edx,edx
.count:
	popcnt	r8,[g_affinity+rdx*8]
	add	ecx,r8d
	inc	edx
	cmp	edx,16
	jb	.count
.counted:
	test	ecx,ecx
	jnz	@f
	mov	ecx,1
@@:
	mov	[g_cpu_count],ecx

	lea	rdi,[env_port]
	mov	esi,env_port.len
	mov	edx,DEFAULT_PORT
	mov	ecx,1
	mov	r8d,65535
	call	env_uint
	mov	[g_port],eax

	lea	rdi,[env_workers]
	mov	esi,env_workers.len
	mov	edx,[g_cpu_count]
	cmp	edx,MAX_WORKERS
	jbe	@f
	mov	edx,MAX_WORKERS
@@:
	mov	ecx,1
	mov	r8d,MAX_WORKERS
	call	env_uint
	mov	[g_workers],eax

	lea	rdi,[env_max_conns]
	mov	esi,env_max_conns.len
	mov	edx,DEFAULT_MAX_CONNS
	mov	ecx,MIN_MAX_CONNS
	mov	r8d,MAX_MAX_CONNS
	call	env_uint
	mov	[g_max_conns],eax

	lea	rdi,[env_busy_poll]
	mov	esi,env_busy_poll.len
	mov	edx,DEFAULT_BUSY_POLL_US
	xor	ecx,ecx
	mov	r8d,1000000
	call	env_uint
	mov	[g_busy_poll_us],eax
	ret
