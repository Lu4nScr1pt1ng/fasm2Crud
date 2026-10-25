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
cstring env_db_host, 'API_DB_HOST='
cstring env_db_port, 'API_DB_PORT='
cstring env_db_user, 'API_DB_USER='
cstring env_db_name, 'API_DB_NAME='
cstring env_db_password, 'API_DB_PASSWORD='
cstring env_db_conns, 'API_DB_CONNS='
cstring env_token_key, 'API_TOKEN_KEY='
cstring default_db_user, 'api'
cstring default_db_name, 'fasm2crud'

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
;   API_DB_HOST    PostgreSQL IPv4 address; unset disables the database
;   API_DB_PORT    (default 5432)
;   API_DB_USER    (default api)
;   API_DB_NAME    (default fasm2crud)
;   API_DB_PASSWORD  required with API_DB_HOST
;   API_DB_CONNS   connections per worker (default 2)
;   API_TOKEN_KEY  base64url of the 32-byte access token key; when unset or
;                  empty a random key is made at startup (tokens die with
;                  the process)
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
	call	config_token_key
	jmp	config_db

; The key is read (or made) before the workers fork, so all share it.
config_token_key:
	lea	rdi,[env_token_key]
	mov	esi,env_token_key.len
	call	getenv
	test	rax,rax
	jz	.random
	cmp	byte [rax],0			; set but empty (compose default): unset
	je	.random
	mov	rsi,rax
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],0
	je	@f
	inc	edx
	cmp	edx,64
	jb	@b
@@:
	cmp	edx,43
	jne	.bad
	lea	rdi,[g_token_key]
	call	base64url_decode
	cmp	rax,32
	jne	.bad
	ret
.random:
	lea	rdi,[g_token_key]
	mov	esi,32
	call	random_bytes
	test	eax,eax
	jnz	.bad
	; The healthcheck subcommand has no use for a key; stay quiet there.
	cmp	qword [g_argc],2
	jae	.done
	call	log_begin
	log_lit 'API_TOKEN_KEY is not set: using a random key, tokens will not survive a restart'
	call	log_end
.done:
	ret
.bad:
	call	log_begin
	log_lit 'API_TOKEN_KEY must be 32 random bytes in base64url (43 characters)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; Database settings. Strings point into the environment block.
config_db:
	lea	rdi,[env_db_host]
	mov	esi,env_db_host.len
	call	getenv
	test	rax,rax
	jz	.disabled
	mov	rsi,rax
	call	parse_ipv4
	jc	.bad_host
	mov	[g_db_addr],eax
	mov	dword [g_db_enabled],1

	lea	rdi,[env_db_port]
	mov	esi,env_db_port.len
	mov	edx,5432
	mov	ecx,1
	mov	r8d,65535
	call	env_uint
	mov	[g_db_port],eax
	lea	rdi,[env_db_conns]
	mov	esi,env_db_conns.len
	mov	edx,2
	mov	ecx,1
	mov	r8d,PG_MAX_CONNS
	call	env_uint
	mov	[g_pg_count],eax

	lea	rdi,[env_db_user]
	mov	esi,env_db_user.len
	lea	rdx,[default_db_user]
	mov	ecx,default_db_user.len
	call	env_string
	mov	[g_db_user],rax
	mov	[g_db_user_len],edx
	lea	rdi,[env_db_name]
	mov	esi,env_db_name.len
	lea	rdx,[default_db_name]
	mov	ecx,default_db_name.len
	call	env_string
	mov	[g_db_name],rax
	mov	[g_db_name_len],edx
	lea	rdi,[env_db_password]
	mov	esi,env_db_password.len
	xor	edx,edx
	xor	ecx,ecx
	call	env_string
	test	edx,edx
	jz	.no_password
	mov	[g_db_pass],rax
	mov	[g_db_pass_len],edx
	ret
.disabled:
	ret
.bad_host:
	call	log_begin
	log_lit 'invalid API_DB_HOST: expected an IPv4 address'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.no_password:
	call	log_begin
	log_lit 'API_DB_PASSWORD is required with API_DB_HOST'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
