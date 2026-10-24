; Shared helpers: logging, numbers, environment, CPU checks.
;
; Calling convention for every routine in this program (SysV-like):
; arguments in rdi, rsi, rdx, rcx, r8; result in rax; rbx, rbp and r12-r15
; are preserved; everything else, including flags, may be clobbered.

LOG_CAP = 480

bss
	g_argc		dq ?
	g_argv		dq ?
	g_envp		dq ?
	g_is_worker	dd ?
	g_worker_id	dd ?
	g_log_len	dd ?
	g_log_buf:	rb LOG_CAP + 1
end bss

cstring str_log_prefix, 'fasm2crud: '

; Append a literal to the current log line.
macro log_lit text&
	local s
	cstring s, text
	lea	rsi,[s]
	mov	edx,s.len
	call	log_str
end macro

; Start a log line: "fasm2crud: " or "fasm2crud: worker N: ".
log_begin:
	mov	dword [g_log_len],0
	lea	rsi,[str_log_prefix]
	mov	edx,str_log_prefix.len
	call	log_str
	cmp	dword [g_is_worker],0
	je	.done
	log_lit 'worker '
	mov	eax,[g_worker_id]
	call	log_u64
	log_lit ': '
.done:
	ret

; rsi = text, edx = length. Truncates silently when the line is full.
log_str:
	mov	ecx,[g_log_len]
	mov	eax,LOG_CAP
	sub	eax,ecx
	cmp	edx,eax
	jbe	@f
	mov	edx,eax
@@:
	lea	rdi,[g_log_buf+rcx]
	add	ecx,edx
	mov	[g_log_len],ecx
	mov	ecx,edx
	rep	movsb
	ret

; rax = unsigned value.
log_u64:
	sub	rsp,24
	lea	rdi,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	rcx
	add	dl,'0'
	dec	rdi
	mov	[rdi],dl
	test	rax,rax
	jnz	@b
	mov	rsi,rdi
	lea	rdx,[rsp+24]
	sub	rdx,rdi
	call	log_str
	add	rsp,24
	ret

; rax = signed value.
log_i64:
	test	rax,rax
	jns	log_u64
	push	rax
	log_lit '-'
	pop	rax
	neg	rax
	jmp	log_u64

; Terminate the line and write it to stderr in a single write.
log_end:
	mov	ecx,[g_log_len]
	mov	byte [g_log_buf+rcx],10
	lea	edx,[rcx+1]
	lea	rsi,[g_log_buf]
	mov	edi,2
	mov	eax,SYS_write
	syscall
	mov	dword [g_log_len],0
	ret

; edi = exit status. Does not return.
exit_process:
	mov	eax,SYS_exit_group
	syscall
	hlt

; rdi, rsi = NUL-terminated strings. eax = 1 when equal.
cstr_eq:
	xor	ecx,ecx
@@:
	mov	al,[rdi+rcx]
	cmp	al,[rsi+rcx]
	jne	.differ
	inc	rcx
	test	al,al
	jnz	@b
	mov	eax,1
	ret
.differ:
	xor	eax,eax
	ret

; rdi = "NAME=" prefix, esi = its length. rax = value or 0 when unset.
getenv:
	mov	r8,[g_envp]
.next:
	mov	r9,[r8]
	test	r9,r9
	jz	.none
	add	r8,8
	xor	ecx,ecx
.compare:
	cmp	ecx,esi
	je	.found
	mov	al,[r9+rcx]
	cmp	al,[rdi+rcx]
	jne	.next
	inc	ecx
	jmp	.compare
.found:
	lea	rax,[r9+rsi]
	ret
.none:
	xor	eax,eax
	ret

; rsi = NUL-terminated decimal (at most 9 digits). rax = value, CF on error.
parse_uint_cstr:
	xor	eax,eax
	xor	ecx,ecx
.digit:
	movzx	edx,byte [rsi+rcx]
	test	edx,edx
	jz	.end
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	cmp	ecx,9
	jae	.bad
	imul	rax,rax,10
	add	rax,rdx
	inc	ecx
	jmp	.digit
.end:
	test	ecx,ecx
	jz	.bad
	clc
	ret
.bad:
	stc
	ret

; Read an unsigned integer setting from the environment.
; rdi = "NAME=", esi = its length, rdx = default, rcx = min, r8 = max.
; rax = value. Exits with EXIT_CONFIG when the value is malformed or out of range.
env_uint:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	mov	r14,rcx
	mov	r15,r8
	call	getenv
	test	rax,rax
	jz	.default
	mov	rsi,rax
	call	parse_uint_cstr
	jc	.invalid
	cmp	rax,r14
	jb	.invalid
	cmp	rax,r15
	ja	.invalid
	jmp	.done
.default:
	mov	rax,r13
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.invalid:
	call	log_begin
	log_lit 'invalid '
	mov	rsi,rbx
	lea	edx,[r12-1]
	call	log_str
	log_lit ': expected an integer from '
	mov	rax,r14
	call	log_u64
	log_lit ' to '
	mov	rax,r15
	call	log_u64
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; The HTTP scanner uses AVX2 and BMI1/BMI2 (x86-64-v3). Refuse to start on
; anything older instead of faulting on the first request.
cpu_require:
	push	rbx
	mov	eax,1
	cpuid
	and	ecx,(1 shl 27) or (1 shl 28)		; OSXSAVE, AVX
	cmp	ecx,(1 shl 27) or (1 shl 28)
	jne	.unsupported
	xor	ecx,ecx
	xgetbv
	and	eax,6					; XMM and YMM state enabled by the OS
	cmp	eax,6
	jne	.unsupported
	mov	eax,7
	xor	ecx,ecx
	cpuid
	and	ebx,(1 shl 3) or (1 shl 5) or (1 shl 8)	; BMI1, AVX2, BMI2
	cmp	ebx,(1 shl 3) or (1 shl 5) or (1 shl 8)
	jne	.unsupported
	pop	rbx
	ret
.unsupported:
	call	log_begin
	log_lit 'this CPU lacks AVX2/BMI2 (x86-64-v3 is required)'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; rax = seconds on the monotonic clock.
monotonic_seconds:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,24
	ret
