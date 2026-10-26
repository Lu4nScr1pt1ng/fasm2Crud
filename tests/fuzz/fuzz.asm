; Fuzz harness for the request parser and the JSON parser, persistent:
; one process reads a stream of cases from stdin and writes one result per
; case to stdout (tests/fuzz/fuzz.py drives it and checks every result
; against a reference implementation).
;
; Case: db kind, dd length, bytes. Kinds:
;   0  HTTP: find_header_end, then parse_request on the header block
;   1  JSON: json_parse_object with the credentials schema
;   2  IPv4 text: ipv4_text
;   3  IPv6 text: ipv6_text
;
; Every input ends right where the memory does: the HTTP data is followed
; by exactly the 32 bytes the SIMD scans may read past it (filled with
; CRLFCRLF, to catch a scan that takes them for data) and then a PROT_NONE
; page; the JSON body and its decoding scratch end at a PROT_NONE page
; with no slack at all. Any read or write past what the contract allows
; is a SIGSEGV, which the driver reports as a crash.

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/config.inc'
include '../../src/http/status.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/http/parser.inc'
include '../../src/http/json.inc'
include '../../src/core/hex.inc'
include '../../src/core/ipaddr.inc'

FUZZ_MAX	= 65536
SLACK		= 32
SCRATCH		= 512

cstring jf_email, 'email'
cstring jf_password, 'password'

rodata
	align 8
	fuzz_spec	dq jf_email
			dd jf_email.len, 254
			dq jf_password
			dd jf_password.len, 128
end rodata

bss
	align 8
	g_http_area	dq ?
	g_json_area	dq ?
	g_scratch_area	dq ?
	g_in_len	dd ?
	g_in_pos	dd ?
	g_out_len	dd ?
	g_case_kind	db ?
	align 8
	g_case_len	dd ?
	g_job:		rb JJ_SIZE
	g_vals:		rb 2 * JV_SIZE
	g_case:		rb FUZZ_MAX
	g_in_buf:	rb 65536
	g_out_buf:	rb 65536 + 4096
end bss

; rsi = bytes, edx = count; appended to the output (flushed when full).
out_bytes:
	mov	eax,[g_out_len]
	lea	rdi,[g_out_buf+rax]
	mov	ecx,edx
	add	[g_out_len],edx
	rep	movsb
	cmp	dword [g_out_len],65536
	jb	.done
	jmp	out_flush
.done:
	ret

out_flush:
	lea	rsi,[g_out_buf]
	mov	edx,[g_out_len]
.more:
	test	edx,edx
	jz	.done
	mov	edi,1
	mov	eax,SYS_write
	push	rsi
	push	rdx
	syscall
	pop	rdx
	pop	rsi
	test	rax,rax
	jle	.dead
	add	rsi,rax
	sub	edx,eax
	jmp	.more
.done:
	mov	dword [g_out_len],0
	ret
.dead:
	mov	edi,3
	jmp	exit_process

; Append the value in eax (4 bytes).
out_u32:
	push	rax
	mov	rsi,rsp
	mov	edx,4
	call	out_bytes
	pop	rax
	ret

; rdi = destination, edx = count: read exactly that much from stdin.
; CF at end of input.
in_read:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12d,edx
.next:
	test	r12d,r12d
	jz	.ok
	mov	eax,[g_in_len]
	sub	eax,[g_in_pos]
	jnz	.copy
	xor	edi,edi
	lea	rsi,[g_in_buf]
	mov	edx,65536
	mov	eax,SYS_read
	syscall
	test	rax,rax
	jle	.eof
	mov	[g_in_len],eax
	mov	dword [g_in_pos],0
	jmp	.next
.copy:
	cmp	eax,r12d
	cmova	eax,r12d
	mov	ecx,eax
	mov	esi,[g_in_pos]
	add	[g_in_pos],eax
	sub	r12d,eax
	lea	rsi,[g_in_buf+rsi]
	mov	rdi,rbx
	add	rbx,rcx
	rep	movsb
	jmp	.next
.ok:
	pop	r12
	pop	rbx
	clc
	ret
.eof:
	pop	r12
	pop	rbx
	stc
	ret

; Two pages of address space and a PROT_NONE page after them.
; rax = start of the guard page.
guarded_area:
	xor	edi,edi
	mov	esi,FUZZ_MAX + 2 * PAGE_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.fail
	push	rax
	lea	rdi,[rax+FUZZ_MAX + PAGE_SIZE]
	mov	esi,PAGE_SIZE
	mov	edx,PROT_NONE
	mov	eax,SYS_mprotect
	syscall
	pop	rax
	add	rax,FUZZ_MAX + PAGE_SIZE
	ret
.fail:
	mov	edi,4
	jmp	exit_process

start:
	mov	rax,[rsp]
	mov	[g_argc],rax
	call	guarded_area
	mov	[g_http_area],rax
	call	guarded_area
	mov	[g_json_area],rax
	call	guarded_area
	mov	[g_scratch_area],rax
.case:
	lea	rdi,[g_case_kind]
	mov	edx,5
	call	in_read
	jc	.end
	mov	edx,dword [g_case_kind+1]
	mov	[g_case_len],edx
	cmp	edx,FUZZ_MAX - SLACK
	ja	.bad_input
	lea	rdi,[g_case]
	call	in_read
	jc	.bad_input
	cmp	byte [g_case_kind],0
	je	.http
	cmp	byte [g_case_kind],1
	je	.json
	cmp	byte [g_case_kind],2
	je	.ipv4
	cmp	byte [g_case_kind],3
	je	.ipv6
.bad_input:
	call	out_flush
	mov	edi,2
	jmp	exit_process
.end:
	call	out_flush
	xor	edi,edi
	jmp	exit_process

; Result: dd find (offset past CRLFCRLF, 0 incomplete, -1 bare LF),
; dd status (HTTP code, 0 when valid or not parsed), then when valid:
; method, version, flags, hosts, headers, length, and offset/length
; pairs (-1 when absent) for path, query, content-type, authorization,
; if-match.
.http:
	; data, then the slack, then the guard page
	mov	rdi,[g_http_area]
	sub	rdi,SLACK
	mov	rax,0x0A0D0A0D0A0D0A0D
	mov	[rdi],rax
	mov	[rdi+8],rax
	mov	[rdi+16],rax
	mov	[rdi+24],rax
	mov	ecx,[g_case_len]
	sub	rdi,rcx
	push	rdi
	lea	rsi,[g_case]
	rep	movsb
	mov	rdi,[rsp]
	mov	esi,[g_case_len]
	xor	edx,edx
	call	find_header_end
	push	rax
	call	out_u32
	pop	rax
	test	eax,eax
	jle	.http_none
	mov	esi,eax
	mov	rdi,[rsp]
	call	parse_request
	test	eax,eax
	jnz	.http_status
	xor	eax,eax
	call	out_u32
	mov	eax,[req_method]
	call	out_u32
	mov	eax,[req_version]
	call	out_u32
	mov	eax,[req_flags]
	call	out_u32
	mov	eax,[req_hosts]
	call	out_u32
	mov	eax,[req_headers]
	call	out_u32
	mov	eax,[req_length]
	call	out_u32
	pop	rbx				; data start
	mov	rax,[req_path]
	mov	ecx,[req_path_len]
	call	.pair
	mov	rax,[req_query]
	mov	ecx,[req_query_len]
	call	.pair
	mov	rax,[req_ctype]
	mov	ecx,[req_ctype_len]
	call	.pair
	mov	rax,[req_auth]
	mov	ecx,[req_auth_len]
	call	.pair
	mov	rax,[req_if_match]
	mov	ecx,[req_if_match_len]
	call	.pair
	jmp	.case
.http_status:
	shl	eax,5
	mov	rsi,[status_tbl+rax]
	movzx	eax,byte [rsi+9]
	sub	eax,'0'
	imul	eax,eax,100
	movzx	ecx,byte [rsi+10]
	sub	ecx,'0'
	imul	ecx,ecx,10
	add	eax,ecx
	movzx	ecx,byte [rsi+11]
	sub	ecx,'0'
	add	eax,ecx
	call	out_u32
	pop	rax
	jmp	.case
.http_none:
	xor	eax,eax
	call	out_u32
	pop	rax
	jmp	.case

; rax = pointer or 0, ecx = length: offset from rbx and length, or -1, 0.
.pair:
	push	rcx
	test	rax,rax
	jz	.absent
	sub	rax,rbx
	call	out_u32
	pop	rax
	jmp	out_u32
.absent:
	mov	eax,-1
	call	out_u32
	pop	rax
	xor	eax,eax
	jmp	out_u32

; Result: db 1 when valid, then dd address (IPv4) or 16 bytes (IPv6).
; The text ends at the guard page, like the JSON bodies.
.ipv4:
	call	.place
	mov	edx,[g_case_len]
	call	ipv4_text
	jmp	.ip_out4
.ipv6:
	call	.place
	mov	edx,[g_case_len]
	sub	rsp,16
	mov	rdi,rsp
	call	ipv6_text
	jc	.ip_bad6
	push	1
	mov	rsi,rsp
	mov	edx,1
	call	out_bytes
	add	rsp,8
	mov	rsi,rsp
	mov	edx,16
	call	out_bytes
	add	rsp,16
	jmp	.case
.ip_bad6:
	add	rsp,16
	jmp	.ip_bad
.ip_out4:
	jc	.ip_bad
	push	rax
	push	1
	mov	rsi,rsp
	mov	edx,1
	call	out_bytes
	add	rsp,8
	mov	rsi,rsp
	mov	edx,4
	call	out_bytes
	add	rsp,8
	jmp	.case
.ip_bad:
	push	0
	mov	rsi,rsp
	mov	edx,1
	call	out_bytes
	add	rsp,8
	jmp	.case

; The case at the end of the JSON area: rsi = its start.
.place:
	mov	rdi,[g_json_area]
	mov	ecx,[g_case_len]
	sub	rdi,rcx
	push	rdi
	lea	rsi,[g_case]
	rep	movsb
	pop	rsi
	ret

; Result: db code, then per field: db present, dw length, the bytes.
.json:
	mov	rdi,[g_json_area]
	mov	ecx,[g_case_len]
	sub	rdi,rcx
	push	rdi
	lea	rsi,[g_case]
	rep	movsb
	pop	rdi
	lea	rax,[g_job]
	mov	[rax+JJ_BODY],rdi
	mov	ecx,[g_case_len]
	mov	[rax+JJ_BODY_LEN],ecx
	lea	rcx,[fuzz_spec]
	mov	[rax+JJ_SPEC],rcx
	mov	dword [rax+JJ_FIELDS],2
	lea	rcx,[g_vals]
	mov	[rax+JJ_OUT],rcx
	mov	rcx,[g_scratch_area]
	sub	rcx,SCRATCH
	mov	[rax+JJ_SCRATCH],rcx
	mov	dword [rax+JJ_SCRATCH_CAP],SCRATCH
	mov	rdi,rax
	call	json_parse_object
	push	rax
	mov	rsi,rsp
	mov	edx,1
	call	out_bytes
	pop	rax
	test	eax,eax
	jnz	.json_nothing
	xor	ebx,ebx
.field:
	mov	eax,ebx
	shl	eax,4
	lea	r12,[g_vals+rax]
	cmp	dword [r12+JV_PRESENT],0
	je	.field_absent
	sub	rsp,8
	mov	byte [rsp],1
	mov	eax,[r12+JV_LEN]
	mov	word [rsp+1],ax
	mov	rsi,rsp
	mov	edx,3
	call	out_bytes
	add	rsp,8
	mov	rsi,[r12+JV_PTR]
	mov	edx,[r12+JV_LEN]
	call	out_bytes
	jmp	.field_next
.field_absent:
	sub	rsp,8
	mov	dword [rsp],0
	mov	rsi,rsp
	mov	edx,3
	call	out_bytes
	add	rsp,8
.field_next:
	inc	ebx
	cmp	ebx,2
	jb	.field
	jmp	.case
.json_nothing:
	sub	rsp,8
	mov	qword [rsp],0
	mov	rsi,rsp
	mov	edx,6
	call	out_bytes
	add	rsp,8
	jmp	.case

segment readable
	rodata_emit

segment readable writeable
	bss_emit

segment gnustack
