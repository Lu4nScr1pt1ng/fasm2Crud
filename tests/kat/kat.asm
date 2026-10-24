; Known-answer tests for the crypto modules (FIPS 180-4, RFC 4231,
; RFC 7914 section 11). Prints one line per vector; exits 1 on any failure.

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/config.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/crypto/ct.inc'
include '../../src/crypto/sha256.inc'
include '../../src/crypto/hmac.inc'

bss
	align 16
	kat_failed	dd ?
	kat_out:	rb 64
	kat_big:	rb 1000000
	kat_ctx:	rb HMAC_CTX_SIZE
	kat_hex:	rb 2
end bss

; Define a test vector: name, input bytes, expected hex digest.
macro vector label*, text&
	cstring label, text
end macro

macro hexbytes label*, hex*
	local s, n, hi, lo
	rodata
		label = $
		virtual at 0
			db hex
			n = $
		end virtual
		repeat n / 2
			virtual at 0
				db hex
				load hi:byte from (% - 1) * 2
				load lo:byte from (% - 1) * 2 + 1
			end virtual
			if hi >= 'a'
				hi = hi - 'a' + 10
			else
				hi = hi - '0'
			end if
			if lo >= 'a'
				lo = lo - 'a' + 10
			else
				lo = lo - '0'
			end if
			db hi * 16 + lo
		end repeat
		label.len = $ - label
	end rodata
end macro

vector v_abc, 'abc'
cstring hex_digits, '0123456789abcdef'
vector v_448, 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
hexbytes d_empty, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
hexbytes d_abc, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
hexbytes d_448, '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
hexbytes d_million, 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'

hexbytes k_4231_1, '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'
vector m_4231_1, 'Hi There'
hexbytes h_4231_1, 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
vector k_4231_2, 'Jefe'
vector m_4231_2, 'what do ya want for nothing?'
hexbytes h_4231_2, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
vector m_4231_6, 'Test Using Larger Than Block-Size Key - Hash Key First'
hexbytes h_4231_6, '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'

vector p_passwd, 'passwd'
vector p_password, 'password'
vector s_salt, 'salt'
hexbytes dk_passwd_1, '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'
hexbytes dk_password_4096, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'

; Compare kat_out with an expected digest and report.
macro check name*, expected*
	local n
	cstring n, name
	lea	rsi,[n]
	mov	edx,n.len
	lea	rdi,[expected]
	call	report
end macro

cstring arg_sha256, 'sha256',0
cstring arg_hmac, 'hmac',0
cstring arg_bench, 'bench',0

start:
	mov	rax,[rsp]
	mov	[g_argc],rax
	lea	rcx,[rsp+8]
	mov	[g_argv],rcx
	call	cpu_require
	cmp	qword [g_argc],2
	jb	.vectors
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_sha256]
	call	cstr_eq
	test	eax,eax
	jnz	digest_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_hmac]
	call	cstr_eq
	test	eax,eax
	jnz	hmac_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_bench]
	call	cstr_eq
	test	eax,eax
	jnz	bench
	mov	edi,2
	jmp	exit_process
.vectors:

	lea	rdi,[kat_out]
	lea	rsi,[kat_out]
	xor	edx,edx
	call	sha256
	check	'sha256 empty', d_empty

	lea	rdi,[kat_out]
	lea	rsi,[v_abc]
	mov	edx,v_abc.len
	call	sha256
	check	'sha256 abc', d_abc

	lea	rdi,[kat_out]
	lea	rsi,[v_448]
	mov	edx,v_448.len
	call	sha256
	check	'sha256 448 bits', d_448

	; One million 'a', fed through the streaming API in uneven pieces so
	; the partial-block paths are exercised too.
	lea	rdi,[kat_big]
	mov	al,'a'
	mov	ecx,1000000
	rep	stosb
	lea	rdi,[kat_ctx]
	call	sha256_init
	xor	ebx,ebx
.feed:
	mov	edx,1000000
	sub	edx,ebx
	cmp	edx,997
	jbe	@f
	mov	edx,997
@@:
	test	edx,edx
	jz	.fed
	lea	rdi,[kat_ctx]
	lea	rsi,[kat_big+rbx]
	add	ebx,edx
	call	sha256_update
	jmp	.feed
.fed:
	lea	rdi,[kat_ctx]
	lea	rsi,[kat_out]
	call	sha256_final
	check	'sha256 million a (streamed)', d_million

	lea	rdi,[kat_out]
	lea	rsi,[k_4231_1]
	mov	edx,k_4231_1.len
	lea	rcx,[m_4231_1]
	mov	r8d,m_4231_1.len
	call	hmac_sha256
	check	'hmac-sha256 rfc4231 #1', h_4231_1

	lea	rdi,[kat_out]
	lea	rsi,[k_4231_2]
	mov	edx,k_4231_2.len
	lea	rcx,[m_4231_2]
	mov	r8d,m_4231_2.len
	call	hmac_sha256
	check	'hmac-sha256 rfc4231 #2', h_4231_2

	lea	rdi,[kat_big]
	mov	al,0xAA
	mov	ecx,131
	rep	stosb
	lea	rdi,[kat_out]
	lea	rsi,[kat_big]
	mov	edx,131
	lea	rcx,[m_4231_6]
	mov	r8d,m_4231_6.len
	call	hmac_sha256
	check	'hmac-sha256 rfc4231 #6 (long key)', h_4231_6

	lea	rdi,[kat_out]
	lea	rsi,[p_passwd]
	mov	edx,p_passwd.len
	lea	rcx,[s_salt]
	mov	r8d,s_salt.len
	mov	r9d,1
	call	pbkdf2_sha256
	check	'pbkdf2-sha256 passwd c=1', dk_passwd_1

	lea	rdi,[kat_out]
	lea	rsi,[p_password]
	mov	edx,p_password.len
	lea	rcx,[s_salt]
	mov	r8d,s_salt.len
	mov	r9d,4096
	call	pbkdf2_sha256
	check	'pbkdf2-sha256 password c=4096', dk_password_4096

	; getrandom: 64 bytes, not all zero.
	lea	rdi,[kat_out]
	mov	ecx,64
	call	secure_zero
	lea	rdi,[kat_out]
	mov	esi,64
	call	random_bytes
	test	eax,eax
	jnz	.random_bad
	lea	rdi,[kat_out]
	lea	rsi,[kat_out+32]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jnz	.random_bad
	call	log_begin
	log_lit 'ok   getrandom'
	call	log_end
	jmp	.finish
.random_bad:
	call	log_begin
	log_lit 'FAIL getrandom'
	call	log_end
	mov	dword [kat_failed],1
.finish:
	mov	edi,[kat_failed]
	jmp	exit_process

; Differential testing against a reference implementation:
;   kat sha256  < data             prints SHA-256(data) in hex
;   kat hmac    < u16 key length (little endian), key, message
; Input is at most 1 MB.
read_stdin:
	xor	ebx,ebx
.read:
	xor	edi,edi
	lea	rsi,[kat_big+rbx]
	mov	edx,1000000
	sub	edx,ebx
	jz	.done
	mov	eax,SYS_read
	syscall
	test	rax,rax
	jle	.done
	add	ebx,eax
	jmp	.read
.done:
	ret

digest_stdin:
	call	read_stdin
	lea	rdi,[kat_out]
	lea	rsi,[kat_big]
	mov	edx,ebx
	call	sha256
	jmp	print_out

hmac_stdin:
	call	read_stdin
	movzx	edx,word [kat_big]
	lea	rsi,[kat_big+2]
	lea	rcx,[rsi+rdx]
	mov	r8d,ebx
	sub	r8d,edx
	sub	r8d,2
	lea	rdi,[kat_out]
	call	hmac_sha256
	jmp	print_out

; kat bench: nanoseconds to hash 1 MB 200 times (memory already touched).
bench:
	lea	rdi,[kat_big]
	mov	al,0x5A
	mov	ecx,1000000
	rep	stosb
	call	now_ns
	push	rax
	mov	ebx,200
.again:
	lea	rdi,[kat_out]
	lea	rsi,[kat_big]
	mov	edx,1000000
	call	sha256
	dec	ebx
	jnz	.again
	call	now_ns
	pop	rcx
	sub	rax,rcx
	push	rax
	mov	dword [g_log_len],0
	pop	rax
	call	log_u64
	call	log_end
	xor	edi,edi
	jmp	exit_process

now_ns:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000000
	add	rax,[rsp+8]
	add	rsp,24
	ret

print_out:
	mov	dword [g_log_len],0
	call	log_hex_out
	call	log_end
	xor	edi,edi
	jmp	exit_process

; Append kat_out (32 bytes) in hex to the log line.
log_hex_out:
	push	rbx
	xor	ebx,ebx
.hex:
	movzx	eax,byte [kat_out+rbx]
	mov	ecx,eax
	shr	eax,4
	and	ecx,15
	mov	al,[hex_digits+rax]
	mov	ah,[hex_digits+rcx]
	mov	[kat_hex],ax
	lea	rsi,[kat_hex]
	mov	edx,2
	call	log_str
	inc	ebx
	cmp	ebx,32
	jb	.hex
	pop	rbx
	ret

; rsi = name, edx = name length, rdi = expected 32 bytes (vs kat_out).
report:
	push	rsi
	push	rdx
	lea	rsi,[kat_out]
	mov	edx,32
	call	ct_equal
	push	rax
	call	log_begin
	pop	rax
	test	eax,eax
	jnz	.ok
	mov	dword [kat_failed],1
	log_lit 'FAIL '
	jmp	.name
.ok:
	log_lit 'ok   '
.name:
	pop	rdx
	pop	rsi
	call	log_str
	cmp	dword [kat_failed],0
	je	log_end
	log_lit ' got '
	call	log_hex_out
	jmp	log_end

segment readable
	rodata_emit

segment readable writeable
	bss_emit

segment gnustack
