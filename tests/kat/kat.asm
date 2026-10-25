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
include '../../src/crypto/blake2b.inc'
include '../../src/crypto/argon2.inc'
include '../../src/core/base64.inc'
include '../../src/db/scram.inc'
include '../../src/core/hex.inc'
include '../../src/http/json.inc'
include '../../src/crypto/phc.inc'
include '../../src/app/validate.inc'
include '../../src/auth/ctx.inc'
include '../../src/auth/token.inc'

; write_u32 lives in the HTTP handler; the tests only need this copy.
write_u32:
	sub	rsp,24
	lea	rsi,[rsp+16]
	mov	ecx,10
@@:
	xor	edx,edx
	div	ecx
	add	dl,'0'
	dec	rsi
	mov	[rsi],dl
	test	eax,eax
	jnz	@b
	lea	rcx,[rsp+16]
	sub	rcx,rsi
	rep	movsb
	add	rsp,24
	ret

bss
	align 16
	kat_failed	dd ?
	kat_report_len	dd ?
	kat_out:	rb 64
	kat_big:	rb 1000000
	kat_ctx:	rb HMAC_CTX_SIZE
	kat_hex:	rb 2
	align 8
	kat_a2:		rb ARGON2_SIZE
	kat_scram:	rb SC_SIZE
	kat_msg:	rb SCRAM_MAX_MSG
	kat_hexbuf:	rb 2050
	align 4096
	kat_mem:	rb 64 * 1024 * 1024
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

hexbytes b2_empty, '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
hexbytes b2_abc, 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
hexbytes a2_tag_d, '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb'
hexbytes a2_tag_i, 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8'
hexbytes a2_tag_id, '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
vector p_passwd, 'passwd'
vector b64_in, 'foobar'
vector b64_out_std, 'Zm9vYmFy'
vector b64_out_f, 'Zg=='
vector b64_out_fo, 'Zm8='
vector b64_out_fob, 'Zm9vYg'
vector b64_bad_pad, 'Zg='
vector b64_bad_bits, 'Zh=='
vector sc_password, 'pencil'
vector sc_nonce, 'rOprNGfwEbeRWgbNEkqO'
vector sc_first, 'n=user,r=rOprNGfwEbeRWgbNEkqO'
vector sc_server, 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
vector sc_final, 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ='
vector sc_verifier, 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='
vector sc_forged, 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G5='
vector sc_bad_nonce, 'r=XXprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
vector p_password, 'password'
vector s_salt, 'salt'
hexbytes dk_passwd_1, '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'
hexbytes dk_password_4096, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'

; Compare kat_out with an expected value and report.
macro check name*, expected*
	local n
	cstring n, name
	lea	rsi,[n]
	mov	edx,n.len
	lea	rdi,[expected]
	mov	ecx,expected.len
	call	report
end macro

cstring arg_sha256, 'sha256',0
cstring arg_hmac, 'hmac',0
cstring arg_bench, 'bench',0
cstring arg_blake2b, 'blake2b',0
cstring arg_argon2, 'argon2',0
cstring arg_b64, 'base64',0
cstring arg_json, 'json',0
cstring arg_email, 'email',0
cstring arg_phc, 'phc',0
cstring jf_email, 'email'
cstring jf_password, 'password'

rodata
	align 8
	kat_json_spec	dq jf_email
			dd jf_email.len, EMAIL_MAX
			dq jf_password
			dd jf_password.len, PASSWORD_MAX
end rodata

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
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_blake2b]
	call	cstr_eq
	test	eax,eax
	jnz	blake2b_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_argon2]
	call	cstr_eq
	test	eax,eax
	jnz	argon2_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_b64]
	call	cstr_eq
	test	eax,eax
	jnz	base64_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_json]
	call	cstr_eq
	test	eax,eax
	jnz	json_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_email]
	call	cstr_eq
	test	eax,eax
	jnz	email_stdin
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[arg_phc]
	call	cstr_eq
	test	eax,eax
	jnz	phc_stdin
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

	lea	rdi,[kat_out]
	mov	esi,64
	lea	rdx,[kat_out]
	xor	ecx,ecx
	call	blake2b
	check	'blake2b-512 empty', b2_empty

	lea	rdi,[kat_out]
	mov	esi,64
	lea	rdx,[v_abc]
	mov	ecx,v_abc.len
	call	blake2b
	check	'blake2b-512 abc', b2_abc

	; RFC 9106 section 5: t=3, m=32 KiB, p=4, 32-byte tag, with secret and AD.
	mov	edi,ARGON2_D
	call	argon2_rfc
	check	'argon2d rfc9106', a2_tag_d
	mov	edi,ARGON2_I
	call	argon2_rfc
	check	'argon2i rfc9106', a2_tag_i
	mov	edi,ARGON2_ID
	call	argon2_rfc
	check	'argon2id rfc9106', a2_tag_id

	call	base64_tests
	call	scram_tests

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
	call	token_tests
	mov	edi,[kat_failed]
	jmp	exit_process

rodata
	kt_user	db 0x01,0x8f,0x2a,0x11,0x22,0x33,0x74,0x44,0x85,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb
end rodata

; Access tokens: round trip, then every way a token must be refused.
; [rsp] user out, [rsp+16] token length, [rsp+32] token.
token_tests:
	push	rbx
	sub	rsp,128
	lea	rdi,[g_token_key]
	mov	al,0x42
	mov	ecx,32
	rep	stosb
	mov	qword [g_unix_now],1700000000
	lea	rdi,[rsp+32]
	lea	rsi,[kt_user]
	mov	edx,7
	call	access_token_make
	mov	[rsp+16],eax
	cmp	eax,ACCESS_TOKEN_LEN
	sete	al
	movzx	eax,al
	expect	'access token length'

	call	.verify
	setnc	bl
	cmp	eax,7
	sete	al
	and	bl,al
	mov	rdi,rsp
	lea	rsi,[kt_user]
	mov	edx,16
	call	ct_equal
	and	al,bl
	movzx	eax,al
	expect	'access token round trip'

	add	qword [g_unix_now],ACCESS_TTL
	call	.verify
	setc	al
	movzx	eax,al
	expect	'access token expired'
	sub	qword [g_unix_now],ACCESS_TTL

	xor	byte [rsp+32+5],1
	call	.verify
	setc	al
	movzx	eax,al
	expect	'access token payload tampered'
	xor	byte [rsp+32+5],1

	xor	byte [rsp+32+40],1
	call	.verify
	setc	al
	movzx	eax,al
	expect	'access token signature tampered'
	xor	byte [rsp+32+40],1

	xor	byte [g_token_key+31],1
	call	.verify
	setc	al
	movzx	eax,al
	expect	'access token under another key'
	xor	byte [g_token_key+31],1

	dec	dword [rsp+16]
	call	.verify
	setc	al
	movzx	eax,al
	expect	'access token truncated'
	inc	dword [rsp+16]

	call	.verify
	setnc	al
	movzx	eax,al
	expect	'access token still valid after restoring'
	add	rsp,128
	pop	rbx
	ret

; Verify the token in the caller's frame (rsp+8 here).
.verify:
	lea	rsi,[rsp+8+32]
	mov	edx,[rsp+8+16]
	lea	rdi,[rsp+8]
	jmp	access_token_verify

; Report a boolean result: eax = 1 passes.
macro expect name*
	local n
	cstring n, name
	lea	rsi,[n]
	mov	edx,n.len
	call	report_bool
end macro

cstring str_ok, 'ok   '
cstring str_fail, 'FAIL '

; eax = result, rsi = name, edx = name length.
report_bool:
	push	rsi
	push	rdx
	push	rax
	call	log_begin
	pop	rax
	lea	rsi,[str_fail]
	lea	rcx,[str_ok]
	test	eax,eax
	cmovnz	rsi,rcx
	sete	cl
	or	byte [kat_failed],cl
	mov	edx,str_ok.len
	call	log_str
	pop	rdx
	pop	rsi
	call	log_str
	jmp	log_end

; rdi = produced, esi = produced length, rdx = expected, ecx = its length.
; eax = 1 when identical.
same_bytes:
	xor	eax,eax
	cmp	esi,ecx
	jne	.done
	mov	rsi,rdx
	mov	edx,ecx
	jmp	ct_equal
.done:
	ret

base64_tests:
	lea	rdi,[kat_out]
	lea	rsi,[b64_in]
	mov	edx,6
	call	base64_encode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_out_std]
	mov	ecx,b64_out_std.len
	call	same_bytes
	expect	'base64 encode foobar'

	lea	rdi,[kat_out]
	lea	rsi,[b64_in]
	mov	edx,1
	call	base64_encode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_out_f]
	mov	ecx,b64_out_f.len
	call	same_bytes
	expect	'base64 encode f (two pad)'

	lea	rdi,[kat_out]
	lea	rsi,[b64_in]
	mov	edx,2
	call	base64_encode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_out_fo]
	mov	ecx,b64_out_fo.len
	call	same_bytes
	expect	'base64 encode fo (one pad)'

	lea	rdi,[kat_out]
	lea	rsi,[b64_in]
	mov	edx,4
	call	base64url_encode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_out_fob]
	mov	ecx,b64_out_fob.len
	call	same_bytes
	expect	'base64url encode foob (no pad)'

	lea	rdi,[kat_out]
	lea	rsi,[b64_out_fo]
	mov	edx,b64_out_fo.len
	call	base64_decode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_in]
	mov	ecx,2
	call	same_bytes
	expect	'base64 decode Zm8='

	lea	rdi,[kat_out]
	lea	rsi,[b64_out_fob]
	mov	edx,b64_out_fob.len
	call	base64url_decode
	lea	rdi,[kat_out]
	mov	esi,eax
	lea	rdx,[b64_in]
	mov	ecx,4
	call	same_bytes
	expect	'base64url decode Zm9vYg'

	lea	rdi,[kat_out]
	lea	rsi,[b64_bad_pad]
	mov	edx,b64_bad_pad.len
	call	base64_decode
	shr	rax,63
	expect	'base64 rejects bad padding'

	lea	rdi,[kat_out]
	lea	rsi,[b64_bad_bits]
	mov	edx,b64_bad_bits.len
	call	base64_decode
	shr	rax,63
	expect	'base64 rejects non-canonical bits'
	ret

; RFC 7677 section 3: user "user", password "pencil".
scram_setup:
	lea	rbx,[kat_scram]
	lea	rax,[sc_password]
	mov	[rbx+SC_PASSWORD],rax
	mov	dword [rbx+SC_PASSWORD_LEN],sc_password.len
	lea	rax,[sc_nonce]
	mov	[rbx+SC_NONCE],rax
	mov	dword [rbx+SC_NONCE_LEN],sc_nonce.len
	lea	rax,[sc_first]
	mov	[rbx+SC_FIRST],rax
	mov	dword [rbx+SC_FIRST_LEN],sc_first.len
	lea	rax,[sc_server]
	mov	[rbx+SC_SERVER],rax
	mov	dword [rbx+SC_SERVER_LEN],sc_server.len
	ret

scram_tests:
	push	rbx
	call	scram_setup
	mov	rdi,rbx
	lea	rsi,[kat_msg]
	call	scram_client_final
	lea	rdi,[kat_msg]
	mov	esi,eax
	lea	rdx,[sc_final]
	mov	ecx,sc_final.len
	call	same_bytes
	expect	'scram-sha-256 client-final rfc7677'

	lea	rdi,[kat_scram]
	lea	rsi,[sc_verifier]
	mov	edx,sc_verifier.len
	call	scram_verify_final
	expect	'scram-sha-256 server signature accepted'

	lea	rdi,[kat_scram]
	lea	rsi,[sc_forged]
	mov	edx,sc_forged.len
	call	scram_verify_final
	xor	eax,1
	expect	'scram-sha-256 forged signature rejected'

	call	scram_setup
	lea	rax,[sc_bad_nonce]
	mov	[rbx+SC_SERVER],rax
	mov	rdi,rbx
	lea	rsi,[kat_msg]
	call	scram_client_final
	shr	rax,63
	expect	'scram-sha-256 foreign nonce rejected'
	pop	rbx
	ret

; edi = type. Runs the RFC 9106 test vector into kat_out.
argon2_rfc:
	push	rdi
	lea	rdi,[kat_big]
	mov	al,1
	mov	ecx,32
	rep	stosb
	mov	al,2
	mov	ecx,16
	rep	stosb
	mov	al,3
	mov	ecx,8
	rep	stosb
	mov	al,4
	mov	ecx,12
	rep	stosb
	pop	rdi
	lea	rbx,[kat_a2]
	mov	[rbx+A2_TYPE],edi
	lea	rax,[kat_out]
	mov	[rbx+A2_OUT],rax
	mov	dword [rbx+A2_OUTLEN],32
	lea	rax,[kat_big]
	mov	[rbx+A2_PWD],rax
	mov	dword [rbx+A2_PWDLEN],32
	add	rax,32
	mov	[rbx+A2_SALT],rax
	mov	dword [rbx+A2_SALTLEN],16
	add	rax,16
	mov	[rbx+A2_SECRET],rax
	mov	dword [rbx+A2_SECRETLEN],8
	add	rax,8
	mov	[rbx+A2_AD],rax
	mov	dword [rbx+A2_ADLEN],12
	mov	dword [rbx+A2_M],32
	mov	dword [rbx+A2_T],3
	mov	dword [rbx+A2_P],4
	lea	rax,[kat_mem]
	mov	[rbx+A2_MEM],rax
	mov	rdi,rbx
	jmp	argon2_hash

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

; kat blake2b < u8 digest length, data
blake2b_stdin:
	call	read_stdin
	movzx	esi,byte [kat_big]
	push	rsi
	lea	rdi,[kat_out]
	lea	rdx,[kat_big+1]
	lea	ecx,[rbx-1]
	call	blake2b
	pop	rcx
	lea	rsi,[kat_out]
	jmp	print_hex_exit

; kat argon2 < u32 type, t, m, p, tag length, then u32 length + bytes for
; password, salt, secret and associated data. Prints the tag in hex.
argon2_stdin:
	call	read_stdin
	lea	rbx,[kat_a2]
	lea	rsi,[kat_big]
	mov	eax,[rsi]
	mov	[rbx+A2_TYPE],eax
	mov	eax,[rsi+4]
	mov	[rbx+A2_T],eax
	mov	eax,[rsi+8]
	mov	[rbx+A2_M],eax
	mov	eax,[rsi+12]
	mov	[rbx+A2_P],eax
	mov	eax,[rsi+16]
	mov	[rbx+A2_OUTLEN],eax
	add	rsi,20
	irp <field,flen>, A2_PWD,A2_PWDLEN, A2_SALT,A2_SALTLEN, A2_SECRET,A2_SECRETLEN, A2_AD,A2_ADLEN
		mov	eax,[rsi]
		mov	[rbx+flen],eax
		add	rsi,4
		mov	[rbx+field],rsi
		add	rsi,rax
	end irp
	lea	rax,[kat_hexbuf+1024]		; tag after the hex area's first half
	mov	[rbx+A2_OUT],rax
	lea	rax,[kat_mem]
	mov	[rbx+A2_MEM],rax
	mov	rdi,rbx
	call	argon2_hash
	test	eax,eax
	jnz	.invalid
	lea	rsi,[kat_hexbuf+1024]
	mov	ecx,[kat_a2+A2_OUTLEN]
	lea	rdi,[kat_big]			; copy the tag out of the hex buffer
	push	rcx
	rep	movsb
	pop	rcx
	lea	rsi,[kat_big]
	jmp	print_hex_exit
.invalid:
	mov	edi,3
	jmp	exit_process

; kat base64 < u8 mode, data. Modes: 0 encode, 1 encode url, 2 decode,
; 3 decode url. Prints the result in hex, or "-" when decoding fails.
base64_stdin:
	call	read_stdin
	movzx	eax,byte [kat_big]
	lea	rsi,[kat_big+1]
	lea	edx,[rbx-1]
	lea	rdi,[kat_mem]
	cmp	eax,1
	jb	.enc
	je	.enc_url
	cmp	eax,2
	je	.dec
	call	base64url_decode
	jmp	.print
.enc:
	call	base64_encode
	jmp	.print
.enc_url:
	call	base64url_encode
	jmp	.print
.dec:
	call	base64_decode
.print:
	test	rax,rax
	js	.invalid
	mov	ecx,eax
	lea	rsi,[kat_mem]
	jmp	print_hex_exit
.invalid:
	mov	edi,4
	jmp	exit_process

; kat json < body: parses {email, password}. Prints, in hex: the result
; code, then per field: present (1 byte), length (2 bytes LE), bytes.
json_stdin:
	call	read_stdin
	lea	rdi,[kat_a2]			; reused as the job
	lea	rax,[kat_json_spec]
	mov	[rdi+JJ_SPEC],rax
	lea	rax,[kat_hexbuf]		; results (2 x 16 bytes)
	mov	[rdi+JJ_OUT],rax
	lea	rax,[kat_mem+65536]
	mov	[rdi+JJ_SCRATCH],rax
	mov	dword [rdi+JJ_SCRATCH_CAP],EMAIL_MAX + PASSWORD_MAX
	lea	rax,[kat_big]
	mov	[rdi+JJ_BODY],rax
	mov	[rdi+JJ_BODY_LEN],ebx
	mov	dword [rdi+JJ_FIELDS],2
	call	json_parse_object
	test	eax,eax
	jz	@f
	; Results are only meaningful on success.
	push	rax
	lea	rdi,[kat_hexbuf]
	xor	eax,eax
	mov	ecx,32
	rep	stosb
	pop	rax
@@:
	lea	rdi,[kat_mem]
	mov	[rdi],al
	inc	rdi
	xor	ebx,ebx
.field:
	mov	eax,ebx
	shl	eax,4
	lea	rdx,[kat_hexbuf+rax]
	mov	eax,[rdx+JV_PRESENT]
	mov	[rdi],al
	mov	ecx,[rdx+JV_LEN]
	mov	[rdi+1],cx
	add	rdi,3
	mov	rsi,[rdx+JV_PTR]
	rep	movsb
	inc	ebx
	cmp	ebx,2
	jb	.field
	lea	rsi,[kat_mem]
	mov	rcx,rdi
	sub	rcx,rsi
	jmp	print_hex_exit

; kat email < address: prints "01" + normalized address, or "00".
email_stdin:
	call	read_stdin
	lea	rdi,[kat_big]
	mov	esi,ebx
	call	email_normalize
	mov	[kat_mem],al
	lea	rdi,[kat_mem+1]
	lea	rsi,[kat_big]
	mov	ecx,ebx
	rep	movsb
	lea	ecx,[rbx+1]
	test	al,al
	jnz	@f
	mov	ecx,1
@@:
	lea	rsi,[kat_mem]
	jmp	print_hex_exit

; kat phc < 'e' + 16-byte salt + 32-byte hash: encodes, decodes the result
; back and prints the string, or exits 5 when the round trip disagrees.
; kat phc < 'd' + string: prints m, t, p, salt and hash, or exits 5.
phc_stdin:
	call	read_stdin
	cmp	byte [kat_big],'d'
	je	.decode
	lea	rdi,[kat_mem]
	lea	rsi,[kat_big+1]
	lea	rdx,[kat_big+17]
	call	phc_encode
	mov	ebx,eax
	lea	rsi,[kat_mem]
	mov	edx,ebx
	lea	rdi,[kat_mem+4096]
	call	phc_decode
	test	eax,eax
	jnz	.fail
	lea	rsi,[kat_mem]
	mov	ecx,ebx
	jmp	print_hex_exit
.decode:
	lea	rsi,[kat_big+1]
	lea	edx,[rbx-1]
	lea	rdi,[kat_mem+4096]
	call	phc_decode
	test	eax,eax
	jnz	.fail
	lea	rsi,[kat_mem+4096]
	mov	ecx,PHC_HASH + 32
	jmp	print_hex_exit
.fail:
	mov	edi,5
	jmp	exit_process

; rsi = bytes, ecx = count (<= 1024). Writes them in hex to stderr; exits 0.
print_hex_exit:
	lea	rdi,[kat_hexbuf]
	xor	edx,edx
.byte:
	cmp	edx,ecx
	jae	.write
	movzx	eax,byte [rsi+rdx]
	mov	r8d,eax
	shr	eax,4
	and	r8d,15
	mov	al,[hex_digits+rax]
	mov	[rdi],al
	mov	al,[hex_digits+r8]
	mov	[rdi+1],al
	add	rdi,2
	inc	edx
	jmp	.byte
.write:
	mov	byte [rdi],10
	lea	rdx,[rdi+1]
	lea	rsi,[kat_hexbuf]
	sub	rdx,rsi
	mov	edi,2
	mov	eax,SYS_write
	syscall
	xor	edi,edi
	jmp	exit_process

print_out:
	mov	dword [g_log_len],0
	call	log_hex_out
	call	log_end
	xor	edi,edi
	jmp	exit_process

; Append kat_out (kat_report_len bytes, at most 64) in hex to the log line.
log_hex_out:
	push	rbx
	xor	ebx,ebx
	cmp	dword [kat_report_len],0
	jne	.hex
	mov	dword [kat_report_len],32
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
	cmp	ebx,[kat_report_len]
	jb	.hex
	pop	rbx
	ret

; rsi = name, edx = name length, rdi = expected, ecx = its length
; (compared with kat_out).
report:
	mov	[kat_report_len],ecx
	push	rsi
	push	rdx
	lea	rsi,[kat_out]
	mov	edx,ecx
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
