; Tokens.
;
; Access token (stateless, ACCESS_TTL seconds):
;   base64url(payload) "." base64url(HMAC-SHA-256(key, payload))
;   payload = version (1) | user id (16) | session epoch (u32 LE) | expiry (u32 LE)
; A 256-bit HMAC key keeps 128-bit security even against Grover's
; algorithm, and verifying costs two SHA-256 compressions and no database
; access. Revocation is by expiry: logout ends the refresh family at once,
; access tokens already issued expire within ACCESS_TTL.
;
; Refresh token: 256 random bits, base64url. The database stores only its
; SHA-256, so a leaked table cannot be replayed.

ACCESS_TTL	= 900
TOKEN_VERSION	= 1
ACCESS_PAYLOAD	= 25
ACCESS_TOKEN_LEN = 34 + 1 + 43
REFRESH_BYTES	= 32
REFRESH_TEXT	= 43

bss
	align 16
	g_token_key:	rb 32
	g_unix_now	dq ?
end bss

; rdi = output (>= ACCESS_TOKEN_LEN), rsi = user id (16 bytes),
; edx = session epoch. rax = length.
access_token_make:
	push	rbx
	push	r12
	sub	rsp,64
	mov	r12,rdi
	mov	byte [rsp],TOKEN_VERSION
	movdqu	xmm0,[rsi]
	movdqu	[rsp+1],xmm0
	mov	[rsp+17],edx
	mov	rax,[g_unix_now]
	add	eax,ACCESS_TTL
	mov	[rsp+21],eax
	mov	rdi,r12
	mov	rsi,rsp
	mov	edx,ACCESS_PAYLOAD
	call	base64url_encode
	mov	byte [rdi],'.'
	inc	rdi
	mov	rbx,rdi
	lea	rdi,[rsp+32]
	lea	rsi,[g_token_key]
	mov	edx,32
	mov	rcx,rsp
	mov	r8d,ACCESS_PAYLOAD
	call	hmac_sha256
	mov	rdi,rbx
	lea	rsi,[rsp+32]
	mov	edx,32
	call	base64url_encode
	mov	rax,rdi
	sub	rax,r12
	add	rsp,64
	pop	r12
	pop	rbx
	ret

; rsi = token text, edx = length, rdi = user id (16 bytes, written only
; when valid). eax = session epoch; CF when the token is malformed, forged
; or expired. The signature is compared in constant time.
access_token_verify:
	push	rbx
	push	r12
	sub	rsp,104
	; [rsp] payload (25, decoded into 32), [rsp+32] signature (32),
	; [rsp+64] expected signature (32)
	mov	r12,rdi
	mov	rbx,rsi
	cmp	edx,ACCESS_TOKEN_LEN
	jne	.bad
	cmp	byte [rbx+34],'.'
	jne	.bad
	mov	rdi,rsp
	mov	rsi,rbx
	mov	edx,34
	call	base64url_decode
	cmp	rax,ACCESS_PAYLOAD
	jne	.bad
	lea	rdi,[rsp+32]
	lea	rsi,[rbx+35]
	mov	edx,43
	call	base64url_decode
	cmp	rax,32
	jne	.bad
	lea	rdi,[rsp+64]
	lea	rsi,[g_token_key]
	mov	edx,32
	mov	rcx,rsp
	mov	r8d,ACCESS_PAYLOAD
	call	hmac_sha256
	lea	rdi,[rsp+32]
	lea	rsi,[rsp+64]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.bad
	; Only signed bytes are trusted from here on.
	cmp	byte [rsp],TOKEN_VERSION
	jne	.bad
	mov	eax,[rsp+21]			; expiry
	cmp	rax,[g_unix_now]
	jbe	.bad
	movdqu	xmm0,[rsp+1]
	movdqu	[r12],xmm0
	mov	eax,[rsp+17]
	add	rsp,104
	pop	r12
	pop	rbx
	clc
	ret
.bad:
	add	rsp,104
	pop	r12
	pop	rbx
	stc
	ret

; "\x" + 64 hex digits of SHA-256(bytes): bytea literal for a parameter.
; rdi = destination (66), rsi = bytes, edx = length.
sha256_bytea:
	push	rbx
	sub	rsp,32
	mov	rbx,rdi
	mov	rdi,rsp
	call	sha256
	mov	word [rbx],'\x'
	lea	rdi,[rbx+2]
	mov	rsi,rsp
	mov	edx,32
	call	hex_encode
	add	rsp,32
	pop	rbx
	ret

; New refresh token into ctx: AC_REFRESH (text) and AC_NEW_HEX (its hash).
; rdi = context. eax = 0, or -1 when getrandom failed.
refresh_token_new:
	push	rbx
	sub	rsp,32
	mov	rbx,rdi
	mov	rdi,rsp
	mov	esi,REFRESH_BYTES
	call	random_bytes
	test	eax,eax
	jnz	.done
	lea	rdi,[rbx+AC_REFRESH]
	mov	rsi,rsp
	mov	edx,REFRESH_BYTES
	call	base64url_encode
	lea	rdi,[rbx+AC_NEW_HEX]
	mov	rsi,rsp
	mov	edx,REFRESH_BYTES
	call	sha256_bytea
	xor	eax,eax
.done:
	push	rax
	lea	rdi,[rsp+8]
	mov	ecx,32
	call	secure_zero
	pop	rax
	add	rsp,32
	pop	rbx
	ret

; A presented refresh token: rsi = text, edx = length, rdi = destination
; for its bytea hash (66). CF when it is not a well-formed token.
refresh_token_hash:
	push	rbx
	sub	rsp,48
	mov	rbx,rdi
	cmp	edx,REFRESH_TEXT
	jne	.bad
	mov	rdi,rsp
	call	base64url_decode
	cmp	rax,REFRESH_BYTES
	jne	.bad
	mov	rdi,rbx
	mov	rsi,rsp
	mov	edx,REFRESH_BYTES
	call	sha256_bytea
	clc
	jmp	.done
.bad:
	stc
.done:
	pushf
	lea	rdi,[rsp+8]
	mov	ecx,48
	call	secure_zero
	popf
	lea	rsp,[rsp+48]			; add would clobber CF
	pop	rbx
	ret
