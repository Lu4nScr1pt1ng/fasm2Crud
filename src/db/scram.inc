; SCRAM-SHA-256 client (RFC 5802, RFC 7677), as pure functions so the
; protocol code stays free of crypto and the math can be tested on the
; RFC example.
;
; No channel binding ("n,,", c=biws): the database link is a private
; network. The server's final signature is always verified, so a server
; that does not know the password cannot impersonate the database.

SC_PASSWORD	= 0		; ptr
SC_PASSWORD_LEN	= 8
SC_NONCE_LEN	= 12		; client nonce length
SC_NONCE	= 16		; ptr
SC_FIRST	= 24		; client-first-message-bare: ptr
SC_FIRST_LEN	= 32
SC_SERVER_LEN	= 36
SC_SERVER	= 40		; server-first-message: ptr
SC_SERVER_SIG	= 48		; 32 bytes: expected server signature
SC_SIZE		= 80

SCRAM_MAX_SALT	= 64
SCRAM_MAX_ITER	= 1000000
SCRAM_MAX_MSG	= 512

cstring scram_client_key, 'Client Key'
cstring scram_server_key, 'Server Key'
cstring scram_final_prefix, 'c=biws,r='

; Frame of scram_client_final.
SF_SALT		= 0		; decoded salt
SF_SALTED	= 64		; SaltedPassword
SF_CLIENT_KEY	= 96
SF_STORED_KEY	= 128
SF_SIG		= 160		; ClientSignature
SF_SERVER_KEY	= 192
SF_AUTH		= 224		; AuthMessage
SF_SIZE		= SF_AUTH + 3 * SCRAM_MAX_MSG

; rdi = SCRAM state, rsi = output buffer (>= SCRAM_MAX_MSG bytes).
; rax = length of client-final-message, or -1 when server-first is invalid.
scram_client_final:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,SF_SIZE
	mov	rbx,rdi
	mov	r12,rsi

	; server-first = "r=" nonce "," "s=" salt "," "i=" iterations [, ...]
	mov	rsi,[rbx+SC_SERVER]
	mov	ecx,[rbx+SC_SERVER_LEN]
	cmp	ecx,SCRAM_MAX_MSG
	ja	.bad
	lea	r15,[rsi+rcx]			; end
	cmp	word [rsi],'r='
	jne	.bad
	lea	r13,[rsi+2]			; combined nonce
	mov	rdi,r13
	call	.field_end
	mov	r14,rax
	sub	r14,r13				; nonce length
	; It must extend our nonce.
	mov	ecx,[rbx+SC_NONCE_LEN]
	cmp	r14d,ecx
	jbe	.bad
	mov	rsi,[rbx+SC_NONCE]
	mov	rdi,r13
	repe	cmpsb
	jne	.bad

	lea	rdi,[r13+r14+1]
	cmp	rdi,r15
	jae	.bad
	cmp	word [rdi],'s='
	jne	.bad
	add	rdi,2
	mov	rbp,rdi				; salt (base64)
	call	.field_end
	mov	rdx,rax
	sub	rdx,rbp
	push	rax
	cmp	edx,(SCRAM_MAX_SALT / 3) * 4
	ja	.bad_pop
	lea	rdi,[rsp+8+SF_SALT]
	mov	rsi,rbp
	call	base64_decode
	test	rax,rax
	jle	.bad_pop
	mov	ebp,eax				; salt length
	pop	rdi

	inc	rdi
	cmp	rdi,r15
	jae	.bad
	cmp	word [rdi],'i='
	jne	.bad
	add	rdi,2
	xor	eax,eax
	xor	ecx,ecx
.digit:
	cmp	rdi,r15
	jae	.iterations
	movzx	edx,byte [rdi]
	cmp	dl,','
	je	.iterations
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	rdi
	inc	ecx
	cmp	ecx,7
	ja	.bad
	jmp	.digit
.iterations:
	test	eax,eax
	jz	.bad
	cmp	eax,SCRAM_MAX_ITER
	ja	.bad

	; SaltedPassword = PBKDF2(password, salt, i)
	mov	r9d,eax
	lea	rdi,[rsp+SF_SALTED]
	mov	rsi,[rbx+SC_PASSWORD]
	mov	edx,[rbx+SC_PASSWORD_LEN]
	lea	rcx,[rsp+SF_SALT]
	mov	r8d,ebp
	call	pbkdf2_sha256
	; ClientKey, StoredKey, ServerKey
	lea	rdi,[rsp+SF_CLIENT_KEY]
	lea	rsi,[rsp+SF_SALTED]
	mov	edx,32
	lea	rcx,[scram_client_key]
	mov	r8d,scram_client_key.len
	call	hmac_sha256
	lea	rdi,[rsp+SF_STORED_KEY]
	lea	rsi,[rsp+SF_CLIENT_KEY]
	mov	edx,32
	call	sha256
	lea	rdi,[rsp+SF_SERVER_KEY]
	lea	rsi,[rsp+SF_SALTED]
	mov	edx,32
	lea	rcx,[scram_server_key]
	mov	r8d,scram_server_key.len
	call	hmac_sha256

	; Output starts with client-final-without-proof = "c=biws,r=" nonce.
	mov	rdi,r12
	lea	rsi,[scram_final_prefix]
	mov	ecx,scram_final_prefix.len
	rep	movsb
	mov	rsi,r13
	mov	rcx,r14
	rep	movsb
	mov	r15,rdi
	sub	r15,r12				; its length

	; AuthMessage = client-first-bare "," server-first "," final-without-proof
	lea	rdi,[rsp+SF_AUTH]
	mov	rsi,[rbx+SC_FIRST]
	mov	ecx,[rbx+SC_FIRST_LEN]
	cmp	ecx,SCRAM_MAX_MSG
	ja	.bad
	rep	movsb
	mov	byte [rdi],','
	inc	rdi
	mov	rsi,[rbx+SC_SERVER]
	mov	ecx,[rbx+SC_SERVER_LEN]
	rep	movsb
	mov	byte [rdi],','
	inc	rdi
	mov	rsi,r12
	mov	rcx,r15
	rep	movsb
	lea	r8,[rsp+SF_AUTH]
	sub	rdi,r8
	mov	r13,rdi				; AuthMessage length

	; ClientProof = ClientKey ^ HMAC(StoredKey, AuthMessage)
	lea	rdi,[rsp+SF_SIG]
	lea	rsi,[rsp+SF_STORED_KEY]
	mov	edx,32
	lea	rcx,[rsp+SF_AUTH]
	mov	r8,r13
	call	hmac_sha256
	movdqu	xmm0,[rsp+SF_SIG]
	movdqu	xmm1,[rsp+SF_CLIENT_KEY]
	pxor	xmm0,xmm1
	movdqu	[rsp+SF_SIG],xmm0
	movdqu	xmm0,[rsp+SF_SIG+16]
	movdqu	xmm1,[rsp+SF_CLIENT_KEY+16]
	pxor	xmm0,xmm1
	movdqu	[rsp+SF_SIG+16],xmm0
	; ServerSignature = HMAC(ServerKey, AuthMessage), kept for verification.
	lea	rdi,[rbx+SC_SERVER_SIG]
	lea	rsi,[rsp+SF_SERVER_KEY]
	mov	edx,32
	lea	rcx,[rsp+SF_AUTH]
	mov	r8,r13
	call	hmac_sha256

	; ",p=" base64(ClientProof)
	lea	rdi,[r12+r15]
	mov	dword [rdi],',p='
	add	rdi,3
	lea	rsi,[rsp+SF_SIG]
	mov	edx,32
	call	base64_encode
	lea	rax,[r15+rax+3]
	jmp	.wipe
.bad_pop:
	add	rsp,8
.bad:
	mov	rax,-1
.wipe:
	push	rax
	lea	rdi,[rsp+8]
	mov	ecx,SF_SIZE
	call	secure_zero
	pop	rax
	add	rsp,SF_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = start of a field; rax = address of the next ',' or the end (r15).
.field_end:
	mov	rax,rdi
@@:
	cmp	rax,r15
	jae	@f
	cmp	byte [rax],','
	je	@f
	inc	rax
	jmp	@b
@@:
	ret

; rdi = SCRAM state, rsi = server-final-message, edx = length.
; eax = 1 when it carries the signature we expect.
scram_verify_final:
	sub	rsp,72
	xor	eax,eax
	cmp	edx,46				; "v=" + 44 characters
	jne	.done
	cmp	word [rsi],'v='
	jne	.done
	push	rdi
	lea	rdi,[rsp+8]
	add	rsi,2
	mov	edx,44
	call	base64_decode
	pop	rdi
	cmp	rax,32
	jne	.fail
	lea	rsi,[rdi+SC_SERVER_SIG]
	mov	rdi,rsp
	mov	edx,32
	call	ct_equal
	jmp	.done
.fail:
	xor	eax,eax
.done:
	add	rsp,72
	ret
