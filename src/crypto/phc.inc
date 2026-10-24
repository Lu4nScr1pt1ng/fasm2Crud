; Argon2id password hashes in PHC string format:
;   $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
; (base64 without padding). New hashes use the OWASP parameters below;
; verification reads the parameters from the stored string, so they can
; be raised later without invalidating existing passwords.

PW_M_KIB	= 19456		; 19 MiB
PW_T		= 2
PW_P		= 1
PW_SALT_LEN	= 16
PW_HASH_LEN	= 32
PW_MAX_M_KIB	= 65536		; the hasher's memory: refuse anything larger
PW_MAX_T	= 10
PHC_MAX		= 128

; Decoded PHC string.
PHC_M		= 0
PHC_T		= 4
PHC_P		= 8
PHC_SALT_LEN	= 12
PHC_SALT	= 16		; up to 64 bytes
PHC_HASH	= 80		; 32 bytes
PHC_SIZE	= 112

cstring phc_prefix, '$argon2id$v=19$m='

; rdi = output (>= PHC_MAX), rsi = 16-byte salt, rdx = 32-byte hash.
; rax = length.
phc_encode:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	rbx,rsi
	mov	r13,rdx
	push	rsi
	lea	rsi,[phc_prefix]
	mov	ecx,phc_prefix.len
	rep	movsb
	pop	rsi
	mov	eax,PW_M_KIB
	call	write_u32
	mov	dword [rdi],',t='
	add	rdi,3
	mov	eax,PW_T
	call	write_u32
	mov	dword [rdi],',p='
	add	rdi,3
	mov	eax,PW_P
	call	write_u32
	mov	byte [rdi],'$'
	inc	rdi
	mov	rsi,rbx
	mov	edx,PW_SALT_LEN
	call	base64_encode_nopad		; advances rdi
	mov	byte [rdi],'$'
	inc	rdi
	mov	rsi,r13
	mov	edx,PW_HASH_LEN
	call	base64_encode_nopad		; advances rdi
	mov	rax,rdi
	sub	rax,r12
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = string, edx = length, rdi = PHC record. eax = 0, or -1 when the
; string is not an Argon2id v19 hash this server can verify.
phc_decode:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	cmp	edx,PHC_MAX
	ja	.bad
	lea	r13,[rsi+rdx]			; end
	cmp	edx,phc_prefix.len
	jb	.bad
	push	rsi
	lea	rdi,[phc_prefix]
	mov	ecx,phc_prefix.len
	repe	cmpsb
	pop	rax
	jne	.bad
	lea	rsi,[rax+phc_prefix.len]
	call	.number
	jc	.bad
	cmp	eax,8
	jb	.bad
	cmp	eax,PW_MAX_M_KIB
	ja	.bad
	mov	[rbx+PHC_M],eax
	call	.key_t
	jc	.bad
	call	.number
	jc	.bad
	test	eax,eax
	jz	.bad
	cmp	eax,PW_MAX_T
	ja	.bad
	mov	[rbx+PHC_T],eax
	call	.key_p
	jc	.bad
	call	.number
	jc	.bad
	cmp	eax,1				; the hasher computes a single lane
	jne	.bad
	mov	[rbx+PHC_P],eax
	cmp	rsi,r13
	jae	.bad
	lodsb
	cmp	al,'$'
	jne	.bad
	; salt
	mov	rdi,rsi
.salt_end:
	cmp	rdi,r13
	jae	.bad
	cmp	byte [rdi],'$'
	je	.salt
	inc	rdi
	jmp	.salt_end
.salt:
	mov	r12,rdi
	mov	rdx,rdi
	sub	rdx,rsi
	cmp	edx,86				; 64 bytes at most
	ja	.bad
	lea	rdi,[rbx+PHC_SALT]
	call	base64_decode_nopad
	cmp	rax,8
	jl	.bad
	mov	[rbx+PHC_SALT_LEN],eax
	; hash: exactly 32 bytes (43 characters)
	lea	rsi,[r12+1]
	mov	rdx,r13
	sub	rdx,rsi
	cmp	edx,43
	jne	.bad
	lea	rdi,[rbx+PHC_HASH]
	call	base64_decode_nopad
	cmp	rax,32
	jne	.bad
	xor	eax,eax
	jmp	.done
.bad:
	mov	eax,-1
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Decimal at rsi (1 to 7 digits, no leading zero). eax = value, CF on error.
.number:
	xor	eax,eax
	xor	ecx,ecx
.digit:
	cmp	rsi,r13
	jae	.number_end
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.number_end
	test	ecx,ecx
	jnz	@f
	test	edx,edx
	jnz	@f
	cmp	byte [rsi+1],','		; a lone "0" is fine, "05" is not
	je	@f
	cmp	byte [rsi+1],'$'
	jne	.number_bad
@@:
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	inc	ecx
	cmp	ecx,7
	ja	.number_bad
	jmp	.digit
.number_end:
	test	ecx,ecx
	jz	.number_bad
	clc
	ret
.number_bad:
	stc
	ret

.key_t:
	lea	rax,[rsi+3]
	cmp	rax,r13
	ja	.key_bad
	cmp	word [rsi],',t'
	jne	.key_bad
	cmp	byte [rsi+2],'='
	jne	.key_bad
	add	rsi,3
	clc
	ret
.key_p:
	lea	rax,[rsi+3]
	cmp	rax,r13
	ja	.key_bad
	cmp	word [rsi],',p'
	jne	.key_bad
	cmp	byte [rsi+2],'='
	jne	.key_bad
	add	rsi,3
	clc
	ret
.key_bad:
	stc
	ret
