; BLAKE2b (RFC 7693), unkeyed, digest length 1..64.
;
; Argon2 uses BLAKE2b only to derive its first blocks and final tag (a few
; dozen compressions per password hash), so this is a straightforward
; scalar version with all 12 rounds unrolled at assembly time. The memory-
; hard part of Argon2 has its own AVX2 code in argon2.inc.
;
;   blake2b_init(rdi ctx, esi digest length)
;   blake2b_update(rdi ctx, rsi data, rdx length)
;   blake2b_final(rdi ctx, rsi digest)
;   blake2b(rdi digest, esi digest length, rdx data, rcx length)

B2_H		= 0		; 8 qwords
B2_T		= 64		; bytes compressed so far
B2_BUFLEN	= 72
B2_OUTLEN	= 76
B2_V		= 80		; 16 qwords of working state
B2_BUF		= 208		; 128-byte block
BLAKE2B_CTX_SIZE = 336

rodata
	align 8
	blake2b_iv	dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
			dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
end rodata

; Message schedule, read at assembly time to unroll the rounds.
virtual at 0
	blake2b_sigma::
	db  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
	db 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3
	db 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4
	db  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8
	db  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13
	db  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9
	db 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11
	db 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10
	db  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5
	db 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0
end virtual

; G on v[a], v[b], v[c], v[d] with message words m[x], m[y].
; rbx = v, rsi = message block.
macro blake2b_g a*, b*, c*, d*, x*, y*
	mov	rax,[rbx+a*8]
	mov	rcx,[rbx+b*8]
	mov	rdx,[rbx+c*8]
	mov	r8,[rbx+d*8]
	add	rax,rcx
	add	rax,[rsi+x*8]
	xor	r8,rax
	ror	r8,32
	add	rdx,r8
	xor	rcx,rdx
	ror	rcx,24
	add	rax,rcx
	add	rax,[rsi+y*8]
	xor	r8,rax
	ror	r8,16
	add	rdx,r8
	xor	rcx,rdx
	ror	rcx,63
	mov	[rbx+a*8],rax
	mov	[rbx+b*8],rcx
	mov	[rbx+c*8],rdx
	mov	[rbx+d*8],r8
end macro

macro blake2b_round r*
	local s, x, y
	s = (r mod 10) * 16
	iterate <a,b,c,d>, 0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15, \
			   0,5,10,15, 1,6,11,12, 2,7,8,13, 3,4,9,14
		load x:byte from blake2b_sigma:s + (% - 1) * 2
		load y:byte from blake2b_sigma:s + (% - 1) * 2 + 1
		blake2b_g a, b, c, d, x, y
	end iterate
end macro

; rdi = ctx, rsi = block, edx = 1 for the final block.
blake2b_compress:
	push	rbx
	lea	rbx,[rdi+B2_V]
	; v[0..7] = h, v[8..15] = IV
	xor	ecx,ecx
@@:
	mov	rax,[rdi+B2_H+rcx*8]
	mov	[rbx+rcx*8],rax
	mov	rax,[blake2b_iv+rcx*8]
	mov	[rbx+64+rcx*8],rax
	inc	ecx
	cmp	ecx,8
	jb	@b
	mov	rax,[rdi+B2_T]
	xor	[rbx+12*8],rax			; t fits in 64 bits for our sizes
	test	edx,edx
	jz	@f
	not	qword [rbx+14*8]
@@:
	push	rdi
	repeat 12, r:0
		blake2b_round r
	end repeat
	pop	rdi
	xor	ecx,ecx
@@:
	mov	rax,[rbx+rcx*8]
	xor	rax,[rbx+64+rcx*8]
	xor	[rdi+B2_H+rcx*8],rax
	inc	ecx
	cmp	ecx,8
	jb	@b
	pop	rbx
	ret

blake2b_init:
	xor	ecx,ecx
@@:
	mov	rax,[blake2b_iv+rcx*8]
	mov	[rdi+B2_H+rcx*8],rax
	inc	ecx
	cmp	ecx,8
	jb	@b
	mov	eax,esi
	or	eax,0x01010000			; fanout 1, depth 1, no key
	xor	[rdi+B2_H],rax
	xor	eax,eax
	mov	[rdi+B2_T],rax
	mov	[rdi+B2_BUFLEN],eax
	mov	[rdi+B2_OUTLEN],esi
	ret

; The last block must be compressed with the final flag, so a full buffer
; is only compressed once more input arrives.
blake2b_update:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
.more:
	test	r13,r13
	jz	.done
	cmp	dword [rbx+B2_BUFLEN],128
	jne	.fill
	add	qword [rbx+B2_T],128
	mov	rdi,rbx
	lea	rsi,[rbx+B2_BUF]
	xor	edx,edx
	call	blake2b_compress
	mov	dword [rbx+B2_BUFLEN],0
.fill:
	mov	eax,[rbx+B2_BUFLEN]
	mov	ecx,128
	sub	ecx,eax
	cmp	rcx,r13
	jbe	@f
	mov	rcx,r13
@@:
	lea	rdi,[rbx+B2_BUF+rax]
	mov	rsi,r12
	add	r12,rcx
	sub	r13,rcx
	add	[rbx+B2_BUFLEN],ecx
	rep	movsb
	jmp	.more
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

blake2b_final:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	mov	eax,[rbx+B2_BUFLEN]
	add	[rbx+B2_T],rax
	lea	rdi,[rbx+B2_BUF+rax]
	mov	ecx,128
	sub	ecx,eax
	xor	eax,eax
	rep	stosb
	mov	rdi,rbx
	lea	rsi,[rbx+B2_BUF]
	mov	edx,1
	call	blake2b_compress
	mov	rdi,r12
	lea	rsi,[rbx+B2_H]
	mov	ecx,[rbx+B2_OUTLEN]
	rep	movsb
	pop	r12
	pop	rbx
	ret

; rdi = digest, esi = digest length, rdx = data, rcx = length.
blake2b:
	push	rbx
	push	r12
	push	r13
	sub	rsp,BLAKE2B_CTX_SIZE
	mov	rbx,rdi
	mov	r12,rdx
	mov	r13,rcx
	mov	rdi,rsp
	call	blake2b_init
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	blake2b_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	blake2b_final
	mov	rdi,rsp
	mov	ecx,BLAKE2B_CTX_SIZE
	call	secure_zero
	add	rsp,BLAKE2B_CTX_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret
