; Argon2 (RFC 9106), version 0x13: Argon2d, Argon2i and Argon2id.
;
; argon2_hash(rdi = ARGON2 parameters) -> eax = 0, or -1 when the
; parameters are invalid. The caller provides the working memory
; (argon2_memory_bytes); it is wiped before returning, as is the stack
; frame. Lanes are processed one after another, which is the same
; computation as the parallel version: segments of one slice never
; reference each other.
;
; The compression function G runs in AVX2: a 16-word BLAKE2 state is four
; ymm registers, so each round is two vector G steps with a diagonal
; rotation in between, instead of eight scalar ones.

ARGON2_D	= 0
ARGON2_I	= 1
ARGON2_ID	= 2
ARGON2_VERSION	= 0x13
ARGON2_MAX_LANES = 16

; Parameters, filled by the caller.
A2_OUT		= 0		; tag
A2_OUTLEN	= 8		; 4..1024
A2_PWDLEN	= 12
A2_PWD		= 16
A2_SALT		= 24
A2_SALTLEN	= 32
A2_SECRETLEN	= 36
A2_SECRET	= 40
A2_AD		= 48
A2_ADLEN	= 56
A2_M		= 60		; memory in KiB, >= 8 * lanes
A2_T		= 64		; passes, >= 1
A2_P		= 68		; lanes, 1..16
A2_TYPE		= 72
A2_MEM		= 80		; argon2_memory_bytes of writable memory
ARGON2_SIZE	= 88

; Stack frame, 64-byte aligned.
F_R		= 0		; G scratch: R (1 KiB) and its copy (1 KiB)
F_ADDR		= 2048		; address block (data-independent addressing)
F_INPUT		= 3072		; input block for the address generator
F_ZERO		= 4096
F_H0		= 5120		; H0 (64 bytes) + two little-endian u32
F_CTX		= 5248		; BLAKE2b context
F_U32		= 5584
F_PASS		= 5588
F_SLICE		= 5592
F_LANE		= 5596
F_Q		= 5600		; blocks per lane
F_SEG		= 5604		; blocks per segment
F_MPRIME	= 5608		; total blocks
F_INDEP		= 5612		; data-independent addressing in this segment
F_REFLANE	= 5616
F_RAND		= 5624		; pseudo-random 64-bit value for the current block
F_SIZE		= 5632

rodata
	align 32
	a2_rot24	db 3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10, 3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10
	a2_rot16	db 2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9, 2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9
end rodata

; edi = memory KiB, esi = lanes. rax = bytes of working memory needed.
argon2_memory_bytes:
	mov	eax,edi
	lea	ecx,[rsi*4]
	xor	edx,edx
	div	ecx
	imul	eax,ecx
	shl	rax,10
	ret

; fBlaMka: x = x + y + 2 * lo32(x) * lo32(y), four lanes at once.
macro blamka_add x*, y*
	vpmuludq ymm4,x,y
	vpaddq	x,x,y
	vpaddq	ymm4,ymm4,ymm4
	vpaddq	x,x,ymm4
end macro

; G on four columns: ymm0..3 = a, b, c, d.
macro blamka_g
	blamka_add ymm0, ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufd	ymm3,ymm3,0xB1			; rotr 32
	blamka_add ymm2, ymm3
	vpxor	ymm1,ymm1,ymm2
	vpshufb	ymm1,ymm1,ymm14			; rotr 24
	blamka_add ymm0, ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufb	ymm3,ymm3,ymm15			; rotr 16
	blamka_add ymm2, ymm3
	vpxor	ymm1,ymm1,ymm2
	vpsrlq	ymm4,ymm1,63			; rotr 63
	vpaddq	ymm1,ymm1,ymm1
	vpor	ymm1,ymm1,ymm4
end macro

; One BLAKE2 round without message: columns, then diagonals.
macro blamka_round
	blamka_g
	vpermq	ymm1,ymm1,0x39
	vpermq	ymm2,ymm2,0x4E
	vpermq	ymm3,ymm3,0x93
	blamka_g
	vpermq	ymm1,ymm1,0x93
	vpermq	ymm2,ymm2,0x4E
	vpermq	ymm3,ymm3,0x39
end macro

; next = G(prev, ref) (xor next when ecx = 1).
; rdi = prev, rsi = ref, rdx = next, r8 = 2 KiB aligned scratch.
; next may alias prev or ref.
argon2_fill_block:
	vmovdqa	ymm14,yword [a2_rot24]
	vmovdqa	ymm15,yword [a2_rot16]
	xor	eax,eax
.init:
	vmovdqu	ymm0,[rdi+rax]
	vpxor	ymm0,ymm0,[rsi+rax]
	vmovdqa	[r8+rax],ymm0
	test	ecx,ecx
	jz	@f
	vpxor	ymm0,ymm0,[rdx+rax]
@@:
	vmovdqa	[r8+1024+rax],ymm0
	add	eax,32
	cmp	eax,1024
	jb	.init

	; Rows: words 16i .. 16i+15.
	xor	eax,eax
.rows:
	vmovdqa	ymm0,[r8+rax]
	vmovdqa	ymm1,[r8+rax+32]
	vmovdqa	ymm2,[r8+rax+64]
	vmovdqa	ymm3,[r8+rax+96]
	blamka_round
	vmovdqa	[r8+rax],ymm0
	vmovdqa	[r8+rax+32],ymm1
	vmovdqa	[r8+rax+64],ymm2
	vmovdqa	[r8+rax+96],ymm3
	sub	eax,-128
	cmp	eax,1024
	jb	.rows

	; Columns: words 2i, 2i+1, 2i+16, 2i+17, ..., 2i+112, 2i+113.
	xor	eax,eax
.columns:
	vmovdqu	xmm0,[r8+rax]
	vinserti128 ymm0,ymm0,[r8+rax+128],1
	vmovdqu	xmm1,[r8+rax+256]
	vinserti128 ymm1,ymm1,[r8+rax+384],1
	vmovdqu	xmm2,[r8+rax+512]
	vinserti128 ymm2,ymm2,[r8+rax+640],1
	vmovdqu	xmm3,[r8+rax+768]
	vinserti128 ymm3,ymm3,[r8+rax+896],1
	blamka_round
	vmovdqu	[r8+rax],xmm0
	vextracti128 [r8+rax+128],ymm0,1
	vmovdqu	[r8+rax+256],xmm1
	vextracti128 [r8+rax+384],ymm1,1
	vmovdqu	[r8+rax+512],xmm2
	vextracti128 [r8+rax+640],ymm2,1
	vmovdqu	[r8+rax+768],xmm3
	vextracti128 [r8+rax+896],ymm3,1
	add	eax,16
	cmp	eax,128
	jb	.columns

	xor	eax,eax
.output:
	vmovdqa	ymm0,[r8+1024+rax]
	vpxor	ymm0,ymm0,[r8+rax]
	vmovdqu	[rdx+rax],ymm0
	add	eax,32
	cmp	eax,1024
	jb	.output
	vzeroupper
	ret

; H' (RFC 9106 3.3): variable-length hash.
; rdi = out, esi = out length, rdx = input, rcx = input length.
B2L_V		= BLAKE2B_CTX_SIZE
B2L_LEN		= BLAKE2B_CTX_SIZE + 64
B2L_SIZE	= BLAKE2B_CTX_SIZE + 64 + 16
blake2b_long:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,B2L_SIZE
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	mov	r14,rcx
	mov	[rsp+B2L_LEN],r12d
	mov	esi,64
	cmp	r12d,64
	cmovbe	esi,r12d
	mov	rdi,rsp
	call	blake2b_init
	mov	rdi,rsp
	lea	rsi,[rsp+B2L_LEN]
	mov	edx,4
	call	blake2b_update
	mov	rdi,rsp
	mov	rsi,r13
	mov	rdx,r14
	call	blake2b_update
	cmp	r12d,64
	ja	.long
	mov	rdi,rsp
	mov	rsi,rbx
	call	blake2b_final
	jmp	.done
.long:
	; V1 .. Vr contribute 32 bytes each; the last hash is emitted whole.
	mov	rdi,rsp
	lea	rsi,[rsp+B2L_V]
	call	blake2b_final
	lea	r15d,[r12-32]
	vmovdqu	ymm0,[rsp+B2L_V]
	vmovdqu	[rbx],ymm0
	add	rbx,32
.next:
	cmp	r15d,64
	jbe	.last
	lea	rdi,[rsp+B2L_V]
	mov	esi,64
	lea	rdx,[rsp+B2L_V]
	mov	ecx,64
	call	blake2b
	vmovdqu	ymm0,[rsp+B2L_V]
	vmovdqu	[rbx],ymm0
	add	rbx,32
	sub	r15d,32
	jmp	.next
.last:
	mov	rdi,rbx
	mov	esi,r15d
	lea	rdx,[rsp+B2L_V]
	mov	ecx,64
	call	blake2b
.done:
	vzeroupper
	mov	rdi,rsp
	mov	ecx,B2L_SIZE
	call	secure_zero
	add	rsp,B2L_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

argon2_hash:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r15,rdi
	mov	rbp,rsp
	sub	rsp,F_SIZE
	and	rsp,-64
	mov	r14,rsp

	mov	eax,[r15+A2_P]
	test	eax,eax
	jz	.invalid
	cmp	eax,ARGON2_MAX_LANES
	ja	.invalid
	cmp	dword [r15+A2_T],0
	je	.invalid
	cmp	dword [r15+A2_TYPE],ARGON2_ID
	ja	.invalid
	mov	edx,[r15+A2_OUTLEN]
	cmp	edx,4
	jb	.invalid
	cmp	edx,1024
	ja	.invalid
	mov	ecx,[r15+A2_M]
	lea	edx,[rax*8]
	cmp	ecx,edx
	jb	.invalid

	; m' = 4p * floor(m / 4p) blocks; q per lane; q / 4 per segment.
	lea	r8d,[rax*4]
	mov	eax,ecx
	xor	edx,edx
	div	r8d
	imul	eax,r8d
	mov	[r14+F_MPRIME],eax
	xor	edx,edx
	div	dword [r15+A2_P]
	mov	[r14+F_Q],eax
	shr	eax,2
	mov	[r14+F_SEG],eax

	call	argon2_h0

	; B[l][0] = H'(H0 || 0 || l), B[l][1] = H'(H0 || 1 || l)
	xor	ebx,ebx
.first_blocks:
	mov	dword [r14+F_H0+64],0
	mov	[r14+F_H0+68],ebx
	mov	eax,ebx
	imul	eax,[r14+F_Q]
	shl	rax,10
	add	rax,[r15+A2_MEM]
	mov	rdi,rax
	mov	esi,1024
	lea	rdx,[r14+F_H0]
	mov	ecx,72
	call	blake2b_long
	mov	dword [r14+F_H0+64],1
	mov	eax,ebx
	imul	eax,[r14+F_Q]
	inc	eax
	shl	rax,10
	add	rax,[r15+A2_MEM]
	mov	rdi,rax
	mov	esi,1024
	lea	rdx,[r14+F_H0]
	mov	ecx,72
	call	blake2b_long
	inc	ebx
	cmp	ebx,[r15+A2_P]
	jb	.first_blocks

	lea	rdi,[r14+F_ZERO]
	mov	ecx,1024
	call	secure_zero

	mov	dword [r14+F_PASS],0
.pass:
	mov	dword [r14+F_SLICE],0
.slice:
	mov	dword [r14+F_LANE],0
.lane:
	call	argon2_segment
	inc	dword [r14+F_LANE]
	mov	eax,[r14+F_LANE]
	cmp	eax,[r15+A2_P]
	jb	.lane
	inc	dword [r14+F_SLICE]
	cmp	dword [r14+F_SLICE],4
	jb	.slice
	inc	dword [r14+F_PASS]
	mov	eax,[r14+F_PASS]
	cmp	eax,[r15+A2_T]
	jb	.pass

	; C = XOR of the last block of every lane; tag = H'(C).
	mov	eax,[r14+F_Q]
	dec	eax
	shl	rax,10
	add	rax,[r15+A2_MEM]
	mov	rsi,rax
	lea	rdi,[r14+F_ADDR]
	mov	ecx,1024
	rep	movsb
	mov	ebx,1
.xor_lanes:
	cmp	ebx,[r15+A2_P]
	jae	.tag
	mov	eax,ebx
	inc	eax
	imul	eax,[r14+F_Q]
	dec	eax
	shl	rax,10
	add	rax,[r15+A2_MEM]
	xor	ecx,ecx
@@:
	vmovdqu	ymm0,[rax+rcx]
	vpxor	ymm0,ymm0,[r14+F_ADDR+rcx]
	vmovdqu	[r14+F_ADDR+rcx],ymm0
	add	ecx,32
	cmp	ecx,1024
	jb	@b
	inc	ebx
	jmp	.xor_lanes
.tag:
	vzeroupper
	mov	rdi,[r15+A2_OUT]
	mov	esi,[r15+A2_OUTLEN]
	lea	rdx,[r14+F_ADDR]
	mov	ecx,1024
	call	blake2b_long

	; Wipe everything derived from the password.
	mov	rdi,[r15+A2_MEM]
	mov	ecx,[r14+F_MPRIME]
	shl	rcx,10
	xor	eax,eax
	rep	stosb
	xor	eax,eax
.wipe_frame:
	push	rax
	mov	rdi,r14
	mov	ecx,F_SIZE
	call	secure_zero
	pop	rax
	mov	rsp,rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
.invalid:
	mov	eax,-1
	jmp	.wipe_frame

; H0 = BLAKE2b-512(p, T, m, t, v, y, |P|, P, |S|, S, |K|, K, |X|, X)
macro h0_u32 value*
	mov	eax,value
	mov	[r14+F_U32],eax
	lea	rdi,[r14+F_CTX]
	lea	rsi,[r14+F_U32]
	mov	edx,4
	call	blake2b_update
end macro

macro h0_bytes ptr*, len*
	lea	rdi,[r14+F_CTX]
	mov	rsi,ptr
	mov	edx,len
	call	blake2b_update
end macro

argon2_h0:
	lea	rdi,[r14+F_CTX]
	mov	esi,64
	call	blake2b_init
	h0_u32	[r15+A2_P]
	h0_u32	[r15+A2_OUTLEN]
	h0_u32	[r15+A2_M]
	h0_u32	[r15+A2_T]
	h0_u32	ARGON2_VERSION
	h0_u32	[r15+A2_TYPE]
	h0_u32	[r15+A2_PWDLEN]
	h0_bytes [r15+A2_PWD], [r15+A2_PWDLEN]
	h0_u32	[r15+A2_SALTLEN]
	h0_bytes [r15+A2_SALT], [r15+A2_SALTLEN]
	h0_u32	[r15+A2_SECRETLEN]
	h0_bytes [r15+A2_SECRET], [r15+A2_SECRETLEN]
	h0_u32	[r15+A2_ADLEN]
	h0_bytes [r15+A2_AD], [r15+A2_ADLEN]
	lea	rdi,[r14+F_CTX]
	lea	rsi,[r14+F_H0]
	jmp	blake2b_final

; Address block for data-independent addressing:
; input[6]++; address = G(zero, G(zero, input)).
argon2_next_addresses:
	inc	qword [r14+F_INPUT+6*8]
	lea	rdi,[r14+F_ZERO]
	lea	rsi,[r14+F_INPUT]
	lea	rdx,[r14+F_ADDR]
	xor	ecx,ecx
	lea	r8,[r14+F_R]
	call	argon2_fill_block
	lea	rdi,[r14+F_ZERO]
	lea	rsi,[r14+F_ADDR]
	lea	rdx,[r14+F_ADDR]
	xor	ecx,ecx
	lea	r8,[r14+F_R]
	jmp	argon2_fill_block

; Fill one segment: F_PASS, F_SLICE, F_LANE select it.
argon2_segment:
	push	rbx
	push	r12
	push	r13

	; Argon2i always, Argon2id in the first half of the first pass.
	xor	eax,eax
	mov	ecx,[r15+A2_TYPE]
	cmp	ecx,ARGON2_I
	je	.independent
	cmp	ecx,ARGON2_ID
	jne	.mode_set
	cmp	dword [r14+F_PASS],0
	jne	.mode_set
	cmp	dword [r14+F_SLICE],2
	jae	.mode_set
.independent:
	mov	eax,1
.mode_set:
	mov	[r14+F_INDEP],eax
	test	eax,eax
	jz	.start
	lea	rdi,[r14+F_INPUT]
	mov	ecx,1024
	call	secure_zero
	mov	eax,[r14+F_PASS]
	mov	[r14+F_INPUT],rax
	mov	eax,[r14+F_LANE]
	mov	[r14+F_INPUT+8],rax
	mov	eax,[r14+F_SLICE]
	mov	[r14+F_INPUT+16],rax
	mov	eax,[r14+F_MPRIME]
	mov	[r14+F_INPUT+24],rax
	mov	eax,[r15+A2_T]
	mov	[r14+F_INPUT+32],rax
	mov	eax,[r15+A2_TYPE]
	mov	[r14+F_INPUT+40],rax

.start:
	; The first two blocks of each lane already exist.
	xor	ebx,ebx
	cmp	dword [r14+F_PASS],0
	jne	.positions
	cmp	dword [r14+F_SLICE],0
	jne	.positions
	mov	ebx,2
	cmp	dword [r14+F_INDEP],0
	je	.positions
	call	argon2_next_addresses

.positions:
	; curr = lane * q + slice * seg + start; prev wraps to the lane's end.
	mov	eax,[r14+F_LANE]
	imul	eax,[r14+F_Q]
	mov	ecx,[r14+F_SLICE]
	imul	ecx,[r14+F_SEG]
	add	eax,ecx
	add	eax,ebx
	mov	r12d,eax
	xor	edx,edx
	div	dword [r14+F_Q]
	lea	r13d,[r12-1]
	test	edx,edx
	jnz	.block
	mov	r13d,r12d
	add	r13d,[r14+F_Q]
	dec	r13d

.block:
	cmp	ebx,[r14+F_SEG]
	jae	.done
	mov	eax,r12d
	xor	edx,edx
	div	dword [r14+F_Q]
	cmp	edx,1
	jne	@f
	lea	r13d,[r12-1]
@@:
	cmp	dword [r14+F_INDEP],0
	je	.dependent
	test	ebx,127
	jnz	@f
	call	argon2_next_addresses
@@:
	mov	eax,ebx
	and	eax,127
	mov	rax,[r14+F_ADDR+rax*8]
	jmp	.random
.dependent:
	mov	rax,r13
	shl	rax,10
	add	rax,[r15+A2_MEM]
	mov	rax,[rax]
.random:
	mov	[r14+F_RAND],rax

	; Reference lane: J2 mod p (own lane in the first slice of pass 0).
	shr	rax,32
	xor	edx,edx
	mov	ecx,[r15+A2_P]
	div	rcx
	cmp	dword [r14+F_PASS],0
	jne	@f
	cmp	dword [r14+F_SLICE],0
	jne	@f
	mov	edx,[r14+F_LANE]
@@:
	mov	[r14+F_REFLANE],edx

	call	argon2_index_alpha
	mov	ecx,[r14+F_REFLANE]
	imul	ecx,[r14+F_Q]
	add	eax,ecx
	shl	rax,10
	add	rax,[r15+A2_MEM]
	mov	rsi,rax
	mov	rdi,r13
	shl	rdi,10
	add	rdi,[r15+A2_MEM]
	mov	rdx,r12
	shl	rdx,10
	add	rdx,[r15+A2_MEM]
	xor	ecx,ecx
	cmp	dword [r14+F_PASS],0		; version 0x13 xors from pass 1 on
	je	@f
	mov	ecx,1
@@:
	lea	r8,[r14+F_R]
	call	argon2_fill_block
	inc	r12d
	inc	r13d
	inc	ebx
	jmp	.block
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Map J1 (low half of F_RAND) to a block index in the reference lane
; (RFC 9106 3.4.1.2). ebx = index in the segment. eax = block in the lane.
argon2_index_alpha:
	mov	ecx,[r14+F_SEG]
	mov	edx,[r14+F_REFLANE]
	cmp	edx,[r14+F_LANE]
	sete	r9b
	cmp	dword [r14+F_PASS],0
	jne	.later_pass
	cmp	dword [r14+F_SLICE],0
	jne	.first_pass
	lea	r8d,[rbx-1]
	jmp	.area
.first_pass:
	mov	r8d,[r14+F_SLICE]
	imul	r8d,ecx
	jmp	.lane_adjust
.later_pass:
	mov	r8d,[r14+F_Q]
	sub	r8d,ecx
.lane_adjust:
	test	r9b,r9b
	jz	.other_lane
	add	r8d,ebx
	dec	r8d
	jmp	.area
.other_lane:
	test	ebx,ebx
	jnz	.area
	dec	r8d
.area:
	; rel = area - 1 - ((area * ((J1 * J1) >> 32)) >> 32)
	mov	eax,[r14+F_RAND]
	imul	rax,rax
	shr	rax,32
	mov	r8d,r8d
	imul	rax,r8
	shr	rax,32
	lea	rcx,[r8-1]
	sub	rcx,rax
	; start: 0 in pass 0 or the last slice, else the next slice.
	xor	eax,eax
	cmp	dword [r14+F_PASS],0
	je	.position
	mov	edx,[r14+F_SLICE]
	cmp	edx,3
	je	.position
	inc	edx
	imul	edx,[r14+F_SEG]
	mov	eax,edx
.position:
	add	rax,rcx
	xor	edx,edx
	mov	ecx,[r14+F_Q]
	div	rcx
	mov	eax,edx
	ret
