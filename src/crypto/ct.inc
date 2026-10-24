; Constant-time and hygiene helpers for secrets.

; rdi = a, rsi = b, edx = length. eax = 1 when equal. The running time
; depends only on the length, never on where the first difference is.
ct_equal:
	xor	eax,eax
	xor	ecx,ecx
	test	edx,edx
	jz	.done
.byte:
	mov	r8b,[rdi+rcx]
	xor	r8b,[rsi+rcx]
	or	al,r8b
	inc	ecx
	cmp	ecx,edx
	jb	.byte
.done:
	; eax = (al == 0) without a branch.
	movzx	eax,al
	sub	eax,1
	shr	eax,31
	ret

; rdi = buffer, ecx = length. Wipes secrets from memory; in assembly there
; is no optimizer that could drop the stores.
secure_zero:
	xor	eax,eax
	rep	stosb
	ret

; rdi = buffer, rsi = length. Fills it from the kernel CSPRNG.
; eax = 0, or -errno.
random_bytes:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
.more:
	test	r12,r12
	jz	.ok
	mov	rdi,rbx
	mov	rsi,r12
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,-EINTR
	je	.more
	test	rax,rax
	js	.done
	add	rbx,rax
	sub	r12,rax
	jmp	.more
.ok:
	xor	eax,eax
.done:
	pop	r12
	pop	rbx
	ret
