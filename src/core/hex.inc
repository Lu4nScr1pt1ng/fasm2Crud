; Hex and UUID text forms.

rodata
	hex_lower	db '0123456789abcdef'
end rodata

; rdi = destination (2 * edx bytes), rsi = bytes, edx = count.
; rdi is advanced past the output.
hex_encode:
	test	edx,edx
	jz	.done
.byte:
	movzx	eax,byte [rsi]
	mov	ecx,eax
	shr	eax,4
	and	ecx,15
	mov	al,[hex_lower+rax]
	mov	cl,[hex_lower+rcx]
	mov	[rdi],al
	mov	[rdi+1],cl
	add	rdi,2
	inc	rsi
	dec	edx
	jnz	.byte
.done:
	ret

; al = character. eax = 0..15, CF when it is not a hex digit.
hex_value:
	movzx	eax,al
	sub	eax,'0'
	cmp	eax,9
	jbe	.ok
	or	eax,0x20
	sub	eax,'a'-'0'
	cmp	eax,5
	ja	.bad
	add	eax,10
.ok:
	clc
	ret
.bad:
	stc
	ret

; rsi = 36-character UUID (8-4-4-4-12, any case), rdi = 16 bytes.
; CF on malformed input.
uuid_parse:
	xor	ecx,ecx				; text position
	xor	edx,edx				; output byte
.pair:
	cmp	ecx,36
	jae	.done
	cmp	ecx,8
	je	.dash
	cmp	ecx,13
	je	.dash
	cmp	ecx,18
	je	.dash
	cmp	ecx,23
	je	.dash
	mov	al,[rsi+rcx]
	call	hex_value
	jc	.bad
	mov	r8d,eax
	mov	al,[rsi+rcx+1]
	call	hex_value
	jc	.bad
	shl	r8d,4
	or	eax,r8d
	mov	[rdi+rdx],al
	inc	edx
	add	ecx,2
	jmp	.pair
.dash:
	cmp	byte [rsi+rcx],'-'
	jne	.bad
	inc	ecx
	jmp	.pair
.done:
	clc
	ret
.bad:
	stc
	ret

; rsi = 16 bytes, rdi = 36-character destination (lowercase).
; rdi is advanced past the output.
uuid_format:
	push	rbx
	xor	ebx,ebx
.group:
	movzx	edx,byte [uuid_groups+rbx]
	test	edx,edx
	jz	.done
	push	rdx
	call	hex_encode
	pop	rdx
	inc	ebx
	cmp	byte [uuid_groups+rbx],0
	je	.done
	mov	byte [rdi],'-'
	inc	rdi
	jmp	.group
.done:
	pop	rbx
	ret

rodata
	uuid_groups	db 4, 2, 2, 2, 6, 0
end rodata
