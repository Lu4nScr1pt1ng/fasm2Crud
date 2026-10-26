; IP address text, with explicit lengths (for header values, which are
; not NUL-terminated). Fuzzed against Python's ipaddress (tests/fuzz).

; Dotted IPv4 text: rsi = text, edx = length. eax = address (network
; order); CF when it is not exactly four decimal octets.
ipv4_text:
	xor	eax,eax
	xor	ecx,ecx				; octets
	lea	r9,[rsi+rdx]
.octet:
	xor	edx,edx
	xor	r8d,r8d				; digits
.digit:
	cmp	rsi,r9
	jae	.end_octet
	movzx	r10d,byte [rsi]
	sub	r10d,'0'
	cmp	r10d,9
	ja	.end_octet
	imul	edx,edx,10
	add	edx,r10d
	inc	rsi
	inc	r8d
	cmp	r8d,3
	ja	.bad
	jmp	.digit
.end_octet:
	test	r8d,r8d
	jz	.bad
	cmp	edx,255
	ja	.bad
	lea	r10d,[rcx*8]
	shlx	edx,edx,r10d
	or	eax,edx
	inc	ecx
	cmp	ecx,4
	je	.last
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'.'
	jne	.bad
	inc	rsi
	jmp	.octet
.last:
	cmp	rsi,r9
	jne	.bad
	clc
	ret
.bad:
	stc
	ret

; IPv6 text (RFC 4291 hex groups, one "::" at most; no zone, no embedded
; IPv4): rsi = text, edx = length, rdi = 16 bytes. CF on anything else.
ipv6_text:
	push	rbx
	push	r12
	sub	rsp,16				; the groups, in order
	lea	r9,[rsi+rdx]
	xor	ebx,ebx				; groups parsed
	mov	r12d,-1				; where "::" was
	cmp	edx,2
	jb	.bad
	cmp	word [rsi],'::'
	jne	.group
	mov	r12d,0
	add	rsi,2
	cmp	rsi,r9
	je	.expand
.group:
	cmp	ebx,8
	jae	.bad
	xor	eax,eax
	xor	ecx,ecx				; digits
.hex:
	cmp	rsi,r9
	jae	.group_end
	movzx	edx,byte [rsi]
	push	rax
	mov	al,dl
	call	hex_value
	mov	edx,eax
	pop	rax
	jc	.group_end
	shl	eax,4
	or	eax,edx
	inc	rsi
	inc	ecx
	cmp	ecx,4
	ja	.bad
	jmp	.hex
.group_end:
	test	ecx,ecx
	jz	.bad
	mov	[rsp+rbx*2],ax
	inc	ebx
	cmp	rsi,r9
	je	.expand
	cmp	byte [rsi],':'
	jne	.bad
	inc	rsi
	cmp	rsi,r9
	je	.bad				; a trailing single ':'
	cmp	byte [rsi],':'
	jne	.group
	cmp	r12d,-1
	jne	.bad				; a second "::"
	mov	r12d,ebx
	inc	rsi
	cmp	rsi,r9
	jne	.group
.expand:
	; Without "::" there are exactly 8 groups; with it at most 7, since it
	; stands for at least one group of zeros. Then: the groups before it,
	; the zeros, the groups after, as big-endian bytes.
	cmp	r12d,-1
	jne	.gap
	cmp	ebx,8
	jne	.bad
	mov	r12d,8
	jmp	@f
.gap:
	cmp	ebx,7
	ja	.bad
@@:
	mov	ecx,8
	sub	ecx,ebx				; zero groups
	xor	edx,edx				; output group
	xor	r8d,r8d				; input group
.out:
	cmp	edx,8
	jae	.done
	cmp	r8d,r12d
	jne	.copy
	test	ecx,ecx
	jz	.copy
	mov	word [rdi+rdx*2],0
	dec	ecx
	inc	edx
	jmp	.out
.copy:
	mov	ax,[rsp+r8*2]
	xchg	al,ah
	mov	[rdi+rdx*2],ax
	inc	r8d
	inc	edx
	jmp	.out
.done:
	add	rsp,16
	pop	r12
	pop	rbx
	clc
	ret
.bad:
	add	rsp,16
	pop	r12
	pop	rbx
	stc
	ret

