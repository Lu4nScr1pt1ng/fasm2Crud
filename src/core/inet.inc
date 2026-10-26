; Client addresses: who a request is from, as a 64-bit key for the rate
; limiter.
;
; The listener is dual-stack, so a connection's address is a sockaddr_in6
; (or a sockaddr_in with the IPv4 fallback). IPv4, mapped or not, counts
; per address; IPv6 counts per /64, the block one subscriber usually gets,
; so a client cannot dodge its limit by moving within it.
;
; Behind a reverse proxy every connection comes from the proxy. When the
; peer is API_TRUSTED_PROXY, the client is the last X-Forwarded-For entry
; (the address the proxy itself saw), read per request, since a proxy
; reuses its connections for many clients. From anyone else the header is
; ignored: clients cannot pick their own key. A trusted request without a
; usable header counts as the proxy.

cstring env_trusted_proxy, 'API_TRUSTED_PROXY='

bss
	g_trusted_proxy	dd ?		; IPv4, network order; 0 = none
end bss

inet_config:
	lea	rdi,[env_trusted_proxy]
	mov	esi,env_trusted_proxy.len
	call	getenv
	test	rax,rax
	jz	.done
	cmp	byte [rax],0
	je	.done
	mov	rsi,rax
	call	parse_ipv4
	jc	.bad
	mov	[g_trusted_proxy],eax
.done:
	ret
.bad:
	call	log_begin
	log_lit 'invalid API_TRUSTED_PROXY: expected an IPv4 address'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; 64-bit finalizer (splitmix64): spreads keys over the table.
; rax in, rax out. Clobbers rdx.
mix64:
	mov	rdx,rax
	shr	rdx,30
	xor	rax,rdx
	mov	rdx,0xBF58476D1CE4E5B9
	imul	rax,rdx
	mov	rdx,rax
	shr	rdx,27
	xor	rax,rdx
	mov	rdx,0x94D049BB133111EB
	imul	rax,rdx
	mov	rdx,rax
	shr	rdx,31
	xor	rax,rdx
	ret

; eax = IPv4 (network order): its key.
key_ipv4:
	mov	edx,4
	shl	rdx,32
	or	rax,rdx
	call	mix64
	or	rax,1				; never 0: 0 marks a free table entry
	ret

; rax = the first 8 bytes of an IPv6 address (its /64): its key.
key_ipv6:
	mov	rdx,0x6666666666666666
	xor	rax,rdx
	call	mix64
	or	rax,1
	ret

; The key of the current request's client. r12 = connection (address
; known). rax = key.
client_key:
	movzx	eax,word [r12+C_PEER_ADDR]
	cmp	eax,AF_INET6
	je	.v6
	mov	eax,[r12+C_PEER_ADDR+4]		; sin_addr (or 0: unknown)
	jmp	.v4
.v6:
	; ::ffff:a.b.c.d is IPv4.
	cmp	qword [r12+C_PEER_ADDR+8],0
	jne	.v6_key
	cmp	dword [r12+C_PEER_ADDR+16],0xFFFF0000
	jne	.v6_key
	mov	eax,[r12+C_PEER_ADDR+20]
.v4:
	cmp	dword [g_trusted_proxy],0
	je	key_ipv4
	cmp	eax,[g_trusted_proxy]
	jne	key_ipv4
	jmp	forwarded_key
.v6_key:
	mov	rax,[r12+C_PEER_ADDR+8]
	jmp	key_ipv6

; From the trusted proxy: the last X-Forwarded-For entry, else the proxy.
; eax = the proxy's address.
forwarded_key:
	push	rax
	mov	rsi,[req_xff]
	mov	edx,[req_xff_len]
	test	edx,edx
	jz	.proxy
	; Last entry: after the last comma, without spaces.
	lea	r8,[rsi+rdx]			; end
	mov	rcx,r8
@@:
	cmp	rcx,rsi
	je	@f
	cmp	byte [rcx-1],','
	je	@f
	dec	rcx
	jmp	@b
@@:
	mov	rsi,rcx
.lead:
	cmp	rsi,r8
	jae	.proxy
	cmp	byte [rsi],' '
	je	.skip
	cmp	byte [rsi],9
	jne	.trail
.skip:
	inc	rsi
	jmp	.lead
.trail:
	cmp	byte [r8-1],' '
	je	@f
	cmp	byte [r8-1],9
	jne	.entry
@@:
	dec	r8
	jmp	.trail
.entry:
	mov	rdx,r8
	sub	rdx,rsi
	; IPv6 when it has a colon.
	mov	rcx,rsi
@@:
	cmp	rcx,r8
	jae	.v4
	cmp	byte [rcx],':'
	je	.v6
	inc	rcx
	jmp	@b
.v4:
	call	ipv4_text
	jc	.proxy
	add	rsp,8
	jmp	key_ipv4
.v6:
	sub	rsp,16
	mov	rdi,rsp
	call	ipv6_text
	mov	rax,[rsp]
	lea	rsp,[rsp+16]
	jc	.proxy
	add	rsp,8
	jmp	key_ipv6
.proxy:
	pop	rax
	jmp	key_ipv4
