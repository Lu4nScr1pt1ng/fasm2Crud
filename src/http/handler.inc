; Request framing and response writing.

cstring hdr_common, 'Content-Type: application/json',13,10, \
		    'X-Content-Type-Options: nosniff',13,10, \
		    'Cache-Control: no-store',13,10, \
		    'Content-Length: '
cstring hdr_close, 'Connection: close',13,10
cstring hdr_no_store, 'Cache-Control: no-store',13,10

; r12 = connection, rdi = request start, esi = bytes available.
; eax = bytes consumed by one request, or 0 when more data is needed.
http_handle:
	push	r13
	push	r14
	push	r15
	mov	r13,rdi
	mov	r14d,esi
	mov	edx,[r12+C_SCAN]
	call	find_header_end
	test	eax,eax
	jz	.need_headers
	js	.bad
	mov	r15d,eax

	mov	rdi,r13
	mov	esi,r15d
	call	parse_request
	test	eax,eax
	jnz	.reject

	mov	ecx,[req_length]
	add	ecx,r15d			; whole request
	cmp	ecx,IN_CAP
	ja	.too_large
	cmp	ecx,r14d
	ja	.need_body
	mov	dword [r12+C_SCAN],0
	lea	rax,[r13+r15]
	mov	[req_body],rax
	mov	eax,[req_length]
	mov	[req_body_len],eax

	; Persistence: HTTP/1.1 keeps the connection unless told otherwise,
	; HTTP/1.0 only when asked to; draining workers close after replying.
	mov	eax,[req_flags]
	test	eax,RQ_CLOSE
	jnz	.close
	cmp	dword [req_version],11
	je	.persist
	test	eax,RQ_KEEPALIVE
	jz	.close
.persist:
	cmp	dword [g_draining],0
	je	.route
.close:
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
.route:
	push	rcx
	call	route
	pop	rax
	jmp	.done

.need_headers:
	; Resume just before the end next time, so the search stays linear
	; however the client splits its writes.
	xor	eax,eax
	lea	ecx,[r14-3]
	cmp	r14d,3
	cmova	eax,ecx
	mov	[r12+C_SCAN],eax
	xor	eax,eax
	jmp	.done
.need_body:
	lea	eax,[r15-4]
	mov	[r12+C_SCAN],eax
	xor	eax,eax
	jmp	.done
.bad:
	mov	eax,ST_400
	jmp	.reject
.too_large:
	mov	eax,ST_413
.reject:
	; The framing can no longer be trusted: answer and drop the rest.
	or	dword [r12+C_FLAGS],F_CLOSE_AFTER
	mov	edi,eax
	call	respond_status
	mov	eax,r14d
.done:
	pop	r15
	pop	r14
	pop	r13
	ret

; edi = ST_xxx, answered with its default body.
respond_status:
	mov	eax,edi
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	xor	ecx,ecx
	xor	r8d,r8d

; Append a JSON response to the output buffer.
; r12 = connection, edi = ST_xxx, rsi = body, edx = body length,
; rcx = extra header lines (CRLF terminated), r8d = their length.
; The caller has checked that RESP_RESERVE bytes are free.
respond:
	push	r13
	push	r14
	push	r15
	mov	r13,rsi
	mov	r14d,edx
	mov	r15,rcx
	push	r8
	mov	eax,edi
	shl	eax,5
	lea	r9,[status_tbl+rax]
	mov	eax,[r12+C_OUT_LEN]
	lea	rdi,[r12+OUT_OFF+rax]

	mov	rsi,[r9]
	mov	rcx,[r9+8]
	rep	movsb
	lea	rsi,[g_date_line]
	mov	ecx,DATE_LINE_LEN
	rep	movsb
	lea	rsi,[hdr_common]
	mov	ecx,hdr_common.len
	rep	movsb
	mov	eax,r14d
	call	write_u32
	mov	word [rdi],0x0A0D
	add	rdi,2
	pop	rcx
	test	ecx,ecx
	jz	@f
	mov	rsi,r15
	rep	movsb
@@:
	test	dword [r12+C_FLAGS],F_CLOSE_AFTER
	jz	@f
	lea	rsi,[hdr_close]
	mov	ecx,hdr_close.len
	rep	movsb
@@:
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rsi,r13
	mov	ecx,r14d
	rep	movsb

	lea	rax,[r12+OUT_OFF]
	sub	rdi,rax
	mov	[r12+C_OUT_LEN],edi
	pop	r15
	pop	r14
	pop	r13
	ret

; 204: no body, and so no Content-Type or Content-Length (RFC 9110 8.6).
; r12 = connection.
respond_no_content:
	mov	eax,[r12+C_OUT_LEN]
	lea	rdi,[r12+OUT_OFF+rax]
	mov	eax,ST_204
	shl	eax,5
	mov	rsi,[status_tbl+rax]
	mov	rcx,[status_tbl+rax+8]
	rep	movsb
	lea	rsi,[g_date_line]
	mov	ecx,DATE_LINE_LEN
	rep	movsb
	lea	rsi,[hdr_no_store]
	mov	ecx,hdr_no_store.len
	rep	movsb
	test	dword [r12+C_FLAGS],F_CLOSE_AFTER
	jz	@f
	lea	rsi,[hdr_close]
	mov	ecx,hdr_close.len
	rep	movsb
@@:
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r12+OUT_OFF]
	sub	rdi,rax
	mov	[r12+C_OUT_LEN],edi
	ret

; eax = value, rdi = destination; rdi is advanced past the digits.
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
