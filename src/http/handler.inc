; Request framing and response writing.

cstring hdr_common, 'Content-Type: application/json',13,10, \
		    'X-Content-Type-Options: nosniff',13,10, \
		    'Cache-Control: no-store',13,10, \
		    'Content-Length: '
cstring hdr_close, 'Connection: close',13,10
cstring hdr_no_store, 'Cache-Control: no-store',13,10

HTTP_WAIT_OUTPUT = -1		; retry once the pending output is sent
HTTP_LARGE_INPUT = -2		; retry from a large input buffer

RESP_HEAD_ROOM	= 512		; room before a body built in place (respond_built)

; r12 = connection, rdi = request start, esi = bytes available.
; eax = bytes consumed by one request, 0 when more data is needed, or
; HTTP_WAIT_OUTPUT / HTTP_LARGE_INPUT.
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
	cmp	ecx,[r12+C_IN_CAP]
	jbe	.fits
	; Routes that take large bodies read them into a large buffer.
	push	rcx
	call	route_input_max
	pop	rcx
	cmp	ecx,eax
	ja	.too_large
	mov	eax,HTTP_LARGE_INPUT
	jmp	.done
.fits:
	cmp	ecx,r14d
	ja	.need_body
	; Routes whose responses are built in place (respond_built) start with
	; an empty output buffer: wait for what is pending to be sent.
	push	rcx
	call	route_output_need
	pop	rcx
	test	eax,eax
	jz	@f
	cmp	dword [r12+C_OUT_LEN],0
	jne	.defer
@@:
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
.defer:
	mov	dword [r12+C_SCAN],0
	mov	eax,HTTP_WAIT_OUTPUT
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
	mov	r13,rsi
	mov	r14d,edx
	mov	esi,edi
	mov	eax,[r12+C_OUT_LEN]
	mov	rdi,[r12+C_OUT_BUF]
	add	rdi,rax
	call	http_head
	mov	rsi,r13
	mov	ecx,r14d
	rep	movsb
	sub	rdi,[r12+C_OUT_BUF]
	mov	[r12+C_OUT_LEN],edi
	pop	r14
	pop	r13
	ret

; Status line and headers of a JSON response, written at rdi (advanced).
; r12 = connection, esi = ST_xxx, edx = body length, rcx = extra header
; lines, r8d = their length. At most 256 bytes plus the extra lines.
http_head:
	push	r13
	push	r14
	push	r15
	mov	r13d,edx
	mov	r14,rcx
	mov	r15d,r8d
	mov	eax,esi
	shl	eax,5
	mov	rsi,[status_tbl+rax]
	mov	rcx,[status_tbl+rax+8]
	rep	movsb
	lea	rsi,[g_date_line]
	mov	ecx,DATE_LINE_LEN
	rep	movsb
	lea	rsi,[hdr_common]
	mov	ecx,hdr_common.len
	rep	movsb
	mov	eax,r13d
	call	write_u32
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	test	dword [r12+C_FLAGS],F_CLOSE_AFTER
	jz	@f
	lea	rsi,[hdr_close]
	mov	ecx,hdr_close.len
	rep	movsb
@@:
	mov	word [rdi],0x0A0D
	add	rdi,2
	pop	r15
	pop	r14
	pop	r13
	ret

; Responses built in place, for bodies of any size up to LARGE_CAP. The
; route asked for an empty output buffer (route_output_need), so the body
; is written straight into it and the head just before it: nothing is
; copied. A body that does not fit the slot's buffer gets a large one.
;
; respond_reserve: edx = exact body length. rax = where to write the body;
; CF when no large buffer is free (503 with Retry-After already answered).
respond_reserve:
	lea	eax,[rdx+RESP_HEAD_ROOM]
	cmp	eax,[r12+C_OUT_CAP]
	jbe	.fits
	call	conn_large_output
	jc	.busy
.fits:
	mov	rax,[r12+C_OUT_BUF]
	add	rax,RESP_HEAD_ROOM
	clc
	ret
.busy:
	call	respond_busy
	stc
	ret

; respond_built: edi = ST_xxx, edx = body length (written where
; respond_reserve said), rcx / r8d = extra header lines (<= 128 bytes).
respond_built:
	push	r13
	push	r14
	mov	r13d,edx
	sub	rsp,RESP_HEAD_ROOM
	mov	esi,edi
	mov	rdi,rsp
	call	http_head
	mov	rcx,rdi
	sub	rcx,rsp				; head length
	mov	r14d,RESP_HEAD_ROOM
	sub	r14d,ecx			; where the head starts
	mov	rdi,[r12+C_OUT_BUF]
	add	rdi,r14
	mov	rsi,rsp
	rep	movsb
	add	rsp,RESP_HEAD_ROOM
	mov	[r12+C_OUT_SENT],r14d
	lea	eax,[r13+RESP_HEAD_ROOM]
	mov	[r12+C_OUT_LEN],eax
	pop	r14
	pop	r13
	ret

; 204: no body, and so no Content-Type or Content-Length (RFC 9110 8.6).
; r12 = connection.
respond_no_content:
	mov	eax,[r12+C_OUT_LEN]
	mov	rdi,[r12+C_OUT_BUF]
	add	rdi,rax
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
	sub	rdi,[r12+C_OUT_BUF]
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
