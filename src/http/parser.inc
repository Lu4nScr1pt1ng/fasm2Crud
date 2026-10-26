; HTTP/1.1 request parser (RFC 9112), strict by design.
;
; Anything ambiguous is rejected with 400 and the connection is closed:
; bare LF, whitespace before ':', control bytes in values, duplicate
; Content-Length, Transfer-Encoding (we accept no chunked bodies, which also
; rules out request smuggling through CL/TE disagreement), and a missing or
; repeated Host in HTTP/1.1.
;
; The parser works in place on the connection's input buffer; the request
; fields below point into it and are valid until the next request is parsed.

M_OTHER		= 0
M_GET		= 1
M_HEAD		= 2
M_POST		= 3
M_PUT		= 4
M_PATCH		= 5
M_DELETE	= 6
M_OPTIONS	= 7

RQ_CLOSE	= 1 shl 0	; "Connection: close"
RQ_KEEPALIVE	= 1 shl 1	; "Connection: keep-alive" (HTTP/1.0)
RQ_HAS_LENGTH	= 1 shl 2

bss
	align 8
	g_req:
	req_path	dq ?
	req_query	dq ?
	req_body	dq ?
	req_ctype	dq ?
	req_auth	dq ?
	req_if_match	dq ?
	req_xff		dq ?		; X-Forwarded-For (trusted only from API_TRUSTED_PROXY)
	req_method	dd ?
	req_version	dd ?		; 10 or 11
	req_flags	dd ?
	req_hosts	dd ?
	req_headers	dd ?
	req_length	dd ?		; Content-Length, 0 when absent
	req_path_len	dd ?
	req_query_len	dd ?
	req_body_len	dd ?
	req_ctype_len	dd ?
	req_auth_len	dd ?
	req_if_match_len dd ?
	req_xff_len	dd ?
	REQ_SIZE = $ - g_req
end bss

rodata
	align 32
	vec_lf	db 32 dup 0x0A
	vec_1f	db 32 dup 0x1F
	vec_09	db 32 dup 0x09
	vec_7f	db 32 dup 0x7F

	; tchar (RFC 9110 5.6.2): token characters for methods and field names.
	tchar_tbl:
	repeat 256, c:0
		if (c >= '0' & c <= '9') | (c >= 'A' & c <= 'Z') | (c >= 'a' & c <= 'z') | \
		   c = '!' | c = '#' | c = '$' | c = '%' | c = '&' | c = "'" | c = '*' | \
		   c = '+' | c = '-' | c = '.' | c = '^' | c = '_' | c = '`' | c = '|' | c = '~'
			db 1
		else
			db 0
		end if
	end repeat
end rodata

; rdi = data, esi = length, edx = offset to resume from.
; eax = offset just past CRLFCRLF, 0 when the header block is incomplete,
; or -1 on a bare LF (every LF in the header block must follow a CR).
; May read up to 31 bytes past the end; callers guarantee they are mapped.
find_header_end:
	vmovdqa	ymm1,yword [vec_lf]
	mov	ecx,edx
.block:
	cmp	ecx,esi
	jae	.none
	vmovdqu	ymm0,[rdi+rcx]
	vpcmpeqb ymm0,ymm0,ymm1
	vpmovmskb eax,ymm0
	mov	edx,esi
	sub	edx,ecx
	cmp	edx,32
	jae	.candidate
	bzhi	eax,eax,edx
.candidate:
	test	eax,eax
	jz	.advance
	tzcnt	r8d,eax
	add	r8d,ecx
	test	r8d,r8d
	jz	.bare_lf
	cmp	byte [rdi+r8-1],13
	jne	.bare_lf
	cmp	r8d,3
	jb	.skip
	cmp	dword [rdi+r8-3],0x0A0D0A0D
	jne	.skip
	lea	eax,[r8+1]
	vzeroupper
	ret
.skip:
	blsr	eax,eax
	jmp	.candidate
.advance:
	add	ecx,32
	jmp	.block
.none:
	xor	eax,eax
	vzeroupper
	ret
.bare_lf:
	mov	eax,-1
	vzeroupper
	ret

; rax = first byte at or after rsi that is a control character other than
; HTAB (or DEL). Returns a value >= r9 when there is none before r9.
scan_field_value:
	vmovdqa	ymm4,yword [vec_1f]
	vmovdqa	ymm5,yword [vec_09]
	vmovdqa	ymm6,yword [vec_7f]
	mov	rax,rsi
.block:
	vmovdqu	ymm0,[rax]
	vpminub	ymm1,ymm0,ymm4
	vpcmpeqb ymm1,ymm1,ymm0			; byte <= 0x1F
	vpcmpeqb ymm2,ymm0,ymm5
	vpandn	ymm1,ymm2,ymm1			; ... and not HTAB
	vpcmpeqb ymm3,ymm0,ymm6
	vpor	ymm1,ymm1,ymm3			; or DEL
	vpmovmskb ecx,ymm1
	test	ecx,ecx
	jnz	.found
	add	rax,32
	cmp	rax,r9
	jb	.block
	ret
.found:
	tzcnt	ecx,ecx
	add	rax,rcx
	ret

; rdi = request, esi = length of the header block (through CRLFCRLF).
; eax = 0 when valid, otherwise the ST_xxx status to answer with.
parse_request:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r8,rdi
	lea	r9,[rdi+rsi]
	lea	rdi,[g_req]
	xor	eax,eax
	mov	ecx,REQ_SIZE/4
	rep	stosd
	mov	rsi,r8

	; method SP
.method:
	movzx	eax,byte [rsi]
	cmp	byte [tchar_tbl+rax],0
	je	.method_end
	inc	rsi
	cmp	rsi,r9
	jb	.method
	jmp	.bad
.method_end:
	cmp	al,' '
	jne	.bad
	mov	rcx,rsi
	sub	rcx,r8
	jz	.bad
	xor	ebx,ebx
	mov	eax,[r8]			; includes the SP for 3-byte methods
	cmp	ecx,3
	jne	.method4
	mov	ebx,M_GET
	cmp	eax,'GET '
	je	.method_known
	mov	ebx,M_PUT
	cmp	eax,'PUT '
	je	.method_known
	jmp	.method_other
.method4:
	cmp	ecx,4
	jne	.method5
	mov	ebx,M_POST
	cmp	eax,'POST'
	je	.method_known
	mov	ebx,M_HEAD
	cmp	eax,'HEAD'
	je	.method_known
	jmp	.method_other
.method5:
	cmp	ecx,5
	jne	.method6
	mov	ebx,M_PATCH
	cmp	eax,'PATC'
	jne	.method_other
	cmp	byte [r8+4],'H'
	je	.method_known
	jmp	.method_other
.method6:
	cmp	ecx,6
	jne	.method7
	mov	ebx,M_DELETE
	cmp	eax,'DELE'
	jne	.method_other
	cmp	word [r8+4],'TE'
	je	.method_known
	jmp	.method_other
.method7:
	cmp	ecx,7
	jne	.method_other
	mov	ebx,M_OPTIONS
	cmp	eax,'OPTI'
	jne	.method_other
	cmp	dword [r8+3],'IONS'
	je	.method_known
.method_other:
	xor	ebx,ebx
.method_known:
	mov	[req_method],ebx
	inc	rsi

	; request-target SP (origin-form only)
	cmp	byte [rsi],'/'
	jne	.bad
	mov	rdi,rsi
	xor	r12d,r12d			; start of the query, if any
.target:
	movzx	eax,byte [rsi]
	cmp	al,' '
	je	.target_end
	lea	ecx,[rax-0x21]
	cmp	ecx,0x7E-0x21
	ja	.bad
	cmp	al,'#'
	je	.bad
	cmp	al,'?'
	jne	.target_next
	test	r12,r12
	jnz	.target_next
	lea	r12,[rsi+1]
.target_next:
	inc	rsi
	cmp	rsi,r9
	jb	.target
	jmp	.bad
.target_end:
	mov	[req_path],rdi
	test	r12,r12
	jz	.no_query
	mov	[req_query],r12
	mov	rax,rsi
	sub	rax,r12
	mov	[req_query_len],eax
	lea	rax,[r12-1]
	sub	rax,rdi
	mov	[req_path_len],eax
	jmp	.version
.no_query:
	mov	rax,rsi
	sub	rax,rdi
	mov	[req_path_len],eax

	; HTTP-version CRLF
.version:
	inc	rsi
	lea	rax,[rsi+10]
	cmp	rax,r9
	ja	.bad
	mov	rax,[rsi]
	mov	rcx,'HTTP/1.1'
	mov	edx,11
	cmp	rax,rcx
	je	.version_crlf
	mov	rcx,'HTTP/1.0'
	mov	edx,10
	cmp	rax,rcx
	je	.version_crlf
	mov	rcx,0xFFFFFFFFFF
	and	rax,rcx
	mov	rcx,'HTTP/'
	cmp	rax,rcx
	jne	.bad
	mov	eax,ST_505
	jmp	.done
.version_crlf:
	cmp	word [rsi+8],0x0A0D
	jne	.bad
	mov	[req_version],edx
	add	rsi,10

	; field-name ":" OWS field-value OWS CRLF
.field:
	cmp	word [rsi],0x0A0D
	je	.fields_done
	inc	dword [req_headers]
	cmp	dword [req_headers],MAX_HEADERS
	ja	.too_many
	mov	r10,rsi
.name:
	movzx	eax,byte [rsi]
	cmp	byte [tchar_tbl+rax],0
	je	.name_end
	inc	rsi
	cmp	rsi,r9
	jb	.name
	jmp	.bad
.name_end:
	cmp	al,':'
	jne	.bad
	mov	r11,rsi
	sub	r11,r10
	jz	.bad
	inc	rsi
.ows:
	mov	al,[rsi]
	cmp	al,' '
	je	.ows_next
	cmp	al,9
	jne	.value
.ows_next:
	inc	rsi
	jmp	.ows
.value:
	mov	r12,rsi
	call	scan_field_value
	cmp	rax,r9
	jae	.bad
	cmp	word [rax],0x0A0D
	jne	.bad
	lea	rsi,[rax+2]
	mov	r13,rax
.trim:
	cmp	r13,r12
	jbe	.trimmed
	mov	cl,[r13-1]
	cmp	cl,' '
	je	.trim_next
	cmp	cl,9
	jne	.trimmed
.trim_next:
	dec	r13
	jmp	.trim
.trimmed:
	sub	r13,r12
	call	header_field
	test	eax,eax
	jnz	.done
	jmp	.field

.fields_done:
	xor	eax,eax
	cmp	dword [req_version],11
	jne	.done
	cmp	dword [req_hosts],1
	je	.done
.bad:
	mov	eax,ST_400
	jmp	.done
.too_many:
	mov	eax,ST_431
.done:
	vzeroupper
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r10 = name, r11 = name length, r12 = value, r13 = value length.
; eax = 0 or ST_xxx. Names compare case-insensitively: OR-ing 0x20 maps
; only A-Z onto a-z among token characters, and leaves '-' unchanged.
header_field:
	mov	rcx,0x2020202020202020
	cmp	r11d,4
	je	.len4
	cmp	r11d,8
	je	.len8
	cmp	r11d,10
	je	.len10
	cmp	r11d,12
	je	.len12
	cmp	r11d,13
	je	.len13
	cmp	r11d,14
	je	.len14
	cmp	r11d,15
	je	.len15
	cmp	r11d,17
	je	.len17
.ignore:
	xor	eax,eax
	ret

.len4:
	mov	eax,[r10]
	or	eax,0x20202020
	cmp	eax,'host'
	jne	.ignore
	inc	dword [req_hosts]
	cmp	dword [req_hosts],1
	ja	.bad
	jmp	.ignore

.len8:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'if-match'
	cmp	rax,rdx
	jne	.ignore
	mov	[req_if_match],r12
	mov	[req_if_match_len],r13d
	jmp	.ignore

.len10:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'connecti'
	cmp	rax,rdx
	jne	.ignore
	movzx	eax,word [r10+8]
	or	eax,0x2020
	cmp	eax,'on'
	jne	.ignore
	jmp	connection_tokens

.len12:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'content-'
	cmp	rax,rdx
	jne	.ignore
	mov	eax,[r10+8]
	or	eax,0x20202020
	cmp	eax,'type'
	jne	.ignore
	mov	[req_ctype],r12
	mov	[req_ctype_len],r13d
	jmp	.ignore

.len13:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'authoriz'
	cmp	rax,rdx
	jne	.ignore
	mov	rax,[r10+5]
	or	rax,rcx
	mov	rdx,'rization'
	cmp	rax,rdx
	jne	.ignore
	mov	[req_auth],r12
	mov	[req_auth_len],r13d
	jmp	.ignore

.len14:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'content-'
	cmp	rax,rdx
	jne	.ignore
	mov	rax,[r10+6]
	or	rax,rcx
	mov	rdx,'t-length'
	cmp	rax,rdx
	jne	.ignore
	test	dword [req_flags],RQ_HAS_LENGTH
	jnz	.bad
	or	dword [req_flags],RQ_HAS_LENGTH
	; 1 to 9 digits, nothing else.
	test	r13d,r13d
	jz	.bad
	cmp	r13d,9
	ja	.too_large
	xor	eax,eax
	xor	ecx,ecx
.digit:
	movzx	edx,byte [r12+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,r13d
	jb	.digit
	mov	[req_length],eax
	jmp	.ignore

.len15:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'x-forwar'
	cmp	rax,rdx
	jne	.ignore
	mov	rax,[r10+7]
	or	rax,rcx
	mov	rdx,'rded-for'
	cmp	rax,rdx
	jne	.ignore
	mov	[req_xff],r12
	mov	[req_xff_len],r13d
	jmp	.ignore

.len17:
	mov	rax,[r10]
	or	rax,rcx
	mov	rdx,'transfer'
	cmp	rax,rdx
	jne	.ignore
	mov	rax,[r10+8]
	or	rax,rcx
	mov	rdx,'-encodin'
	cmp	rax,rdx
	jne	.ignore
	mov	al,[r10+16]
	or	al,0x20
	cmp	al,'g'
	jne	.ignore
	mov	eax,ST_501
	ret

.too_large:
	mov	eax,ST_413
	ret
.bad:
	mov	eax,ST_400
	ret

; Connection header: comma separated tokens; only "close" and "keep-alive"
; matter. r12 = value, r13 = length. eax = 0. Preserves rsi: it is the
; header loop's cursor.
connection_tokens:
	push	rsi
	call	.scan
	pop	rsi
	xor	eax,eax
	ret
.scan:
	mov	rsi,r12
	lea	rdi,[r12+r13]
.skip:
	cmp	rsi,rdi
	jae	.done
	mov	al,[rsi]
	cmp	al,' '
	je	.skip_next
	cmp	al,9
	je	.skip_next
	cmp	al,','
	jne	.token
.skip_next:
	inc	rsi
	jmp	.skip
.token:
	mov	rdx,rsi
.token_char:
	cmp	rsi,rdi
	jae	.token_end
	mov	al,[rsi]
	cmp	al,','
	je	.token_end
	cmp	al,' '
	je	.token_end
	cmp	al,9
	je	.token_end
	inc	rsi
	jmp	.token_char
.token_end:
	mov	rcx,rsi
	sub	rcx,rdx
	cmp	ecx,5
	jne	.keep_alive
	mov	eax,[rdx]
	or	eax,0x20202020
	cmp	eax,'clos'
	jne	.skip
	mov	al,[rdx+4]
	or	al,0x20
	cmp	al,'e'
	jne	.skip
	or	dword [req_flags],RQ_CLOSE
	jmp	.skip
.keep_alive:
	cmp	ecx,10
	jne	.skip
	mov	rax,[rdx]
	mov	rcx,0x2020202020202020
	or	rax,rcx
	mov	rcx,'keep-ali'
	cmp	rax,rcx
	jne	.skip
	movzx	eax,word [rdx+8]
	or	eax,0x2020
	cmp	eax,'ve'
	jne	.skip
	or	dword [req_flags],RQ_KEEPALIVE
	jmp	.skip
.done:
	xor	eax,eax
	ret
