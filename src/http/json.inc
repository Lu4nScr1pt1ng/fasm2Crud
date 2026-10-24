; Strict JSON for request bodies: one flat object whose members are all
; strings (RFC 8259). Escapes are decoded, UTF-8 is validated, and
; anything outside the schema is rejected rather than ignored: unknown
; members, duplicates, non-string values. U+0000 and lone surrogates are
; refused as invalid. Values are decoded into caller-provided scratch.
;
; The whole body is always checked for syntax: malformed JSON is 400 even
; when a schema problem shows up first, which is then 422.

JSON_OK		= 0
JSON_SYNTAX	= 1		; not valid JSON: 400
JSON_SCHEMA	= 2		; valid JSON, wrong shape: 422

; Field spec entry (16 bytes): dq name, dd name length, dd max value bytes.
JF_NAME		= 0
JF_NAME_LEN	= 8
JF_MAX		= 12
JF_SIZE		= 16

; Result per field (16 bytes): dq value, dd length, dd present.
JV_PTR		= 0
JV_LEN		= 8
JV_PRESENT	= 12
JV_SIZE		= 16

; Parse job.
JJ_SPEC		= 0
JJ_OUT		= 8
JJ_SCRATCH	= 16
JJ_BODY		= 24
JJ_FIELDS	= 32
JJ_SCRATCH_CAP	= 36
JJ_BODY_LEN	= 40
JJ_SIZE		= 48

JSON_MAX_KEY	= 32
JSON_MAX_DEPTH	= 32
JSON_SCHEMA_FLAG = JSON_MAX_KEY		; stack slot: a schema rule was broken

; rdi = job. eax = JSON_xxx; on JSON_OK the results are filled in.
json_parse_object:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,JSON_MAX_KEY + 8
	mov	rbx,rdi
	; Clear the results.
	mov	rdi,[rbx+JJ_OUT]
	mov	ecx,[rbx+JJ_FIELDS]
	shl	ecx,4
	xor	eax,eax
	rep	stosb
	mov	rsi,[rbx+JJ_BODY]
	mov	r15d,[rbx+JJ_BODY_LEN]
	add	r15,rsi
	mov	r14,[rbx+JJ_SCRATCH]
	mov	r13d,[rbx+JJ_SCRATCH_CAP]
	add	r13,r14
	mov	dword [rsp+JSON_SCHEMA_FLAG],0

	call	json_ws
	cmp	rsi,r15
	jae	.syntax
	cmp	byte [rsi],'{'
	jne	.not_object
	inc	rsi
	call	json_ws
	cmp	rsi,r15
	jae	.syntax
	cmp	byte [rsi],'}'
	je	.close

.member:
	cmp	rsi,r15
	jae	.syntax
	cmp	byte [rsi],'"'
	jne	.syntax
	inc	rsi
	mov	rdi,rsp
	mov	ecx,JSON_MAX_KEY
	call	json_string
	cmp	rax,-1
	je	.syntax
	mov	r12,rax				; key length, or -2 when too long
	call	json_ws
	cmp	rsi,r15
	jae	.syntax
	cmp	byte [rsi],':'
	jne	.syntax
	inc	rsi
	call	json_ws

	; Which field is it?
	test	r12,r12
	js	.skip_member
	xor	ebp,ebp
.find:
	cmp	ebp,[rbx+JJ_FIELDS]
	jae	.skip_member			; unknown member
	mov	rax,[rbx+JJ_SPEC]
	mov	ecx,ebp
	shl	ecx,4
	add	rax,rcx
	cmp	[rax+JF_NAME_LEN],r12d
	jne	.next_field
	push	rsi
	mov	rsi,[rax+JF_NAME]
	mov	rdi,rsp
	add	rdi,8
	mov	ecx,r12d
	repe	cmpsb
	pop	rsi
	je	.found
.next_field:
	inc	ebp
	jmp	.find
.found:
	mov	rdi,[rbx+JJ_OUT]
	mov	eax,ebp
	shl	eax,4
	add	rdi,rax
	cmp	dword [rdi+JV_PRESENT],0
	jne	.skip_member			; duplicate member
	cmp	rsi,r15
	jae	.syntax
	cmp	byte [rsi],'"'
	jne	.skip_member			; not a string
	inc	rsi
	push	rdi
	mov	rax,[rbx+JJ_SPEC]
	mov	ecx,ebp
	shl	ecx,4
	mov	ecx,[rax+rcx+JF_MAX]
	mov	rax,r13
	sub	rax,r14
	cmp	rcx,rax
	cmova	rcx,rax				; never past the scratch area
	mov	rdi,r14
	call	json_string
	pop	rdi
	cmp	rax,-1
	je	.syntax
	test	rax,rax
	js	.too_long
	mov	[rdi+JV_PTR],r14
	mov	[rdi+JV_LEN],eax
	mov	dword [rdi+JV_PRESENT],1
	add	r14,rax
.after_value:
	call	json_ws
	cmp	rsi,r15
	jae	.syntax
	lodsb
	cmp	al,'}'
	je	.end
	cmp	al,','
	jne	.syntax
	call	json_ws
	jmp	.member

.close:
	inc	rsi
.end:
	call	json_ws
	cmp	rsi,r15
	jne	.syntax
	mov	eax,JSON_OK
	cmp	dword [rsp+JSON_SCHEMA_FLAG],0
	je	.done
	mov	eax,JSON_SCHEMA
	jmp	.done

	; Schema problems are remembered; parsing goes on to check the syntax.
.too_long:
	mov	dword [rsp+JSON_SCHEMA_FLAG],1
	jmp	.after_value
.skip_member:
	mov	dword [rsp+JSON_SCHEMA_FLAG],1
	xor	r10d,r10d
	call	json_skip_value
	jc	.syntax
	jmp	.after_value
.not_object:
	mov	dword [rsp+JSON_SCHEMA_FLAG],1
	xor	r10d,r10d
	call	json_skip_value
	jc	.syntax
	jmp	.end
.syntax:
	mov	eax,JSON_SYNTAX
	jmp	.done
.schema:
	mov	eax,JSON_SCHEMA
.done:
	add	rsp,JSON_MAX_KEY + 8
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; Skip one JSON value of any type. rsi = cursor, r15 = end,
; r10d = nesting depth. CF on a syntax error.
json_skip_value:
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,'"'
	je	.string
	cmp	al,'{'
	je	.object
	cmp	al,'['
	je	.array
	cmp	al,'t'
	je	.true
	cmp	al,'f'
	je	.false
	cmp	al,'n'
	je	.null
	cmp	al,'-'
	je	.number
	lea	ecx,[rax-'0']
	cmp	ecx,9
	jbe	.number
.bad:
	stc
	ret

.string:
	inc	rsi
	push	r10				; json_string uses r8-r10
	xor	ecx,ecx
	mov	rdi,rsi				; capacity 0: nothing is written
	call	json_string
	pop	r10
	cmp	rax,-1
	je	.bad
	clc
	ret

.object:
	inc	r10d
	cmp	r10d,JSON_MAX_DEPTH
	ja	.bad
	inc	rsi
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	cmp	byte [rsi],'}'
	je	.object_end
.object_member:
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	cmp	byte [rsi],'"'
	jne	.bad
	call	.string
	jc	.bad
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	cmp	byte [rsi],':'
	jne	.bad
	inc	rsi
	call	json_skip_value
	jc	.bad
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	lodsb
	cmp	al,','
	je	.object_member
	cmp	al,'}'
	jne	.bad
	dec	r10d
	clc
	ret
.object_end:
	inc	rsi
	dec	r10d
	clc
	ret

.array:
	inc	r10d
	cmp	r10d,JSON_MAX_DEPTH
	ja	.bad
	inc	rsi
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	cmp	byte [rsi],']'
	je	.array_end
.element:
	call	json_skip_value
	jc	.bad
	call	json_ws
	cmp	rsi,r15
	jae	.bad
	lodsb
	cmp	al,','
	je	.element
	cmp	al,']'
	jne	.bad
	dec	r10d
	clc
	ret
.array_end:
	inc	rsi
	dec	r10d
	clc
	ret

.true:
	mov	eax,'true'
	jmp	.literal4
.null:
	mov	eax,'null'
.literal4:
	lea	rcx,[rsi+4]
	cmp	rcx,r15
	ja	.bad
	cmp	[rsi],eax
	jne	.bad
	add	rsi,4
	clc
	ret
.false:
	lea	rcx,[rsi+5]
	cmp	rcx,r15
	ja	.bad
	cmp	dword [rsi],'fals'
	jne	.bad
	cmp	byte [rsi+4],'e'
	jne	.bad
	add	rsi,5
	clc
	ret

	; -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
.number:
	cmp	byte [rsi],'-'
	jne	@f
	inc	rsi
@@:
	call	.digit
	jc	.bad
	cmp	byte [rsi-1],'0'
	jne	.integer
	call	.digit				; "0" must stand alone
	jnc	.bad
	jmp	.fraction
.integer:
	call	.digits
.fraction:
	cmp	rsi,r15
	jae	.number_done
	cmp	byte [rsi],'.'
	jne	.exponent
	inc	rsi
	call	.digit
	jc	.bad
	call	.digits
.exponent:
	cmp	rsi,r15
	jae	.number_done
	mov	al,[rsi]
	or	al,0x20
	cmp	al,'e'
	jne	.number_done
	inc	rsi
	cmp	rsi,r15
	jae	.bad
	mov	al,[rsi]
	cmp	al,'+'
	je	.sign
	cmp	al,'-'
	jne	.exponent_digits
.sign:
	inc	rsi
.exponent_digits:
	call	.digit
	jc	.bad
	call	.digits
.number_done:
	clc
	ret

; One digit at rsi (consumed), CF when there is none (nothing consumed).
.digit:
	cmp	rsi,r15
	jae	.no_digit
	movzx	eax,byte [rsi]
	sub	eax,'0'
	cmp	eax,9
	ja	.no_digit
	inc	rsi
	clc
	ret
.no_digit:
	stc
	ret
.digits:
	call	.digit
	jnc	.digits
	ret

; Skip insignificant whitespace. rsi = cursor, r15 = end.
json_ws:
	cmp	rsi,r15
	jae	.done
	mov	al,[rsi]
	cmp	al,' '
	je	.skip
	cmp	al,9
	je	.skip
	cmp	al,10
	je	.skip
	cmp	al,13
	jne	.done
.skip:
	inc	rsi
	jmp	json_ws
.done:
	ret

; Decode a string body. rsi = after the opening quote, r15 = end,
; rdi = destination, ecx = capacity. rsi ends after the closing quote.
; rax = decoded length, -1 on a syntax error, -2 when longer than ecx
; (the string is still parsed to its end, so the caller can go on).
json_string:
	push	rbx
	push	r12
	mov	r12,rdi
	lea	rbx,[rdi+rcx]			; capacity end
	xor	r8d,r8d				; overflowed
.char:
	cmp	rsi,r15
	jae	.syntax
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'"'
	je	.end
	cmp	al,'\'
	je	.escape
	cmp	al,0x20
	jb	.syntax
	cmp	al,0x80
	jae	.utf8
	call	.put
	jmp	.char

.escape:
	cmp	rsi,r15
	jae	.syntax
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'"'
	je	.literal
	cmp	al,'\'
	je	.literal
	cmp	al,'/'
	je	.literal
	mov	ecx,8
	cmp	al,'b'
	je	.control
	mov	ecx,12
	cmp	al,'f'
	je	.control
	mov	ecx,10
	cmp	al,'n'
	je	.control
	mov	ecx,13
	cmp	al,'r'
	je	.control
	mov	ecx,9
	cmp	al,'t'
	je	.control
	cmp	al,'u'
	jne	.syntax
	call	.hex4
	jc	.syntax
	mov	edx,eax
	cmp	edx,0xD800
	jb	.codepoint
	cmp	edx,0xDFFF
	ja	.codepoint
	cmp	edx,0xDBFF
	ja	.syntax				; lone low surrogate
	; High surrogate: a low one must follow.
	lea	rax,[rsi+6]
	cmp	rax,r15
	ja	.syntax
	cmp	word [rsi],'\u'
	jne	.syntax
	add	rsi,2
	push	rdx
	call	.hex4
	pop	rdx
	jc	.syntax
	cmp	eax,0xDC00
	jb	.syntax
	cmp	eax,0xDFFF
	ja	.syntax
	sub	edx,0xD800
	shl	edx,10
	sub	eax,0xDC00
	lea	edx,[rdx+rax+0x10000]
.codepoint:
	test	edx,edx
	jz	.syntax				; U+0000 is refused
	mov	eax,edx
	cmp	eax,0x80
	jb	.one
	cmp	eax,0x800
	jb	.two
	cmp	eax,0x10000
	jb	.three
	shr	eax,18
	or	al,0xF0
	call	.put
	mov	eax,edx
	shr	eax,12
	and	al,0x3F
	or	al,0x80
	call	.put
	jmp	.last2
.three:
	shr	eax,12
	or	al,0xE0
	call	.put
.last2:
	mov	eax,edx
	shr	eax,6
	and	al,0x3F
	or	al,0x80
	call	.put
	jmp	.last1
.two:
	shr	eax,6
	or	al,0xC0
	call	.put
.last1:
	mov	eax,edx
	and	al,0x3F
	or	al,0x80
.one:
	call	.put
	jmp	.char
.literal:
	call	.put
	jmp	.char
.control:
	mov	eax,ecx
	call	.put
	jmp	.char

	; Raw UTF-8 (RFC 3629): no overlong forms, no surrogates, <= U+10FFFF.
.utf8:
	mov	ecx,1				; continuation bytes
	mov	edx,0x80			; allowed range of the second byte
	mov	r9d,0xBF
	cmp	al,0xC2
	jb	.syntax
	cmp	al,0xDF
	jbe	.sequence
	mov	ecx,2
	cmp	al,0xE0
	jne	@f
	mov	edx,0xA0
	jmp	.sequence
@@:
	cmp	al,0xED
	jne	@f
	mov	r9d,0x9F
	jmp	.sequence
@@:
	cmp	al,0xEF
	jbe	.sequence
	mov	ecx,3
	cmp	al,0xF0
	jne	@f
	mov	edx,0x90
	jmp	.sequence
@@:
	cmp	al,0xF4
	ja	.syntax
	jne	.sequence
	mov	r9d,0x8F
.sequence:
	lea	r10,[rsi+rcx]
	cmp	r10,r15
	ja	.syntax
	movzx	r10d,byte [rsi]
	cmp	r10d,edx
	jb	.syntax
	cmp	r10d,r9d
	ja	.syntax
	call	.put				; lead byte
.continuation:
	movzx	eax,byte [rsi]
	mov	r10d,eax
	and	r10d,0xC0
	cmp	r10d,0x80
	jne	.syntax
	inc	rsi
	push	rcx
	call	.put
	pop	rcx
	dec	ecx
	jnz	.continuation
	jmp	.char

.end:
	mov	rax,rdi
	sub	rax,r12
	test	r8d,r8d
	jz	.done
	mov	rax,-2
	jmp	.done
.syntax:
	mov	rax,-1
.done:
	pop	r12
	pop	rbx
	ret

; Store al at rdi unless the capacity is exhausted (then flag r8d).
.put:
	cmp	rdi,rbx
	jae	.full
	mov	[rdi],al
	inc	rdi
	ret
.full:
	mov	r8d,1
	ret

; Four hex digits at rsi. eax = value, CF on error.
.hex4:
	lea	rax,[rsi+4]
	cmp	rax,r15
	ja	.hex_bad
	xor	eax,eax
	mov	ecx,4
.hex_digit:
	movzx	edx,byte [rsi]
	inc	rsi
	shl	eax,4
	sub	edx,'0'
	cmp	edx,9
	jbe	.hex_add
	or	edx,0x20			; 'A'-'0' | 0x20 = 'a'-'0'
	sub	edx,'a'-'0'
	cmp	edx,5
	ja	.hex_bad
	add	edx,10
.hex_add:
	or	eax,edx
	dec	ecx
	jnz	.hex_digit
	clc
	ret
.hex_bad:
	stc
	ret
