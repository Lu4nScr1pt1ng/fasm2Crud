; Notes of the signed-in user (Authorization: Bearer <access token>).
;
;   GET    /v1/notes?limit=&cursor=          200 {"items":[summary],"next_cursor"}
;   POST   /v1/notes       {"title","body"?}   201 note, Location, ETag
;   GET    /v1/notes/{id}                      200 note, ETag
;   PATCH  /v1/notes/{id}  {"title"?,"body"?}  200 note, ETag; needs If-Match
;   DELETE /v1/notes/{id}                      204; needs If-Match
;
; note    = {"id","title","body","version","created_at","updated_at"}
; summary = {"id","title","version","updated_at"}
; Times are RFC 3339 in UTC with microseconds.
;
; The ETag is the version, "<n>". PATCH and DELETE need If-Match with the
; current one: 428 without it, 412 (with the current ETag) when it is
; stale, so concurrent writers never lose each other's updates; the check
; and the write are one statement. Notes of other users are 404.
;
; Sizes: title 1..200 bytes and body up to 3000 bytes of UTF-8, with no
; control characters but tab, LF and CR. Escaped, a whole note response
; then fits in NOTE_RESP_MAX, and a notes request waits until the output
; buffer has that much room (route_output_need). Pages are keyset, newest
; first: "cursor" is the last id seen, "limit" 1..50 (default 20). A page
; may hold fewer than "limit" items when the output buffer is full;
; next_cursor is null only at the end.

NOTE_TITLE_MAX	= 200
NOTE_BODY_MAX	= 3000
NOTES_LIMIT	= 20
NOTES_LIMIT_MAX	= 50
NOTE_RESP_MAX	= 7168		; headers + the largest escaped note
NOTE_HDR_ROOM	= 384		; status line, headers, ETag, Location
NOTE_OUT_CAP	= NOTE_RESP_MAX - NOTE_HDR_ROOM
SUMMARY_MAX	= 576		; largest escaped summary
LIST_TAIL	= 64		; '],"next_cursor":"<id>"}'

cstring name_title, 'title'
cstring name_body, 'body'
cstring allow_notes, 'Allow: GET, POST',13,10
cstring allow_note, 'Allow: GET, PATCH, DELETE',13,10
cstring hdr_www_bearer, 'WWW-Authenticate: Bearer',13,10

rodata
	align 8
	spec_note:
		dq name_title
		dd name_title.len, NOTE_TITLE_MAX
		dq name_body
		dd name_body.len, NOTE_BODY_MAX
end rodata

bss
	align 8
	g_note_params:	rb 5 * 16
	g_note_uid:	rb 36		; signed-in user, UUID text
	g_note_id:	rb 36		; note in the path
	g_note_cursor:	rb 36
	g_note_ver:	rb 12		; If-Match version, digits
	g_note_ver_len	dd ?
	g_note_limit	dd ?
	g_note_has_cursor dd ?
	g_note_num:	rb 12
	g_note_hdr:	rb 128
	g_note_out:	rb NOTE_OUT_CAP
end bss

; g_note_params[index] = ptr, len (clobbers rax).
macro note_param index*, ptr*, len*
	lea	rax,[ptr]
	mov	[g_note_params + (index) * 16],rax
	mov	dword [g_note_params + (index) * 16 + 8],len
end macro

; r12 = connection, rsi = path ("/v1/notes..."), eax = its length.
notes_route:
	cmp	eax,9
	je	.collection
	cmp	eax,46
	jne	.not_found
	cmp	byte [rsi+9],'/'
	jne	.not_found
	add	rsi,10
	sub	rsp,24
	push	rsi
	lea	rdi,[rsp+8]
	call	uuid_parse
	pop	rsi
	lea	rsp,[rsp+24]			; keeps CF
	jc	.not_found
	lea	rdi,[g_note_id]
	mov	ecx,36
	rep	movsb
	mov	eax,[req_method]
	cmp	eax,M_GET
	je	note_get
	cmp	eax,M_PATCH
	je	note_patch
	cmp	eax,M_DELETE
	je	note_delete
	lea	rcx,[allow_note]
	mov	r8d,allow_note.len
	jmp	.not_allowed
.collection:
	mov	eax,[req_method]
	cmp	eax,M_GET
	je	notes_list
	cmp	eax,M_POST
	je	note_create
	lea	rcx,[allow_notes]
	mov	r8d,allow_notes.len
.not_allowed:
	mov	eax,ST_405
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_405
	jmp	respond
.not_found:
	mov	edi,ST_404
	jmp	respond_status

; The signed-in user into g_note_uid. CF when there is none (401 sent).
note_auth:
	sub	rsp,24
	mov	rdi,rsp
	call	request_bearer
	jc	.unauthorized
	mov	rsi,rsp
	lea	rdi,[g_note_uid]
	call	uuid_format
	add	rsp,24
	clc
	ret
.unauthorized:
	add	rsp,24
	mov	eax,ST_401
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_401
	lea	rcx,[hdr_www_bearer]
	mov	r8d,hdr_www_bearer.len
	call	respond
	stc
	ret

; If-Match: "<version>" into g_note_ver. eax = 0, ST_428 when absent, or
; ST_412 when it cannot match (weak, a list, "*", leading zeros, ...).
note_if_match:
	mov	rsi,[req_if_match]
	mov	ecx,[req_if_match_len]
	test	ecx,ecx
	jz	.missing
	cmp	ecx,3
	jb	.stale
	cmp	ecx,11
	ja	.stale
	cmp	byte [rsi],'"'
	jne	.stale
	cmp	byte [rsi+rcx-1],'"'
	jne	.stale
	inc	rsi
	sub	ecx,2
	cmp	byte [rsi],'0'
	je	.stale
	mov	[g_note_ver_len],ecx
	xor	edx,edx
.digit:
	movzx	eax,byte [rsi+rdx]
	lea	r8d,[rax-'0']
	cmp	r8d,9
	ja	.stale
	mov	[g_note_ver+rdx],al
	inc	edx
	cmp	edx,ecx
	jb	.digit
	xor	eax,eax
	ret
.missing:
	mov	eax,ST_428
	ret
.stale:
	mov	eax,ST_412
	ret

; rsi = text, edx = length: CF when it holds a control character other
; than tab, LF and CR (the JSON decoder already refused bad UTF-8 and NUL).
note_text_ok:
	test	edx,edx
	jz	.ok
.byte:
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,0x20
	jae	.next
	cmp	al,9
	je	.next
	cmp	al,10
	je	.next
	cmp	al,13
	jne	.bad
.next:
	dec	edx
	jnz	.byte
.ok:
	clc
	ret
.bad:
	stc
	ret

; Parse and check a note body (spec_note). esi = 1 when the title is
; required. eax = 0, or the ST_xxx to answer.
note_body:
	push	rsi
	call	json_content_type
	pop	rsi
	test	eax,eax
	jz	.media_type
	push	rsi
	lea	rdi,[spec_note]
	mov	esi,2
	call	json_body_parse
	pop	rsi
	test	eax,eax
	jnz	.done
	mov	eax,[g_auth_vals+JV_PRESENT]
	or	eax,[g_auth_vals+JV_SIZE+JV_PRESENT]
	jz	.invalid			; nothing to write
	cmp	dword [g_auth_vals+JV_PRESENT],0
	jne	.title
	test	esi,esi
	jnz	.invalid
	jmp	.body
.title:
	mov	edx,[g_auth_vals+JV_LEN]
	test	edx,edx
	jz	.invalid
	mov	rsi,[g_auth_vals+JV_PTR]
	call	note_text_ok
	jc	.invalid
.body:
	cmp	dword [g_auth_vals+JV_SIZE+JV_PRESENT],0
	je	.ok
	mov	rsi,[g_auth_vals+JV_SIZE+JV_PTR]
	mov	edx,[g_auth_vals+JV_SIZE+JV_LEN]
	call	note_text_ok
	jc	.invalid
.ok:
	xor	eax,eax
.done:
	ret
.invalid:
	mov	eax,ST_422
	ret
.media_type:
	mov	eax,ST_415
	ret

; Parameter slot ecx (0..4) from a decoded member (JV entry at rsi), or
; NULL when the member is absent.
note_member_param:
	shl	ecx,4
	cmp	dword [rsi+JV_PRESENT],0
	je	.null
	mov	rax,[rsi+JV_PTR]
	mov	[g_note_params+rcx],rax
	mov	eax,[rsi+JV_LEN]
	mov	[g_note_params+rcx+8],eax
	ret
.null:
	mov	qword [g_note_params+rcx],0
	mov	dword [g_note_params+rcx+8],-1
	ret

; edi = STMT_xxx, esi = CONT_xxx, ecx = parameter count (g_note_params).
note_query:
	lea	rdx,[g_note_params]
	xor	r8d,r8d
	call	db_query
	test	eax,eax
	jnz	respond_db_unavailable
	ret

; ---------------------------------------------------------------- handlers

note_create:
	call	note_auth
	jc	.done
	mov	esi,1
	call	note_body
	test	eax,eax
	jnz	.status
	note_param 0, g_note_uid, 36
	lea	rsi,[g_auth_vals]
	mov	ecx,1
	call	note_member_param
	lea	rsi,[g_auth_vals+JV_SIZE]
	mov	ecx,2
	call	note_member_param
	mov	edi,STMT_NOTE_INSERT
	mov	esi,CONT_NOTE_CREATED
	mov	ecx,3
	jmp	note_query
.status:
	mov	edi,eax
	jmp	respond_status
.done:
	ret

note_get:
	call	note_auth
	jc	.done
	note_param 0, g_note_id, 36
	note_param 1, g_note_uid, 36
	mov	edi,STMT_NOTE_GET
	mov	esi,CONT_NOTE_GET
	mov	ecx,2
	jmp	note_query
.done:
	ret

note_patch:
	call	note_auth
	jc	.done
	call	note_if_match
	test	eax,eax
	jnz	.status
	xor	esi,esi
	call	note_body
	test	eax,eax
	jnz	.status
	note_param 0, g_note_id, 36
	note_param 1, g_note_uid, 36
	mov	ecx,[g_note_ver_len]
	note_param 2, g_note_ver, ecx
	lea	rsi,[g_auth_vals]
	mov	ecx,3
	call	note_member_param
	lea	rsi,[g_auth_vals+JV_SIZE]
	mov	ecx,4
	call	note_member_param
	mov	edi,STMT_NOTE_UPDATE
	mov	esi,CONT_NOTE_UPDATED
	mov	ecx,5
	jmp	note_query
.status:
	mov	edi,eax
	jmp	respond_status
.done:
	ret

note_delete:
	call	note_auth
	jc	.done
	call	note_if_match
	test	eax,eax
	jnz	.status
	note_param 0, g_note_id, 36
	note_param 1, g_note_uid, 36
	mov	ecx,[g_note_ver_len]
	note_param 2, g_note_ver, ecx
	mov	edi,STMT_NOTE_DELETE
	mov	esi,CONT_NOTE_DELETED
	mov	ecx,3
	jmp	note_query
.status:
	mov	edi,eax
	jmp	respond_status
.done:
	ret

notes_list:
	call	note_auth
	jc	.done
	call	notes_query
	jc	.bad_query
	; The continuation needs the page size: keep it on the connection.
	mov	eax,[g_note_limit]
	mov	[r12+C_AUX],eax
	inc	eax
	lea	rdi,[g_note_num]
	call	write_u32
	lea	rax,[g_note_num]
	sub	rdi,rax
	note_param 0, g_note_uid, 36
	note_param 1, g_note_num, edi
	note_param 2, g_note_cursor, 36
	mov	edi,STMT_NOTES_PAGE
	mov	ecx,2
	cmp	dword [g_note_has_cursor],0
	je	@f
	mov	edi,STMT_NOTES_PAGE_AFTER
	mov	ecx,3
@@:
	mov	esi,CONT_NOTES_PAGE
	jmp	note_query
.bad_query:
	mov	edi,ST_400
	jmp	respond_status
.done:
	ret

; Query string: "limit=<1..50>" and "cursor=<uuid>", each at most once,
; nothing else. Sets g_note_limit, g_note_cursor, g_note_has_cursor.
; CF when it is not such a query.
notes_query:
	push	rbx
	mov	dword [g_note_limit],NOTES_LIMIT
	mov	dword [g_note_has_cursor],0
	xor	ebx,ebx				; 1: limit seen, 2: cursor seen
	mov	rsi,[req_query]
	mov	ecx,[req_query_len]
	lea	r9,[rsi+rcx]
.pair:
	cmp	rsi,r9
	jae	.ok
	; key
	mov	rdx,rsi
@@:
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'&'
	je	.bad
	cmp	byte [rsi],'='
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	r8,rsi
	sub	r8,rdx				; key length
	inc	rsi
	; value: rsi .. r10
	mov	r10,rsi
@@:
	cmp	r10,r9
	jae	@f
	cmp	byte [r10],'&'
	je	@f
	inc	r10
	jmp	@b
@@:
	mov	rcx,r10
	sub	rcx,rsi				; value length
	cmp	r8,5
	je	.limit
	cmp	r8,6
	jne	.bad
	cmp	dword [rdx],'curs'
	jne	.bad
	cmp	word [rdx+4],'or'
	jne	.bad
	test	ebx,2
	jnz	.bad
	or	ebx,2
	cmp	ecx,36
	jne	.bad
	push	rsi
	push	r9
	push	r10
	sub	rsp,24
	lea	rdi,[rsp]
	call	uuid_parse
	lea	rsp,[rsp+24]
	pop	r10
	pop	r9
	pop	rsi
	jc	.bad
	lea	rdi,[g_note_cursor]
	mov	ecx,36
	rep	movsb
	mov	dword [g_note_has_cursor],1
	jmp	.next
.limit:
	cmp	dword [rdx],'limi'
	jne	.bad
	cmp	byte [rdx+4],'t'
	jne	.bad
	test	ebx,1
	jnz	.bad
	or	ebx,1
	test	ecx,ecx
	jz	.bad
	cmp	ecx,2
	ja	.bad
	cmp	byte [rsi],'0'
	je	.bad
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	dec	ecx
	jnz	@b
	cmp	eax,NOTES_LIMIT_MAX
	ja	.bad
	mov	[g_note_limit],eax
.next:
	mov	rsi,r10
	cmp	rsi,r9
	jae	.ok
	inc	rsi				; '&'
	jmp	.pair
.ok:
	pop	rbx
	clc
	ret
.bad:
	pop	rbx
	stc
	ret

; ---------------------------------------------------------------- replies

; Write a JSON string body (no quotes): rdi = destination, rsi = UTF-8
; text, edx = length. rdi is advanced. At most 2 bytes per input byte for
; the text notes accept (6 for other control characters).
json_write_string:
	test	edx,edx
	jz	.done
.byte:
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'"'
	je	.escape
	cmp	al,'\'
	je	.escape
	cmp	al,0x20
	jb	.control
	mov	[rdi],al
	inc	rdi
	jmp	.next
.escape:
	mov	byte [rdi],'\'
	mov	[rdi+1],al
	add	rdi,2
	jmp	.next
.control:
	mov	cl,'n'
	cmp	al,10
	je	.short
	mov	cl,'r'
	cmp	al,13
	je	.short
	mov	cl,'t'
	cmp	al,9
	je	.short
	mov	dword [rdi],'\u00'
	mov	ecx,eax
	shr	ecx,4
	mov	cl,[hex_lower+rcx]
	mov	[rdi+4],cl
	and	eax,15
	mov	al,[hex_lower+rax]
	mov	[rdi+5],al
	add	rdi,6
	jmp	.next
.short:
	mov	byte [rdi],'\'
	mov	[rdi+1],cl
	add	rdi,2
.next:
	dec	edx
	jnz	.byte
.done:
	ret

; Copy column ecx of the DataRow at r13 to rdi, raw or as JSON string
; text. Nothing is written for NULL.
note_col_raw:
	push	rdi
	mov	rsi,r13
	call	pg_field
	pop	rdi
	jc	.done
	mov	rsi,rax
	mov	ecx,edx
	rep	movsb
.done:
	ret

note_col_text:
	push	rdi
	mov	rsi,r13
	call	pg_field
	pop	rdi
	jc	.done
	mov	rsi,rax
	jmp	json_write_string
.done:
	ret

; rdi = destination, rsi = DataRow (id, title, body, version, created_at,
; updated_at). rdi is advanced past the object.
write_note:
	push	r13
	mov	r13,rsi
	put_lit '{"id":"'
	xor	ecx,ecx
	call	note_col_raw
	put_lit '","title":"'
	mov	ecx,1
	call	note_col_text
	put_lit '","body":"'
	mov	ecx,2
	call	note_col_text
	put_lit '","version":'
	mov	ecx,3
	call	note_col_raw
	put_lit ',"created_at":"'
	mov	ecx,4
	call	note_col_raw
	put_lit '","updated_at":"'
	mov	ecx,5
	call	note_col_raw
	put_lit '"}'
	pop	r13
	ret

; rdi = destination, rsi = DataRow (id, title, version, updated_at).
write_summary:
	push	r13
	mov	r13,rsi
	put_lit '{"id":"'
	xor	ecx,ecx
	call	note_col_raw
	put_lit '","title":"'
	mov	ecx,1
	call	note_col_text
	put_lit '","version":'
	mov	ecx,2
	call	note_col_raw
	put_lit ',"updated_at":"'
	mov	ecx,3
	call	note_col_raw
	put_lit '"}'
	pop	r13
	ret

; 'ETag: "<version>"' into g_note_hdr from rsi (text), edx = length.
; rdi = end of the header lines.
note_etag:
	push	rsi
	push	rdx
	lea	rdi,[g_note_hdr]
	put_lit 'ETag: "'
	pop	rcx
	pop	rsi
	rep	movsb
	put_lit '"',13,10
	ret

; edi = ST_200 or ST_201, rsi = DataRow of a note.
respond_note:
	push	r13
	push	r14
	mov	r14d,edi
	mov	r13,rsi
	lea	rdi,[g_note_out]
	call	write_note
	push	rdi
	mov	rsi,r13
	mov	ecx,3
	call	pg_field
	mov	rsi,rax
	call	note_etag
	cmp	r14d,ST_201
	jne	@f
	put_lit 'Location: /v1/notes/'
	xor	ecx,ecx
	call	note_col_raw
	put_lit 13,10
@@:
	mov	r8,rdi
	lea	rcx,[g_note_hdr]
	sub	r8,rcx
	pop	rdx
	lea	rsi,[g_note_out]
	sub	rdx,rsi
	mov	edi,r14d
	pop	r14
	pop	r13
	jmp	respond

; 412 with the current ETag: rax = version text, edx = length.
respond_stale:
	mov	rsi,rax
	call	note_etag
	mov	r8,rdi
	lea	rcx,[g_note_hdr]
	sub	r8,rcx
	mov	eax,ST_412
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_412
	jmp	respond

; eax = PGR_xxx (not PGR_OK).
respond_query_failed:
	cmp	eax,PGR_SQL_ERROR
	jne	respond_db_unavailable
	mov	edi,ST_500
	jmp	respond_status

; Continuations: eax = PGR_xxx, rsi/rdx = reply.

cont_note_created:
	cmp	eax,PGR_OK
	je	.created
	cmp	eax,PGR_SQL_ERROR
	jne	respond_db_unavailable
	; foreign_key_violation: the account is gone, the token outlived it.
	cmp	dword [g_pg_sqlstate],'2350'
	jne	respond_query_failed
	cmp	byte [g_pg_sqlstate+4],'3'
	jne	respond_query_failed
	mov	edi,ST_401
	jmp	respond_status
.created:
	call	pg_find_row
	jc	.error
	mov	edi,ST_201
	jmp	respond_note
.error:
	mov	edi,ST_500
	jmp	respond_status

cont_note_get:
	cmp	eax,PGR_OK
	jne	respond_query_failed
	call	pg_find_row
	jc	.not_found
	mov	edi,ST_200
	jmp	respond_note
.not_found:
	mov	edi,ST_404
	jmp	respond_status

; Row: the note (NULL when the version did not match), current version.
cont_note_updated:
	cmp	eax,PGR_OK
	jne	respond_query_failed
	call	pg_find_row
	jc	.not_found
	xor	ecx,ecx
	call	pg_field
	jc	.stale
	mov	edi,ST_200
	jmp	respond_note
.stale:
	mov	ecx,6
	call	pg_field
	jc	.error
	jmp	respond_stale
.not_found:
	mov	edi,ST_404
	jmp	respond_status
.error:
	mov	edi,ST_500
	jmp	respond_status

; Row: current version, rows deleted.
cont_note_deleted:
	cmp	eax,PGR_OK
	jne	respond_query_failed
	call	pg_find_row
	jc	.not_found
	mov	ecx,1
	call	pg_field
	jc	.error
	cmp	edx,1
	jne	.error
	cmp	byte [rax],'1'
	je	respond_no_content
	xor	ecx,ecx
	call	pg_field
	jc	.error
	jmp	respond_stale
.not_found:
	mov	edi,ST_404
	jmp	respond_status
.error:
	mov	edi,ST_500
	jmp	respond_status

; Up to limit + 1 summary rows; the page size is in C_AUX.
cont_notes_page:
	cmp	eax,PGR_OK
	jne	respond_query_failed
	push	rbx
	push	rbp
	push	r13
	push	r14
	push	r15
	mov	r13,rsi				; next message
	mov	r14,rdx				; end
	mov	ebp,[r12+C_AUX]
	xor	r15d,r15d			; items written
	xor	ebx,ebx				; last row written
	lea	rdi,[g_note_out]
	put_lit '{"items":['
.row:
	mov	rsi,r13
	mov	rdx,r14
	call	pg_find_row
	jc	.end
	cmp	r15d,ebp
	jae	.more				; a row past the page: more follow
	lea	rax,[g_note_out + NOTE_OUT_CAP - SUMMARY_MAX - LIST_TAIL]
	cmp	rdi,rax
	ja	.more				; no room for another: stop here
	test	r15d,r15d
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	rbx,rsi
	call	write_summary
	inc	r15d
	mov	rsi,rbx
	call	pg_skip_message
	mov	r13,rsi
	jmp	.row
.more:
	test	rbx,rbx
	jz	.end
	put_lit '],"next_cursor":"'
	mov	r13,rbx
	xor	ecx,ecx
	call	note_col_raw
	put_lit '"}'
	jmp	.send
.end:
	put_lit '],"next_cursor":null}'
.send:
	lea	rsi,[g_note_out]
	mov	rdx,rdi
	sub	rdx,rsi
	pop	r15
	pop	r14
	pop	r13
	pop	rbp
	pop	rbx
	mov	edi,ST_200
	xor	ecx,ecx
	xor	r8d,r8d
	jmp	respond
