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
; Limits are the schema's: a title of 1..200 characters and a body of up
; to 4000, any Unicode text (control characters are escaped on output).
; Requests up to LARGE_CAP and responses of any size these limits allow
; are handled through large buffers (src/core/conn.inc); every response is
; measured exactly, then written once, in place. Pages are keyset, newest
; first: "cursor" is the last id seen, "limit" 1..50 (default 20), and a
; page always holds min(limit, what is left); next_cursor is null at the
; end.

NOTE_TITLE_CHARS = 200
NOTE_BODY_CHARS	= 4000
NOTES_LIMIT	= 20
NOTES_LIMIT_MAX	= 50

; Worst cases, checked against the buffers at assembly time. A character
; is at most 4 bytes of UTF-8, 6 bytes escaped in a response (\u001f) and
; 12 in a request (a surrogate pair, "\ud83d\ude00").
NOTE_REQUEST_MAX = IN_CAP + 64 + (NOTE_TITLE_CHARS + NOTE_BODY_CHARS) * 12
NOTE_JSON_MAX	= 160 + 36 + 10 + 2 * 27 + (NOTE_TITLE_CHARS + NOTE_BODY_CHARS) * 6
SUMMARY_JSON_MAX = 80 + 36 + 10 + 27 + NOTE_TITLE_CHARS * 6
PAGE_JSON_MAX	= 64 + NOTES_LIMIT_MAX * (SUMMARY_JSON_MAX + 1)
; One DataRow per column set: 7 bytes, 4 per column, the values.
PAGE_REPLY_MAX	= 128 + (NOTES_LIMIT_MAX + 1) * (7 + 4 * 4 + 36 + NOTE_TITLE_CHARS * 4 + 10 + 27)
assert NOTE_REQUEST_MAX <= LARGE_CAP
assert NOTE_JSON_MAX + RESP_HEAD_ROOM <= LARGE_CAP
assert PAGE_JSON_MAX + RESP_HEAD_ROOM <= LARGE_CAP
assert PAGE_REPLY_MAX < PG_RX_CAP
assert NOTE_TITLE_CHARS * 4 + NOTE_BODY_CHARS * 4 <= AUTH_SCRATCH

cstring name_title, 'title'
cstring name_body, 'body'
cstring allow_notes, 'Allow: GET, POST',13,10
cstring allow_note, 'Allow: GET, PATCH, DELETE',13,10
cstring hdr_www_bearer, 'WWW-Authenticate: Bearer',13,10

rodata
	align 8
	spec_note:
		dq name_title
		dd name_title.len, NOTE_TITLE_CHARS * 4
		dq name_body
		dd name_body.len, NOTE_BODY_CHARS * 4
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
end bss

; The fixed parts of the JSON, named so their lengths add up at assembly
; time.
cstring nj_id, '{"id":"'
cstring nj_title, '","title":"'
cstring nj_body, '","body":"'
cstring nj_version, '","version":'
cstring nj_created, ',"created_at":"'
cstring nj_updated, '","updated_at":"'
cstring nj_sum_updated, ',"updated_at":"'
cstring nj_end, '"}'
cstring nj_items, '{"items":['
cstring nj_cursor, '],"next_cursor":"'
cstring nj_no_cursor, '],"next_cursor":null}'
NOTE_FIXED = nj_id.len + nj_title.len + nj_body.len + nj_version.len + nj_created.len + nj_updated.len + nj_end.len
SUMMARY_FIXED = nj_id.len + nj_title.len + nj_version.len + nj_sum_updated.len + nj_end.len

macro put_str name*
	lea	rsi,[name]
	mov	ecx,name.len
	rep	movsb
end macro

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

; rsi = UTF-8 text (valid: the JSON decoder checked it), edx = length.
; eax = characters, as PostgreSQL's length() counts them.
utf8_chars:
	xor	eax,eax
	test	edx,edx
	jz	.done
.byte:
	movzx	ecx,byte [rsi]
	inc	rsi
	and	ecx,0xC0
	cmp	ecx,0x80			; continuation bytes do not count
	je	@f
	inc	eax
@@:
	dec	edx
	jnz	.byte
.done:
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
	mov	rsi,[g_auth_vals+JV_PTR]
	mov	edx,[g_auth_vals+JV_LEN]
	call	utf8_chars
	test	eax,eax
	jz	.invalid
	cmp	eax,NOTE_TITLE_CHARS
	ja	.invalid
.body:
	cmp	dword [g_auth_vals+JV_SIZE+JV_PRESENT],0
	je	.ok
	mov	rsi,[g_auth_vals+JV_SIZE+JV_PTR]
	mov	edx,[g_auth_vals+JV_SIZE+JV_LEN]
	call	utf8_chars
	cmp	eax,NOTE_BODY_CHARS
	ja	.invalid
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
; text, edx = length. rdi is advanced; json_string_len says by how much.
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

; Escaped length of rsi/edx, exactly as json_write_string writes it.
json_string_len:
	mov	eax,edx
	test	edx,edx
	jz	.done
.byte:
	movzx	ecx,byte [rsi]
	inc	rsi
	cmp	cl,'"'
	je	.two
	cmp	cl,'\'
	je	.two
	cmp	cl,0x20
	jae	.next
	cmp	cl,10
	je	.two
	cmp	cl,13
	je	.two
	cmp	cl,9
	je	.two
	add	eax,4				; \u00XX
.two:
	inc	eax
.next:
	dec	edx
	jnz	.byte
.done:
	ret

; Column ecx of the DataRow at r13: copy it to rdi, raw or as JSON string
; text (nothing for NULL); or add its raw or escaped length to r14d.
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

note_len_raw:
	mov	rsi,r13
	call	pg_field
	jc	.done
	add	r14d,edx
.done:
	ret

note_len_text:
	mov	rsi,r13
	call	pg_field
	jc	.done
	mov	rsi,rax
	call	json_string_len
	add	r14d,eax
.done:
	ret

; Lengths of the JSON objects below. r13 = DataRow; r14d += length.
note_measure:
	add	r14d,NOTE_FIXED
	xor	ecx,ecx
	call	note_len_raw
	mov	ecx,1
	call	note_len_text
	mov	ecx,2
	call	note_len_text
	mov	ecx,3
	call	note_len_raw
	mov	ecx,4
	call	note_len_raw
	mov	ecx,5
	jmp	note_len_raw

summary_measure:
	add	r14d,SUMMARY_FIXED
	xor	ecx,ecx
	call	note_len_raw
	mov	ecx,1
	call	note_len_text
	mov	ecx,2
	call	note_len_raw
	mov	ecx,3
	jmp	note_len_raw

; rdi = destination, r13 = DataRow (id, title, body, version, created_at,
; updated_at). rdi is advanced past the object.
write_note:
	put_str nj_id
	xor	ecx,ecx
	call	note_col_raw
	put_str nj_title
	mov	ecx,1
	call	note_col_text
	put_str nj_body
	mov	ecx,2
	call	note_col_text
	put_str nj_version
	mov	ecx,3
	call	note_col_raw
	put_str nj_created
	mov	ecx,4
	call	note_col_raw
	put_str nj_updated
	mov	ecx,5
	call	note_col_raw
	put_str nj_end
	ret

; rdi = destination, r13 = DataRow (id, title, version, updated_at).
write_summary:
	put_str nj_id
	xor	ecx,ecx
	call	note_col_raw
	put_str nj_title
	mov	ecx,1
	call	note_col_text
	put_str nj_version
	mov	ecx,2
	call	note_col_raw
	put_str nj_sum_updated
	mov	ecx,3
	call	note_col_raw
	put_str nj_end
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
	push	r15
	mov	r15d,edi
	mov	r13,rsi
	xor	r14d,r14d
	call	note_measure
	mov	edx,r14d
	call	respond_reserve
	jc	.done
	mov	rdi,rax
	call	write_note
	mov	rsi,r13
	mov	ecx,3
	call	pg_field
	mov	rsi,rax
	call	note_etag
	cmp	r15d,ST_201
	jne	@f
	put_lit 'Location: /v1/notes/'
	xor	ecx,ecx
	call	note_col_raw
	put_lit 13,10
@@:
	mov	r8,rdi
	lea	rcx,[g_note_hdr]
	sub	r8,rcx
	mov	edi,r15d
	mov	edx,r14d
	call	respond_built
.done:
	pop	r15
	pop	r14
	pop	r13
	ret

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

; Up to limit + 1 summary rows; the page size is in C_AUX. The page holds
; the first min(limit, rows); a row past the limit means more follow, and
; next_cursor is then the last id in the page. Measured, then written.
; [rsp] = last row of the page, [rsp+8] = more follow, [rsp+12] = written.
cont_notes_page:
	cmp	eax,PGR_OK
	jne	respond_query_failed
	push	rbx
	push	rbp
	push	r13
	push	r14
	push	r15
	sub	rsp,24
	mov	rbx,rsi				; first message
	mov	r15,rdx				; end
	mov	qword [rsp],0
	mov	dword [rsp+8],0
	xor	ebp,ebp				; items in the page
	mov	r14d,nj_items.len + nj_no_cursor.len
	mov	rsi,rbx
.measure:
	mov	rdx,r15
	call	pg_find_row
	jc	.measured
	cmp	ebp,[r12+C_AUX]
	jae	.more
	mov	r13,rsi
	mov	[rsp],rsi
	call	summary_measure
	inc	ebp
	mov	rsi,r13
	call	pg_skip_message
	jmp	.measure
.more:
	mov	dword [rsp+8],1
	add	r14d,nj_cursor.len + 36 + nj_end.len - nj_no_cursor.len
.measured:
	test	ebp,ebp
	jz	@f
	lea	r14d,[r14+rbp-1]		; commas
@@:
	mov	edx,r14d
	call	respond_reserve
	jc	.done
	mov	rdi,rax
	put_str nj_items
	mov	dword [rsp+12],0
	mov	rsi,rbx
.write:
	mov	eax,[rsp+12]
	cmp	eax,ebp
	jae	.tail
	test	eax,eax
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	rdx,r15
	call	pg_find_row
	mov	r13,rsi
	call	write_summary
	inc	dword [rsp+12]
	mov	rsi,r13
	call	pg_skip_message
	jmp	.write
.tail:
	cmp	dword [rsp+8],0
	je	.null
	put_str nj_cursor
	mov	r13,[rsp]
	xor	ecx,ecx
	call	note_col_raw
	put_str nj_end
	jmp	.send
.null:
	put_str nj_no_cursor
.send:
	mov	edi,ST_200
	mov	edx,r14d
	xor	ecx,ecx
	xor	r8d,r8d
	call	respond_built
.done:
	add	rsp,24
	pop	r15
	pop	r14
	pop	r13
	pop	rbp
	pop	rbx
	ret
