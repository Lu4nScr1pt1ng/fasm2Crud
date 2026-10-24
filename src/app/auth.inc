; Account endpoints. All are POST with a JSON body (Content-Type
; application/json, else 415):
;
;   /v1/auth/register  {"email","password"}  201 {"id","email"}, 409 if taken
;   /v1/auth/login     {"email","password"}  200 tokens, 401
;   /v1/auth/refresh   {"refresh_token"}     200 tokens, 401; the old one is spent
;   /v1/auth/logout    {"refresh_token"}     204; ends that whole login
;
; Tokens: {"token_type":"Bearer","expires_in":900,"access_token":"...",
; "refresh_token":"..."} (src/auth/token.inc). Malformed JSON is 400, a body
; of the wrong shape or an unacceptable e-mail or password is 422. A wrong
; password and an unknown address get the same 401 after the same work.
;
; A request keeps its state in an auth context (src/auth/ctx.inc) across
; the hasher and database round trips:
;   register  hash -> INSERT user
;   login     SELECT user -> hash (a dummy one when unknown) -> INSERT refresh
;   refresh   rotate (one statement)
;   logout    revoke the family (no context needed)
; Whoever ends the flow, a continuation or a dropped reply, frees it.

HCONT_REGISTER	= 0
HCONT_LOGIN	= 1

AUTH_SCRATCH	= 512

cstring name_email, 'email'
cstring name_password, 'password'
cstring name_refresh_token, 'refresh_token'
cstring allow_post, 'Allow: POST',13,10
cstring hdr_retry_after, 'Retry-After: 1',13,10

rodata
	align 8
	hash_cont_tbl	dq hcont_register, hcont_login
	spec_credentials:
		dq name_email
		dd name_email.len, EMAIL_MAX
		dq name_password
		dd name_password.len, PASSWORD_MAX
	spec_refresh:
		dq name_refresh_token
		dd name_refresh_token.len, 64
end rodata

bss
	align 8
	g_auth_vals:	rb 2 * JV_SIZE
	g_auth_job:	rb JJ_SIZE
	g_auth_scratch:	rb AUTH_SCRATCH
	g_auth_body:	rb 512
end bss

; Append a literal at rdi.
macro put_lit text&
	local s
	cstring s, text
	lea	rsi,[s]
	mov	ecx,s.len
	rep	movsb
end macro

; r12 = connection, rsi = path ("/v1/auth/..."), eax = its length.
auth_route:
	sub	eax,9
	lea	rdx,[rsi+9]
	cmp	eax,8
	je	.len8
	cmp	eax,7
	je	.len7
	cmp	eax,6
	je	.len6
	cmp	eax,5
	je	.len5
.not_found:
	mov	edi,ST_404
	jmp	respond_status
.len8:
	mov	rax,'register'
	cmp	[rdx],rax
	jne	.not_found
	lea	rax,[auth_register]
	jmp	.endpoint
.len7:
	cmp	dword [rdx],'refr'
	jne	.not_found
	cmp	dword [rdx+3],'resh'
	jne	.not_found
	lea	rax,[auth_refresh]
	jmp	.endpoint
.len6:
	cmp	dword [rdx],'logo'
	jne	.not_found
	cmp	word [rdx+4],'ut'
	jne	.not_found
	lea	rax,[auth_logout]
	jmp	.endpoint
.len5:
	cmp	dword [rdx],'logi'
	jne	.not_found
	cmp	byte [rdx+4],'n'
	jne	.not_found
	lea	rax,[auth_login]
.endpoint:
	cmp	dword [req_method],M_POST
	jne	.post_only
	push	rax
	call	json_content_type
	pop	rcx
	test	eax,eax
	jz	.media_type
	call	rcx
	; The scratch held the decoded password.
	lea	rdi,[g_auth_scratch]
	mov	ecx,AUTH_SCRATCH
	call	secure_zero
	lea	rdi,[g_auth_vals]
	mov	ecx,2 * JV_SIZE
	jmp	secure_zero
.media_type:
	mov	edi,ST_415
	jmp	respond_status
.post_only:
	mov	eax,ST_405
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_405
	lea	rcx,[allow_post]
	mov	r8d,allow_post.len
	jmp	respond

; eax = 1 when Content-Type is application/json, parameters allowed.
json_content_type:
	xor	eax,eax
	mov	rsi,[req_ctype]
	mov	ecx,[req_ctype_len]
	cmp	ecx,16
	jb	.done
	mov	rdx,0x2020202020202020
	mov	r8,[rsi]
	or	r8,rdx
	mov	r9,'applicat'
	cmp	r8,r9
	jne	.done
	mov	r8,[rsi+8]
	or	r8,rdx
	mov	r9,'ion/json'
	cmp	r8,r9
	jne	.done
	cmp	ecx,16
	je	.yes
	mov	dl,[rsi+16]
	cmp	dl,';'
	je	.yes
	cmp	dl,' '
	je	.yes
	cmp	dl,9
	jne	.done
.yes:
	mov	eax,1
.done:
	ret

; Parse the body into g_auth_vals. rdi = field spec, esi = field count;
; every field is required. eax = 0, or the ST_xxx to answer.
auth_parse:
	lea	rax,[g_auth_job]
	mov	[rax+JJ_SPEC],rdi
	mov	[rax+JJ_FIELDS],esi
	lea	rcx,[g_auth_vals]
	mov	[rax+JJ_OUT],rcx
	lea	rcx,[g_auth_scratch]
	mov	[rax+JJ_SCRATCH],rcx
	mov	dword [rax+JJ_SCRATCH_CAP],AUTH_SCRATCH
	mov	rcx,[req_body]
	mov	[rax+JJ_BODY],rcx
	mov	ecx,[req_body_len]
	mov	[rax+JJ_BODY_LEN],ecx
	push	rsi
	mov	rdi,rax
	call	json_parse_object
	pop	rsi
	cmp	eax,JSON_SYNTAX
	je	.syntax
	cmp	eax,JSON_OK
	jne	.schema
	xor	ecx,ecx
.present:
	mov	edx,ecx
	shl	edx,4
	cmp	dword [g_auth_vals+rdx+JV_PRESENT],0
	je	.schema
	inc	ecx
	cmp	ecx,esi
	jb	.present
	xor	eax,eax
	ret
.syntax:
	mov	eax,ST_400
	ret
.schema:
	mov	eax,ST_422
	ret

; A context holding the parsed e-mail and password.
; eax = context (id + 1), or 0 when the pool is empty; rdx = its memory.
auth_ctx_credentials:
	call	auth_ctx_alloc
	test	eax,eax
	jz	.done
	push	rax
	mov	edi,eax
	call	auth_ctx_ptr
	mov	rdx,rax
	mov	ecx,[g_auth_vals+JV_LEN]
	mov	[rdx+AC_EMAIL_LEN],ecx
	mov	rsi,[g_auth_vals+JV_PTR]
	lea	rdi,[rdx+AC_EMAIL]
	rep	movsb
	mov	ecx,[g_auth_vals+JV_SIZE+JV_LEN]
	mov	[rdx+AC_PW_LEN],ecx
	mov	rsi,[g_auth_vals+JV_SIZE+JV_PTR]
	lea	rdi,[rdx+AC_PW]
	rep	movsb
	pop	rax
.done:
	ret

; 503 with Retry-After: the hasher queue or the context pool is full.
respond_busy:
	mov	eax,ST_503
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_503
	lea	rcx,[hdr_retry_after]
	mov	r8d,hdr_retry_after.len
	jmp	respond

; esi = HASH_xxx (not HASH_OK).
respond_hash_failed:
	cmp	esi,HASH_UNAVAILABLE
	je	respond_busy
	mov	edi,ST_500
	jmp	respond_status

; esi = ST_xxx; the body is g_auth_body up to rdi.
respond_auth_body:
	lea	rax,[g_auth_body]
	mov	rdx,rdi
	sub	rdx,rax
	mov	edi,esi
	mov	rsi,rax
	xor	ecx,ecx
	xor	r8d,r8d
	jmp	respond

; Session epoch text: rsi = digits, edx = length. eax = value, CF if bad.
parse_epoch:
	xor	eax,eax
	test	edx,edx
	jz	.bad
	cmp	edx,9
	ja	.bad
.digit:
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,ecx
	inc	rsi
	dec	edx
	jnz	.digit
	clc
	ret
.bad:
	stc
	ret

; 200 with a new access token and the context's new refresh token.
; rdi = context (AC_USER, AC_EPOCH, AC_REFRESH).
respond_tokens:
	push	r15
	sub	rsp,32
	mov	r15,rdi
	lea	rsi,[r15+AC_USER]
	mov	rdi,rsp
	call	uuid_parse
	jc	.bad
	lea	rsi,[r15+AC_EPOCH]
	mov	edx,[r15+AC_EPOCH_LEN]
	call	parse_epoch
	jc	.bad
	mov	[rsp+16],eax
	lea	rdi,[g_auth_body]
	put_lit '{"token_type":"Bearer","expires_in":'
	mov	eax,ACCESS_TTL
	call	write_u32
	put_lit ',"access_token":"'
	mov	[rsp+24],rdi
	mov	rsi,rsp
	mov	edx,[rsp+16]
	call	access_token_make
	mov	rdi,[rsp+24]
	add	rdi,rax
	put_lit '","refresh_token":"'
	lea	rsi,[r15+AC_REFRESH]
	mov	ecx,REFRESH_TEXT
	rep	movsb
	put_lit '"}'
	mov	esi,ST_200
	call	respond_auth_body
	jmp	.done
.bad:
	mov	edi,ST_500
	call	respond_status
.done:
	add	rsp,32
	pop	r15
	ret

; Copy a column of the reply's row into the context.
; r14/rbp = reply range, ecx = column, rdi = destination, r8d = capacity.
; eax = length, CF when there is no row, the value is NULL or too long.
copy_field:
	push	rdi
	push	r8
	mov	rsi,r14
	mov	rdx,rbp
	call	pg_row_field
	pop	r8
	pop	rdi
	jc	.done
	cmp	edx,r8d
	ja	.too_long
	mov	rsi,rax
	mov	ecx,edx
	mov	eax,edx
	rep	movsb
	clc
.done:
	ret
.too_long:
	stc
	ret

; ---------------------------------------------------------------- register

auth_register:
	push	r13
	push	r15
	lea	rdi,[spec_credentials]
	mov	esi,2
	call	auth_parse
	test	eax,eax
	jnz	.status
	mov	rdi,[g_auth_vals+JV_PTR]
	mov	esi,[g_auth_vals+JV_LEN]
	call	email_normalize
	test	eax,eax
	jz	.invalid
	mov	esi,[g_auth_vals+JV_SIZE+JV_LEN]
	call	password_acceptable
	test	eax,eax
	jz	.invalid
	call	auth_ctx_credentials
	test	eax,eax
	jz	.busy
	mov	r13d,eax
	mov	r15,rdx
	lea	rdi,[r15+AC_SALT]
	mov	esi,PW_SALT_LEN
	call	random_bytes
	test	eax,eax
	jnz	.busy_free
	mov	edi,r13d
	lea	rsi,[r15+AC_SALT]
	mov	edx,PW_SALT_LEN
	mov	ecx,PW_M_KIB
	mov	r8d,PW_T
	mov	r9d,HCONT_REGISTER
	call	hasher_submit
	test	eax,eax
	jz	.done
.busy_free:
	mov	edi,r13d
	call	auth_ctx_free
.busy:
	call	respond_busy
	jmp	.done
.invalid:
	mov	eax,ST_422
.status:
	mov	edi,eax
	call	respond_status
.done:
	pop	r15
	pop	r13
	ret

; eax = HASH_xxx, ecx = context, rsi = tag.
hcont_register:
	push	r13
	push	r14
	push	r15
	sub	rsp,32
	mov	r13d,ecx
	mov	r14,rsi
	push	rax
	mov	edi,ecx
	call	auth_ctx_ptr
	mov	r15,rax
	lea	rdi,[r15+AC_PW]
	mov	ecx,PASSWORD_MAX
	call	secure_zero
	pop	rax
	test	eax,eax
	jnz	.hash_failed
	lea	rdi,[r15+AC_PHC_TEXT]
	lea	rsi,[r15+AC_SALT]
	mov	rdx,r14
	call	phc_encode
	mov	[r15+AC_PHC_LEN],eax
	lea	rax,[r15+AC_EMAIL]
	mov	[rsp],rax
	mov	eax,[r15+AC_EMAIL_LEN]
	mov	[rsp+8],eax
	lea	rax,[r15+AC_PHC_TEXT]
	mov	[rsp+16],rax
	mov	eax,[r15+AC_PHC_LEN]
	mov	[rsp+24],eax
	mov	edi,STMT_INSERT_USER
	mov	esi,CONT_REGISTER
	mov	rdx,rsp
	mov	ecx,2
	mov	r8d,r13d
	call	db_query
	test	eax,eax
	jz	.done
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_db_unavailable
	jmp	.done
.hash_failed:
	mov	r14d,eax
	mov	edi,r13d
	call	auth_ctx_free
	mov	esi,r14d
	call	respond_hash_failed
.done:
	add	rsp,32
	pop	r15
	pop	r14
	pop	r13
	ret

; eax = PGR_xxx, ecx = context, rsi/rdx = reply.
cont_register:
	push	r13
	push	r15
	mov	r13d,ecx
	cmp	eax,PGR_OK
	je	.created
	cmp	eax,PGR_SQL_ERROR
	jne	.unavailable
	; unique_violation: the address is taken.
	cmp	dword [g_pg_sqlstate],'2350'
	jne	.error
	cmp	byte [g_pg_sqlstate+4],'5'
	jne	.error
	mov	edi,ST_409
	call	respond_status
	jmp	.done
.created:
	xor	ecx,ecx
	call	pg_row_field
	jc	.error
	cmp	edx,36
	jne	.error
	mov	r15,rax
	mov	edi,r13d
	call	auth_ctx_ptr
	push	rax
	lea	rdi,[g_auth_body]
	put_lit '{"id":"'
	mov	rsi,r15
	mov	ecx,36
	rep	movsb
	; Addresses are atext and dots only: nothing to escape.
	put_lit '","email":"'
	pop	rax
	lea	rsi,[rax+AC_EMAIL]
	mov	ecx,[rax+AC_EMAIL_LEN]
	rep	movsb
	put_lit '"}'
	mov	esi,ST_201
	call	respond_auth_body
	jmp	.done
.error:
	mov	edi,ST_500
	call	respond_status
	jmp	.done
.unavailable:
	call	respond_db_unavailable
.done:
	mov	edi,r13d
	call	auth_ctx_free
	pop	r15
	pop	r13
	ret

; ---------------------------------------------------------------- login

auth_login:
	push	r13
	sub	rsp,16
	lea	rdi,[spec_credentials]
	mov	esi,2
	call	auth_parse
	test	eax,eax
	jnz	.status
	; Nothing could ever match these: refuse without asking anyone.
	mov	rdi,[g_auth_vals+JV_PTR]
	mov	esi,[g_auth_vals+JV_LEN]
	call	email_normalize
	test	eax,eax
	jz	.refused
	cmp	dword [g_auth_vals+JV_SIZE+JV_LEN],0
	je	.refused
	call	auth_ctx_credentials
	test	eax,eax
	jz	.busy
	mov	r13d,eax
	lea	rax,[rdx+AC_EMAIL]
	mov	[rsp],rax
	mov	eax,[rdx+AC_EMAIL_LEN]
	mov	[rsp+8],eax
	mov	edi,STMT_USER_BY_EMAIL
	mov	esi,CONT_LOGIN_USER
	mov	rdx,rsp
	mov	ecx,1
	mov	r8d,r13d
	call	db_query
	test	eax,eax
	jz	.done
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_db_unavailable
	jmp	.done
.busy:
	call	respond_busy
	jmp	.done
.refused:
	mov	eax,ST_401
.status:
	mov	edi,eax
	call	respond_status
.done:
	add	rsp,16
	pop	r13
	ret

; eax = PGR_xxx, ecx = context, rsi/rdx = reply (id, password_hash,
; session_epoch, or no row).
cont_login_user:
	push	rbp
	push	r13
	push	r14
	push	r15
	mov	r13d,ecx
	mov	r14,rsi
	mov	rbp,rdx
	push	rax
	mov	edi,ecx
	call	auth_ctx_ptr
	mov	r15,rax
	pop	rax
	cmp	eax,PGR_OK
	jne	.unavailable
	xor	ecx,ecx
	lea	rdi,[r15+AC_USER]
	mov	r8d,36
	call	copy_field
	jc	.unknown
	cmp	eax,36
	jne	.unknown
	mov	ecx,2
	lea	rdi,[r15+AC_EPOCH]
	mov	r8d,15
	call	copy_field
	jc	.unknown
	mov	[r15+AC_EPOCH_LEN],eax
	mov	ecx,1
	mov	rsi,r14
	mov	rdx,rbp
	call	pg_row_field
	jc	.unknown
	mov	rsi,rax
	lea	rdi,[r15+AC_PHC]
	call	phc_decode
	test	eax,eax
	jnz	.unknown
	lea	rsi,[r15+AC_PHC+PHC_SALT]
	mov	edx,[r15+AC_PHC+PHC_SALT_LEN]
	mov	ecx,[r15+AC_PHC+PHC_M]
	mov	r8d,[r15+AC_PHC+PHC_T]
	jmp	.hash
.unknown:
	; Same work as a real login, then 401.
	or	dword [r15+AC_FLAGS],ACF_NO_USER
	lea	rsi,[pw_dummy_salt]
	mov	edx,PW_SALT_LEN
	mov	ecx,PW_M_KIB
	mov	r8d,PW_T
.hash:
	mov	edi,r13d
	mov	r9d,HCONT_LOGIN
	call	hasher_submit
	test	eax,eax
	jz	.done
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_busy
	jmp	.done
.unavailable:
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_db_unavailable
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	rbp
	ret

; eax = HASH_xxx, ecx = context, rsi = tag.
hcont_login:
	push	r13
	push	r14
	push	r15
	sub	rsp,32
	mov	r13d,ecx
	mov	r14d,eax
	push	rsi
	mov	edi,ecx
	call	auth_ctx_ptr
	mov	r15,rax
	lea	rdi,[r15+AC_PW]
	mov	ecx,PASSWORD_MAX
	call	secure_zero
	pop	rdi
	test	r14d,r14d
	jnz	.hash_failed
	lea	rsi,[r15+AC_PHC+PHC_HASH]
	mov	edx,PW_HASH_LEN
	call	ct_equal
	test	dword [r15+AC_FLAGS],ACF_NO_USER
	jz	@f
	xor	eax,eax
@@:
	test	eax,eax
	jz	.refused
	mov	rdi,r15
	call	refresh_token_new
	test	eax,eax
	jnz	.busy
	lea	rax,[r15+AC_NEW_HEX]
	mov	[rsp],rax
	mov	dword [rsp+8],66
	lea	rax,[r15+AC_USER]
	mov	[rsp+16],rax
	mov	dword [rsp+24],36
	mov	edi,STMT_INSERT_REFRESH
	mov	esi,CONT_LOGIN_TOKEN
	mov	rdx,rsp
	mov	ecx,2
	mov	r8d,r13d
	call	db_query
	test	eax,eax
	jz	.done
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_db_unavailable
	jmp	.done
.refused:
	mov	edi,r13d
	call	auth_ctx_free
	mov	edi,ST_401
	call	respond_status
	jmp	.done
.busy:
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_busy
	jmp	.done
.hash_failed:
	mov	edi,r13d
	call	auth_ctx_free
	mov	esi,r14d
	call	respond_hash_failed
.done:
	add	rsp,32
	pop	r15
	pop	r14
	pop	r13
	ret

; eax = PGR_xxx, ecx = context.
cont_login_token:
	push	r13
	mov	r13d,ecx
	cmp	eax,PGR_OK
	jne	.failed
	mov	edi,ecx
	call	auth_ctx_ptr
	mov	rdi,rax
	call	respond_tokens
	jmp	.done
.failed:
	call	respond_db_unavailable
.done:
	mov	edi,r13d
	call	auth_ctx_free
	pop	r13
	ret

; ---------------------------------------------------------------- refresh

auth_refresh:
	push	r13
	push	r15
	sub	rsp,40
	lea	rdi,[spec_refresh]
	mov	esi,1
	call	auth_parse
	test	eax,eax
	jnz	.status
	call	auth_ctx_alloc
	test	eax,eax
	jz	.busy
	mov	r13d,eax
	mov	edi,eax
	call	auth_ctx_ptr
	mov	r15,rax
	lea	rdi,[r15+AC_OLD_HEX]
	mov	rsi,[g_auth_vals+JV_PTR]
	mov	edx,[g_auth_vals+JV_LEN]
	call	refresh_token_hash
	jc	.refused
	mov	rdi,r15
	call	refresh_token_new
	test	eax,eax
	jnz	.busy_free
	lea	rax,[r15+AC_OLD_HEX]
	mov	[rsp],rax
	mov	dword [rsp+8],66
	lea	rax,[r15+AC_NEW_HEX]
	mov	[rsp+16],rax
	mov	dword [rsp+24],66
	mov	edi,STMT_ROTATE_REFRESH
	mov	esi,CONT_REFRESH
	mov	rdx,rsp
	mov	ecx,2
	mov	r8d,r13d
	call	db_query
	test	eax,eax
	jz	.done
	mov	edi,r13d
	call	auth_ctx_free
	call	respond_db_unavailable
	jmp	.done
.refused:
	mov	edi,r13d
	call	auth_ctx_free
	mov	eax,ST_401
	jmp	.status
.busy_free:
	mov	edi,r13d
	call	auth_ctx_free
.busy:
	call	respond_busy
	jmp	.done
.status:
	mov	edi,eax
	call	respond_status
.done:
	add	rsp,40
	pop	r15
	pop	r13
	ret

; eax = PGR_xxx, ecx = context, rsi/rdx = reply (id, session_epoch of the
; new token's owner, or no row: unknown, expired, revoked or reused).
cont_refresh:
	push	rbp
	push	r13
	push	r14
	push	r15
	mov	r13d,ecx
	mov	r14,rsi
	mov	rbp,rdx
	push	rax
	mov	edi,ecx
	call	auth_ctx_ptr
	mov	r15,rax
	pop	rax
	cmp	eax,PGR_OK
	jne	.unavailable
	xor	ecx,ecx
	lea	rdi,[r15+AC_USER]
	mov	r8d,36
	call	copy_field
	jc	.refused
	cmp	eax,36
	jne	.error
	mov	ecx,1
	lea	rdi,[r15+AC_EPOCH]
	mov	r8d,15
	call	copy_field
	jc	.error
	mov	[r15+AC_EPOCH_LEN],eax
	mov	rdi,r15
	call	respond_tokens
	jmp	.done
.refused:
	mov	edi,ST_401
	call	respond_status
	jmp	.done
.error:
	mov	edi,ST_500
	call	respond_status
	jmp	.done
.unavailable:
	call	respond_db_unavailable
.done:
	mov	edi,r13d
	call	auth_ctx_free
	pop	r15
	pop	r14
	pop	r13
	pop	rbp
	ret

; ---------------------------------------------------------------- logout

; The reply needs nothing from the request: no context.
auth_logout:
	sub	rsp,88
	lea	rdi,[spec_refresh]
	mov	esi,1
	call	auth_parse
	test	eax,eax
	jnz	.status
	lea	rdi,[rsp+16]
	mov	rsi,[g_auth_vals+JV_PTR]
	mov	edx,[g_auth_vals+JV_LEN]
	call	refresh_token_hash
	jc	.refused
	lea	rax,[rsp+16]
	mov	[rsp],rax
	mov	dword [rsp+8],66
	mov	edi,STMT_REVOKE_FAMILY
	mov	esi,CONT_LOGOUT
	mov	rdx,rsp
	mov	ecx,1
	xor	r8d,r8d
	call	db_query
	test	eax,eax
	jz	.done
	call	respond_db_unavailable
	jmp	.done
.refused:
	mov	eax,ST_401
.status:
	mov	edi,eax
	call	respond_status
.done:
	add	rsp,88
	ret

; eax = PGR_xxx. Revoking a family that is already gone is still a 204.
cont_logout:
	cmp	eax,PGR_OK
	jne	respond_db_unavailable
	jmp	respond_no_content
