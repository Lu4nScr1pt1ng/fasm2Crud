; Routes.

cstring allow_get, 'Allow: GET',13,10
cstring body_ready, '{"status":"ready"}'
cstring body_db_unavailable, '{"error":"database_unavailable"}'

; Continuations for database replies (see pg_deliver), indexed by CONT_xxx.
CONT_READY	= 0
CONT_REGISTER	= 1
CONT_LOGIN_USER	= 2
CONT_LOGIN_TOKEN = 3
CONT_REFRESH	= 4
CONT_LOGOUT	= 5

rodata
	align 8
	pg_cont_tbl	dq cont_ready, cont_register, cont_login_user, cont_login_token
			dq cont_refresh, cont_logout
end rodata

; r12 = connection; g_req holds the parsed request.
route:
	cmp	dword [req_method],M_OTHER
	je	.not_implemented
	mov	rsi,[req_path]
	mov	eax,[req_path_len]
	cmp	eax,8
	je	.len8
	cmp	eax,7
	je	.len7
	cmp	eax,9
	ja	.long
.not_found:
	mov	edi,ST_404
	jmp	respond_status

.long:
	mov	rcx,'/v1/auth'
	cmp	[rsi],rcx
	jne	.not_found
	cmp	byte [rsi+8],'/'
	jne	.not_found
	jmp	auth_route

.len8:
	mov	rax,'/healthz'
	cmp	[rsi],rax
	jne	.not_found
	jmp	.health
.len7:
	cmp	dword [rsi],'/rea'
	jne	.not_found
	cmp	dword [rsi+3],'adyz'
	jne	.not_found
	; Readiness is a real round trip through the query pipeline.
	cmp	dword [req_method],M_GET
	jne	.get_only
	mov	edi,STMT_PING
	mov	esi,CONT_READY
	xor	edx,edx
	xor	ecx,ecx
	call	db_query
	test	eax,eax
	jnz	respond_db_unavailable
	ret
.health:
	cmp	dword [req_method],M_GET
	jne	.get_only
	mov	edi,ST_200
	jmp	respond_status

.get_only:
	mov	eax,ST_405
	shl	eax,5
	mov	rsi,[status_tbl+rax+16]
	mov	edx,[status_tbl+rax+24]
	mov	edi,ST_405
	lea	rcx,[allow_get]
	mov	r8d,allow_get.len
	jmp	respond

.not_implemented:
	mov	edi,ST_501
	jmp	respond_status

respond_db_unavailable:
	mov	edi,ST_503
	lea	rsi,[body_db_unavailable]
	mov	edx,body_db_unavailable.len
	xor	ecx,ecx
	xor	r8d,r8d
	jmp	respond

; eax = PGR_xxx.
cont_ready:
	cmp	eax,PGR_OK
	jne	respond_db_unavailable
	mov	edi,ST_200
	lea	rsi,[body_ready]
	mov	edx,body_ready.len
	xor	ecx,ecx
	xor	r8d,r8d
	jmp	respond
