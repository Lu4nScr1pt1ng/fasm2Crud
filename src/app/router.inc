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
CONT_NOTE_CREATED = 6
CONT_NOTE_GET	= 7
CONT_NOTE_UPDATED = 8
CONT_NOTE_DELETED = 9
CONT_NOTES_PAGE	= 10

rodata
	align 8
	pg_cont_tbl	dq cont_ready, cont_register, cont_login_user, cont_login_token
			dq cont_refresh, cont_logout
			dq cont_note_created, cont_note_get, cont_note_updated, cont_note_deleted
			dq cont_notes_page
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
	jae	.long
.not_found:
	mov	edi,ST_404
	jmp	respond_status

.long:
	mov	rcx,'/v1/auth'
	cmp	[rsi],rcx
	jne	.notes
	cmp	byte [rsi+8],'/'
	jne	.not_found
	jmp	auth_route
.notes:
	mov	rcx,'/v1/note'
	cmp	[rsi],rcx
	jne	.not_found
	cmp	byte [rsi+8],'s'
	jne	.not_found
	jmp	notes_route

.len8:
	mov	rax,'/healthz'
	cmp	[rsi],rax
	je	.health
	mov	rax,'/metrics'
	cmp	[rsi],rax
	je	metrics_route
	jmp	.not_found
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

; 405 for a GET-only route.
route_get_only:
	jmp	route.get_only

; Routes with large bodies (notes). ZF clear (and eax = 1) for them.
route_is_notes:
	xor	eax,eax
	cmp	dword [req_path_len],9
	jb	.done
	mov	rdx,[req_path]
	mov	rcx,'/v1/note'
	cmp	[rdx],rcx
	jne	.done
	cmp	byte [rdx+8],'s'
	jne	.done
	inc	eax
.done:
	test	eax,eax
	ret

; eax = 1 when the route builds its responses in place (respond_built),
; which needs an empty output buffer to start from: notes and /metrics.
route_output_need:
	call	route_is_notes
	jnz	.done
	cmp	dword [req_path_len],8
	jne	.done
	mov	rdx,[req_path]
	mov	rcx,'/metrics'
	cmp	[rdx],rcx
	jne	.done
	inc	eax
.done:
	ret

; eax = the largest request the route accepts: notes take large buffers,
; everything else fits the slot.
route_input_max:
	call	route_is_notes
	mov	eax,IN_CAP
	jz	.done
	mov	eax,LARGE_CAP
.done:
	ret

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
