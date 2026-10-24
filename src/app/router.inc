; Routes.

cstring allow_get, 'Allow: GET',13,10

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
.not_found:
	mov	edi,ST_404
	jmp	respond_status

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
