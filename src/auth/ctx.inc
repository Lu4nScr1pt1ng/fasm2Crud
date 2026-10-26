; Auth flow contexts: state an auth request keeps across its database
; round trips (the request bytes themselves may move in the input buffer
; meanwhile). A fixed pool per worker; when it is empty, auth requests get
; 503. Every context is wiped when released.

AUTH_CTX_MAX	= 128
AUTH_CTX_SIZE	= 1024

AC_EMAIL_LEN	= 0
AC_PW_LEN	= 4
AC_PHC_LEN	= 8
AC_EPOCH_LEN	= 12
AC_SLOT		= 16		; HTTP request waiting on the hasher
AC_GEN		= 20
AC_HCONT	= 24		; HCONT_xxx
AC_FLAGS	= 28
AC_EMAIL	= 64		; 256
AC_PW		= 320		; 128
AC_SALT		= 448		; 16
AC_TAG		= 464		; 32
AC_USER		= 496		; 36: user id, UUID text
AC_EPOCH	= 544		; 16: session epoch, decimal text
AC_REFRESH	= 560		; 43: new refresh token, base64url
AC_OLD_HEX	= 608		; 66: "\x" + hex SHA-256 of the presented token
AC_NEW_HEX	= 680		; 66: "\x" + hex SHA-256 of the new token
AC_PHC		= 752		; PHC_SIZE: decoded stored hash
AC_PHC_TEXT	= 864		; 128: PHC string

ACF_HASHING	= 1 shl 0	; a job is at the hasher: freed only by its reply
ACF_NO_USER	= 1 shl 1	; login for an unknown address: hash, then refuse
ACF_DELETE	= 1 shl 2	; password checked to delete the account

bss
	align 64
	g_auth_ctx:	rb AUTH_CTX_MAX * AUTH_CTX_SIZE
	g_auth_free:	rd AUTH_CTX_MAX
	g_auth_free_top	dd ?
end bss

auth_ctx_init:
	xor	eax,eax
@@:
	lea	ecx,[rax+1]
	mov	[g_auth_free+rax*4],ecx
	inc	eax
	cmp	eax,AUTH_CTX_MAX
	jb	@b
	mov	[g_auth_free_top],eax
	ret

; eax = context id + 1, or 0 when the pool is empty.
auth_ctx_alloc:
	mov	eax,[g_auth_free_top]
	test	eax,eax
	jz	.done
	dec	eax
	mov	[g_auth_free_top],eax
	mov	eax,[g_auth_free+rax*4]
.done:
	ret

; edi = context id + 1. rax = its memory.
auth_ctx_ptr:
	lea	eax,[rdi-1]
	shl	rax,10
	lea	rax,[g_auth_ctx+rax]
	ret

; edi = context id + 1, or 0 (nothing to do). Anything out of range is
; ignored rather than trusted: wiping 1 KiB at a wrong address would be
; far worse than a context leaked by a bug.
auth_ctx_free:
	lea	eax,[rdi-1]
	cmp	eax,AUTH_CTX_MAX
	jae	.done
	push	rdi
	call	auth_ctx_ptr
	mov	rdi,rax
	mov	ecx,AUTH_CTX_SIZE
	call	secure_zero
	pop	rdi
	mov	eax,[g_auth_free_top]
	mov	[g_auth_free+rax*4],edi
	inc	eax
	mov	[g_auth_free_top],eax
.done:
	ret
