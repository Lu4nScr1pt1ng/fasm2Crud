; Housekeeping queries one worker runs in the background.
;
; Expired refresh tokens are deleted in batches of 5000 every
; PURGE_INTERVAL seconds by worker 0 (an index range scan on expires_at,
; nothing to do most of the time): up to 1.8 million an hour. Nobody waits
; for the reply (DB_BACKGROUND).

PURGE_INTERVAL	= 10

bss
	g_purge_next	dd ?
end bss

; Once per tick.
maintenance_tick:
	cmp	dword [g_worker_id],0
	jne	.done
	cmp	dword [g_draining],0
	jne	.done
	mov	eax,[g_tick]
	cmp	eax,[g_purge_next]
	jb	.done
	add	eax,PURGE_INTERVAL
	mov	[g_purge_next],eax
	push	rbx
	mov	ebx,DB_BACKGROUND
	mov	edi,STMT_PURGE_REFRESH
	mov	esi,CONT_READY			; never called: the reply is dropped
	xor	edx,edx
	xor	ecx,ecx
	xor	r8d,r8d
	call	db_query
	pop	rbx
.done:
	ret
