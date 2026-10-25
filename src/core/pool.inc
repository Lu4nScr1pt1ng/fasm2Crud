; Pools of fixed-size items that give their memory back.
;
; Items (connection slots, large buffers) come from a LIFO stack: the most
; recently released one, still in cache and faulted in, goes out first, so
; resident memory follows the load. When the load goes down, items that
; stay at the bottom of the stack, beyond the pool's warm reserve and
; unused for g_trim_idle seconds, have their pages returned to the kernel
; (MADV_DONTNEED) on the timer tick, at most POOL_TRIM_BUDGET per tick. A
; busy pool never trims, so it never pays page faults for this; a trimmed
; item that is taken again faults in zero pages as it is written.
;
; Release ticks grow from the bottom of the stack to the top, so trimmed
; items are always a prefix of the stack: P_TRIMMED counts them, and each
; tick resumes where the last one stopped.

P_BASE		= 0		; dq: item 0
P_LIST		= 8		; dq: u32 item per stack position
P_TICKS		= 16		; dq: u32 release tick per stack position
P_SHIFT		= 24		; log2 of the item size
P_KEEP		= 28		; bytes at the start of an item that are never trimmed
P_COUNT		= 32
P_TOP		= 36		; free items
P_TRIMMED	= 40
P_WARM		= 44		; free items always kept resident
P_SIZE		= 48

POOL_TRIM_BUDGET = 256
DEFAULT_TRIM_IDLE = 30		; seconds

bss
	g_trim_idle	dd ?
end bss

; rdi = pool with P_BASE, P_SHIFT, P_KEEP, P_COUNT and P_WARM set. Every
; item starts free and untouched (so counted as trimmed).
; eax = 0 or -errno.
pool_init:
	push	rbx
	mov	rbx,rdi
	xor	edi,edi
	mov	esi,[rbx+P_COUNT]
	shl	esi,3
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[rbx+P_LIST],rax
	mov	ecx,[rbx+P_COUNT]
	lea	rdx,[rax+rcx*4]
	mov	[rbx+P_TICKS],rdx
	mov	[rbx+P_TOP],ecx
	mov	[rbx+P_TRIMMED],ecx
	; list[i] = count - 1 - i: item 0 is on top.
	xor	edx,edx
@@:
	dec	ecx
	mov	[rax+rdx*4],ecx
	inc	edx
	test	ecx,ecx
	jnz	@b
	xor	eax,eax
.done:
	pop	rbx
	ret

; rdi = pool. eax = item; CF when the pool is empty.
pool_take:
	mov	eax,[rdi+P_TOP]
	test	eax,eax
	jz	.empty
	dec	eax
	mov	[rdi+P_TOP],eax
	cmp	eax,[rdi+P_TRIMMED]
	jae	@f
	mov	[rdi+P_TRIMMED],eax
@@:
	mov	rcx,[rdi+P_LIST]
	mov	eax,[rcx+rax*4]
	clc
	ret
.empty:
	stc
	ret

; rdi = pool, esi = item.
pool_put:
	mov	eax,[rdi+P_TOP]
	mov	rcx,[rdi+P_LIST]
	mov	[rcx+rax*4],esi
	mov	rcx,[rdi+P_TICKS]
	mov	edx,[g_tick]
	mov	[rcx+rax*4],edx
	inc	eax
	mov	[rdi+P_TOP],eax
	ret

; rdi = pool, esi = item. rax = its memory.
pool_ptr:
	mov	ecx,[rdi+P_SHIFT]
	mov	eax,esi
	shl	rax,cl
	add	rax,[rdi+P_BASE]
	ret

; Once per tick: return the pages of items idle for long enough.
pool_trim:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r12d,[rbx+P_TRIMMED]
	mov	r13d,POOL_TRIM_BUDGET
	mov	r14d,[rbx+P_TOP]
	sub	r14d,[rbx+P_WARM]		; stack positions below are cold
	jle	.done
.next:
	cmp	r12d,r14d
	jae	.done
	test	r13d,r13d
	jz	.done
	mov	rcx,[rbx+P_TICKS]
	mov	eax,[g_tick]
	sub	eax,[rcx+r12*4]
	cmp	eax,[g_trim_idle]
	jb	.done				; everything above is newer
	mov	rcx,[rbx+P_LIST]
	mov	esi,[rcx+r12*4]
	mov	rdi,rbx
	call	pool_ptr
	mov	edi,[rbx+P_KEEP]
	add	rdi,rax
	mov	esi,1
	mov	ecx,[rbx+P_SHIFT]
	shl	esi,cl
	sub	esi,[rbx+P_KEEP]
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	metric_add M_RETURNED, rsi
	inc	r12d
	dec	r13d
	jmp	.next
.done:
	mov	[rbx+P_TRIMMED],r12d
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
