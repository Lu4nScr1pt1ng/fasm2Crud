; io_uring: one ring per worker, used from a single thread.
;
; Setup flags:
;   SINGLE_ISSUER + DEFER_TASKRUN  completions are processed only when we ask,
;                                  on our own thread, without IPIs
;   SUBMIT_ALL                     a failing SQE does not stall the ones after it
;   NO_SQARRAY                     SQ tail indexes the SQE array directly
;   CQSIZE                         completion queue 4x the submission queue

bss
	align 8
	g_sq_head_ptr	dq ?
	g_sq_tail_ptr	dq ?
	g_sqes		dq ?
	g_cq_head_ptr	dq ?
	g_cq_tail_ptr	dq ?
	g_cqes		dq ?
	g_ring_fd	dd ?
	g_sq_entries	dd ?
	g_sq_mask	dd ?
	g_cq_mask	dd ?
	g_sq_tail	dd ?		; local tail, published on ring_enter
	g_sq_flushed	dd ?		; SQEs the kernel has consumed
	g_uparams:	rb UP_SIZE
end bss

; eax = 0 or -errno (or -1 when the kernel lacks a required feature).
ring_init:
	push	rbx
	push	r12
	lea	rdi,[g_uparams]
	xor	eax,eax
	mov	ecx,UP_SIZE/8
	rep	stosq
	mov	dword [g_uparams+UP_FLAGS],IORING_SETUP_SINGLE_ISSUER or IORING_SETUP_DEFER_TASKRUN or IORING_SETUP_SUBMIT_ALL or IORING_SETUP_NO_SQARRAY or IORING_SETUP_CQSIZE or IORING_SETUP_CLAMP
	mov	dword [g_uparams+UP_CQ_ENTRIES],CQ_ENTRIES
	mov	edi,RING_ENTRIES
	lea	rsi,[g_uparams]
	mov	eax,SYS_io_uring_setup
	syscall
	test	eax,eax
	js	.done
	mov	[g_ring_fd],eax
	mov	ebx,eax

	mov	eax,[g_uparams+UP_FEATURES]
	and	eax,IORING_FEAT_SINGLE_MMAP or IORING_FEAT_NODROP
	cmp	eax,IORING_FEAT_SINGLE_MMAP or IORING_FEAT_NODROP
	mov	eax,-1
	jne	.done

	; SQ and CQ rings share one mapping; it must cover the larger of the two.
	mov	eax,[g_uparams+UP_SQ_ENTRIES]
	mov	[g_sq_entries],eax
	shl	eax,2
	add	eax,[g_uparams+UP_SQ_ARRAY]
	mov	ecx,[g_uparams+UP_CQ_ENTRIES]
	shl	ecx,4
	add	ecx,[g_uparams+UP_CQ_CQES]
	cmp	ecx,eax
	cmova	eax,ecx
	xor	edi,edi
	mov	esi,eax
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_POPULATE
	mov	r8d,ebx
	mov	r9d,IORING_OFF_SQ_RING
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	r12,rax

	mov	eax,[g_uparams+UP_SQ_HEAD]
	add	rax,r12
	mov	[g_sq_head_ptr],rax
	mov	eax,[g_uparams+UP_SQ_TAIL]
	add	rax,r12
	mov	[g_sq_tail_ptr],rax
	mov	eax,[g_uparams+UP_SQ_MASK]
	mov	eax,[r12+rax]
	mov	[g_sq_mask],eax
	mov	eax,[g_uparams+UP_CQ_HEAD]
	add	rax,r12
	mov	[g_cq_head_ptr],rax
	mov	eax,[g_uparams+UP_CQ_TAIL]
	add	rax,r12
	mov	[g_cq_tail_ptr],rax
	mov	eax,[g_uparams+UP_CQ_MASK]
	mov	eax,[r12+rax]
	mov	[g_cq_mask],eax
	mov	eax,[g_uparams+UP_CQ_CQES]
	add	rax,r12
	mov	[g_cqes],rax

	xor	edi,edi
	mov	esi,[g_sq_entries]
	shl	esi,6
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_POPULATE
	mov	r8d,ebx
	mov	r9d,IORING_OFF_SQES
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[g_sqes],rax
	xor	eax,eax
.done:
	pop	r12
	pop	rbx
	ret

; Sparse table of direct descriptors, one per connection slot. Accepted
; sockets never enter the process fd table, which saves the fd lookup and
; reference counting on every operation.
; eax = 0 or -errno.
ring_register_files:
	sub	rsp,40
	mov	eax,[g_max_conns]
	mov	[rsp],eax				; nr
	mov	dword [rsp+4],IORING_RSRC_REGISTER_SPARSE
	xor	eax,eax
	mov	[rsp+8],rax				; resv2
	mov	[rsp+16],rax				; data
	mov	[rsp+24],rax				; tags
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_FILES2
	mov	rdx,rsp
	mov	r10d,32
	mov	eax,SYS_io_uring_register
	syscall
	add	rsp,40
	ret

; rax = zeroed SQE. Flushes the queue when it is full.
ring_get_sqe:
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_head_ptr]
	mov	ecx,eax
	sub	ecx,[rdx]
	cmp	ecx,[g_sq_entries]
	jae	.full
.take:
	mov	ecx,eax
	and	ecx,[g_sq_mask]
	shl	rcx,6
	add	rcx,[g_sqes]
	inc	eax
	mov	[g_sq_tail],eax
	vpxor	xmm0,xmm0,xmm0
	vmovdqu	[rcx],xmm0
	vmovdqu	[rcx+16],xmm0
	vmovdqu	[rcx+32],xmm0
	vmovdqu	[rcx+48],xmm0
	mov	rax,rcx
	ret
.full:
	call	ring_flush
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_head_ptr]
	mov	ecx,eax
	sub	ecx,[rdx]
	cmp	ecx,[g_sq_entries]
	jb	.take
	; The kernel refused new work: crash this worker and let the supervisor
	; start a clean one instead of spinning.
	call	log_begin
	log_lit 'submission queue stuck'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; Submit pending SQEs without waiting.
ring_flush:
	xor	edi,edi

; Submit pending SQEs and wait for at least edi completions.
ring_enter:
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_tail_ptr]
	mov	[rdx],eax			; x86 stores are ordered: SQE contents first
	mov	esi,eax
	sub	esi,[g_sq_flushed]
	mov	edx,edi
	mov	edi,[g_ring_fd]
	mov	r10d,IORING_ENTER_GETEVENTS
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_io_uring_enter
	syscall
	test	eax,eax
	js	.done				; EINTR, EBUSY, ...: the caller just retries
	add	[g_sq_flushed],eax
.done:
	ret

; Completion dispatch. Every handler receives:
;   ebx = slot from user_data, r14 = res (sign extended), r15d = cqe flags.
; Handlers may clobber rbx, r12-r15 but must preserve rbp.
OP_ACCEPT	= 0
OP_RECV		= 1
OP_SEND		= 2
OP_TIMER	= 3
OP_SIGNAL	= 4
OP_IGNORE	= 5
OP_COUNT	= 6

rodata
	align 8
	dispatch_tbl	dq on_accept, on_recv, on_send, on_timer, on_signal, on_ignore
end rodata

ring_reap:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebp,REAP_BUDGET
.next:
	mov	rax,[g_cq_head_ptr]
	mov	ecx,[rax]
	mov	rdx,[g_cq_tail_ptr]
	cmp	ecx,[rdx]
	je	.done
	mov	edx,ecx
	and	edx,[g_cq_mask]
	shl	edx,4
	add	rdx,[g_cqes]
	mov	rbx,[rdx+CQE_USER_DATA]
	movsxd	r14,dword [rdx+CQE_RES]
	mov	r15d,[rdx+CQE_FLAGS]
	inc	ecx
	mov	[rax],ecx			; release the CQE before handling it
	mov	rax,rbx
	shr	rax,32
	mov	ebx,ebx
	cmp	eax,OP_COUNT
	jae	.next
	call	qword [dispatch_tbl+rax*8]
	dec	ebp
	jnz	.next
	; Long batch: hand the kernel what we have queued so far.
	call	ring_flush
	mov	ebp,REAP_BUDGET
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

on_ignore:
	ret
