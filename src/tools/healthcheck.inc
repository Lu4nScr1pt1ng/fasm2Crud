; "fasm2crud healthcheck": the container image has no shell or curl, so the
; binary checks itself. Exit 0 when GET /healthz answers 200 within 2 s.

cstring hc_request, 'GET /healthz HTTP/1.1',13,10,'Host: localhost',13,10,'Connection: close',13,10,13,10
cstring hc_expect, 'HTTP/1.1 200 '

rodata
	align 8
	hc_timeout	dq 2, 0		; struct timeval
end rodata

bss
	hc_buf:	rb 64
end bss

healthcheck_main:
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.fail
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[hc_timeout]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[hc_timeout]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall

	sub	rsp,16
	mov	eax,[g_port]
	xchg	al,ah
	shl	eax,16
	or	eax,AF_INET
	mov	[rsp],eax
	mov	dword [rsp+4],INADDR_LOOPBACK
	mov	qword [rsp+8],0
	mov	edi,ebx
	mov	rsi,rsp
	mov	edx,16
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.fail

	mov	edi,ebx
	lea	rsi,[hc_request]
	mov	edx,hc_request.len
	mov	eax,SYS_write
	syscall
	cmp	rax,hc_request.len
	jne	.fail

	xor	r12d,r12d
.read:
	mov	edi,ebx
	lea	rsi,[hc_buf+r12]
	mov	edx,64
	sub	edx,r12d
	mov	eax,SYS_read
	syscall
	test	rax,rax
	jle	.check
	add	r12d,eax
	cmp	r12d,hc_expect.len
	jb	.read
.check:
	cmp	r12d,hc_expect.len
	jb	.fail
	lea	rsi,[hc_buf]
	lea	rdi,[hc_expect]
	mov	ecx,hc_expect.len
	repe	cmpsb
	jne	.fail
	mov	edi,EXIT_OK
	jmp	exit_process
.fail:
	mov	edi,EXIT_FAILURE
	jmp	exit_process
