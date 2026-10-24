; Cached "Date:" header (RFC 9110 5.6.7 IMF-fixdate), rebuilt once per tick.

DATE_LINE_LEN = 37			; "Date: " + 29 + CRLF

bss
	g_date_line:	rb 40
end bss

rodata
	day_names	db 'Thu,Fri,Sat,Sun,Mon,Tue,Wed,'	; 1970-01-01 was a Thursday
	month_names	db 'JanFebMarAprMayJunJulAugSepOctNovDec'
	month_days	db 31,28,31,30,31,30,31,31,30,31,30,31
end rodata

date_init:
	mov	dword [g_date_line],'Date'
	mov	word [g_date_line+4],': '
	mov	word [g_date_line+35],0x0A0D

date_update:
	sub	rsp,24
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,24
	lea	rdi,[g_date_line+6]
	jmp	format_http_date

; rax = unix seconds, rdi = destination (29 bytes):
; "Sun, 06 Nov 1994 08:49:37 GMT"
format_http_date:
	push	rbx
	mov	rbx,rdi
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	mov	r8,rdx				; seconds into the day
	mov	r9,rax				; days since the epoch

	xor	edx,edx
	mov	ecx,7
	div	rcx
	mov	eax,dword [day_names+rdx*4]
	mov	[rbx],eax
	mov	byte [rbx+4],' '

	; Year: walk forward from 1970 (at most a few hundred steps, once a second).
	mov	r10d,1970
.year:
	mov	edi,r10d
	call	is_leap_year
	lea	r11d,[365+rax]
	cmp	r9,r11
	jb	.month
	sub	r9,r11
	inc	r10d
	jmp	.year
.month:
	mov	esi,eax				; 1 in leap years
	xor	edx,edx
.next_month:
	movzx	ecx,byte [month_days+rdx]
	cmp	edx,1
	jne	@f
	add	ecx,esi
@@:
	cmp	r9,rcx
	jb	.write
	sub	r9,rcx
	inc	edx
	jmp	.next_month
.write:
	lea	rdi,[rbx+5]
	lea	eax,[r9+1]
	call	put2
	mov	byte [rbx+7],' '
	lea	rcx,[rdx+rdx*2]
	mov	ax,word [month_names+rcx]
	mov	[rbx+8],ax
	mov	al,[month_names+rcx+2]
	mov	[rbx+10],al
	mov	byte [rbx+11],' '
	mov	eax,r10d
	xor	edx,edx
	mov	ecx,100
	div	ecx
	push	rdx
	lea	rdi,[rbx+12]
	call	put2
	pop	rax
	lea	rdi,[rbx+14]
	call	put2
	mov	byte [rbx+16],' '

	mov	rax,r8
	xor	edx,edx
	mov	ecx,3600
	div	ecx
	push	rdx
	lea	rdi,[rbx+17]
	call	put2
	mov	byte [rbx+19],':'
	pop	rax
	xor	edx,edx
	mov	ecx,60
	div	ecx
	push	rdx
	lea	rdi,[rbx+20]
	call	put2
	mov	byte [rbx+22],':'
	pop	rax
	lea	rdi,[rbx+23]
	call	put2
	mov	dword [rbx+25],' GMT'
	pop	rbx
	ret

; edi = year. eax = 1 for leap years, else 0.
is_leap_year:
	xor	eax,eax
	test	edi,3
	jnz	.done
	push	rdx
	push	rcx
	mov	eax,edi
	xor	edx,edx
	mov	ecx,100
	div	ecx
	test	edx,edx
	jnz	.leap
	mov	eax,edi
	xor	edx,edx
	mov	ecx,400
	div	ecx
	xor	eax,eax
	test	edx,edx
	jnz	.restore
.leap:
	mov	eax,1
.restore:
	pop	rcx
	pop	rdx
.done:
	ret

; eax = 0..99, rdi = destination. Writes two digits; preserves rdx.
put2:
	push	rdx
	xor	edx,edx
	mov	ecx,10
	div	ecx
	add	al,'0'
	add	dl,'0'
	mov	[rdi],al
	mov	[rdi+1],dl
	pop	rdx
	ret
