; Input rules for accounts.

EMAIL_MIN	= 3
EMAIL_MAX	= 254
EMAIL_LOCAL_MAX	= 64
PASSWORD_MIN	= 8
PASSWORD_MAX	= 128		; bytes of UTF-8

rodata
	; RFC 5322 atext, plus '.': what we accept in an address.
	email_char_tbl:
	repeat 256, c:0
		if (c >= '0' & c <= '9') | (c >= 'a' & c <= 'z') | (c >= 'A' & c <= 'Z') | \
		   c = '!' | c = '#' | c = '$' | c = '%' | c = '&' | c = "'" | c = '*' | \
		   c = '+' | c = '-' | c = '/' | c = '=' | c = '?' | c = '^' | c = '_' | \
		   c = '`' | c = '{' | c = '|' | c = '}' | c = '~' | c = '.'
			db 1
		else
			db 0
		end if
	end repeat
end rodata

; rdi = address, esi = length. Lowercases it in place.
; eax = 1 when it is a plausible address: local@domain, one '@', allowed
; characters only, domain with a dot, no empty labels.
email_normalize:
	xor	eax,eax
	cmp	esi,EMAIL_MIN
	jb	.done
	cmp	esi,EMAIL_MAX
	ja	.done
	xor	ecx,ecx
	mov	r8d,-1				; position of '@'
.char:
	cmp	ecx,esi
	jae	.scanned
	movzx	edx,byte [rdi+rcx]
	cmp	dl,'@'
	je	.at
	cmp	byte [email_char_tbl+rdx],0
	je	.no
	lea	r9d,[rdx-'A']
	cmp	r9d,'Z'-'A'
	ja	@f
	or	byte [rdi+rcx],0x20
@@:
	inc	ecx
	jmp	.char
.at:
	cmp	r8d,-1
	jne	.no				; a second '@'
	mov	r8d,ecx
	inc	ecx
	jmp	.char
.scanned:
	; local part: 1..64, no leading/trailing dot, no ".."
	test	r8d,r8d
	jle	.no
	cmp	r8d,EMAIL_LOCAL_MAX
	ja	.no
	mov	rdx,rdi
	mov	ecx,r8d
	call	.labels
	jc	.no
	; domain: at least one dot, same label rules
	lea	rdx,[rdi+r8+1]
	mov	ecx,esi
	sub	ecx,r8d
	dec	ecx
	jz	.no
	xor	r9d,r9d
	xor	r10d,r10d
@@:
	cmp	r10d,ecx
	jae	@f
	cmp	byte [rdx+r10],'.'
	sete	r11b
	or	r9b,r11b
	inc	r10d
	jmp	@b
@@:
	test	r9b,r9b
	jz	.no
	call	.labels
	jc	.no
	mov	eax,1
.done:
	ret
.no:
	xor	eax,eax
	ret

; rdx = text, ecx = length: CF when it starts or ends with '.' or has "..".
.labels:
	cmp	byte [rdx],'.'
	je	.bad_label
	cmp	byte [rdx+rcx-1],'.'
	je	.bad_label
	xor	r10d,r10d
@@:
	inc	r10d
	cmp	r10d,ecx
	jae	@f
	cmp	word [rdx+r10-1],'..'
	je	.bad_label
	jmp	@b
@@:
	clc
	ret
.bad_label:
	stc
	ret

; esi = password length in bytes (already valid UTF-8). eax = 1 when ok.
password_acceptable:
	xor	eax,eax
	cmp	esi,PASSWORD_MIN
	jb	.done
	cmp	esi,PASSWORD_MAX
	ja	.done
	mov	eax,1
.done:
	ret
