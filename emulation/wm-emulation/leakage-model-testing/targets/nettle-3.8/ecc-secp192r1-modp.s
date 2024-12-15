




















	.file "ecc-secp192r1-modp.asm"




 







	
	.text
	.align 16

.globl _nettle_ecc_secp192r1_modp
.type _nettle_ecc_secp192r1_modp,%function
_nettle_ecc_secp192r1_modp: endbr64
	
  

	mov	16(%rdx), %rax
	mov	24(%rdx), %r8
	mov	40(%rdx), %r9
	xor	%r10, %r10
	xor	%r11, %r11

	add	%r9, %rax
	adc	%r9, %r8
	
	setc	%r11b
	
	mov	8(%rdx), %rcx
	mov	32(%rdx), %r9
	adc	%r9, %rcx
	adc	%r9, %rax
	
	setc	%r10b
	
	mov	(%rdx), %rdi
	adc	%r8, %rdi
	adc	%r8, %rcx
	adc	$0, %r11

	
	add	%r10, %rcx
	adc	%r11, %rax
	setc	%r10b

	
	adc	$0, %rdi
	adc	%r10, %rcx
	adc	$0, %rax

	mov	%rdi, (%rsi)
	mov	%rcx, 8(%rsi)
	mov	%rax, 16(%rsi)

	
  

	ret
.size _nettle_ecc_secp192r1_modp, . - _nettle_ecc_secp192r1_modp


	.pushsection ".note.gnu.property", "a"
	.p2align 3
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	.asciz "GNU"
1:
	.p2align 3
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align 3
4:
	.popsection
.section .note.GNU-stack,"",%progbits
