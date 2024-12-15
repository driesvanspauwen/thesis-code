




















	.file "ecc-secp224r1-modp.asm"





	




	



	
.globl _nettle_ecc_secp224r1_modp
.type _nettle_ecc_secp224r1_modp,%function
_nettle_ecc_secp224r1_modp: endbr64
	
  

	push	%rsi

	mov	48(%rdx), %rax
	mov	56(%rdx), %r8
	
	mov	%rax, %rsi
	mov	%rax, %r10
	shl	$32, %rsi
	shr	$32, %r10
	mov	%r8, %r11
	mov	%r8, %rdi
	shl	$32, %rdi
	shr	$32, %r11
	or	%rdi, %r10

	xor	%r9, %r9
	mov	16(%rdx), %rdi
	mov	24(%rdx), %rcx
	sub	%rsi, %rdi
	sbb	%r10, %rcx
	sbb	%r11, %rax
	sbb	$0, %r8		

	adc	32(%rdx), %rax
	adc	40(%rdx), %r8
	adc	$0, %r9

	
	
	mov	%rax, %rsi
	mov	%rax, %r10
	add	%rdi, %rax
	mov	%r8, %r11
	mov	%r8, %rdi
	adc	%rcx, %r8
	mov	%r9, %rcx
	adc	$0, %r9

	
	shl	$32, %rsi
	shr	$32, %r10
	shl	$32, %rdi
	shr	$32, %r11
	shl	$32, %rcx
	or	%rdi, %r10
	or	%rcx, %r11

	mov	(%rdx), %rdi
	mov	8(%rdx), %rcx
	sub	%rsi, %rdi
	sbb	%r10, %rcx
	sbb	%r11, %rax
	sbb	$0, %r8
	sbb	$0, %r9

	
	
	
	

	mov	%r8, %rsi
	mov	%r8, %r10
	mov	%r9, %r11
	movl	%r8d, %r8d	
	sub	%r8, %r10			
	shr	$32, %rsi
	shl	$32, %r9
	or	%r9, %rsi

	sub	%rsi, %rdi
	sbb	$0, %r10
	sbb	$0, %r11
	add	%r10, %rcx
	adc	%r11, %rax
	adc	$0, %r8

	pop	%rsi
	mov	%rdi, (%rsi)
	mov	%rcx, 8(%rsi)
	mov	%rax, 16(%rsi)
	mov	%r8, 24(%rsi)

	
  

	ret
.size _nettle_ecc_secp224r1_modp, . - _nettle_ecc_secp224r1_modp


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
