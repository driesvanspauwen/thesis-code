




















	.file "ecc-25519-modp.asm"


	
	







.globl _nettle_ecc_curve25519_modp
.type _nettle_ecc_curve25519_modp,%function
_nettle_ecc_curve25519_modp: endbr64
	
  

	push	%rbx
	push	%rsi
	mov	%rdx, %rsi

	
	mov	56(%rsi), %rax
	mov	$38, %rbx
	mul	%rbx
	mov	24(%rsi), %r9
	xor	%r10, %r10
	add	%rax, %r9
	adc	%rdx, %r10

	mov	40(%rsi), %rax	
	mul	%rbx
	
	add	%r9, %r9
	adc	%r10, %r10
	shr	%r9		

	
	imul	$19, %r10

	mov	(%rsi), %rdi
	mov	8(%rsi), %rcx
	mov	16(%rsi), %r8
	add	%r10, %rdi
	adc	%rax, %rcx
	mov	32(%rsi), %rax
	adc	%rdx, %r8
	adc	$0, %r9

	
	mul	%rbx
	mov	%rax, %r10
	mov	48(%rsi), %rax
	mov	%rdx, %r11
	mul	%rbx

	pop	%rsi

	add	%r10, %rdi
	mov	%rdi, (%rsi)
	adc	%r11, %rcx
	mov	%rcx, 8(%rsi)
	adc	%rax, %r8
	mov	%r8, 16(%rsi)
	adc	%rdx, %r9
	mov	%r9, 24(%rsi)

	pop	%rbx
	
  

	ret
.size _nettle_ecc_curve25519_modp, . - _nettle_ecc_curve25519_modp


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
