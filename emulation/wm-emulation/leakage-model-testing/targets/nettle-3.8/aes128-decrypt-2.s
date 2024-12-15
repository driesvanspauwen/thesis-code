














































	.file "aes128-decrypt.asm"

	
	
	

	.text
	.align 16

.globl _nettle_aes128_decrypt_aesni
.type _nettle_aes128_decrypt_aesni,%function
_nettle_aes128_decrypt_aesni: endbr64
	
  

	shr	$4, %rsi
	test	%rsi, %rsi
	jz	.Lend

	movups	(%rdi), %xmm0
	movups	16(%rdi), %xmm1
	movups	32(%rdi), %xmm2
	movups	48(%rdi), %xmm3
	movups	64(%rdi), %xmm4
	movups	80(%rdi), %xmm5
	movups	96(%rdi), %xmm6
	movups	112(%rdi), %xmm7
	movups	128(%rdi), %xmm8
	movups	144(%rdi), %xmm9
	movups	160(%rdi), %xmm10
	shr	%rsi
	jnc	.Lblock_loop

	movups	(%rcx), %xmm11
	pxor	%xmm0, %xmm11
	aesdec	%xmm1, %xmm11
	aesdec	%xmm2, %xmm11
	aesdec	%xmm3, %xmm11
	aesdec	%xmm4, %xmm11
	aesdec	%xmm5, %xmm11
	aesdec	%xmm6, %xmm11
	aesdec	%xmm7, %xmm11
	aesdec	%xmm8, %xmm11
	aesdec	%xmm9, %xmm11
	aesdeclast %xmm10, %xmm11

	movups	%xmm11, (%rdx)
	add	$16, %rcx
	add	$16, %rdx
	test	%rsi, %rsi
	jz	.Lend

.Lblock_loop:
	movups	(%rcx), %xmm11
	movups	16(%rcx), %xmm12
	pxor	%xmm0, %xmm11
	pxor	%xmm0, %xmm12
	aesdec	%xmm1, %xmm11
	aesdec	%xmm1, %xmm12
	aesdec	%xmm2, %xmm11
	aesdec	%xmm2, %xmm12
	aesdec	%xmm3, %xmm11
	aesdec	%xmm3, %xmm12
	aesdec	%xmm4, %xmm11
	aesdec	%xmm4, %xmm12
	aesdec	%xmm5, %xmm11
	aesdec	%xmm5, %xmm12
	aesdec	%xmm6, %xmm11
	aesdec	%xmm6, %xmm12
	aesdec	%xmm7, %xmm11
	aesdec	%xmm7, %xmm12
	aesdec	%xmm8, %xmm11
	aesdec	%xmm8, %xmm12
	aesdec	%xmm9, %xmm11
	aesdec	%xmm9, %xmm12
	aesdeclast %xmm10, %xmm11
	aesdeclast %xmm10, %xmm12

	movups	%xmm11, (%rdx)
	movups	%xmm12, 16(%rdx)
	add	$32, %rcx
	add	$32, %rdx
	dec	%rsi
	jnz	.Lblock_loop

.Lend:
	
  

	ret
.size _nettle_aes128_decrypt_aesni, . - _nettle_aes128_decrypt_aesni



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
