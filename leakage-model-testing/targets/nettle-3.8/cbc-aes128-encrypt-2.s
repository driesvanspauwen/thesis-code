















































	.file "cbc-aes128-encrypt.asm"

	
	
	

	.text
	.align 16

.globl _nettle_cbc_aes128_encrypt_aesni
.type _nettle_cbc_aes128_encrypt_aesni,%function
_nettle_cbc_aes128_encrypt_aesni: endbr64
	
  

	shr	$4, %rdx
	test	%rdx, %rdx
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
	movups	(%rsi), %xmm11

.Lblock_loop:
	movups	(%r8), %xmm12	
	pxor	%xmm0, %xmm11
	pxor	%xmm12, %xmm11
	aesenc	%xmm1, %xmm11
	aesenc	%xmm2, %xmm11
	aesenc	%xmm3, %xmm11
	aesenc	%xmm4, %xmm11
	aesenc	%xmm5, %xmm11
	aesenc	%xmm6, %xmm11
	aesenc	%xmm7, %xmm11
	aesenc	%xmm8, %xmm11
	aesenc	%xmm9, %xmm11
	aesenclast %xmm10, %xmm11

	movups	%xmm11, (%rcx)
	add	$16, %r8
	add	$16, %rcx

	dec	%rdx
	jnz	.Lblock_loop

	movups	%xmm11, (%rsi)

.Lend:
	
  

	ret
.size _nettle_cbc_aes128_encrypt_aesni, . - _nettle_cbc_aes128_encrypt_aesni



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
