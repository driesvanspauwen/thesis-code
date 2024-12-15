



















































	.file "cbc-aes256-encrypt.asm"

	
	
	

	.text
	.align 16

.globl _nettle_cbc_aes256_encrypt_aesni
.type _nettle_cbc_aes256_encrypt_aesni,%function
_nettle_cbc_aes256_encrypt_aesni: endbr64
	
  

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
	movups	128(%rdi), %xmm7
	movups	144(%rdi), %xmm8
	movups	160(%rdi), %xmm9
	movups	176(%rdi), %xmm10
	movups	192(%rdi), %xmm11
	movups	208(%rdi), %xmm12
	movups	224(%rdi), %xmm13
	movups	(%rsi), %xmm14

.Lblock_loop:
	movups	(%r8), %xmm15	
	pxor	%xmm0, %xmm14
	movups	112(%rdi), %xmm0
	pxor	%xmm15, %xmm14
	aesenc	%xmm1, %xmm14
	aesenc	%xmm2, %xmm14
	aesenc	%xmm3, %xmm14
	aesenc	%xmm4, %xmm14
	aesenc	%xmm5, %xmm14
	aesenc	%xmm6, %xmm14
	aesenc	%xmm0, %xmm14
	movups	(%rdi), %xmm0
	aesenc	%xmm7, %xmm14
	aesenc	%xmm8, %xmm14
	aesenc	%xmm9, %xmm14
	aesenc	%xmm10, %xmm14
	aesenc	%xmm11, %xmm14
	aesenc	%xmm12, %xmm14
	aesenclast %xmm13, %xmm14

	movups	%xmm14, (%rcx)
	add	$16, %r8
	add	$16, %rcx

	dec	%rdx
	jnz	.Lblock_loop

	movups	%xmm14, (%rsi)

.Lend:
	
  

	ret
.size _nettle_cbc_aes256_encrypt_aesni, . - _nettle_cbc_aes256_encrypt_aesni



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
