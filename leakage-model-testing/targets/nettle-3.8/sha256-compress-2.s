

























	.file "sha256-compress.asm"




	









	








	
	

	.text
	.align 16

.Lswap_mask:
	.byte 3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
.globl _nettle_sha256_compress_sha_ni
.type _nettle_sha256_compress_sha_ni,%function
_nettle_sha256_compress_sha_ni: endbr64
	
  

	movups	(%rdi), %xmm9
	movups	16(%rdi), %xmm5

	pshufd	$0x1b, %xmm9, %xmm9
	pshufd	$0x1b, %xmm5, %xmm5

	
	movdqa	%xmm5, %xmm6
	punpckhqdq %xmm9, %xmm5
	punpcklqdq %xmm9, %xmm6


	movdqa	.Lswap_mask(%rip), %xmm9

	movdqa	%xmm5, %xmm7
	movdqa	%xmm6, %xmm8

	movups	(%rsi), %xmm1
	pshufb	%xmm9, %xmm1

	movdqa	(%rdx), %xmm0
	paddd	%xmm1, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		

	movups	16(%rsi), %xmm2
	pshufb	%xmm9, %xmm2

	movdqa	16(%rdx), %xmm0
	paddd	%xmm2, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		
	sha256msg1 %xmm2, %xmm1

	movups	32(%rsi), %xmm3
	pshufb	%xmm9, %xmm3

	movdqa	32(%rdx), %xmm0
	paddd	%xmm3, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		
	sha256msg1 %xmm3, %xmm2

	movups	48(%rsi), %xmm4
	pshufb	%xmm9, %xmm4

	
	movdqa	48(%rdx), %xmm0
	paddd	%xmm4, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm4, %xmm9
	palignr	$4, %xmm3, %xmm9
	paddd	%xmm9, %xmm1
	sha256msg2 %xmm4, %xmm1
	sha256msg1 %xmm4, %xmm3
		
	
	movdqa	64(%rdx), %xmm0
	paddd	%xmm1, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm1, %xmm9
	palignr	$4, %xmm4, %xmm9
	paddd	%xmm9, %xmm2
	sha256msg2 %xmm1, %xmm2
	sha256msg1 %xmm1, %xmm4
	
	
	movdqa	80(%rdx), %xmm0
	paddd	%xmm2, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm2, %xmm9
	palignr	$4, %xmm1, %xmm9
	paddd	%xmm9, %xmm3
	sha256msg2 %xmm2, %xmm3
	sha256msg1 %xmm2, %xmm1
	
	
	movdqa	96(%rdx), %xmm0
	paddd	%xmm3, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm3, %xmm9
	palignr	$4, %xmm2, %xmm9
	paddd	%xmm9, %xmm4
	sha256msg2 %xmm3, %xmm4
	sha256msg1 %xmm3, %xmm2
	
	
	movdqa	112(%rdx), %xmm0
	paddd	%xmm4, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm4, %xmm9
	palignr	$4, %xmm3, %xmm9
	paddd	%xmm9, %xmm1
	sha256msg2 %xmm4, %xmm1
	sha256msg1 %xmm4, %xmm3
	
	
	movdqa	128(%rdx), %xmm0
	paddd	%xmm1, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm1, %xmm9
	palignr	$4, %xmm4, %xmm9
	paddd	%xmm9, %xmm2
	sha256msg2 %xmm1, %xmm2
	sha256msg1 %xmm1, %xmm4
	
	
	movdqa	144(%rdx), %xmm0
	paddd	%xmm2, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm2, %xmm9
	palignr	$4, %xmm1, %xmm9
	paddd	%xmm9, %xmm3
	sha256msg2 %xmm2, %xmm3
	sha256msg1 %xmm2, %xmm1
	
	
	movdqa	160(%rdx), %xmm0
	paddd	%xmm3, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm3, %xmm9
	palignr	$4, %xmm2, %xmm9
	paddd	%xmm9, %xmm4
	sha256msg2 %xmm3, %xmm4
	sha256msg1 %xmm3, %xmm2
	
	
	movdqa	176(%rdx), %xmm0
	paddd	%xmm4, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm4, %xmm9
	palignr	$4, %xmm3, %xmm9
	paddd	%xmm9, %xmm1
	sha256msg2 %xmm4, %xmm1
	sha256msg1 %xmm4, %xmm3
	
	
	movdqa	192(%rdx), %xmm0
	paddd	%xmm1, %xmm0
	sha256rnds2 %xmm5, %xmm6
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5
	movdqa	%xmm1, %xmm9
	palignr	$4, %xmm4, %xmm9
	paddd	%xmm9, %xmm2
	sha256msg2 %xmm1, %xmm2
	sha256msg1 %xmm1, %xmm4
	

	movdqa	208(%rdx), %xmm0
	paddd	%xmm2, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		
	movdqa	%xmm2, %xmm9
	palignr	$4, %xmm1, %xmm9
	paddd	%xmm9, %xmm3
	sha256msg2 %xmm2, %xmm3

	movdqa	224(%rdx), %xmm0
	paddd	%xmm3, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		
	movdqa	%xmm3, %xmm9
	palignr	$4, %xmm2, %xmm9
	paddd	%xmm9, %xmm4
	sha256msg2 %xmm3, %xmm4

	movdqa	240(%rdx), %xmm0
	paddd	%xmm4, %xmm0
	sha256rnds2 %xmm5, %xmm6		
	pshufd	$0xe, %xmm0, %xmm0
	sha256rnds2 %xmm6, %xmm5		

	paddd %xmm7, %xmm5
	paddd %xmm8, %xmm6

	
	movdqa	%xmm6, %xmm9
	punpckhqdq %xmm5, %xmm6
	punpcklqdq %xmm5, %xmm9


	pshufd	$0x1b, %xmm6, %xmm6
	pshufd	$0x1b, %xmm9, %xmm9
	movups	%xmm6, 0(%rdi)
	movups	%xmm9, 16(%rdi)

	
  

	ret
.size _nettle_sha256_compress_sha_ni, . - _nettle_sha256_compress_sha_ni



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
