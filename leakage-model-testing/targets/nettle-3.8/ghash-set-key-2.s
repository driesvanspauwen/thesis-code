





































    

.globl _nettle_ghash_set_key_pclmul
.type _nettle_ghash_set_key_pclmul,%function
_nettle_ghash_set_key_pclmul: endbr64
	
  

	movdqa	.Lpolynomial(%rip), %xmm0
	movdqa	.Lbswap(%rip), %xmm1
	movups	(%rsi), %xmm2
	pshufb	%xmm1, %xmm2
	
	movdqa	%xmm2, %xmm4
	psllq	$1, %xmm4
	psrlq	$63, %xmm2		
	pshufd	$0xaa, %xmm2, %xmm5	
	pslldq	$8, %xmm2		
	por	%xmm4, %xmm2
	pxor	%xmm4, %xmm4
	psubd	%xmm5, %xmm4		
	pand	%xmm0, %xmm4
	pxor	%xmm4, %xmm2
	movups	%xmm2, (%rdi)

	
	pshufd	$0x4e, %xmm2, %xmm3	
	pclmullqhqdq %xmm0, %xmm2
	pxor	%xmm2, %xmm3
	movups	%xmm3, 16(%rdi)
	
  

	ret
.size _nettle_ghash_set_key_pclmul, . - _nettle_ghash_set_key_pclmul

	.section .rodata
	
	
	
	
	
	.align 16

.Lpolynomial:
	.byte 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xC2
.Lbswap:
	.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0



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
