







































































	
	
	

.globl _nettle_ghash_update_pclmul
.type _nettle_ghash_update_pclmul,%function
_nettle_ghash_update_pclmul: endbr64
	
  

	movdqa		.Lpolynomial(%rip), %xmm0
	movdqa		.Lbswap(%rip), %xmm1
	movups		(%rdi), %xmm2
	movups		16(%rdi), %xmm3
	movups		(%rsi), %xmm5
	pshufb		%xmm1, %xmm5

	sub		$1, %rdx
	jc		.Ldone

.Loop:
	movups		(%rcx), %xmm6
	pshufb		%xmm1, %xmm6
.Lblock:
	pxor		%xmm6, %xmm5
	movdqa		%xmm5, %xmm6
	movdqa		%xmm5, %xmm7
	movdqa		%xmm5, %xmm4
	pclmullqlqdq	%xmm3, %xmm7 	
	pclmullqhqdq	%xmm3, %xmm5	
	pclmulhqlqdq	%xmm2, %xmm4	
	pclmulhqhqdq	%xmm2, %xmm6	
	pxor		%xmm4, %xmm7
	pxor		%xmm6, %xmm5

	pshufd		$0x4e, %xmm7, %xmm4		
	pxor		%xmm4, %xmm5
	pclmullqhqdq	%xmm0, %xmm7
	pxor		%xmm7, %xmm5

	add		$16, %rcx
	sub		$1, %rdx
	jnc		.Loop

.Ldone:
	pshufb		%xmm1, %xmm5
	movups		%xmm5, (%rsi)
	mov		%rcx, %rax
	
  

	ret
.size _nettle_ghash_update_pclmul, . - _nettle_ghash_update_pclmul

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
