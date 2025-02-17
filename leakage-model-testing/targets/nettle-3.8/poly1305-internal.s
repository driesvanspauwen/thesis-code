




















	.file "poly1305-internal.asm"


 



	
	.text
	.align 16

.globl _nettle_poly1305_set_key
.type _nettle_poly1305_set_key,%function
_nettle_poly1305_set_key: endbr64
	
  

	mov	$0x0ffffffc0fffffff,  %r8
	mov	(%rsi), %rax
	and	 %r8, %rax
	and	$-4,  %r8
	mov	%rax, 0 (%rdi)
	imul	$5, %rax
	mov	%rax, 16 (%rdi)	
	mov	8(%rsi), %rax
	and	 %r8, %rax
	mov	%rax, 8 (%rdi)
	shr	$2, %rax
	imul	$5, %rax
	mov	%rax, 24 (%rdi)	
	xor	%eax, %eax
	mov	%rax, 32 (%rdi)
	mov	%rax, 40 (%rdi)
	mov	%rax, 48 (%rdi)
	
	
  

	ret




.size _nettle_poly1305_set_key, . - _nettle_poly1305_set_key


	






















	
	
.globl _nettle_poly1305_block
.type _nettle_poly1305_block,%function
_nettle_poly1305_block: endbr64
	
  

	push	%r12
	mov	(%rsi), %rcx
	mov	8(%rsi), %rsi
	mov	%edx, %r8d	

	add	32 (%rdi), %rcx
	adc	40 (%rdi), %rsi
	adc	48 (%rdi), %r8

	mov	8 (%rdi), %rax
	mul	%rcx			
	mov	%rax, %r11
	mov	%rdx, %r12

	mov	%rcx, %rax		
	mov	0 (%rdi), %rcx
	mul	%rcx			
	mov	%rax, %r9
	mov	%rdx, %r10

	mov	%rsi, %rax
	mul	%rcx			
	add	%rax, %r11
	adc	%rdx, %r12

	mov	24 (%rdi), %rcx
	mov	%rsi, %rax		
	mul	%rcx			
	add	%rax, %r9
	adc	%rdx, %r10

	mov	%r8, %rax
	mul	%rcx			
	add	%rax, %r11
	adc	%rdx, %r12

	mov	$3, %esi
	and	%r8, %rsi

	shr	$2, %r8
	mov	16 (%rdi), %rax
	mul	%r8			
	add	%rax, %r9
	adc	%rdx, %r10

	imul	0 (%rdi), %rsi	
	add	%r11, %r10
	adc	%rsi, %r12

	mov	%r9, 32 (%rdi)
	mov	%r10, 40 (%rdi)
	mov	%r12, 48 (%rdi)
	pop	%r12
	
  

	ret
.size _nettle_poly1305_block, . - _nettle_poly1305_block








	







	

.globl _nettle_poly1305_digest
.type _nettle_poly1305_digest,%function
_nettle_poly1305_digest: endbr64
	
  


	mov	32 (%rdi), %r9
	mov	40 (%rdi), %r10
	mov	48 (%rdi), %r11

	xor	%eax, %eax
	mov	%rax, 32 (%rdi)
	mov	%rax, 40 (%rdi)
	mov	%rax, 48 (%rdi)

	mov	$3, %eax
	and 	%r11d, %eax
	shr	$2, %r11
	imul	$5, %r11
	add	%r11, %r9
	adc	$0, %r10
	adc	$0, %eax

	
	mov	$5, %rcx
	xor	%r8, %r8
	add	%r9, %rcx
	adc	%r10, %r8
	adc	$-4, %eax		
	cmovc	%rcx, %r9
	cmovc	%r8, %r10

	add	%r9, (%rsi)
	adc	%r10, 8(%rsi)

	
  

	ret
.size _nettle_poly1305_digest, . - _nettle_poly1305_digest



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
