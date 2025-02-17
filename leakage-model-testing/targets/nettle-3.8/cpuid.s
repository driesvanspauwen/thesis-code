
























	.file "cpuid.asm"

	

	.text
	.align 16

.globl _nettle_cpuid
.type _nettle_cpuid,%function
_nettle_cpuid: endbr64
	
  

	push	%rbx

	movl	%edi, %eax
	xorl	%ecx, %ecx      
	cpuid
	mov	%eax, (%rsi)
	mov	%ebx, 4(%rsi)
	mov	%ecx, 8(%rsi)
	mov	%edx, 12(%rsi)

	pop	%rbx
	
  

	ret
.size _nettle_cpuid, . - _nettle_cpuid



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
