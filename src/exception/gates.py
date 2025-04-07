ASM_START = """
BITS 64
DEFAULT REL

section .text
global _start

_start:
"""

ASM_EXCEPTION_ASSIGN = """
; Trigger division by zero exception
xor rdx, rdx               ; rdx = 0 (clear rdx for division)
div dl                     ; Divide rax by dl (dl is lower 8 bits of rdx)

; Set output (assign)
movzx rcx, byte [r14]      ; rcx = value at address pointed by r14 (X[0])
mov rdx, rcx               ; Move rcx to rdx for output address calculation
add rdx, r15               ; Add the base address of out1 to rdx (Y[X[0]])
mov dl, byte [rdx]         ; Cache the value at Y[X[0]] by loading it to dl
"""

def get_asm_exception_assign(in1):
    res = ASM_START
    if in1: 
        res += "mov [r14], byte 0\n"
    res += ASM_EXCEPTION_ASSIGN
    return res

ASM_EXCEPTION_OR = """
; Trigger division by zero exception
xor rdx, rdx
div dl

; Set output (OR)
movzx rcx, byte [r13] ; Load the first input byte into rcx
add rcx, r15          ; Add r15 (output base address) to rcx
mov al, byte [rcx]    ; Access memory at rcx, causing cache side effect

movzx rcx, byte [r14] ; Load the second input byte into rcx
add rcx, r15          ; Add r15 (output base address) to rcx
mov dl, byte [rcx]    ; Access memory at rcx, causing cache side effect
"""

def get_asm_exception_or(in1, in2):
    res = ASM_START
    if in1: 
        res += "mov [r13], byte 0\n"
    if in2:
        res += "mov [r14], byte 0\n"
    res += ASM_EXCEPTION_OR
    return res