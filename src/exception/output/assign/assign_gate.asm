
BITS 64
DEFAULT REL

section .text
global _start

_start:
; Set input
; mov [r14], byte 0          ; Include this line to set logical input to 1 (by caching input register)

; Trigger division by zero exception
xor rdx, rdx               ; rdx = 0 (clear rdx for division)
div dl                     ; Divide rax by dl (dl is lower 8 bits of rdx)

; Set output (assign)
movzx rcx, byte [r14]      ; rcx = value at address pointed by r14 (X[0])
mov rdx, rcx               ; Move rcx to rdx for output address calculation
add rdx, r15               ; Add the base address of out1 to rdx (Y[X[0]])
mov dl, byte [rdx]         ; Cache the value at Y[X[0]] by loading it to dl
