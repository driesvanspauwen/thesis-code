
BITS 64
DEFAULT REL

section .text
global _start

_start:
mov [r14], byte 0          ; Caches the input register (sets input of assign gate to 1)
xor rdx, rdx               ; rdx = 0 (clear rdx for division)
div dl                     ; Divide rax by dl (rdx = 0)
movzx rcx, byte [r14]      ; rcx = value at address pointed by r14
mov rdx, rcx               ; Move rcx to rdx for output address calculation
add rdx, r15               ; Add the base address of out1 to rdx
mov dl, byte [rdx]         ; Load the value from memory at the calculated address into dl
