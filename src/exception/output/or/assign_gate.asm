
BITS 64
DEFAULT REL

section .text
global _start

_start:
; Set inputs
mov [r13], byte 0
mov [r14], byte 0

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
