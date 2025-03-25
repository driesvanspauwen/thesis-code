
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
movzx rcx, byte [r13]
add rcx, byte [r15]
mov rcx, al

movzx rcx, byte [r14]
add rcx, byte [r15]
mov rcx, dl
