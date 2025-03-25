
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
movzx rcx, byte [r13]     ; Load the first input byte into rcx
add rcx, r15              ; Add r15 (output base address) to rcx
mov rcx, al               ; Store something in rcx (side effect: cache the address)

movzx rcx, byte [r14]     ; Load the second input byte into rcx
add rcx, r15              ; Add r15 (output base address) to rcx
mov rcx, dl               ; Store something in rcx (side effect: cache the address)
