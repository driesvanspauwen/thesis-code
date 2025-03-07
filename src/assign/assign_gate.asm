
BITS 64
DEFAULT REL

section .text
global _start

_start:
    ; Exception-based assign gate
    xor rdx, rdx         ; Set rdx to 0
    div rdx              ; Divide by zero to trigger exception
    
    ; Following instructions execute transiently
    mov rcx, [r14]       ; Load input value
    lea rdx, [r14 + rcx] ; Compute output address
    mov dl, [rdx]        ; Load from output address (leaks via cache)
