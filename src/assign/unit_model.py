ASM_HEADER = """
.intel_syntax noprefix
.test_case_enter:
.section .data.main
"""

ASM_ASSIGN_GATE_TRUE = ASM_HEADER + """
; Initialize memory regions
mov byte ptr [r14], 1        ; in[0] = 1 (input true)
mov byte ptr [r14 + 8], 42   ; out1[0] = 42
mov byte ptr [r14 + 16], 84  ; out2[0] = 84

; Setup pointers for assign_gate
mov r10, r14                 ; r10 = pointer to in
mov r11, r14                 ; r11 = pointer to out1
add r11, 8
mov r12, r14                 ; r12 = pointer to out2
add r12, 16

; Execute the assign_gate
xor rdx, rdx                 ; Clear rdx (prepare for division by zero)
div dl                       ; Divide by zero to cause exception

; These instructions would execute speculatively
movzx rcx, byte ptr [r10]    ; Load in[0] into rcx
mov rdx, rcx                 ; Copy to rdx
add rdx, r11                 ; Calculate out1 + in[0]
mov dl, byte ptr [rdx]       ; Load out1[in[0]] into dl
add rcx, r12                 ; Calculate out2 + in[0]
mov cl, byte ptr [rcx]       ; Load out2[in[0]] into cl
"""