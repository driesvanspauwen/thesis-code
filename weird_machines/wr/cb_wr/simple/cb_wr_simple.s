section .data
wr_var: dd 0               ; 32-bit variable for storage

section .text
global write_wr
write_wr:
    test edi, edi          ; test if input value (in edi) is 0
    jz .flush
    mov dword [wr_var], 42 ; store 42 in memory
    ret
.flush:
    lea rax, [wr_var]      ; get address of wr_var
    clflush [rax]          ; flush from cache
    ret

global read_wr 
read_wr:
    push rbx               ; save rbx (will store start time)
    push rbp               ; save rbp (will be aux var pointer)
    sub rsp, 8            ; allocate space for aux variable
    
    lea rdi, [rsp]        ; pointer for aux variable
    rdtscp                ; get start time
    mov ebx, eax          ; save start time
    
    mov eax, [wr_var]     ; read the variable (cache access we're timing)
    
    lea rdi, [rsp]        ; pointer for aux again
    rdtscp                ; get end time
    
    sub eax, ebx          ; calculate time difference
    cmp eax, 99           ; compare with threshold
    setbe al              ; set al to 1 if below/equal threshold, 0 if above
    
    add rsp, 8            ; cleanup stack
    pop rbp
    pop rbx
    ret