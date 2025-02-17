section .data
    wr_var dd 0              ; Our cache-based register variable
    cache_hit_threshold dd 100

section .text
global write_weird_register
global read_weird_register

write_weird_register:
    ; Input value in rdi (first parameter in x64 calling convention)
    test rdi, rdi           ; Test if input is 0
    jz .write_zero
    
    ; Write 1 (cache the value)
    mov dword [wr_var], 42
    ret

.write_zero:
    ; Write 0 (flush from cache)
    clflush [wr_var]
    ret

read_weird_register:
    ; Save registers we'll use
    push rbx
    
    ; First RDTSCP
    rdtscp                  ; Returns TSC in EDX:EAX, processor ID in ECX
    mov rbx, rax           ; Save first timestamp
    
    ; Memory read
    mov eax, [wr_var]      ; Read the variable
    
    ; Second RDTSCP
    rdtscp
    sub rax, rbx           ; Calculate time difference
    
    ; Compare with threshold
    cmp rax, [cache_hit_threshold]
    setb al                ; Set al to 1 if below threshold, 0 otherwise
    movzx eax, al          ; Zero-extend al to eax for return value
    
    ; Restore registers and return
    pop rbx
    ret