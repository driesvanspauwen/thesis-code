section .data
    fmt_write db "Writing %d to register", 10, 0
    fmt_read db "Read value from register: %d", 10, 0
    fmt_timing db "Access time: %llu cycles", 10, 0

section .text
extern printf
extern write_weird_register
extern read_weird_register
global main

main:
    push rbp
    mov rbp, rsp
    sub rsp, 32          ; Align stack for function calls

    ; Test writing 1
    mov rdi, fmt_write
    mov rsi, 1
    xor rax, rax
    call printf

    mov rdi, 1
    call write_weird_register

    ; Read and print result
    call read_weird_register
    mov rsi, rax          ; Result in rax
    mov rdi, fmt_read
    xor rax, rax
    call printf

    ; Test writing 0
    mov rdi, fmt_write
    mov rsi, 0
    xor rax, rax
    call printf

    mov rdi, 0
    call write_weird_register

    ; Read and print result
    call read_weird_register
    mov rsi, rax
    mov rdi, fmt_read
    xor rax, rax
    call printf

    ; Clean exit
    xor eax, eax
    leave
    ret