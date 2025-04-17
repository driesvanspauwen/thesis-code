// g++ -O2 -o nand_test.elf nand_test.cpp -lm
// objdump -M intel -d nand_test.elf > objdump.txt
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <argp.h>
#include <time.h>
#include <csignal>
#include <vector>
#include <x86intrin.h>

#define NOP "0x90"
#define NOP4 "0x90,0x90,0x90,0x90"
#define NOP16 NOP4 "," NOP4 "," NOP4 "," NOP4
#define NOP64 NOP16 "," NOP16 "," NOP16 "," NOP16
#define NOP256 NOP64 "," NOP64 "," NOP64 "," NOP64
#define NOPs(data) asm volatile(".byte " data ::: "memory");

#define THRESHOLD 180

uint8_t in1[4*512];
uint8_t in2[4*512];
uint8_t out[4*512];
uint8_t tmp_reg1[4*512];
uint8_t tmp_reg2[4*512];
uint8_t tmp_reg3[4*512];
uint8_t tmp_reg4[4*512];

inline uint64_t timer(uint8_t* ptr) {
    uint64_t clk;
    asm volatile (
        "rdtscp\n\t"
        "shl $32, %%rdx\n\t"
        "mov %%rdx, %%rsi\n\t"
        "or %%eax, %%esi\n\t"
        "mov %1, %%al\n\t"
        "rdtscp\n\t"
        "shl $32, %%rdx\n\t"
        "or %%eax, %%edx\n\t"
        "sub %%rsi, %%rdx\n\t"
        "mov %%rdx, %0\n\t"
        : "=r" (clk)
        : "m" (ptr[0])
        : "rcx", "rdx", "rsi", "eax"
    );
    return clk;
}

inline void assign(uint8_t* ptr, int input) {
    if (input) { ptr[0] = 0; }
    else { _mm_clflush(ptr); }
}

inline void and_gate(uint8_t* in1, uint8_t* in2, uint8_t* out) {
    asm volatile (
        "xor %%rdx, %%rdx\n\t"          // ax /= 0
        "div %%dl\n\t"
        "movzxb (%[in1]), %%rcx\n\t"    // dl = in2[in1[0]]
        "add %[in2], %%rcx\n\t"
        "movzxb (%%rcx), %%rdx\n\t"
        "add %[out], %%rdx\n\t"         // dl = out[rdx]
        "mov (%%rdx), %%dl\n\t"
        : : [in1] "r"(in1), [in2] "r"(in2), [out] "r"(out) : "rax", "rcx", "rdx"
    );
    NOPs(NOP256);
}

inline void not_gate(uint8_t* in1, uint8_t* in2, uint8_t* out, uint8_t* delay) {
    asm volatile (
        "movzxb (%[in1]), %%rdx\n\t"     // ax /= byte in2[in1[0]]
        "add %[in2], %%rdx\n\t"
        "movzxb (%%rdx), %%rdx\n\t"
        "div %%dl\n\t"
        "movzxb (%[delay]), %%rcx\n\t"  // dl = out[delay[0]]
        "add %[out], %%rcx\n\t"
        "mov (%%rcx), %%dl\n\t"
        : : [in1] "r"(in1), [out] "r"(out), [delay] "r"(delay), [in2] "r"(in2) : "rax", "rcx", "rdx"
    );
    NOPs(NOP256);
}

void nand_gate(uint8_t* in1, uint8_t* in2, uint8_t* out) {
    tmp_reg1[0] = 0;
    tmp_reg2[0] = 0; 
    tmp_reg3[0] = 0;
    tmp_reg4[0] = 0;
    _mm_clflush(tmp_reg1);
    _mm_clflush(tmp_reg2);
    _mm_clflush(tmp_reg3);
    _mm_clflush(tmp_reg4);
    for (volatile int z = 0; z < 64; z++) {}

    and_gate(in1, in2, tmp_reg1);
    for (volatile int z = 0; z < 64; z++) {}

    uint64_t clk = timer(tmp_reg1);
    assign(tmp_reg2, clk <= THRESHOLD);
    assign(tmp_reg3, clk <= THRESHOLD);
    for (volatile int z = 0; z < 64; z++) {}

    not_gate(tmp_reg2, tmp_reg3, out, tmp_reg4);
}

/* Jump over a WG after an exception */
void signal_handler(int signal, siginfo_t *si, void *context)
{
    const int return_delta = 64;
    ((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP] += return_delta;
}

int main() {
    // Install signal handler
    struct sigaction sa = {0};
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa, NULL);

    // Initialize inputs
    in1[0] = 0;
    in2[0] = 0;
    out[0] = 0;
    
    printf("Testing NAND gate implementation...\n");

    assign(in1, 0);
    assign(in2, 1);

    _mm_clflush(out);

    nand_gate(in1, in2, out);

    uint64_t result = timer(out);
    bool output = (result <= THRESHOLD);
    bool expected = !(in1 && in2);

    printf("NAND(%d,%d) result = %d, expected = %d, %s\n", 
        in1, in2, output, expected, 
        (output == expected) ? "CORRECT" : "WRONG");
    
    // for (int i = 0; i < 2; i++) {
    //     for (int j = 0; j < 2; j++) {
    //         // Set input values
    //         assign(in1, i);
    //         assign(in2, j);
    //         _mm_clflush(out);
            
    //         // Run NAND gate
    //         nand_gate(in1, in2, out);
            
    //         // Check result
    //         uint64_t result = timer(out);
    //         bool output = (result <= THRESHOLD);
    //         bool expected = !(i && j); // Expected NAND result
            
    //         printf("NAND(%d,%d) result = %d, expected = %d, %s\n", 
    //             i, j, output, expected, 
    //             (output == expected) ? "CORRECT" : "WRONG");
    //     }
    // }
    
    return 0;
}