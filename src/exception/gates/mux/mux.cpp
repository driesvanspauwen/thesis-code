// g++ -O2 -o mux.elf mux.cpp -lm
// objdump -M intel -d mux.elf > mux_objdump.txt

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

#define THRESHOLD 150
#define DELAY 1024

unsigned tot_trials = 100;
unsigned single_trial = 10000;

uint8_t reg1[4*512];
uint8_t reg2[4*512];
uint8_t reg3[4*512];
uint8_t reg4[4*512];
uint8_t reg5[4*512];

uint8_t in1[4*512];
uint8_t in2[4*512];
uint8_t in3[4*512];
uint8_t out[4*512];

uint8_t tmp_reg1[4*512];
uint8_t tmp_reg2[4*512];
uint8_t tmp_reg3[4*512];
uint8_t tmp_reg4[4*512];
uint8_t tmp_reg5[4*512];
uint8_t tmp_reg6[4*512];
uint8_t tmp_reg7[4*512];
uint8_t tmp_reg8[4*512];
uint8_t tmp_reg9[4*512];
uint8_t tmp_reg10[4*512];

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

inline void or_gate(uint8_t* in1, uint8_t* in2, uint8_t* out) {
    asm volatile (
        "xor %%rdx, %%rdx\n\t"          // ax /= 0
        "div %%dl\n\t"
        "movzxb (%[in1]), %%rcx\n\t"    // dl = out[in1[0]]
        "add %[out], %%rcx\n\t"
        "mov (%%rcx), %%al\n\t"
        "movzxb (%[in2]), %%rcx\n\t"    // dl = out[in2[0]]
        "add %[out], %%rcx\n\t"
        "mov (%%rcx), %%dl\n\t"
        : : [in1] "r"(in1), [in2] "r"(in2), [out] "r"(out) : "rax", "rdx", "rcx"
    );
    NOPs(NOP256);
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

// in1: input 1
// in2: input 2
// in3: input selector (0 for in1, 1 for in2)
// OUT = (IN1 AND NOT IN3) OR (IN2 AND IN3)
void mux_gate(uint8_t* in1, uint8_t* in2, uint8_t* in3, uint8_t* out, unsigned input) {
    tmp_reg1[0] = 0;
    tmp_reg2[0] = 0;
    tmp_reg3[0] = 0;
    tmp_reg4[0] = 0;
    tmp_reg5[0] = 0;
    tmp_reg6[0] = 0;
    assign(tmp_reg1, input & 4);
    assign(tmp_reg2, input & 4);
    _mm_clflush(tmp_reg3);
    _mm_clflush(tmp_reg4);
    _mm_clflush(tmp_reg5);
    _mm_clflush(tmp_reg6);

    for (volatile int z = 0; z < DELAY; z++) {}

    assign(in1, input & 1);
    and_gate(in2, in3, tmp_reg3);
    not_gate(tmp_reg1, tmp_reg2, tmp_reg4, tmp_reg5);
    for (volatile int z = 0; z < DELAY; z++) {}
    
    uint64_t clk = timer(tmp_reg4);
    assign(tmp_reg4, clk <= THRESHOLD);
    uint64_t clk2 = timer(tmp_reg3);
    and_gate(in1, tmp_reg4, tmp_reg6);
    for (volatile int z = 0; z < DELAY; z++) {}
    
    clk = timer(tmp_reg6);
    assign(tmp_reg6, clk <= THRESHOLD);
    assign(tmp_reg3, clk2 <= THRESHOLD);
    for (volatile int z = 0; z < DELAY; z++) {}

    or_gate(tmp_reg3, tmp_reg6, out);
}

bool do_mux_gate(unsigned input) {    
    reg1[0] = 0;
    reg2[0] = 0;
    reg3[0] = 0;
    reg4[0] = 0;
    assign(reg1, input & 1);
    assign(reg2, input & 2);
    assign(reg3, input & 4);
    _mm_clflush(reg4);
    
    mux_gate(reg1, reg2, reg3, reg4, input);
    for (volatile int z = 0; z < 512; z++) {}
    
    uint64_t clk = timer(reg4);
    return (clk <= THRESHOLD) == (
        (input & 4) ? ((input & 2) == 2) : (input & 1)
    );
}

/* Jump over a WG after an exception */
void signal_handler(int signal, siginfo_t *si, void *context)
{
    const int return_delta = 256;
    ((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP] += return_delta;
}

/* Report accuracy */
void calc_avg_std(
    std::vector<unsigned>& tot_counts,
    std::vector<unsigned>& tot_error_counts,
    unsigned input_size
) {
    const unsigned in_space = 1 << input_size;
    double sum = 0;
    std::vector<double> sum_error(in_space, 0);
    std::vector<double> avg_error(in_space, 0);

    for (int i = 0; i < tot_trials; i++) {
        sum += tot_counts[i];
        for (int j = 0; j < in_space; j++) {
            sum_error[j] += tot_error_counts[(i * in_space) + j];
        }
    }

    double avg = sum / tot_trials;
    sum = 0;
    for (int i = 0; i < in_space; i++) {
        avg_error[i] = sum_error[i]/tot_trials;
        sum_error[i] = 0;
    }

    for (int i = 0; i < tot_trials; i++) {
        sum += (tot_counts[i] - avg) * (tot_counts[i] - avg);
        for (int j = 0; j < in_space; j++) {
            double tmp = tot_error_counts[(i * in_space) + j] - avg_error[j];
            sum_error[j] +=  tmp * tmp;
        }
    }
    
    printf(
        "Correct rate: (avg, std) = (%.4lf%%, %.4lf)\n", 
        (avg * 100) / single_trial, 
        sqrt(sum / tot_trials) / single_trial
    );

    for (int i = 0; i < in_space; i++) {
        printf("Input (%d", i&1);
        for (int j = 1; j < input_size; j++)
            printf(", %d", (i & (1 << j)) >> j);
        printf(") Error rate: (avg, std) = ");
        printf("(%.4lf%%, %.4lf)\n", (avg_error[i] * 100) / single_trial, sqrt(sum_error[i] / tot_trials) / single_trial);
    }
}

int main() {
    // Install signal handler
    struct sigaction sa = {0};
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &sa, NULL);
    
    const unsigned in_space = 1 << 3;
    std::vector<unsigned> tot_counts(tot_trials, 0);  // amount of correct executions per trial
    std::vector<unsigned> tot_error_counts(tot_trials * in_space, 0);  // amount of errors per input combination per trial

    printf("Testing MUX gate implementation...\n");
    
    clock_t end_t, start_t = clock();

    for (unsigned trial = 0; trial < tot_trials; trial++) {
        unsigned seed = 0;

        for (int seed = 0; seed < single_trial; seed++) {
            bool correct = do_mux_gate(seed);

            if (correct) {
                tot_counts[trial]++;
                // printf("Trial %d, Seed %d: Correct\n", trial, seed);
            }
            else {
                tot_error_counts[(trial * in_space) + (seed % in_space)]++;
                // printf("Trial %d, Seed %d: Error\n", trial, seed);
            }
        }
    }

    end_t = clock();

    printf("=== %s gate (Exception) ===\n", "MUX");
    calc_avg_std(tot_counts, tot_error_counts, 3);
    printf("Time usage: %.3fs ", (double)(end_t - start_t) / CLOCKS_PER_SEC);
    printf("over %d iterations.\n", tot_trials * single_trial);

    return 0;
}