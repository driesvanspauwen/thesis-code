#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>  // For rdtsc and clflush
#include <cpuid.h>

volatile int wr_var = 0;

uint64_t timed_memory_read() {
    uint64_t start, end;
    int temp = 0;

    // Serialize before reading the timestamp
    unsigned int aux;
    __cpuid(0, aux, aux, aux, aux);
    start = __rdtsc();

    temp = wr_var;

    // Serialize after reading the timestamp
    __cpuid(0, aux, aux, aux, aux);
    end = __rdtsc();

    return (end - start);
}

int main() {
    wr_var = 42;
    printf("Timed memory read - cached: %llu\n", timed_memory_read());

    _mm_clflush((const void *)&wr_var);
    __asm__ __volatile__("" ::: "memory");
    __builtin_ia32_pause();
    printf("Timed memory read - not cached: %llu\n", timed_memory_read());

    return 0;
}