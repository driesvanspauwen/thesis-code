/*
Implements a cache-based weird register (CB-WR) using Flush+Reload

Value in cache -> logical 1
Value not in cache -> logical 0
*/

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>  // For rdtsc and clflush
#include <cpuid.h>      // For __cpuid

#define CACHE_HIT_THRESHOLD 180

volatile int wr_var = 0;

// Function to write to the WR
void write_weird_register(int value) {
    if (value) {
        wr_var = 42;
    } else {
        _mm_clflush((const void *)&wr_var);
    }
}

uint64_t timed_memory_read() {
    uint64_t start, end;
    int temp = 0;

    unsigned int aux;
    __cpuid(0, aux, aux, aux, aux);
    start = __rdtsc();

    temp = wr_var;

    __cpuid(0, aux, aux, aux, aux);
    end = __rdtsc();

    return (end - start);
}

int read_weird_register() {
    uint64_t time_to_read = timed_memory_read();

    return time_to_read < CACHE_HIT_THRESHOLD ? 1 : 0;
}

int main() {
    write_weird_register(1);
    printf("WR set to 1, reading WR: %d\n", read_weird_register());

    write_weird_register(0);
    printf("WR set to 0, reading WR: %d\n", read_weird_register());

    return 0;
}