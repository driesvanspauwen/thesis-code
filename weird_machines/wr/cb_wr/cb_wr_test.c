/*
Example output:
Percentage of correct reads: 100.00%

-> gives almost always 100%
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>     // For rand() and srand()
#include <time.h>       // For time()
#include <x86intrin.h>  // For rdtsc and clflush
#include <cpuid.h>      // For __cpuid

#define CACHE_HIT_THRESHOLD 100  // See cache-timing/cache-timing.c
#define NUM_TESTS 10000

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

    start = __rdtsc();
    temp = wr_var;
    _mm_mfence();  // Memory fence to ensure proper ordering
    end = __rdtsc();

    return (end - start);
}

// Function to read the WR
int read_weird_register() {
    uint64_t time_to_read = timed_memory_read();

    return time_to_read < CACHE_HIT_THRESHOLD ? 1 : 0;
}

int main() {
    int correct_reads = 0;

    // Seed the random number generator
    srand(time(NULL));

    for (int i = 0; i < NUM_TESTS; i++) {
        int value = rand() % 2;  // Randomly choose between 0 and 1
        write_weird_register(value);
        if (read_weird_register() == value) {
            correct_reads++;
        }
    }

    double accuracy = (double)correct_reads / NUM_TESTS * 100;
    printf("Percentage of correct reads: %.2f%%\n", accuracy);

    return 0;
}