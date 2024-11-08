#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>  // For rdtsc and clflush

#define CACHE_HIT_THRESHOLD 100  // Adjust based on your system

volatile int wr_var = 0;  // Weird register variable

// Function to read the timer
uint64_t rdtsc() {
    return __rdtsc();
}

// Function to write the WR (Cache to set to "1", Flush to set to "0")
void write_weird_register(int value) {
    if (value == 1) {
        wr_var = 42;
    } else {
        _mm_clflush(&wr_var);
    }
}

// Function to read the WR
int read_weird_register() {
    uint64_t start, end;
    int temp = 0;

    start = rdtsc();
    temp = wr_var;
    end = rdtsc();

    return (end - start) < CACHE_HIT_THRESHOLD ? 1 : 0;
}

int main() {
    write_weird_register(1);
    printf("WR set to 1, reading WR: %d\n", read_weird_register());

    write_weird_register(0);
    printf("WR set to 0, reading WR: %d\n", read_weird_register());

    return 0;
}
