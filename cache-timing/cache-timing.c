/*
Times memory reads for a cached and uncached variable.

Example outputs:

Timed memory read - cached: 78
Timed memory read - not cached: 320

Timed memory read - cached: 34
Timed memory read - not cached: 202

Timed memory read - cached: 62
Timed memory read - not cached: 196

We use `rdscp`, it works the same as `rdsc` but also serializes the instruction stream.
It also works using __cpuid to serialize instead, see older code.
*/

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>  // For rdtscp and clflush
#include <cpuid.h>

volatile int wr_var = 0;

uint64_t timed_memory_read() {
    uint64_t start, end;
    int temp = 0;
    unsigned int aux;

    start = __rdtscp(&aux);

    temp = wr_var;

    end = __rdtscp(&aux);

    return (end - start);
}

int main() {
    wr_var = 42;
    printf("Timed memory read - cached: %llu\n", timed_memory_read());

    _mm_clflush((const void *)&wr_var);
    printf("Timed memory read - not cached: %llu\n", timed_memory_read());

    return 0;
}