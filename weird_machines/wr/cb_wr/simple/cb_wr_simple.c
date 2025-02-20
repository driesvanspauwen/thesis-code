#include <x86intrin.h> 
volatile int wr_var = 0;

void write_wr(int value) {
    if (value) {
        wr_var = 42;
    } else {
        asm volatile("clflush (%0)" :: "r" (&wr_var));
    }
}

int read_wr() {
    unsigned int aux;
    unsigned long long start, end;
    int temp;
    
    start = __rdtscp(&aux);
    temp = wr_var;
    end = __rdtscp(&aux);
    
    return (end - start < 100) ? 1 : 0;
}