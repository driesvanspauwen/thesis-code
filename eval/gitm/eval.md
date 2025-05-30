# Evaluation "Ghost is the machine" paper
## Grid search
The `grid-search.py` script tests a range of combinations for the threshold and delay values.

1. Creates tables for every gate in `grid-search-results/<gate_name>_results.txt`
2. For each combination of treshold/delay values:
    - builds the main.elf file
    - runs it with 100 trials of 10000 iterations each (as in the paper's evaluation)
    - reads the accuracy for every gate and adds this to the gate's respective table
3. Retrieves the highest accuracy combination from every gate's table and prints it to the terminal

Evaluation parameters:
```python
THRESHOLDS = range(100, 301, 25)
DELAYS = [32, 48, 64, 96, 128, 192, 256, 512, 1024]
AMT_TRIALS = 100
```

| Gate   | Threshold | Delay | Accuracy |
|--------|-----------|-------|----------|
| AND    | 225       | 128   | 99.981%  |
| OR     | 275       | 128   | 99.988%  |
| ASSIGN | 250       | 128   | 99.982%  |
| NOT    | 150       | 512   | 99.970%  |
| NAND   | 100       | 512   | 99.886%  |
| XOR    | 275       | 1024  | 74.996%  |
| MUX    | 275       | 256   | 99.711%  |

## Binary generation
The `create-optimal-binaries.py` script creates one binary per gate, in which the binary uses the optimal configuration for that gate.

We re-run the each of those binaries to verify them:

This was used in the paper for timing:
=== AND gate (Exception) ===
Correct rate: (avg, std) = (99.9978%, 0.0000)
Time usage: 1.600s over 1000000 iterations.
=== OR gate (Exception) ===
Correct rate: (avg, std) = (99.9864%, 0.0001)
Time usage: 1.558s over 1000000 iterations.
=== ASSIGN gate (Exception) ===
Correct rate: (avg, std) = (99.9910%, 0.0001)
Time usage: 1.603s over 1000000 iterations.
=== NOT gate (Exception) ===
Correct rate: (avg, std) = (98.7318%, 0.0012)
Time usage: 2.631s over 1000000 iterations.
=== NAND gate (Exception) ===
Correct rate: (avg, std) = (98.9181%, 0.0014)
Time usage: 7.401s over 1000000 iterations.
=== XOR gate (Exception) ===
Correct rate: (avg, std) = (75.2187%, 0.0032)
Time usage: 20.744s over 1000000 iterations.
=== MUX gate (Exception) ===
Correct rate: (avg, std) = (99.9497%, 0.0009)
Time usage: 8.971s over 1000000 iterations.

The timings are made with:
```cpp
void test_gate(
    const char* name,
    bool (*gate_fn)(unsigned), 
    unsigned input_size
) {
    const unsigned in_space = 1 << input_size;  // 2^input_size (total amount of possible input combinations)
    std::vector<unsigned> tot_counts(tot_trials, 0);  // amount of correct executions per trial
    std::vector<unsigned> tot_error_counts(tot_trials * in_space, 0);  // amount of errors per input combination per trial
    clock_t end_t, start_t = clock();

    for (unsigned trial = 0; trial < tot_trials; trial++) {
        unsigned seed = 0;

        for (int seed = 0; seed < single_trial; seed++) {
            bool correct = gate_fn(seed);

            if (correct) {
                tot_counts[trial]++;
            }
            else {
                tot_error_counts[(trial * in_space) + (seed % in_space)]++;
            }
        }
    }
    
    end_t = clock();

    printf("=== %s gate (Exception) ===\n", name);
    calc_avg_std(tot_counts, tot_error_counts, input_size);
    printf("Time usage: %.3fs ", (double)(end_t - start_t) / CLOCKS_PER_SEC);
    printf("over %d iterations.\n", tot_trials * single_trial);
}
```
- they measure all gate iterations in total

This was used in the paper for accuracy:
| Binary          | Accuracy  |
|-----------------|-----------|
| main_and.elf    | 99.9894%  |
| main_or.elf     | 99.9865%  |
| main_assign.elf | 99.9740%  |
| main_not.elf    | 98.5672%  |
| main_nand.elf   | 97.1843%  |
| main_xor.elf    | 74.9915%  |
| main_mux.elf    | 99.6083%  |

