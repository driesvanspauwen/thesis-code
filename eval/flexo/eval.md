# Evaluation "Bending muwms" paper (Flexo framework)
## Gates
### Accuracies
The Flexo compiler can be configured by setting environment variables. The script `optimizer.py` can be used for finding the best parameters to build gates (`circuits/gates/gates.elf`). The script tests different combinations of `RET_WM_DIV_ROUNDS`, `WM_DELAY`, `WR_OFFSET`, prints the results of all combinations in `grid_search_results` and outputs the best performing combination as well for every gate:
FLEXO RSB-BASED μWM OPTIMIZATION RESULTS
==================================================

Optimization completed: 2025-05-27 19:09:40
Total configurations tested: 300
Parameter ranges: {'RET_WM_DIV_ROUNDS': range(1, 51), 'WR_OFFSET': [192, 320, 448, 576, 960, 1088]}

BEST CONFIGURATION PER GATE:
------------------------------

AND Gate:
  RET_WM_DIV_ROUNDS: 7
  WR_OFFSET: 576
  Accuracy: 96.383%
  Error detected: 3.615%
  Undetected error: 0.002%
  Score: 96.38

MUX Gate:
  RET_WM_DIV_ROUNDS: 5
  WR_OFFSET: 576
  Accuracy: 93.112%
  Error detected: 6.777%
  Undetected error: 0.111%
  Score: 92.78

NAND Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 91.258%
  Error detected: 8.611%
  Undetected error: 0.131%
  Score: 90.86

NOT Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 94.624%
  Error detected: 5.305%
  Undetected error: 0.071%
  Score: 94.41

OR Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 91.792%
  Error detected: 8.101%
  Undetected error: 0.107%
  Score: 91.47

XOR Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 94.239%
  Error detected: 5.696%
  Undetected error: 0.065%
  Score: 94.04

XOR3 Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 93.719%
  Error detected: 6.220%
  Undetected error: 0.061%
  Score: 93.54

XOR4 Gate:
  RET_WM_DIV_ROUNDS: 25
  WR_OFFSET: 960
  Accuracy: 94.159%
  Error detected: 5.749%
  Undetected error: 0.092%
  Score: 93.88

We verified this configuration manually with 1,000,000 iterations and found the following accuracies:
```
=== AND gate ===
Accuracy: 94.16670%, Error detected: 5.69020%, Undetected error: 0.14310%
Time usage: 0.703 (us)
over 1000000 iterations.
=== OR gate ===
Accuracy: 94.51460%, Error detected: 5.39200%, Undetected error: 0.09340%
Time usage: 0.809 (us)
over 1000000 iterations.
=== NOT gate ===
Accuracy: 93.48670%, Error detected: 6.24990%, Undetected error: 0.26340%
Time usage: 0.707 (us)
over 1000000 iterations.
=== NAND gate ===
Accuracy: 93.10750%, Error detected: 6.70860%, Undetected error: 0.18390%
Time usage: 0.816 (us)
over 1000000 iterations.
=== XOR gate ===
Accuracy: 94.66880%, Error detected: 5.16680%, Undetected error: 0.16440%
Time usage: 0.788 (us)
over 1000000 iterations.
=== MUX gate ===
Accuracy: 93.38730%, Error detected: 6.43040%, Undetected error: 0.18230%
Time usage: 0.855 (us)
over 1000000 iterations.
=== XOR3 gate ===
Accuracy: 94.88570%, Error detected: 4.98310%, Undetected error: 0.13120%
Time usage: 0.935 (us)
over 1000000 iterations.
=== XOR4 gate ===
Accuracy: 94.64830%, Error detected: 5.20880%, Undetected error: 0.14290%
Time usage: 1.81 (us)
over 1000000 iterations.
```

### Timing
Using the optimal config from before, we time:
=== AND gate ===
Accuracy: 93.85280%, Error detected: 6.02440%, Undetected error: 0.12280%
Time usage: 0.716 (us)
Total nanoseconds: 716294907 (= 0.7162949 seconds)
over 1000000 iterations.


## Arithmetic circuits
- use fixed parameters: RET_WM_DIV_ROUNDS=25 WR_OFFSET=960
- these are shown to be reliable by the grid search of the gates

dries@aeolus:~/thesis/Flexo$ ./circuits/arithmetic/adder.elf 
=== ADDER 8 ===
Accuracy: 94.77650%, Error detected: 5.22350%, Undetected error: 0.00000%
Time usage: 14.58141s over 1000000 iterations.
=== ADDER 16 ===
Accuracy: 97.81560%, Error detected: 2.18430%, Undetected error: 0.00010%
Time usage: 41.23991s over 1000000 iterations.
=== ADDER 32 ===
Accuracy: 97.42880%, Error detected: 2.57110%, Undetected error: 0.00010%
Time usage: 91.82856s over 1000000 iterations.

## SHA1
### Grid search with 100,000 iterations:
BEST CONFIGURATION:
--------------------
Config: RET_WM_DIV_ROUNDS=3, WR_OFFSET=320
Best accuracy: 90.410%

### Manual verification with 1,000,000 iterations:
=== SHA1 Round ===
Accuracy: 88.16490%, Error detected: 11.83370%, Undetected error: 0.00140%
Time usage: 266.709 (us)
over 1000000 iterations.

### Broken configuration:
RET_WM_DIV_ROUNDS=1, WR_OFFSET=192

=== SHA1 Round ===
Accuracy: 0.00000%, Error detected: 100.00000%, Undetected error: 0.00000%
Time usage: 250.123 (us)
over 1000000 iterations.