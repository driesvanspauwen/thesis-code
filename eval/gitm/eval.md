# Evaluation "Ghost is the machine" paper
## Grid search
The `grid-search.py` script tests a range of combinations for the threshold and delay values.

1. Creates tables for every gate in `grid-search-results/<gate_name>_results.txt`
2. For each combination of treshold/delay values:
    - builds the main.elf file
    - runs it with 100 trials of 10000 iterations each (as in the paper's evaluation)
    - reads the accuracy for every gate and adds this to the gate's respective table
3. Retrieves the highest accuracy combination from every gate's table and prints it to the terminal

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

We re-run the each of those binaries to verify the accuracy:

| Binary          | Accuracy  |
|-----------------|-----------|
| main_and.elf    | 99.9894%  |
| main_or.elf     | 99.9865%  |
| main_assign.elf | 99.9740%  |
| main_not.elf    | 98.5672%  |
| main_nand.elf   | 97.1843%  |
| main_xor.elf    | 74.9915%  |
| main_mux.elf    | 99.6083%  |
