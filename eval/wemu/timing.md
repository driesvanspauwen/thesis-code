# Flexo AND
AND(0, 0) = 0 (expected 0) [True] - 0.053087457 s
AND(0, 1) = 0 (expected 0) [True] - 0.047408572 s
AND(1, 0) = 0 (expected 0) [True] - 0.048554487 s
AND(1, 1) = 1 (expected 1) [True] - 0.052086596 s
Average Flexo AND gate time: 0.050284278 s

# Flexo SHA1 round
Testing single SHA1 round with:
  State: ['0x5d4ab876', '0xc27048bd', '0x6ca8f4a7', '0x56d8e4b6', '0xc6be62bd']
  W: 0x18165530

=== Single SHA1 Round ===
Expected: ['0x375724f8', '0x5d4ab876', '0x709c122f', '0x6ca8f4a7', '0x56d8e4b6']
Got:      ['0x375724f8', '0x5d4ab876', '0x709c122f', '0x6ca8f4a7', '0x56d8e4b6']
Match:    True
Time:     15.861863299 s

# GITM AND & MUX
(venv) root@9f376a38db3d:/code/src# python timing_tests.py 
AND(0, 0) - 0.068734526 s
AND(0, 1) - 0.054482484 s
AND(1, 0) - 0.049860117 s
AND(1, 1) - 0.047436462 s
Average AND gate time: 0.055128397 s
MUX(0, 0, 0) - 0.319193049 s
MUX(0, 0, 1) - 0.341206379 s
MUX(0, 1, 0) - 0.295388507 s
MUX(0, 1, 1) - 0.301409685 s
MUX(1, 0, 0) - 0.294904476 s
MUX(1, 0, 1) - 0.335362601 s
MUX(1, 1, 0) - 0.293380121 s
MUX(1, 1, 1) - 0.303023753 s
Average MUX gate time: 0.310483571 s
