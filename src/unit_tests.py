import sys
import struct
import itertools
from random import randint
from emulator import MuWMEmulator
from loader import *
from gates.asm import *
from unicorn.x86_const import *
from gates.flexo.sha1.sha1_ref import ref_sha1_round
# from tests.helper import run_gate_test, run_all_tests

# Import tests
from tests.asm_tests import *
from tests.flexo_tests import *
from tests.gitm_tests import *

##########################################
# ASM tests
##########################################

def test_assign_asm():
    verifier = lambda a: a
    return run_gate_test('ASSIGN', run_assign_asm, verifier, 1)

def test_and_asm():
    verifier = lambda a, b: a and b
    return run_gate_test('AND', run_and_asm, verifier, 2)

def test_or_asm():
    verifier = lambda a, b: a or b
    return run_gate_test('OR', run_or_asm, verifier, 2)

def test_not_asm():
    verifier = lambda a: not a
    return run_gate_test('NOT', run_not_asm, verifier, 1)

def test_and_or_asm():
    verifier = lambda a, b, c: (a and b) or c
    return run_gate_test('AND-OR', run_and_or_asm, verifier, 3)

##########################################
# GITM tests
##########################################

def test_assign_gitm():
    verifier = lambda a: a
    return run_gate_test('ASSIGN', run_assign_gitm, verifier, 1)

def test_and_gitm():
    verifier = lambda a, b: a and b
    return run_gate_test('AND', run_and_gitm, verifier, 2)

def test_or_gitm():
    verifier = lambda a, b: a or b
    return run_gate_test('OR', run_or_gitm, verifier, 2)

def test_not_gitm():
    verifier = lambda a: not a
    return run_gate_test('NOT', run_not_gitm, verifier, 1)

def test_nand_gitm():
    verifier = lambda a, b: not (a and b)
    return run_gate_test('NAND', run_nand_gitm, verifier, 2)

def test_mux_gitm():
    verifier = lambda a, b, sel: a if sel == 0 else b
    return run_gate_test('MUX', run_mux_gitm, verifier, 3)

def test_xor_gitm():
    verifier = lambda a, b: a ^ b
    return run_gate_test('XOR', run_xor_gitm, verifier, 2)

##########################################
# Flexo tests
##########################################

def test_and_flexo():
    verifier = lambda a, b: a and b
    return run_gate_test('FLEXO-AND', run_and_flexo, verifier, 2)

def test_or_flexo():
    verifier = lambda a, b: a or b
    return run_gate_test('FLEXO-OR', run_or_flexo, verifier, 2)

def test_not_flexo():
    verifier = lambda a: not a
    return run_gate_test('FLEXO-NOT', run_not_flexo, verifier, 1)

def test_nand_flexo():
    verifier = lambda a, b: not (a and b)
    return run_gate_test('FLEXO-NAND', run_nand_flexo, verifier, 2)

def test_xor_flexo():
    verifier = lambda a, b: a ^ b
    return run_gate_test('FLEXO-XOR', run_xor_flexo, verifier, 2)

def test_xor3_flexo():
    verifier = lambda a, b, c: a ^ b ^ c
    return run_gate_test('FLEXO-XOR3', run_xor3_flexo, verifier, 3)

def test_xor4_flexo():
    verifier = lambda a, b, c, d: a ^ b ^ c ^ d
    return run_gate_test('FLEXO-XOR4', run_xor4_flexo, verifier, 4)

def test_mux_flexo():
    verifier = lambda a, b, sel: a if sel == 0 else b
    return run_gate_test('FLEXO-MUX', run_mux_flexo, verifier, 3)

# run_xor_flexo(0, 1, True)
# run_and_flexo(0, 1, True)

##########################################
# CLI
##########################################

def run_gate_test(gate_name, run_function, verifier, num_inputs, debug=False):
    """
    Generic test runner.
    
    Args:
        gate_name: name of the gate for (logging)
        run_function: function to run the gate
        verifier: function that computes expected output
        num_inputs: number of inputs for the gate (1, 2 or 3)
        debug: whether to enable debug logging
    """
    all_passed = True
    
    # Generate all possible input combinations
    for inputs in itertools.product([0, 1], repeat=num_inputs):
        try:
            # Run the gate with the inputs
            if num_inputs == 1:
                result = run_function(inputs[0], debug=debug)
            elif num_inputs == 2:
                result = run_function(inputs[0], inputs[1], debug=debug)
            elif num_inputs == 3:
                result = run_function(inputs[0], inputs[1], inputs[2], debug=debug)
            elif num_inputs == 4:
                result = run_function(inputs[0], inputs[1], inputs[2], inputs[3], debug=debug)
            else:
                raise ValueError(f"Unsupported number of inputs: {num_inputs}")
            
            # Compute expected result using verifier
            expected = verifier(*inputs)
            
            if result == expected:
                print(f"Test passed for {gate_name}{inputs}")
            else:
                print(f"Test failed for {gate_name}{inputs}:")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {result}")
                all_passed = False
                
        except Exception as e:
            print(f"Test error for {gate_name}{inputs}: {e}")
            all_passed = False
    
    return all_passed

def run_all_tests():
    """
    Run all test functions in this module (functions that start with 'test_').
    """
    test_functions = [name for name in globals() 
                     if name.startswith('test_') and callable(globals()[name])]
    
    print(f"Running {len(test_functions)} tests:")
    for test_func_name in test_functions:
        print(f"\n--- Running {test_func_name} ---")
        globals()[test_func_name]()
    
    print("\nAll tests have been run!")



def run_flexo_sha1_round(state_in, w_in, debug=False):
    # Constants (adjust these according to your .elf layout)
    INPUT_ADDR = 0x40000
    OUTPUT_ADDR = 0x50000
    ERROR_OUTPUT_ADDR = 0x60000
    PAGE_SIZE = 0x1000

    # Function addresses
    WEIRD_SHA1_ADDR = 0x1550
    RAND_CALL_ADDR = 0x157f
    SHA1_RET_ADDR   = 0x28e73

    # Create emulator
    loader = ELFLoader("gates/flexo/sha1/sha1_round.elf", stack_addr=0x80000,stack_size=0x1000000)
    emulator = MuWMEmulator('flexo-sha1', loader, True)

    emulator.code_start_address = WEIRD_SHA1_ADDR
    emulator.code_exit_addr = SHA1_RET_ADDR

    # Set up memory for inputs and outputs
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE)

    # Write input: state (5x uint32) + w (1x uint32)
    input_data = state_in + [w_in]
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<6I", *input_data))

    # Zero output and error buffer
    emulator.uc.mem_write(OUTPUT_ADDR, b"\x00" * 20)
    emulator.uc.mem_write(ERROR_OUTPUT_ADDR, b"\x00" * 20)

    # Register setup: rdi=input, rsi=w, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, w_in)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)

    # The rand@plt function call is skipped
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:  # or address of call rand
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            uc.reg_write(UC_X86_REG_RIP, address + 5)
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_SHA1_ADDR, SHA1_RET_ADDR)

    # Emulate
    emulator.emulate()

    # Read outputs
    result = list(struct.unpack("<5I", emulator.uc.mem_read(OUTPUT_ADDR, 20)))
    err_out = list(struct.unpack("<5I", emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 20)))

    return result, err_out

def test_sha1_round():
    # Generate random test inputs
    state = [randint(0, 0xFFFFFFFF) for _ in range(5)]
    w = randint(0, 0xFFFFFFFF)
    
    print(f"Input state: {[hex(x) for x in state]}")
    print(f"Input w: {hex(w)}")
    
    # Run your emulated version
    out, err = run_flexo_sha1_round(state, w)
    
    # Run reference implementation (assuming round 1 based on SHA1_ROUND macro)
    ref = ref_sha1_round(state, w, round_num=0)  # Note: C code uses 1-based, we use 0-based
    
    print(f"Emulator output: {[hex(x) for x in out]}")
    print(f"Reference output: {[hex(x) for x in ref]}")
    print(f"Emulator error output: {[hex(x) for x in err]}")
    
    # Compare results
    match = all(out[i] == ref[i] for i in range(5))
    print(f"Result matches reference: {match}")
    
    if not match:
        for i in range(5):
            if out[i] != ref[i]:
                print(f"\tMismatch at position {i}: {hex(out[i])} != {hex(ref[i])}")
    
    return match


run_and_asm(1, 1, True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unit_tests.py <test_name>")
        print("       python unit_tests.py all (to run all tests)")
        print("Available tests:")
        # List all functions that start with 'test_'
        tests = [name for name in globals() if name.startswith('test_')]
        for test in tests:
            print(f"  - {test}")
        sys.exit(1)

    test_name = sys.argv[1]
    if test_name.lower() == 'all':
        run_all_tests()
    elif test_name in globals() and test_name.startswith('test_'):
        globals()[test_name]()  # Run the requested test
        print("Finished unit tests")
    else:
        print(f"Error: Test '{test_name}' not found")
        sys.exit(1)