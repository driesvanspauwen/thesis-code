import sys
from emulator import MuWMEmulator
from loader import *
from gates.asm import *
from unicorn.x86_const import *
from random import randint
import struct
from gates.flexo.sha1.sha1_ref import ref_sha1_round

from tests.asm_tests import *
from tests.elf_tests import *

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

# test_sha1_round()

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
    
    print("\nAll tests completed!")

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