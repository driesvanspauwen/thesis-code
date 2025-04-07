import sys
from exception_emulator import ExceptionEmulator
from ooo_emulator import OOOEmulator
from gates import *
from unicorn.x86_const import *

def run_assign(in1, debug=False):
    code = get_asm_exception_assign(in1)
    emulator = OOOEmulator(code, 'assign', debug)

    # Set input and output addresses of assign gate
    input_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R14, input_address)
    output_address = emulator.DATA_BASE + emulator.cache.line_size  # makes sure output goes in different cache set than input
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_assign():
    for in1 in range(2):
        res = run_assign(in1)
        if res == in1:
            print(f"Successful emulation of Assign({in1})")
        else:
            print(f"Unsuccessful emulation of Assign({in1}):")
            print(f"\tExpected: {in1}")
            print(f"\tResult: {res}")

def run_or(in1, in2, debug=False):
    code = get_asm_exception_or(in1, in2)
    emulator = OOOEmulator(code, 'or', debug)

    emulator.logger.log(f"Starting emulation of OR({in1}, {in2})...")

    # Set input and output addresses of OR gate
    input1_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.DATA_BASE + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.DATA_BASE + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_or():
    for in1 in range(2):
        for in2 in range(2):
            res = run_or(in1, in2)
            if res == in1 or in2:
                print(f"Successful emulation of OR({in1}, {in2})")
            else:
                print(f"Unsuccessful emulation of OR({in1}, {in2}):")
                print(f"\tExpected: {in1 or in2}")
                print(f"\tResult: {res}")

def run_and(in1, in2, debug=False):
    code = get_asm_exception_and(in1, in2)
    emulator = OOOEmulator(code, 'and', debug)

    emulator.logger.log(f"Starting emulation of AND({in1}, {in2})...")

    # Set input and output addresses of AND gate
    input1_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.DATA_BASE + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.DATA_BASE + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_and():
    for in1 in range(2):
        for in2 in range(2):
            res = run_and(in1, in2)
            expected = in1 and in2
            if res == expected:
                print(f"Successful emulation of AND({in1}, {in2})")
            else:
                print(f"Unsuccessful emulation of AND({in1}, {in2}):")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {res}")

def run_and_or(in1, in2, in3, debug=False):
    code = get_asm_exception_and_or(in1, in2, in3)
    emulator = OOOEmulator(code, 'and_or', debug)

    emulator.logger.log(f"Starting emulation of AND-OR({in1}, {in2}, {in3})...")

    # Set input and output addresses
    input1_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.DATA_BASE + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    
    input3_address = emulator.DATA_BASE + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R12, input3_address)
    
    output_address = emulator.DATA_BASE + 3 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    result = emulator.cache.is_cached(output_address)
    emulator.logger.log(f"Output value: {result}")

    return result

def test_and_or():
    for in1 in range(2):
        for in2 in range(2):
            for in3 in range(2):
                res = run_and_or(in1, in2, in3)
                expected = (in1 and in2) or in3
                if res == expected:
                    print(f"Successful emulation of AND-OR({in1}, {in2}, {in3})")
                else:
                    print(f"Unsuccessful emulation of AND-OR({in1}, {in2}, {in3}):")
                    print(f"\tExpected: {expected}")
                    print(f"\tResult: {res}")

# Run tests with `python unit_tests.py <test_name>`
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unit_tests.py <test_name>")
        print("Available tests:")
        # List all functions that start with 'test_'
        tests = [name for name in globals() if name.startswith('test_')]
        for test in tests:
            print(f"  - {test}")
        sys.exit(1)

    test_name = sys.argv[1]
    if test_name in globals() and test_name.startswith('test_'):
        globals()[test_name]()  # Run the requested test
        print("Finished unit test")
    else:
        print(f"Error: Test '{test_name}' not found")
        sys.exit(1)