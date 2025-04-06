import sys
from exception_emulator import ExceptionEmulator
from ooo_emulator import OOOEmulator
from gates import *
from unicorn.x86_const import *

def test_assign_gate():
    emulator = ExceptionEmulator(ASM_EXCEPTION_ASSIGN, 'assign')

    # Set input and output addresses of assign gate
    input_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R14, input_address)
    output_address = emulator.DATA_BASE + emulator.cache.line_size  # makes sure output goes in different cache set than input
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")


def test_or_gate():
    # emulator = ExceptionEmulator(ASM_EXCEPTION_OR, 'or')
    emulator = OOOEmulator(ASM_EXCEPTION_OR, 'or')

    # Set input and output addresses of OR gate
    input1_address = emulator.DATA_BASE
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.DATA_BASE + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.DATA_BASE + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

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