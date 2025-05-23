from emulator import MuWMEmulator
from loader import AsmLoader
from gates.asm import *
from unicorn.x86_const import *

def run_assign(in1, debug=False):
    code = get_asm_exception_assign(in1)
    loader = AsmLoader(code)
    emulator = MuWMEmulator('assign', loader, debug)

    # Set input and output addresses of assign gate
    input_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R14, input_address)
    output_address = emulator.data_start_addr + emulator.cache.line_size  # makes sure output goes in different cache set than input
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_assign():
    for in1 in range(2):
        res = run_assign(in1)
        if res == in1:
            print(f"Test passed for Assign({in1})")
        else:
            print(f"Test failed for Assign({in1}):")
            print(f"\tExpected: {in1}")
            print(f"\tResult: {res}")

def run_or(in1, in2, debug=False):
    code = get_asm_exception_or(in1, in2)
    loader = AsmLoader(code)
    emulator = MuWMEmulator('or', loader, debug)

    emulator.logger.log(f"Starting emulation of OR({in1}, {in2})...")

    # Set input and output addresses of OR gate
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_or():
    for in1 in range(2):
        for in2 in range(2):
            res = run_or(in1, in2)
            if res == in1 or in2:
                print(f"Test passed for OR({in1}, {in2})")
            else:
                print(f"Test failed for OR({in1}, {in2}):")
                print(f"\tExpected: {in1 or in2}")
                print(f"\tResult: {res}")

def run_and(in1, in2, debug=False):
    code = get_asm_exception_and(in1, in2)
    loader = AsmLoader(code)
    emulator = MuWMEmulator('and', loader, debug)

    emulator.logger.log(f"Starting emulation of AND({in1}, {in2})...")

    # Set input and output addresses of AND gate
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def test_and():
    for in1 in range(2):
        for in2 in range(2):
            res = run_and(in1, in2)
            expected = in1 and in2
            if res == expected:
                print(f"Test passed for AND({in1}, {in2})")
            else:
                print(f"Test failed for AND({in1}, {in2}):")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {res}")

# Test Out[0] = (In1[0] ∧ In2[0]) ∨ In3[0]
def run_and_or(in1, in2, in3, debug=False):
    code = get_asm_exception_and_or(in1, in2, in3)
    loader = AsmLoader(code)
    emulator = MuWMEmulator('and_or', loader, debug)

    emulator.logger.log(f"Starting emulation of AND-OR({in1}, {in2}, {in3})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    
    input3_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R12, input3_address)
    
    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

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
                    print(f"Test passed for AND-OR({in1}, {in2}, {in3})")
                else:
                    print(f"Test failed for AND-OR({in1}, {in2}, {in3}):")
                    print(f"\tExpected: {expected}")
                    print(f"\tResult: {res}")

def run_not(in1, debug=False):
    code = get_asm_exception_not(in1)
    loader = AsmLoader(code)
    emulator = MuWMEmulator('not', loader, True)

    emulator.logger.log(f"Starting emulation of NOT({in1})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)

    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    result = emulator.cache.is_cached(output_address)
    emulator.logger.log(f"Output value: {result}")

    return result

def test_not():
    for in1 in range(2):
        res = run_not(in1)
        expected = not in1
        if res == expected:
            print(f"Test passed for NOT({in1})")
        else:
            print(f"Test failed for NOT({in1}):")
            print(f"\tExpected: {expected}")
            print(f"\tResult: {res}")