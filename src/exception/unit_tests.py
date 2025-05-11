import sys
from exception_emulator import ExceptionEmulator
from loader import *
from gates.asm import *
from unicorn.x86_const import *

def run_assign(in1, debug=False):
    code = get_asm_exception_assign(in1)
    loader = AsmLoader(code)
    emulator = ExceptionEmulator('assign', loader, debug)

    # Set input and output addresses of assign gate
    input_address = emulator.data_start_addr
    emulator.mu.reg_write(UC_X86_REG_R14, input_address)
    output_address = emulator.data_start_addr + emulator.cache.line_size  # makes sure output goes in different cache set than input
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

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
    emulator = ExceptionEmulator('or', loader, debug)

    emulator.logger.log(f"Starting emulation of OR({in1}, {in2})...")

    # Set input and output addresses of OR gate
    input1_address = emulator.data_start_addr
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

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
    emulator = ExceptionEmulator('and', loader, debug)

    emulator.logger.log(f"Starting emulation of AND({in1}, {in2})...")

    # Set input and output addresses of AND gate
    input1_address = emulator.data_start_addr
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
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
                print(f"Test passed for AND({in1}, {in2})")
            else:
                print(f"Test failed for AND({in1}, {in2}):")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {res}")

# Test Out[0] = (In1[0] ∧ In2[0]) ∨ In3[0]
def run_and_or(in1, in2, in3, debug=False):
    code = get_asm_exception_and_or(in1, in2, in3)
    loader = AsmLoader(code)
    emulator = ExceptionEmulator('and_or', loader, debug)

    emulator.logger.log(f"Starting emulation of AND-OR({in1}, {in2}, {in3})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)
    
    input3_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R12, input3_address)
    
    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
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
                    print(f"Test passed for AND-OR({in1}, {in2}, {in3})")
                else:
                    print(f"Test failed for AND-OR({in1}, {in2}, {in3}):")
                    print(f"\tExpected: {expected}")
                    print(f"\tResult: {res}")

def run_not(in1, debug=False):
    code = get_asm_exception_not(in1)
    loader = AsmLoader(code)
    emulator = ExceptionEmulator('not', loader, True)

    emulator.logger.log(f"Starting emulation of NOT({in1})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.mu.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R14, input2_address)

    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
    emulator.mu.reg_write(UC_X86_REG_R15, output_address)

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

def run_nand(in1, in2, debug=False):
    # Memory addresses from the disassembly/source code
    IN1_ADDR = 0x7040
    IN2_ADDR = 0x6840
    OUT_ADDR = 0x6040
    TMP_REG1_ADDR = 0x5840  # output AND
    TMP_REG2_ADDR = 0x5040  # input NOT (1)
    TMP_REG3_ADDR = 0x4840  # input NOT (2)
    TMP_REG4_ADDR = 0x4040  # delay NOT

    # Function address
    NAND_GATE_START_ADDR = 0x13a0
    NAND_GATE_END_ADDR = 0x16df  # ret instruction of nand_gate
    FAULT_HANDLER_ADDR = 0x1390

    # Load ELF file
    loader = ELFLoader("gates/nand/nand.elf")
    emulator = ExceptionEmulator('nand', loader, debug)
    emulator.code_start_address = NAND_GATE_START_ADDR
    emulator.code_exit_addr = NAND_GATE_END_ADDR
    emulator.fault_handler_addr = FAULT_HANDLER_ADDR

    # Set inputs
    if in1:
        emulator.cache.read(IN1_ADDR, emulator.mu)
    if in2:
        emulator.cache.read(IN2_ADDR, emulator.mu)
    emulator.mu.reg_write(UC_X86_REG_RDI, IN1_ADDR)
    emulator.mu.reg_write(UC_X86_REG_RSI, IN2_ADDR)
    emulator.mu.reg_write(UC_X86_REG_RDX, OUT_ADDR)

    emulator.logger.log(f"Starting emulation of NAND({in1}, {in2})...")

    emulator.emulate()

    result = emulator.cache.is_cached(OUT_ADDR)
    emulator.logger.log(f"Output value: {result}")

    return result

def test_nand():
    for in1 in range(2):
        for in2 in range(2):
            res = run_nand(in1, in2)
            expected = not (in1 and in2)
            if res == expected:
                print(f"Test passed for NAND({in1}, {in2})")
            else:
                print(f"Test failed for NAND({in1}, {in2}):")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {res}")

def run_mux(in1, in2, in3, debug=False):
    # OUT = (IN1 AND NOT IN3) OR (IN2 AND IN3)
    IN1_ADDR = 0xe040
    IN2_ADDR = 0xd840
    IN3_ADDR = 0xd040
    OUT_ADDR = 0xc840
    
    TMP_REG1_ADDR = 0x9840  # selector bit - first input NOT gate
    TMP_REG2_ADDR = 0x9040  # selector bit - second input NOT gate
    TMP_REG3_ADDR = 0x8840  # result of AND(in2, in3)
    TMP_REG4_ADDR = 0x8040  # result of NOT(tmp_reg1, tmp_reg2)
    TMP_REG5_ADDR = 0x7840  # delay for NOT
    TMP_REG6_ADDR = 0x7040  # result of AND(in1, tmp_reg4)

    # Function addresses
    MUX_GATE_START_ADDR = 0x1560
    MUX_GATE_END_ADDR = 0x1bae  # ret instruction of mux_gate
    FAULT_HANDLER_ADDR = 0x1550

    # Calculate the input parameter as a 3-bit value
    input_param = (in1) | (in2 << 1) | (in3 << 2)

    # Initialize emulator
    loader = ELFLoader("gates/mux/mux.elf")
    emulator = ExceptionEmulator('mux', loader, debug)
    emulator.code_start_address = MUX_GATE_START_ADDR
    emulator.code_exit_addr = MUX_GATE_END_ADDR
    emulator.fault_handler_addr = FAULT_HANDLER_ADDR

    # Set up inputs in cache if needed
    if in1:
        emulator.cache.read(IN1_ADDR, emulator.mu)
    if in2:
        emulator.cache.read(IN2_ADDR, emulator.mu)
    if in3:
        emulator.cache.read(IN3_ADDR, emulator.mu)

    # Set up registers according to calling convention
    emulator.mu.reg_write(UC_X86_REG_RDI, IN1_ADDR)  # in1
    emulator.mu.reg_write(UC_X86_REG_RSI, IN2_ADDR)  # in2
    emulator.mu.reg_write(UC_X86_REG_RDX, IN3_ADDR)  # in3
    emulator.mu.reg_write(UC_X86_REG_RCX, OUT_ADDR)  # out
    emulator.mu.reg_write(UC_X86_REG_R8D, input_param)  # input parameter

    # Run the emulation
    emulator.emulate()

    # Check the result
    result = emulator.cache.is_cached(OUT_ADDR)
    expected = in1 if (in3 == 0) else in2  # MUX logic
    
    return result, expected

def test_mux():
    for in1_val in range(2):
        for in2_val in range(2):
            for in3_val in range(2):
                res, expected = run_mux(in1_val, in2_val, in3_val, debug=False)
                if res == expected:
                    print(f"Test passed for MUX({in1_val}, {in2_val}, {in3_val})")
                else:
                    print(f"Test failed for MUX({in1_val}, {in2_val}, {in3_val})")
                    print(f"\tExpected: {expected}")
                    print(f"\tResult: {res}")

def run_flexo_and(in1, in2, debug=False):
    POS_WIRE_ADDR = 0x800ea48  # Address of positive wire (from log)
    NEG_WIRE_ADDR = 0x800fc48  # Address of negative wire (from log)
    OUT_ADDR = 0x8000

    # Function addresses
    AND_GATE_START_ADDR = 0x11d0
    AND_GATE_END_ADDR = 0x13eb  # ret instruction of __weird__and
    
    loader = ELFLoader("gates/flexo/test.elf")
    emulator = ExceptionEmulator('flexo-and', loader, debug)
    emulator.code_start_address = AND_GATE_START_ADDR
    emulator.code_exit_addr = AND_GATE_END_ADDR

    try:
        # Check if memory is already mapped
        emulator.mu.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.mu.mem_map(OUT_ADDR & 0xFFFFF000, 0x1000, UC_PROT_ALL)

    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        # Check if we're at the call to rand@plt
        if address == 0x11e9:  # The address of the call instruction
            # Simply skip the call and put a fixed value in RAX
            # (since rand returns an integer in RAX)
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            # Skip to the instruction after the call
            uc.reg_write(UC_X86_REG_RIP, 0x11ee)  # Address after the call
            return True
        return False

    # Add hook for the call instruction
    emulator.mu.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x11e9, 0x11ea)

    # Set up inputs according to calling convention
    emulator.mu.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.mu.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.mu.reg_write(UC_X86_REG_RDX, OUT_ADDR)  # Output byte pointer

    # Run the emulation
    emulator.emulate()

    # Retrieve the output
    result_bytes = emulator.mu.mem_read(0x8000, 1)
    return int(result_bytes[0])

def test_flexo_and():
    for in1 in range(2):
        for in2 in range(2):
            res = run_flexo_and(in1, in2)
            expected = in1 and in2
            if res == expected:
                print(f"Test passed for AND({in1}, {in2})")
            else:
                print(f"Test failed for AND({in1}, {in2}):")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {res}")

run_flexo_and(1, 1, debug=True)

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

# run_mux(0, 0, 0, debug=True)
# run_and(1, 1, debug=True)
# run_nand(1, 0, debug=True)
# run_and_or(1, 1, 0, debug=True)
# run_not(1, debug=True)

# Run tests with `python unit_tests.py <test_name>` or `python unit_tests.py all`
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