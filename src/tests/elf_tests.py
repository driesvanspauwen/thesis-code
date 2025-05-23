from emulator import MuWMEmulator
from loader import ELFLoader
from gates.asm import *
from unicorn import *
from unicorn.x86_const import *

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
    emulator = MuWMEmulator('nand', loader, debug)
    emulator.code_start_address = NAND_GATE_START_ADDR
    emulator.code_exit_addr = NAND_GATE_END_ADDR
    emulator.fault_handler_addr = FAULT_HANDLER_ADDR

    # Set inputs
    if in1:
        emulator.cache.read(IN1_ADDR, emulator.uc)
    if in2:
        emulator.cache.read(IN2_ADDR, emulator.uc)
    emulator.uc.reg_write(UC_X86_REG_RDI, IN1_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, IN2_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)

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
    emulator = MuWMEmulator('mux', loader, debug)
    emulator.code_start_address = MUX_GATE_START_ADDR
    emulator.code_exit_addr = MUX_GATE_END_ADDR
    emulator.fault_handler_addr = FAULT_HANDLER_ADDR

    # Set up inputs in cache if needed
    if in1:
        emulator.cache.read(IN1_ADDR, emulator.uc)
    if in2:
        emulator.cache.read(IN2_ADDR, emulator.uc)
    if in3:
        emulator.cache.read(IN3_ADDR, emulator.uc)

    # Set up registers according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, IN1_ADDR)  # in1
    emulator.uc.reg_write(UC_X86_REG_RSI, IN2_ADDR)  # in2
    emulator.uc.reg_write(UC_X86_REG_RDX, IN3_ADDR)  # in3
    emulator.uc.reg_write(UC_X86_REG_RCX, OUT_ADDR)  # out
    emulator.uc.reg_write(UC_X86_REG_R8D, input_param)  # input parameter

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
    emulator = MuWMEmulator('flexo-and', loader, debug)
    emulator.code_start_address = AND_GATE_START_ADDR
    emulator.code_exit_addr = AND_GATE_END_ADDR

    try:
        # Check if memory is already mapped
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(OUT_ADDR & 0xFFFFF000, 0x1000, UC_PROT_ALL)

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
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x11e9, 0x11ea)

    # Set up inputs according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)  # Output byte pointer

    # Run the emulation
    emulator.emulate()

    # Retrieve the output
    result_bytes = emulator.uc.mem_read(0x8000, 1)
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