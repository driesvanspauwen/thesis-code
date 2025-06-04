import struct
from typing import Tuple
from emulator import MuWMEmulator
from loader import ELFLoader
from gates.asm import *
from unicorn import *
from unicorn.x86_const import *
import time
import struct
from random import randint

def emulate_flexo_and(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses
    AND_GATE_START_ADDR = 0x11e0
    AND_GATE_END_ADDR = 0x13fb
    
    loader = ELFLoader("gates/flexo/gates/gate_and.elf")
    emulator = MuWMEmulator(name='flexo-and', loader=loader, debug=debug)
    emulator.code_start_address = AND_GATE_START_ADDR
    emulator.code_exit_addr = AND_GATE_END_ADDR
    
    try:
        # Check if memory is already mapped
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x11f9:  # The address of the call instruction
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    # Fix: Register hook for the correct address range
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x11f9, 0x11fa)
    
    # Set up inputs according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)   # Output byte pointer
    
    # Run the emulation
    emulator.emulate()
    
    # Retrieve the output
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_or(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for OR gate
    OR_GATE_START_ADDR = 0x1400
    OR_GATE_END_ADDR = 0x161b  # ret instruction of __weird__or
    
    loader = ELFLoader("gates/flexo/gates/gate_or.elf")  # Adjust path as needed
    emulator = MuWMEmulator(name='flexo-or', loader=loader, debug=debug)
    emulator.code_start_address = OR_GATE_START_ADDR
    emulator.code_exit_addr = OR_GATE_END_ADDR
    
    try:
        # Check if memory is already mapped
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    # Initialize the output location
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x1419:  # The address of the call instruction for OR
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    # Register hook for the correct address range
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x1419, 0x141a)
    
    # Set up inputs according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)   # Output byte pointer
    
    # Run the emulation
    emulator.emulate()
    
    # Retrieve the output
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])


def emulate_flexo_not(in1, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for NOT gate
    NOT_GATE_START_ADDR = 0x1620
    NOT_GATE_END_ADDR = 0x17d5  # ret instruction of __weird__not
    
    loader = ELFLoader("gates/flexo/gates/gate_not.elf")  # Adjust path as needed
    emulator = MuWMEmulator(name='flexo-not', loader=loader, debug=debug)
    emulator.code_start_address = NOT_GATE_START_ADDR
    emulator.code_exit_addr = NOT_GATE_END_ADDR
    
    try:
        # Check if memory is already mapped
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    # Initialize the output location
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x1632:  # The address of the call instruction for NOT
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    # Register hook for the correct address range
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x1632, 0x1633)
    
    # Set up inputs according to calling convention
    # Note: NOT gate only takes one input, so only RDI and RSI (output pointer)
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # Boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, OUT_ADDR)   # Output byte pointer (different from AND/OR!)
    
    # Run the emulation
    emulator.emulate()
    
    # Retrieve the output
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_nand(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for NAND
    NAND_GATE_START_ADDR = 0x17e0
    NAND_GATE_END_ADDR = 0x19fb  # ret instruction of __weird__nand
    
    loader = ELFLoader("gates/flexo/gates/gate_nand.elf")
    emulator = MuWMEmulator(name='flexo-nand', loader=loader, debug=debug)
    emulator.code_start_address = NAND_GATE_START_ADDR
    emulator.code_exit_addr = NAND_GATE_END_ADDR
    
    try:
        # Check if memory is already mapped
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        # If not, map it
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    # Initialize the output location
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x17f9:  # The address of the call instruction for NAND
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    # Register hook for the correct address range
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x17f9, 0x17fa)
    
    # Set up inputs according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)   # Output byte pointer
    
    # Run the emulation
    emulator.emulate()
    
    # Retrieve the output
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_xor(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR
    XOR_GATE_START_ADDR = 0x1a00
    XOR_GATE_END_ADDR = 0x1c1b  # ret instruction of __weird__xor
    
    loader = ELFLoader("gates/flexo/gates/gate_xor.elf")  # Same ELF file
    emulator = MuWMEmulator(name='flexo-xor', loader=loader, debug=debug)
    emulator.code_start_address = XOR_GATE_START_ADDR
    emulator.code_exit_addr = XOR_GATE_END_ADDR
    
    try:
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    # Initialize the output location
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    # Add hook to skip the call to rand@plt
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x1a19:  # The address from XOR disassembly
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x1a19, 0x1a1a)
    
    # Set up inputs according to calling convention
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)   # Output byte pointer
    
    # Run the emulation
    emulator.emulate()
    
    # Retrieve the output
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_xor3(in1, in2, in3, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR3
    XOR3_GATE_START_ADDR = 0x1ed0
    XOR3_GATE_END_ADDR = 0x2172  # ret instruction of __weird__xor3
    
    loader = ELFLoader("gates/flexo/gates/gate_xor3.elf")
    emulator = MuWMEmulator(name='flexo-xor3', loader=loader, debug=debug)
    emulator.code_start_address = XOR3_GATE_START_ADDR
    emulator.code_exit_addr = XOR3_GATE_END_ADDR
    
    try:
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x1ef2:  # The address from XOR3 disassembly
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x1ef2, 0x1ef3)
    
    # Set up inputs for 3-input function
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, in3 & 0x1)  # Third boolean input
    emulator.uc.reg_write(UC_X86_REG_RCX, OUT_ADDR)   # Output byte pointer
    
    emulator.emulate()
    
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_xor4(in1, in2, in3, in4, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR4
    XOR4_GATE_START_ADDR = 0x2180
    XOR4_GATE_END_ADDR = 0x24b3  # ret instruction of __weird__xor4
    
    loader = ELFLoader("gates/flexo/gates/gate_xor4.elf")
    emulator = MuWMEmulator(name='flexo-xor4', loader=loader, debug=debug)
    emulator.code_start_address = XOR4_GATE_START_ADDR
    emulator.code_exit_addr = XOR4_GATE_END_ADDR
    
    try:
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x21ab:  # The address from XOR4 disassembly
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x21ab, 0x21ac)
    
    # Set up inputs for 4-input function
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First boolean input
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second boolean input
    emulator.uc.reg_write(UC_X86_REG_RDX, in3 & 0x1)  # Third boolean input
    emulator.uc.reg_write(UC_X86_REG_RCX, in4 & 0x1)  # Fourth boolean input
    emulator.uc.reg_write(UC_X86_REG_R8, OUT_ADDR)    # Output byte pointer (5th argument goes to R8)
    
    emulator.emulate()
    
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_mux(in1, in2, sel, debug=False):
    OUT_ADDR = 0x10000000 # pick an address not in code and stack sections
    
    # Function addresses for MUX
    MUX_GATE_START_ADDR = 0x1c20
    MUX_GATE_END_ADDR = 0x1ec2  # ret instruction of __weird__mux
    
    loader = ELFLoader("gates/flexo/gates/gate_mux.elf")
    emulator = MuWMEmulator(name='flexo-mux', loader=loader, debug=debug)
    emulator.code_start_address = MUX_GATE_START_ADDR
    emulator.code_exit_addr = MUX_GATE_END_ADDR
    
    try:
        emulator.uc.mem_read(OUT_ADDR, 1)
    except:
        emulator.logger.log(f"Manually mapping memory for output address {OUT_ADDR:#x}")
        emulator.uc.mem_map(0x10000000, 0x1000, UC_PROT_ALL)
    
    emulator.uc.mem_write(OUT_ADDR, b'\x00')
    
    def hook_rand_call(uc, address, size, user_data):
        if address == 0x1c42:  # The address from MUX disassembly
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, 0x1c42, 0x1c43)
    
    # Set up inputs for MUX (multiplexer: output = sel ? in2 : in1)
    emulator.uc.reg_write(UC_X86_REG_RDI, in1 & 0x1)  # First input (selected when sel=0)
    emulator.uc.reg_write(UC_X86_REG_RSI, in2 & 0x1)  # Second input (selected when sel=1)  
    emulator.uc.reg_write(UC_X86_REG_RDX, sel & 0x1)  # Selector
    emulator.uc.reg_write(UC_X86_REG_RCX, OUT_ADDR)   # Output byte pointer
    
    emulator.emulate()
    
    result_bytes = emulator.uc.mem_read(OUT_ADDR, 1)
    return int(result_bytes[0])

def emulate_flexo_adder8(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    """
    Emulate the Flexo‐compiled 8‐bit weird‐machine adder (__weird__adder8).
    Returns (sum, error_flag) as two 8-bit integers.
    """

    # Addresses for code and data
    ADDER_START_ADDR = 0x1270
    ADDER_END_ADDR   = 0x362e  # address of 'ret' in __weird__adder8
    RAND_CALL_ADDR   = 0x12a0  # call to rand@plt
    MEM_SIZE         = 0x1000

    # data buffers in guest RAM
    IN1_ADDR     = 0x20000000
    IN2_ADDR     = 0x20001000
    OUT_ADDR     = 0x20002000
    ERR_OUT_ADDR = 0x20003000

    # load binary and create emulator
    loader = ELFLoader("gates/flexo/arithmetic/adder.elf")
    emulator = MuWMEmulator(name="flexo-adder8", loader=loader, debug=debug)
    emulator.code_start_address = ADDER_START_ADDR
    emulator.code_exit_addr = ADDER_END_ADDR

    # map and initialize memory for inputs/outputs
    for addr in (IN1_ADDR, IN2_ADDR, OUT_ADDR, ERR_OUT_ADDR):
        try:
            emulator.uc.mem_read(addr, 1)
        except:
            emulator.logger.log(f"Mapping 0x{addr:08x}")
            emulator.uc.mem_map(addr, MEM_SIZE, UC_PROT_ALL)

    # write little‐endian 8‐byte inputs (only low byte nonzero)
    in1_bytes = bytes([a & 0xFF] + [0]*7)
    in2_bytes = bytes([b & 0xFF] + [0]*7)
    emulator.uc.mem_write(IN1_ADDR,     in1_bytes)
    emulator.uc.mem_write(IN2_ADDR,     in2_bytes)
    emulator.uc.mem_write(OUT_ADDR,     b'\x00'*8)
    emulator.uc.mem_write(ERR_OUT_ADDR, b'\x00'*8)

    # intercept rand() calls to deterministic value
    def hook_rand(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False

    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand, None, RAND_CALL_ADDR, RAND_CALL_ADDR+1)

    # set up function arguments:
    emulator.uc.reg_write(UC_X86_REG_RDI, IN1_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, IN2_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERR_OUT_ADDR)

    # run until ret in __weird__adder8
    emulator.emulate()

    # fetch results (low bytes only)
    result = emulator.uc.mem_read(OUT_ADDR, 1)[0]
    error_flag = emulator.uc.mem_read(ERR_OUT_ADDR, 1)[0]

    return result, error_flag

def emulate_flexo_adder16(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    # Addresses from objdump
    ADDER_START_ADDR = 0x3630
    ADDER_END_ADDR   = 0x94da  # address of 'ret' in __weird__adder16
    RAND_CALL_ADDR   = 0x3660  # call to rand@plt
    MEM_SIZE         = 0x1000

    # data buffers
    IN1_ADDR     = 0x20000000
    IN2_ADDR     = 0x20001000
    OUT_ADDR     = 0x20002000
    ERR_OUT_ADDR = 0x20003000

    loader   = ELFLoader("gates/flexo/arithmetic/adder.elf")
    emulator = MuWMEmulator(name="flexo-adder16", loader=loader, debug=debug)
    emulator.code_start_address = ADDER_START_ADDR
    emulator.code_exit_addr = ADDER_END_ADDR

    # map memory
    for addr in (IN1_ADDR, IN2_ADDR, OUT_ADDR, ERR_OUT_ADDR):
        try:
            emulator.uc.mem_read(addr, 1)
        except:
            emulator.uc.mem_map(addr, MEM_SIZE, UC_PROT_ALL)

    # write inputs (8‐byte buffers, low 2 bytes hold the value)
    in1 = (a & 0xFFFF).to_bytes(2, 'little') + b'\x00'*6
    in2 = (b & 0xFFFF).to_bytes(2, 'little') + b'\x00'*6
    emulator.uc.mem_write(IN1_ADDR,     in1)
    emulator.uc.mem_write(IN2_ADDR,     in2)
    emulator.uc.mem_write(OUT_ADDR,     b'\x00'*8)
    emulator.uc.mem_write(ERR_OUT_ADDR, b'\x00'*8)

    # hook rand()
    def hook_rand(uc, addr, size, ud):
        if addr == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand, None, RAND_CALL_ADDR, RAND_CALL_ADDR+1)

    # arguments: rdi, rsi, rdx, rcx
    uc = emulator.uc
    uc.reg_write(UC_X86_REG_RDI, IN1_ADDR)
    uc.reg_write(UC_X86_REG_RSI, IN2_ADDR)
    uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)
    uc.reg_write(UC_X86_REG_RCX, ERR_OUT_ADDR)

    emulator.emulate()

    # read 2-byte result and error_flag
    result = int.from_bytes(uc.mem_read(OUT_ADDR, 2), 'little')
    error_flag = uc.mem_read(ERR_OUT_ADDR, 1)[0]
    return result, error_flag

def emulate_flexo_adder32(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    # Addresses from objdump
    ADDER_START_ADDR = 0x94e0
    ADDER_END_ADDR   = 0x16bd1  # address of 'ret' in __weird__adder16
    RAND_CALL_ADDR   = 0x9510  # call to rand@plt
    MEM_SIZE         = 0x1000

    # data buffers
    IN1_ADDR     = 0x20000000
    IN2_ADDR     = 0x20001000
    OUT_ADDR     = 0x20002000
    ERR_OUT_ADDR = 0x20003000

    loader   = ELFLoader("gates/flexo/arithmetic/adder.elf")
    # cache = LRUCache(amt_sets=64, amt_ways=8, line_size=64, debug=False)
    emulator = MuWMEmulator(name="flexo-adder32", loader=loader, debug=debug)
    
    emulator.code_start_address = ADDER_START_ADDR
    emulator.code_exit_addr = ADDER_END_ADDR

    # map memory
    for addr in (IN1_ADDR, IN2_ADDR, OUT_ADDR, ERR_OUT_ADDR):
        try:
            emulator.uc.mem_unmap(addr, MEM_SIZE)
        except:
            pass
        emulator.uc.mem_map(addr, MEM_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    # write inputs (8‐byte buffers, low 4 bytes hold the value)
    in1 = (a & 0xFFFFFFFF).to_bytes(4, 'little') + b'\x00'*4
    in2 = (b & 0xFFFFFFFF).to_bytes(4, 'little') + b'\x00'*4
    emulator.uc.mem_write(IN1_ADDR,     in1)
    emulator.uc.mem_write(IN2_ADDR,     in2)
    emulator.uc.mem_write(OUT_ADDR,     b'\x00'*8)
    emulator.uc.mem_write(ERR_OUT_ADDR, b'\x00'*8)

    # Hook rand@plt function call to make it deterministic
    def hook_rand(uc, addr, size, ud):
        if addr == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand, None, RAND_CALL_ADDR, RAND_CALL_ADDR+1)

    # arguments
    uc = emulator.uc
    uc.reg_write(UC_X86_REG_RDI, IN1_ADDR)
    uc.reg_write(UC_X86_REG_RSI, IN2_ADDR)
    uc.reg_write(UC_X86_REG_RDX, OUT_ADDR)
    uc.reg_write(UC_X86_REG_RCX, ERR_OUT_ADDR)

    emulator.emulate()

    # read 4-byte result and error_flag
    result = int.from_bytes(uc.mem_read(OUT_ADDR, 4), 'little')
    error_flag = uc.mem_read(ERR_OUT_ADDR, 1)[0]
    return result, error_flag

def emulate_flexo_sha1_round(state_in, w_in, debug=False):
    # Constants
    INPUT_ADDR = 0x200000  # well above ELF segments
    KEY_ADDR = 0x201000
    OUTPUT_ADDR = 0x202000
    ERROR_OUTPUT_ADDR = 0x203000
    PAGE_SIZE = 0x1000

    # Function addresses
    WEIRD_SHA1_ADDR = 0x1550
    RAND_CALL_ADDR = 0x157f
    SHA1_RET_ADDR   = 0x28e73

    # Create emulator
    loader = ELFLoader("gates/flexo/sha1/sha1_round.elf")
    emulator = MuWMEmulator(name='flexo-sha1', loader=loader, debug=debug)

    emulator.code_start_address = WEIRD_SHA1_ADDR
    emulator.code_exit_addr = SHA1_RET_ADDR

    # Set up memory for inputs and outputs
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE)

    # Write input: state (5x uint32) + w (1x uint32)
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<5I", *state_in))

    # Register setup: rdi=input, rsi=w, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, w_in)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)

    # Hook rand@plt function call to make it deterministic
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_SHA1_ADDR, SHA1_RET_ADDR)

    # Emulate
    emulator.emulate()

    # Read outputs
    result = list(struct.unpack("<5I", emulator.uc.mem_read(OUTPUT_ADDR, 20)))
    err_out = list(struct.unpack("<5I", emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 20)))

    return result, err_out

def emulate_flexo_aes_round(input_block, key_block, debug=False):
    # Constants
    INPUT_ADDR = 0x200000  # well above ELF segments
    KEY_ADDR = 0x201000
    OUTPUT_ADDR = 0x202000
    ERROR_OUTPUT_ADDR = 0x203000
    PAGE_SIZE = 0x1000
    
    # Function addresses
    WEIRD_AES_ADDR = 0x1c30
    RAND_CALL_ADDR = 0x1c60
    AES_RET_ADDR = 0xb4f44
    
    # Create emulator
    loader = ELFLoader("gates/flexo/aes/aes_round-16.elf")
    emulator = MuWMEmulator(name='flexo-aes', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_AES_ADDR
    emulator.code_exit_addr = AES_RET_ADDR
    
    # Set up memory for inputs and outputs
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(KEY_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE)
    
    # Write input: 16-byte block and 16-byte key
    emulator.uc.mem_write(INPUT_ADDR, bytes(input_block))
    emulator.uc.mem_write(KEY_ADDR, bytes(key_block))
    
    # Register setup: rdi=input, rsi=key, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, KEY_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)
    
    # Hook rand@plt function call to make it deterministic
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_AES_ADDR, AES_RET_ADDR)
    
    # Emulate
    emulator.emulate()
    
    # Read outputs
    result = list(emulator.uc.mem_read(OUTPUT_ADDR, 16))
    err_out = list(emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 16))
    
    return result, err_out

def emulate_flexo_simon32(input_block, key_block, debug=False):
    # Constants - Use addresses that don't conflict with ELF segments
    INPUT_ADDR = 0x200000  # well above ELF segments
    KEY_ADDR = 0x201000
    OUTPUT_ADDR = 0x202000
    ERROR_OUTPUT_ADDR = 0x203000
    PAGE_SIZE = 0x1000
    
    # Function addresses
    WEIRD_SIMON_ADDR = 0x1440
    RAND_CALL_ADDR = 0x1470
    SIMON_RET_ADDR = 0x116246
    
    # Create emulator
    loader = ELFLoader("gates/flexo/simon/simon32-14.elf")
    emulator = MuWMEmulator(name='flexo-simon32', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_SIMON_ADDR
    emulator.code_exit_addr = SIMON_RET_ADDR
    
    # Set up memory for inputs and outputs
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(KEY_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE)
    
    # Write input: 4-byte block and 8-byte key
    emulator.uc.mem_write(INPUT_ADDR, bytes(input_block))
    emulator.uc.mem_write(KEY_ADDR, bytes(key_block))
    
    # Register setup: rdi=input, rsi=key, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, KEY_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)
    
    # Hook rand@plt function call to make it deterministic
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_SIMON_ADDR, SIMON_RET_ADDR)
    
    # Emulate
    emulator.emulate()
    
    # Read outputs
    result = list(emulator.uc.mem_read(OUTPUT_ADDR, 4))
    err_out = list(emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 4))
    
    return result, err_out
