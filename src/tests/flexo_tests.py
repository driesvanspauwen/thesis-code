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
from tests.ref import *

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

def emulate_flexo_sha1_2blocks(block1, block2, debug=False):
    # Constants
    INPUT_ADDR = 0x200000
    STATES_ADDR = 0x201000
    PAGE_SIZE = 0x1000

    # Function addresses
    SHA1_BLOCK_ADDR = 0xa2820
    SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
    # Round function addresses (you need to provide these)
    WEIRD_SHA1_ROUND1_ADDR = 0x1560  # You need to find
    WEIRD_SHA1_ROUND2_ADDR = 0x28e90  # You need to find  
    WEIRD_SHA1_ROUND3_ADDR = 0x50820  # You need to find
    WEIRD_SHA1_ROUND4_ADDR = 0x7a560  # You need to find

    # Create emulator
    loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-2blocks', loader=loader, debug=debug)

    # Set up memory
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE * 3)  # Space for both blocks + states
    
    # Initialize SHA-1 state (standard initial values)
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))
    
    # Process first block
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block1))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
    # Set up registers for sha1_block(block1, states, false)
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)      # block pointer
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)     # states pointer  
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)               # do_ref = false

    # Hook the weird round functions to make rand() deterministic
    def hook_dyn_calls(uc: Uc, address, size, user_data):
        # Handle rand calls within weird functions
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        
        # Handle memset call at 0xa284f
        elif address == 0xa284f:  # memset@plt
            # memset(rdi, rsi, rdx) - set memory
            rdi = uc.reg_read(UC_X86_REG_RDI)  # destination
            rsi = uc.reg_read(UC_X86_REG_RSI)  # value (should be 0)
            rdx = uc.reg_read(UC_X86_REG_RDX)  # size (should be 0xa0 = 160 bytes)
            
            print(f"MEMSET: addr={hex(rdi)}, value={rsi}, size={rdx}")
            
            # Implement memset: fill memory with the specified value
            data = bytes([rsi & 0xFF] * int(rdx))   # Convert rdx to int
            uc.mem_write(rdi, data)
            
            emulator.skip_curr_insn()
            return True
        
        # Handle memcpy call at 0xa2869  
        elif address == 0xa2869:  # memcpy@plt
            rdi = int(uc.reg_read(UC_X86_REG_RDI))
            rsi = int(uc.reg_read(UC_X86_REG_RSI))
            rdx = int(uc.reg_read(UC_X86_REG_RDX))

            print(f"MEMCPY: dest={hex(rdi)}, src={hex(rsi)}, size={rdx}")
            print(f"  (types: rdi={type(rdi)}, rsi={type(rsi)}, rdx={type(rdx)})")

            # First, just try the read:
            try:
                raw_chunk = uc.mem_read(rsi, rdx)
            except Exception as e_read:
                print(f"  ERROR reading src: {e_read!r}")
                emulator.skip_curr_insn()
                return True

            try:
                chunk = bytes(raw_chunk)                  # ← IMPORTANT: make it a real bytes
            except Exception as e_cast:
                print(f"  ERROR casting to bytes: {e_cast!r}")
                emulator.skip_curr_insn()
                return True

            try:
                uc.mem_write(rdi, chunk)
                print(f"  Copied {rdx} bytes from {hex(rsi)} to {hex(rdi)}")
            except Exception as e_write:
                print(f"  ERROR writing to dst: {e_write!r}")
                emulator.skip_curr_insn()
                return True

            print(f"  Copied {rdx} bytes from {hex(rsi)} to {hex(rdi)}")

            # Now read back first 16 bytes to verify:
            if rdx >= 16:
                try:
                    raw = uc.mem_read(rdi, 16)
                    print(f"  [debug] post‐write raw type: {type(raw)}, length: {len(raw)}")
                    if not isinstance(raw, bytes):
                        raw = bytes(raw)
                    if len(raw) != 16:
                        raise ValueError(f"Expected 16 bytes, got {len(raw)}")
                    words = struct.unpack("<4I", raw)
                    print(f"  First 4 words copied: {[hex(w) for w in words]}")
                except Exception as e_verify:
                    print(f"  ERROR verifying copied data: {e_verify!r}")

            emulator.skip_curr_insn()
            return True

        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530) # start round1, finish __DualGate__2_1_6

    # Emulate first block
    print("Processing first block...")
    emulator.emulate()
    
    # Get intermediate state after first block
    intermediate_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    print(f"Intermediate state after first block: {[hex(x) for x in intermediate_state]}")
    
    # Process second block
    print("Processing second block...")
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block2))
    
    # Reset registers for second block
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)
    
    # Emulate second block
    emulator.emulate()
    
    # Read final result
    final_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    
    return final_state

def emulate_flexo_sha1_1block(block1, debug=False):
    debug = True

    # Constants
    INPUT_ADDR = 0x200000
    STATES_ADDR = 0x201000
    PAGE_SIZE = 0x1000

    # Function addresses
    SHA1_BLOCK_ADDR = 0xa2820
    SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
    # Round function addresses (you need to provide these)
    WEIRD_SHA1_ROUND1_ADDR = 0x1560  # You need to find
    WEIRD_SHA1_ROUND2_ADDR = 0x28e90  # You need to find  
    WEIRD_SHA1_ROUND3_ADDR = 0x50820  # You need to find
    WEIRD_SHA1_ROUND4_ADDR = 0x7a560  # You need to find

    # Create emulator
    loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-2blocks', loader=loader, debug=debug)

    # Set up memory
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE * 3)  # Space for both blocks + states
    
    # Initialize SHA-1 state (standard initial values)
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))
    
    # Process first block
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block1))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
    # Set up registers for sha1_block(block1, states, false)
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)      # block pointer
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)     # states pointer  
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)               # do_ref = false

    # Hook the weird round functions to make rand() deterministic
    def hook_dyn_calls(uc, address, size, user_data):
        # Add addresses for rand calls within each weird function
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:  # You may need to adjust these
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        # Handle dynamic calls in sha1_block
        elif address in [0xa284f, 0xa2869]:
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530) # start round1, finish __DualGate__2_1_6

    # Emulate first block
    print("Processing first block...")
    emulator.emulate()
    
    # Get intermediate state after first block
    result = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    print(f"Result after 1 block:: {[hex(x) for x in result]}")
    
    return result

class SHA1ReferenceTracker:
    def __init__(self, block, initial_state):
        self.block = block
        self.state = list(initial_state)
        self.original_state = list(initial_state)
        self.current_round = 0
        
        # Expand w array once
        def rol(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        
        self.w = list(block)
        for i in range(16, 80):
            self.w.append(rol(self.w[i-3] ^ self.w[i-8] ^ self.w[i-14] ^ self.w[i-16], 1) & 0xFFFFFFFF)
    
    def step_to_round(self, target_round):
        """Advance reference state to target_round"""
        while self.current_round < target_round:
            round_type = 0 if self.current_round <= 19 else 1 if self.current_round <= 39 else 2 if self.current_round <= 59 else 3
            self.state = ref_sha1_round(self.state, self.w[self.current_round], round_num=round_type)
            self.current_round += 1
        
        return list(self.state)
    
    def get_final_state(self):
        """Get final state after all rounds + original state addition"""
        self.step_to_round(80)
        final_state = []
        for i in range(5):
            final_state.append((self.state[i] + self.original_state[i]) & 0xFFFFFFFF)
        return final_state

def emulate_flexo_sha1_1block_with_round_debugging(block, debug=False):
    # Constants
    INPUT_ADDR = 0x200000  
    STATES_ADDR = 0x201000
    PAGE_SIZE = 0x1000

    # Function addresses (you need to provide these)
    SHA1_BLOCK_ADDR = 0xa2820
    SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
    # Round function return addresses (you need to find these)
    WEIRD_SHA1_ROUND1_RET = 0x28e83
    WEIRD_SHA1_ROUND2_RET = 0x50813
    WEIRD_SHA1_ROUND3_RET = 0x7a556
    WEIRD_SHA1_ROUND4_RET = 0xa2816

    # Create emulator
    loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-debug', loader=loader, debug=debug)

    # Set up memory
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(STATES_ADDR, PAGE_SIZE)
    
    # Initialize SHA-1 state
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))
    
    # Prepare reference computation
    ref_state = list(initial_state)
    
    # Expand block into w array for reference
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    w = list(block)
    for i in range(16, 80):
        w.append(rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) & 0xFFFFFFFF)
    
    # Round tracking
    current_round = 0
    round_mismatches = []
    
    def get_round_type(round_num):
        if round_num <= 19:
            return 0
        elif round_num <= 39:
            return 1
        elif round_num <= 59:
            return 2
        else:
            return 3
    
    # def hook_round_returns(uc, address, size, user_data):
    #     nonlocal current_round, ref_state
        
    #     # Check if we're at a round function return
    #     if address in [WEIRD_SHA1_ROUND1_RET, WEIRD_SHA1_ROUND2_RET, 
    #                   WEIRD_SHA1_ROUND3_RET, WEIRD_SHA1_ROUND4_RET]:
            
    #         # Read current emulator state
    #         emu_state = list(struct.unpack("<5I", uc.mem_read(STATES_ADDR, 20)))
            
    #         # Update reference state for this round
    #         round_type = get_round_type(current_round)
    #         w_value = w[current_round]
    #         ref_state = ref_sha1_round(ref_state, w_value, round_num=round_type)
            
    #         # Compare states
    #         match = all(emu_state[i] == ref_state[i] for i in range(5))
            
    #         if debug or not match:
    #             print(f"Round {current_round:2d} (type {round_type}, w={hex(w_value)}):")
    #             print(f"  REF: {[hex(x) for x in ref_state]}")
    #             print(f"  EMU: {[hex(x) for x in emu_state]}")
    #             if not match:
    #                 print(f"  *** MISMATCH ***")
    #                 round_mismatches.append(current_round)
    #             print()
            
    #         current_round += 1
        
    #     return False
    
    def hook_dyn_calls(uc, address, size, user_data):
        # Add addresses for rand calls within each weird function
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:  # You may need to adjust these
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        # Handle dynamic calls in sha1_block
        elif address in [0xa284f, 0xa2869]:
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530) # start round1, finish __DualGate__2_1_6
    
    state_changes = []
    
    def hook_state_writes(uc, type, address, size, value, user_data):
        if address >= STATES_ADDR and address < STATES_ADDR + 20:
            # State memory being written
            current_state = list(struct.unpack("<5I", uc.mem_read(STATES_ADDR, 20)))
            state_changes.append(current_state.copy())
            if debug:
                print(f"State update at {hex(address)}: {[hex(x) for x in current_state]}")
        return False
    
    # Hook memory writes
    emulator.uc.hook_add(UC_HOOK_MEM_WRITE, hook_state_writes)
    
    # Add hooks
    # emulator.uc.hook_add(UC_HOOK_CODE, hook_round_returns, None, 0x1560, 0xa3530)

    # Process the block
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)  # do_ref = false
    
    print(f"Starting SHA-1 block processing with {len(block)} words...")
    print(f"Initial state: {[hex(x) for x in initial_state]}")
    print()
    
    emulator.emulate()
    
    # Read final emulator result
    final_emu_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    
    # Calculate final reference result (add original state)
    for i in range(5):
        ref_state[i] = (ref_state[i] + initial_state[i]) & 0xFFFFFFFF
    
    print("=== FINAL COMPARISON ===")
    print(f"Reference final: {[hex(x) for x in ref_state]}")
    print(f"Emulator final:  {[hex(x) for x in final_emu_state]}")
    print(f"Final match: {all(ref_state[i] == final_emu_state[i] for i in range(5))}")
    
    if round_mismatches:
        print(f"Round mismatches occurred at rounds: {round_mismatches}")
    else:
        print("All rounds matched!")
    
    return final_emu_state, ref_state, round_mismatches

# was monitoring memory instead of stack -- sha1_block uses stack for intermediate state
# def emulate_flexo_sha1_1block_full_debug(block, debug=False):
#     # Same setup as before...
#     INPUT_ADDR = 0x200000  
#     STATES_ADDR = 0x201000
#     PAGE_SIZE = 0x1000
#     SHA1_BLOCK_ADDR = 0xa2820
#     SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
#     loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
#     emulator = MuWMEmulator(name='flexo-sha1-debug', loader=loader, debug=debug)
    
#     emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
#     emulator.uc.mem_map(STATES_ADDR, PAGE_SIZE)
    
#     initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
#     emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))
    
#     def hook_everything(uc, address, size, user_data):
#         # Hook function calls
#         if size >= 5:
#             insn = uc.mem_read(address, min(size, 5))
#             if insn[0] == 0xe8:  # CALL rel32
#                 rel_offset = struct.unpack("<i", insn[1:5])[0]
#                 target = (address + size + rel_offset) & 0xFFFFFFFF
#                 print(f"CALL at {hex(address)} -> {hex(target)}")
        
#         # Hook round function entries
#         if address in [0x1560, 0x28e90, 0x50820, 0x7a560]:
#             rdi = uc.reg_read(UC_X86_REG_RDI)
#             rsi = uc.reg_read(UC_X86_REG_RSI)  
#             print(f"Round function {hex(address)} - RDI: {hex(rdi)}, RSI: {hex(rsi)}")
#             if rdi >= STATES_ADDR and rdi < STATES_ADDR + 100:
#                 try:
#                     state = list(struct.unpack("<5I", uc.mem_read(rdi, 20)))
#                     print(f"  Input state: {[hex(x) for x in state]}")
#                 except:
#                     pass
        
#         return False
    
#     def hook_state_writes(uc, type, address, size, value, user_data):
#         if address >= STATES_ADDR and address < STATES_ADDR + 20:
#             current_state = list(struct.unpack("<5I", uc.mem_read(STATES_ADDR, 20)))
#             offset = (address - STATES_ADDR) // 4
#             print(f"State[{offset}] = {hex(value)} -> {[hex(x) for x in current_state]}")
#         return False
    
#     def hook_dyn_calls(uc, address, size, user_data):
#         # Add addresses for rand calls within each weird function
#         if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:  # You may need to adjust these
#             uc.reg_write(UC_X86_REG_RAX, 0x12345678)
#             emulator.skip_curr_insn()
#             return True
#         # Handle dynamic calls in sha1_block
#         elif address in [0xa284f, 0xa2869]:
#             emulator.skip_curr_insn()
#             return True
#         return False
#     emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530) # start round1, finish __DualGate__2_1_6

#     # Add all hooks
#     emulator.uc.hook_add(UC_HOOK_CODE, hook_everything, None, 0x1000, 0xb0000)
#     emulator.uc.hook_add(UC_HOOK_MEM_WRITE, hook_state_writes)
    
#     # Same execution as before...
#     emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block))
#     emulator.code_start_address = SHA1_BLOCK_ADDR
#     emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
#     emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
#     emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
#     emulator.uc.reg_write(UC_X86_REG_RDX, 0)
    
#     print("Starting debug emulation...")
#     emulator.emulate()
    
#     final_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
#     return final_state

def emulate_flexo_sha1_1block_full_debug(block, debug=False):
    INPUT_ADDR = 0x200000  
    STATES_ADDR = 0x201000
    PAGE_SIZE = 0x1000
    SHA1_BLOCK_ADDR = 0xa2820
    SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
    loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-debug', loader=loader, debug=debug)

    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(STATES_ADDR, PAGE_SIZE)
    
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))
    
    # Prepare reference calculation for comparison
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    w = list(block)
    for i in range(16, 80):
        w.append(rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) & 0xFFFFFFFF)
    
    ref_state = list(initial_state)
    round_count = 0
    
    def get_round_type(round_num):
        if round_num <= 19:
            return 0
        elif round_num <= 39:
            return 1
        elif round_num <= 59:
            return 2
        else:
            return 3
    
    def hook_weird_function_entries(uc, address, size, user_data):
        nonlocal round_count, ref_state
        
        # Hook the actual weird function addresses (not the CALL instructions)
        if address in [0x1560, 0x28e90, 0x50820, 0x7a560]:  # Weird function entry points
            # Read parameters according to x86-64 calling convention
            rdi = uc.reg_read(UC_X86_REG_RDI)  # input state pointer
            rsi = uc.reg_read(UC_X86_REG_RSI)  # w value
            rdx = uc.reg_read(UC_X86_REG_RDX)  # output state pointer
            rcx = uc.reg_read(UC_X86_REG_RCX)  # error output pointer
            
            try:
                # Read input state
                input_state = list(struct.unpack("<5I", uc.mem_read(rdi, 20)))
                
                # Calculate reference for this round
                round_type = get_round_type(round_count)
                w_value = w[round_count] if round_count < 80 else 0
                ref_output = ref_sha1_round(input_state, w_value, round_num=round_type)
                
                print(f"\nRound {round_count} (type {round_type}, w={hex(w_value)}):")
                print(f"  EMU Input:  {[hex(x) for x in input_state]}")
                print(f"  REF Output: {[hex(x) for x in ref_output]}")
                
                # Update reference state for next round
                ref_state = ref_output
                round_count += 1
                
            except Exception as e:
                print(f"Error reading weird function parameters: {e}")
        
        return False
    
    def hook_weird_function_detailed_params(uc, address, size, user_data):
        if address == 0x1560:  # First weird round function
            rdi = uc.reg_read(UC_X86_REG_RDI)  # input state pointer
            rsi = uc.reg_read(UC_X86_REG_RSI)  # w value
            rdx = uc.reg_read(UC_X86_REG_RDX)  # output state pointer
            rcx = uc.reg_read(UC_X86_REG_RCX)  # error output pointer
            
            print(f"\n=== WEIRD FUNCTION PARAMETERS ===")
            print(f"RDI (input ptr): {hex(rdi)}")
            print(f"RSI (w value): {hex(rsi)}")
            print(f"RDX (output ptr): {hex(rdx)}")
            print(f"RCX (error ptr): {hex(rcx)}")
            
            # Read the actual input state
            try:
                input_state = list(struct.unpack("<5I", uc.mem_read(rdi, 20)))
                print(f"Input state: {[hex(x) for x in input_state]}")
                
                # Verify this matches what we expect
                expected = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
                print(f"Expected:    {[hex(x) for x in expected]}")
                print(f"Match: {input_state == expected}")
                
            except:
                print("Could not read input state")
        
        return False
    
    def hook_function_calls(uc, address, size, user_data):
        # Hook the CALL instructions to get the RDX parameter (output pointer)
        if address in [0xa29b8, 0xa2a8a, 0xa2b57, 0xa2c0a]:  # CALL to weird functions
            # The RDX register should contain the output pointer
            rdx = uc.reg_read(UC_X86_REG_RDX)
            
            # Store this for later when we want to read the output
            setattr(hook_function_calls, 'last_output_ptr', rdx)
        
        # After a weird function returns, read its output
        elif address in [0xa29bd, 0xa2a8f, 0xa2b5c, 0xa2c0f]:  # Instructions after CALL returns
            if hasattr(hook_function_calls, 'last_output_ptr'):
                try:
                    output_ptr = hook_function_calls.last_output_ptr
                    output_state = list(struct.unpack("<5I", uc.mem_read(output_ptr, 20)))
                    print(f"  EMU Output: {[hex(x) for x in output_state]}")
                    
                    # Compare with reference
                    if round_count > 0:  # We should have calculated ref in the entry hook
                        ref_output = ref_state  # This should be the expected output
                        match = all(output_state[i] == ref_output[i] for i in range(5))
                        if not match:
                            print(f"  *** MISMATCH ***")
                        else:
                            print(f"  ✓ MATCH")
                        
                except Exception as e:
                    print(f"Error reading output state: {e}")
        
    def hook_dyn_calls(uc: Uc, address, size, user_data):
        # Handle rand calls within weird functions
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        
        # Handle memset call at 0xa284f
        elif address == 0xa284f:  # memset@plt
            # memset(rdi, rsi, rdx) - set memory
            rdi = uc.reg_read(UC_X86_REG_RDI)  # destination
            rsi = uc.reg_read(UC_X86_REG_RSI)  # value (should be 0)
            rdx = uc.reg_read(UC_X86_REG_RDX)  # size (should be 0xa0 = 160 bytes)
            
            print(f"MEMSET: addr={hex(rdi)}, value={rsi}, size={rdx}")
            
            # Implement memset: fill memory with the specified value
            data = bytes([rsi & 0xFF] * int(rdx))   # Convert rdx to int
            uc.mem_write(rdi, data)
            
            emulator.skip_curr_insn()
            return True
        
        # Handle memcpy call at 0xa2869  
        elif address == 0xa2869:  # memcpy@plt
            rdi = int(uc.reg_read(UC_X86_REG_RDI))
            rsi = int(uc.reg_read(UC_X86_REG_RSI))
            rdx = int(uc.reg_read(UC_X86_REG_RDX))

            print(f"MEMCPY: dest={hex(rdi)}, src={hex(rsi)}, size={rdx}")
            print(f"  (types: rdi={type(rdi)}, rsi={type(rsi)}, rdx={type(rdx)})")

            # First, just try the read:
            try:
                raw_chunk = uc.mem_read(rsi, rdx)
            except Exception as e_read:
                print(f"  ERROR reading src: {e_read!r}")
                emulator.skip_curr_insn()
                return True

            try:
                chunk = bytes(raw_chunk)                  # ← IMPORTANT: make it a real bytes
            except Exception as e_cast:
                print(f"  ERROR casting to bytes: {e_cast!r}")
                emulator.skip_curr_insn()
                return True

            try:
                uc.mem_write(rdi, chunk)
                print(f"  Copied {rdx} bytes from {hex(rsi)} to {hex(rdi)}")
            except Exception as e_write:
                print(f"  ERROR writing to dst: {e_write!r}")
                emulator.skip_curr_insn()
                return True

            print(f"  Copied {rdx} bytes from {hex(rsi)} to {hex(rdi)}")

            # Now read back first 16 bytes to verify:
            if rdx >= 16:
                try:
                    raw = uc.mem_read(rdi, 16)
                    print(f"  [debug] post‐write raw type: {type(raw)}, length: {len(raw)}")
                    if not isinstance(raw, bytes):
                        raw = bytes(raw)
                    if len(raw) != 16:
                        raise ValueError(f"Expected 16 bytes, got {len(raw)}")
                    words = struct.unpack("<4I", raw)
                    print(f"  First 4 words copied: {[hex(w) for w in words]}")
                except Exception as e_verify:
                    print(f"  ERROR verifying copied data: {e_verify!r}")

            emulator.skip_curr_insn()
            return True

        return False

    
    def hook_sha1_block_call_setup(uc, address, size, user_data):
        # Hook right before the call to weird function
        if address == 0xa29b8:  # CALL to __weird__sha1_round1
            rsp = uc.reg_read(UC_X86_REG_RSP)
            
            # Read what should be the w value
            try:
                w_from_stack = struct.unpack("<I", uc.mem_read(rsp + 0x70, 4))[0]
                print(f"Value at [rsp+0x70] (should be w): {hex(w_from_stack)}")
                
                # Also check RSI before the call
                rsi_before = uc.reg_read(UC_X86_REG_RSI)
                print(f"RSI before call: {hex(rsi_before)}")
                
                # Check what was loaded into ESI at 0xa2992
                print(f"Expected w for round 0: 0x3193ca54")
                
            except Exception as e:
                print(f"Error reading stack: {e}")
        
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530) # start round1, finish __DualGate__2_1_6
    
    # Add hooks
    emulator.uc.hook_add(UC_HOOK_CODE, hook_weird_function_entries, None, 0x1560, 0xa3530)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_weird_function_detailed_params, None, 0x1560, 0xa3530)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_sha1_block_call_setup, None, 0x1560, 0xa3530)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_function_calls, None, 0xa2000, 0xa3000)

    # Execute
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)
    
    print(f"Starting SHA-1 block with initial state: {[hex(x) for x in initial_state]}")
    
    emulator.emulate()
    
    # Read final result
    final_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    print(f"\nFinal emulator state: {[hex(x) for x in final_state]}")
    
    # Calculate final reference (add initial state)
    final_ref = list(ref_state)
    for i in range(5):
        final_ref[i] = (final_ref[i] + initial_state[i]) & 0xFFFFFFFF
    
    print(f"Final reference state: {[hex(x) for x in final_ref]}")
    print(f"Final match: {all(final_state[i] == final_ref[i] for i in range(5))}")
    
    return final_state


# 2BLOCK
def emulate_flexo_sha1_2blocks(block1, block2, debug=False):
    """Process 2 blocks sequentially using the working 1-block function"""
    
    # Process first block with initial state
    print("=== PROCESSING FIRST BLOCK ===")
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    
    # Use the working 1-block function
    intermediate_state = emulate_flexo_sha1_1block_with_state(block1, initial_state, debug)
    print(f"Intermediate state after first block: {[hex(x) for x in intermediate_state]}")
    
    # Process second block with intermediate state
    print("\n=== PROCESSING SECOND BLOCK ===")
    final_state = emulate_flexo_sha1_1block_with_state(block2, intermediate_state, debug)
    print(f"Final state after second block: {[hex(x) for x in final_state]}")
    
    return final_state

def emulate_flexo_sha1_1block_with_state(block, input_state, debug=False):
    """Modified 1-block function that accepts custom input state"""
    
    INPUT_ADDR = 0x200000  
    STATES_ADDR = 0x201000
    PAGE_SIZE = 0x1000
    SHA1_BLOCK_ADDR = 0xa2820
    SHA1_BLOCK_RET_ADDR = 0xa2cdf
    
    # Create a FRESH emulator instance for each block
    loader = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name=f'flexo-sha1-block', loader=loader, debug=False)

    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE)
    emulator.uc.mem_map(STATES_ADDR, PAGE_SIZE)
    
    # Use the provided input state instead of hardcoded initial state
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *input_state))
    
    def hook_dyn_calls(uc: Uc, address, size, user_data):
        # Handle rand calls within weird functions
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        
        # Handle memset call at 0xa284f
        elif address == 0xa284f:  # memset@plt
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            
            if debug:
                print(f"MEMSET: addr={hex(rdi)}, value={rsi}, size={rdx}")
            
            data = bytes([rsi & 0xFF] * int(rdx))
            uc.mem_write(rdi, data)
            
            emulator.skip_curr_insn()
            return True
        
        # Handle memcpy call at 0xa2869  
        elif address == 0xa2869:  # memcpy@plt
            rdi = int(uc.reg_read(UC_X86_REG_RDI))
            rsi = int(uc.reg_read(UC_X86_REG_RSI))
            rdx = int(uc.reg_read(UC_X86_REG_RDX))

            if debug:
                print(f"MEMCPY: dest={hex(rdi)}, src={hex(rsi)}, size={rdx}")

            try:
                raw_chunk = uc.mem_read(rsi, rdx)
                chunk = bytes(raw_chunk)
                uc.mem_write(rdi, chunk)
                
                if debug:
                    print(f"  Copied {rdx} bytes from {hex(rsi)} to {hex(rdi)}")
                    
                    if rdx >= 16:
                        raw = uc.mem_read(rdi, 16)
                        if not isinstance(raw, bytes):
                            raw = bytes(raw)
                        words = struct.unpack("<4I", raw)
                        print(f"  First 4 words copied: {[hex(w) for w in words]}")
                        
            except Exception as e:
                print(f"  ERROR in memcpy: {e}")

            emulator.skip_curr_insn()
            return True

        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530)

    # Execute
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)
    
    if debug:
        print(f"Starting SHA-1 block with input state: {[hex(x) for x in input_state]}")
    
    emulator.emulate()
    
    # Read final result
    final_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    
    if debug:
        print(f"Block result: {[hex(x) for x in final_state]}")
    
    return final_state