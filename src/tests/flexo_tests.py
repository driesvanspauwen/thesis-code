from typing import Tuple
from emulator import MuWMEmulator
from loader import ELFLoader
from gates.asm import *
from unicorn import *
from unicorn.x86_const import *

def emulate_and_flexo(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses
    AND_GATE_START_ADDR = 0x11e0
    AND_GATE_END_ADDR = 0x13fb
    
    loader = ELFLoader("gates/flexo/gates/gate_and.elf")
    emulator = MuWMEmulator('flexo-and', loader, debug)
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

def emulate_or_flexo(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for OR gate
    OR_GATE_START_ADDR = 0x1400
    OR_GATE_END_ADDR = 0x161b  # ret instruction of __weird__or
    
    loader = ELFLoader("gates/flexo/gates/gate_or.elf")  # Adjust path as needed
    emulator = MuWMEmulator('flexo-or', loader, debug)
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


def emulate_not_flexo(in1, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for NOT gate
    NOT_GATE_START_ADDR = 0x1620
    NOT_GATE_END_ADDR = 0x17d5  # ret instruction of __weird__not
    
    loader = ELFLoader("gates/flexo/gates/gate_not.elf")  # Adjust path as needed
    emulator = MuWMEmulator('flexo-not', loader, debug)
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

def emulate_nand_flexo(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for NAND
    NAND_GATE_START_ADDR = 0x17e0
    NAND_GATE_END_ADDR = 0x19fb  # ret instruction of __weird__nand
    
    loader = ELFLoader("gates/flexo/gates/gate_nand.elf")
    emulator = MuWMEmulator('flexo-nand', loader, debug)
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

def emulate_xor_flexo(in1, in2, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR
    XOR_GATE_START_ADDR = 0x1a00
    XOR_GATE_END_ADDR = 0x1c1b  # ret instruction of __weird__xor
    
    loader = ELFLoader("gates/flexo/gates/gate_xor.elf")  # Same ELF file
    emulator = MuWMEmulator('flexo-xor', loader, debug)
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

def emulate_xor3_flexo(in1, in2, in3, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR3
    XOR3_GATE_START_ADDR = 0x1ed0
    XOR3_GATE_END_ADDR = 0x2172  # ret instruction of __weird__xor3
    
    loader = ELFLoader("gates/flexo/gates/gate_xor3.elf")
    emulator = MuWMEmulator('flexo-xor3', loader, debug)
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

def emulate_xor4_flexo(in1, in2, in3, in4, debug=False):
    OUT_ADDR = 0x10000000
    
    # Function addresses for XOR4
    XOR4_GATE_START_ADDR = 0x2180
    XOR4_GATE_END_ADDR = 0x24b3  # ret instruction of __weird__xor4
    
    loader = ELFLoader("gates/flexo/gates/gate_xor4.elf")
    emulator = MuWMEmulator('flexo-xor4', loader, debug)
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

def emulate_mux_flexo(in1, in2, sel, debug=False):
    OUT_ADDR = 0x10000000 # pick an address not in code and stack sections
    
    # Function addresses for MUX
    MUX_GATE_START_ADDR = 0x1c20
    MUX_GATE_END_ADDR = 0x1ec2  # ret instruction of __weird__mux
    
    loader = ELFLoader("gates/flexo/gates/gate_mux.elf")
    emulator = MuWMEmulator('flexo-mux', loader, debug)
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

def emulate_adder8_flexo(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
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
    emulator = MuWMEmulator("flexo-adder8", loader, debug)
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

def emulate_adder16_flexo(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
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
    emulator = MuWMEmulator("flexo-adder16", loader, debug)
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

def verify_memory_layout(emulator: MuWMEmulator):
    """Verify memory regions don't overlap"""
    regions = []
    
    # Add all mapped regions
    for region in emulator.uc.mem_regions():
        start, end, perms = region
        regions.append((start, end, "mapped"))
    
    # Sort by start address
    regions.sort(key=lambda x: x[0])
    
    # Check for overlaps
    for i in range(len(regions) - 1):
        if regions[i][1] > regions[i+1][0]:
            print(f"WARNING: Memory overlap detected!")
            print(f"  Region 1: 0x{regions[i][0]:x} - 0x{regions[i][1]:x}")
            print(f"  Region 2: 0x{regions[i+1][0]:x} - 0x{regions[i+1][1]:x}")

def emulate_adder32_flexo(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
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
    emulator = MuWMEmulator("flexo-adder32", loader, debug)
    
    emulator.reset_state()
    
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

    # hook rand()
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

    verify_memory_layout(emulator)

    emulator.emulate()

    # read 4-byte result and error_flag
    result = int.from_bytes(uc.mem_read(OUT_ADDR, 4), 'little')
    error_flag = uc.mem_read(ERR_OUT_ADDR, 1)[0]
    return result, error_flag