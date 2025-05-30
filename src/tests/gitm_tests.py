from emulator import MuWMEmulator
from loader import ELFLoader
from gates.asm import *
from unicorn import *
from unicorn.x86_const import *

def emulate_gitm_assign(input_val, debug=False):
    # Memory addresses (based on disassembly)
    IN_ADDR = 0x81c0   # reg1
    OUT1_ADDR = 0x79c0  # reg2 
    OUT2_ADDR = 0x71c0  # reg3
    
    # Function addresses (based on disassembly)
    ASSIGN_GATE_START_ADDR = 0x1490  # _Z14do_assign_gatej
    ASSIGN_GATE_END_ADDR = 0x160f    # Last nop before rdtscp timing section
    
    # Load ELF file
    loader = ELFLoader("gates/gitm/main_assign.elf")
    emulator = MuWMEmulator(name='gitm_assign', loader=loader, debug=debug)
    emulator.code_start_address = ASSIGN_GATE_START_ADDR
    emulator.code_exit_addr = ASSIGN_GATE_END_ADDR
    
    # Set input
    if input_val:
        emulator.cache.read(IN_ADDR, emulator.uc)
    
    # Set input parameter (only 1 bit for assign gate)
    emulator.uc.reg_write(UC_X86_REG_RDI, input_val & 1)
    
    # Run emulation
    emulator.logger.log(f"Starting emulation of ASSIGN({input_val})...")
    emulator.emulate()
    
    # Check both outputs (assign gate writes to both reg2 and reg3)
    result1 = emulator.cache.is_cached(OUT1_ADDR)
    result2 = emulator.cache.is_cached(OUT2_ADDR)
    
    emulator.logger.log(f"Output values: reg2={result1}, reg3={result2}")
    
    # Both outputs should match the input for assign gate
    return result1 and result2 == input_val

def emulate_gitm_and(in1, in2, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    
    # Function addresses (based on disassembly)
    AND_GATE_START_ADDR = 0x1490  # _Z11do_and_gatej
    AND_GATE_END_ADDR = 0x161d    # Last nop before rdtscp timing section
    
    # Load ELF file
    loader = ELFLoader("gates/gitm/main_and.elf")
    emulator = MuWMEmulator(name='gitm_and', loader=loader, debug=debug)
    emulator.code_start_address = AND_GATE_START_ADDR
    emulator.code_exit_addr = AND_GATE_END_ADDR
    
    # Set inputs
    # if in1:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    # if in2:
    #     emulator.cache.read(IN2_ADDR, emulator.uc)
    
    input_param = (in1) | (in2 << 1)  # Combine inputs into parameter (based on source code)
    emulator.uc.reg_write(UC_X86_REG_RDI, input_param)
    
    # Run emulation
    emulator.logger.log(f"Starting emulation of AND({in1}, {in2})...")
    emulator.emulate()
    
    # Retrieve output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)
    emulator.logger.log(f"Output value: {result}")
    
    return result

def emulate_gitm_or(in1, in2, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0  # reg1
    IN2_ADDR = 0x79c0  # reg2
    OUT_ADDR = 0x71c0  # reg3
    
    # Function addresses (based on disassembly)
    OR_GATE_START_ADDR = 0x1490  # _Z10do_or_gatej
    OR_GATE_END_ADDR = 0x1620    # Last nop before rdtscp timing section
    
    # Load ELF file
    loader = ELFLoader("gates/gitm/main_or.elf")
    emulator = MuWMEmulator(name='gitm_or', loader=loader, debug=debug)
    emulator.code_start_address = OR_GATE_START_ADDR
    emulator.code_exit_addr = OR_GATE_END_ADDR
    
    # Set inputs
    # if in1:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    # if in2:
    #     emulator.cache.read(IN2_ADDR, emulator.uc)
    
    # Combine inputs into parameter (based on source code pattern)
    input_param = (in1) | (in2 << 1)
    emulator.uc.reg_write(UC_X86_REG_RDI, input_param)
    
    # Run emulation
    emulator.logger.log(f"Starting emulation of OR({in1}, {in2})...")
    emulator.emulate()
    
    # Retrieve output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)
    emulator.logger.log(f"Output value: {result}")
    
    return result

def emulate_gitm_not(input_val, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0  # reg1
    IN2_ADDR = 0x79c0  # reg2 (also used as input)
    OUT_ADDR = 0x71c0  # reg3
    DELAY_ADDR = 0x69c0 # reg4 (delay register)
    
    # Function addresses (based on disassembly)
    NOT_GATE_START_ADDR = 0x1490  # _Z11do_not_gatej
    NOT_GATE_END_ADDR = 0x1628    # Last nop before rdtscp timing section
    
    # Load ELF file
    loader = ELFLoader("gates/gitm/main_not.elf")
    emulator = MuWMEmulator(name='gitm_not', loader=loader, debug=debug)
    emulator.code_start_address = NOT_GATE_START_ADDR
    emulator.code_exit_addr = NOT_GATE_END_ADDR
    
    # Set inputs (NOT gate uses same input for reg1 and reg2 based on C++ code)
    # if input_val:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    #     emulator.cache.read(IN2_ADDR, emulator.uc)
    
    # Set input parameter (only 1 bit for NOT gate)
    emulator.uc.reg_write(UC_X86_REG_RDI, input_val & 1)
    
    # Run emulation
    emulator.logger.log(f"Starting emulation of NOT({input_val})...")
    emulator.emulate()
    
    # Retrieve output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)
    emulator.logger.log(f"Output value: {result}")
    
    return result

def emulate_gitm_nand(in1, in2, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    TMP_REG1_ADDR = 0xd1e0  # output AND
    TMP_REG2_ADDR = 0xc9e0  # input NOT (1)
    TMP_REG3_ADDR = 0xc1e0  # input NOT (2)
    TMP_REG4_ADDR = 0xb9e0  # delay NOT

    # Function address (based on disassembly)
    NAND_GATE_START_ADDR = 0x1490  # Start of _Z12do_nand_gatej
    NAND_GATE_END_ADDR = 0x2a6e  # Last nop of NOT gate (in _Z9nand_gatePhS_S_) - bypass rdtscp section

    # Load ELF file
    loader = ELFLoader("gates/gitm/main_nand.elf")
    emulator = MuWMEmulator(name='gitm_nand', loader=loader, debug=debug)
    emulator.code_start_address = NAND_GATE_START_ADDR
    emulator.code_exit_addr = NAND_GATE_END_ADDR

    # Set inputs
    input_param = (in2 << 1) | in1 # Combine inputs into parameter (based on source code)

    # if in1:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    # if in2:
    #     emulator.cache.read(IN2_ADDR, emulator.uc)

    emulator.uc.reg_write(UC_X86_REG_EDI, input_param)

    # Run emulation
    emulator.logger.log(f"Starting emulation of NAND({in1}, {in2})...")
    emulator.emulate()

    # Read output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)

    return result

# OUT = (IN1 AND NOT IN3) OR (IN2 AND IN3)
def emulate_gitm_mux(in1, in2, in3, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    IN3_ADDR = 0x71c0
    OUT_ADDR = 0x69c0
    
    TMP_REG1_ADDR = 0xd1e0  # selector bit - first input NOT gate
    TMP_REG2_ADDR = 0xc9e0  # selector bit - second input NOT gate
    TMP_REG3_ADDR = 0xc1e0  # result of AND(in2, in3)
    TMP_REG4_ADDR = 0xb9e0  # result of NOT(tmp_reg1, tmp_reg2)
    TMP_REG5_ADDR = 0xb1e0  # delay for NOT
    TMP_REG6_ADDR = 0xa9e0  # result of AND(in1, tmp_reg4)

    # Function addresses (based on disassembly)
    MUX_GATE_START_ADDR = 0x1ea0  # start of _Z11do_mux_gatej
    MUX_GATE_END_ADDR = 0x356d  # last nop of OR gate (in _Z8mux_gatePhS_S_S_j) - bypass rdtscp section

    # Load ELF file
    loader = ELFLoader("gates/gitm/main_mux.elf")
    emulator = MuWMEmulator(name='gitm_mux', loader=loader, debug=debug)
    emulator.code_start_address = MUX_GATE_START_ADDR
    emulator.code_exit_addr = MUX_GATE_END_ADDR

    # Set inputs
    input_param = (in1) | (in2 << 1) | (in3 << 2) # Combine inputs into parameter (based on source code)
    
    # if in1:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    # if in2:
    #     emulator.cache.read(IN2_ADDR, emulator.uc)
    # if in3:
    #     emulator.cache.read(IN3_ADDR, emulator.uc)

    emulator.uc.reg_write(UC_X86_REG_EDI, input_param)

    # Run emulation
    emulator.emulate()

    # Retrieve output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)
    return result

def emulate_gitm_xor(in1, in2, debug=False):
    # Memory addresses (based on disassembly)
    IN1_ADDR = 0x81c0  # reg1
    IN2_ADDR = 0x79c0  # reg2
    OUT_ADDR = 0x71c0  # reg3
    
    # Function addresses (based on disassembly)
    XOR_GATE_START_ADDR = 0x1490  # _Z11do_xor_gatej
    XOR_GATE_END_ADDR = 0x2e54    # Last nop before rdtscp timing section
    
    # Load ELF file
    loader = ELFLoader("gates/gitm/main_xor.elf")
    emulator = MuWMEmulator(name='gitm_xor', loader=loader, debug=debug)
    emulator.code_start_address = XOR_GATE_START_ADDR
    emulator.code_exit_addr = XOR_GATE_END_ADDR
    
    # Set inputs
    # if in1:
    #     emulator.cache.read(IN1_ADDR, emulator.uc)
    # if in2:
    #     emulator.cache.read(IN2_ADDR, emulator.uc)
    
    input_param = (in1) | (in2 << 1)  # Combine inputs into parameter (based on source code)
    emulator.uc.reg_write(UC_X86_REG_RDI, input_param)
    
    # Run emulation
    emulator.logger.log(f"Starting emulation of XOR({in1}, {in2})...")
    emulator.emulate()
    
    # Retrieve output from cache-based weird register
    result = emulator.cache.is_cached(OUT_ADDR)
    emulator.logger.log(f"Output value: {result}")
    
    return result