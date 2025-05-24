from emulator import MuWMEmulator
from loader import ELFLoader
from gates.asm import *
from unicorn import *
from unicorn.x86_const import *

def run_and_flexo(in1, in2, debug=False):
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