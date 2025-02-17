from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct

# Memory address where emulation starts
ADDRESS = 0x1000000
DATA_ADDRESS = 0x2000000  # Address for wr_var

# Assembly code from cache_reg.asm converted to bytes
X86_CODE = b"\x48\x85\xff\x74\x0a\xc7\x05\x00\x00\x00\x00\x2a\x00\x00\x00\xc3\x0f\xae\x05\x00\x00\x00\x00\xc3"  # write_weird_register
X86_CODE += b"\x53\x0f\x01\xf9\x48\x89\xc3\x8b\x05\x00\x00\x00\x00\x0f\x01\xf9\x48\x29\xd8\x3b\x05\x00\x00\x00\x00\x0f\x92\xc0\x0f\xb6\xc0\x5b\xc3"  # read_weird_register

def hook_code(uc, address, size, user_data):
    # Create Capstone object for instruction disassembly
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Read the instruction bytes
    instruction = uc.mem_read(address, size)
    
    # Disassemble
    for i in md.disasm(instruction, address):
        print(f">>> Executing: {i.mnemonic} {i.op_str}")

def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f">>> Memory write at 0x{address:x}, size = {size}, value = 0x{value:x}")
    else:   # READ
        print(f">>> Memory read at 0x{address:x}, size = {size}")

def emulate_cache_register():
    print("Emulating cache-based register code")
    try:
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # Map memory for the emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)  # Code section
        mu.mem_map(DATA_ADDRESS, 4096)         # Data section

        # Initialize wr_var and cache_hit_threshold
        mu.mem_write(DATA_ADDRESS, struct.pack("<I", 0))  # wr_var
        mu.mem_write(DATA_ADDRESS + 4, struct.pack("<I", 100))  # cache_hit_threshold

        # Write code to memory
        mu.mem_write(ADDRESS, X86_CODE)

        # Add hooks for debugging
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

        # Test write_weird_register(1)
        print("\nTesting write_weird_register(1)")
        mu.reg_write(UC_X86_REG_RDI, 1)  # Set first argument
        mu.emu_start(ADDRESS, ADDRESS + 24)  # Length of write function

        # Test read_weird_register()
        print("\nTesting read_weird_register()")
        mu.emu_start(ADDRESS + 24, ADDRESS + 56)  # Start after write function
        result = mu.reg_read(UC_X86_REG_RAX)
        print(f">>> Read result: {result}")

        # Test write_weird_register(0)
        print("\nTesting write_weird_register(0)")
        mu.reg_write(UC_X86_REG_RDI, 0)
        mu.emu_start(ADDRESS, ADDRESS + 24)

        # Test read_weird_register() again
        print("\nTesting read_weird_register() after write(0)")
        mu.emu_start(ADDRESS + 24, ADDRESS + 56)
        result = mu.reg_read(UC_X86_REG_RAX)
        print(f">>> Read result: {result}")

    except UcError as e:
        print(f"ERROR: {e}")

if __name__ == '__main__':
    emulate_cache_register()