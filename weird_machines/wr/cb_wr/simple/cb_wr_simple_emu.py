from unicorn import * # load basic unicorn constants
from unicorn.x86_const import * # load x86-specific constants
import struct
from elftools.elf.elffile import ELFFile
from cache import L1DCache

CODE_BASE = 0x401000
DATA_BASE = 0x402000 # wr_var is at 0x402000 (seen in mov instructions)
REGION_SIZE = 0x1000 # 4KB for each region
STACK_BASE = 0x0
STACK_SIZE = 1024*1024 # 1MB

# CPU cycle parameters
CACHE_HIT_CYCLES = 10     # Typical CPU cycles for L1 cache hit
CACHE_MISS_CYCLES = 200   # Typical CPU cycles for memory access on cache miss
REGULAR_INSTR_CYCLES = 1  # Regular instruction timing

RDTSCP_OPCODE = bytes([0x0f, 0x01, 0xf9])

def get_text_section(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        return text_section.data()

def hook_code(mu, address, size, user_data):
    log_file = user_data['log_file']

    log_file.write(f"Executing instruction at 0x{address:x}, instruction size = 0x{size:x}\n")

    try:
        instruction_bytes = mu.mem_read(address, 3)
        if instruction_bytes == RDTSCP_OPCODE:
            log_file.write(f"\tDetected rdtscp instruction at 0x{address:x}\n")

            # skip rdtscp instruction because it's not supported by Unicorn
            rip = mu.reg_read(UC_X86_REG_RIP)
            mu.reg_write(UC_X86_REG_RIP, rip + 1)

    except UcError as e:
        log_file.write(f"\tError interpreting instruction at 0x{address:x}: {e}\n")
    
    tsc['value'] += REGULAR_INSTR_CYCLES

def hook_error(uc, error, user_data):
    log_file = user_data['log_file']

    log_file.write(f"Error: {error}\n")
    return False

def hook_mem_write(uc, access, address, size, value, user_data):
    cache, log_file, tsc = user_data['cache'], user_data['log_file'], user_data['tsc']
    
    cache.write(address, value)
    tsc['value'] += CACHE_HIT_CYCLES # # Assume writes are always "hits" for simplicityx
    log_file.write(f"Memory write: address=0x{address:x}, size={size}, value={value}\n")
    log_file.write(f"\tCurrent TSC value: {tsc['value']}\n")
    return True

def hook_mem_read(uc, access, address, size, value, user_data):
    cache, log_file, tsc = user_data['cache'], user_data['log_file'], user_data['tsc']

    is_hit = cache.read(address)

    if is_hit:
        tsc['value'] += CACHE_HIT_CYCLES
        log_file.write(f"Memory read: address=0x{address:x}, size={size}, CACHE HIT, TSC += {CACHE_HIT_CYCLES}\n")
    else:
        tsc['value'] += CACHE_MISS_CYCLES
        log_file.write(f"Memory read: address=0x{address:x}, size={size}, CACHE MISS, TSC += {CACHE_MISS_CYCLES}\n")

    log_file.write(f"\tCurrent TSC value: {tsc['value']}\n")
    return True

def wr_write_1(mu, log_file):
    log_file.write("\n--Calling write_wr(1)--\n")
    log_file.write(f"--Running instructions from 0x{CODE_BASE:x} to 0x{CODE_BASE + 0x0f:x}--\n")
    mu.reg_write(UC_X86_REG_EDI, 1) # Set 1
    mu.emu_start(CODE_BASE, CODE_BASE + 0x0f) # Stop at ret

def wr_write_0(mu, log_file):
    log_file.write("\n--Calling write_wr(0)--\n")
    log_file.write(f"--Running instructions from 0x{CODE_BASE:x} to 0x{CODE_BASE + 0x1b:x}--\n")
    mu.reg_write(UC_X86_REG_EDI, 0) # Set 0
    mu.emu_start(CODE_BASE, CODE_BASE + 0x1b) # Stop at ret

def wr_read(mu, log_file):
    log_file.write("\n--Calling read_wr()--\n")
    log_file.write(f"--Running instructions from 0x{CODE_BASE + 0x1c:x} to 0x{CODE_BASE + 0x47:x}--\n")
    mu.emu_start(CODE_BASE + 0x1c, CODE_BASE + 0x47) # read_wr function
    result = mu.reg_read(UC_X86_REG_AL) # Result is in AL
    log_file.write(f"READ RESULT: {result}\n")

if __name__ == "__main__":
    log_file = open('emulation_log.txt', 'w')
    log_file.write("Starting emulation...\n")

    # Initialize Unicorn Engine for x86_64
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map memory regions with proper permissions
    mu.mem_map(CODE_BASE, REGION_SIZE, UC_PROT_ALL)
    mu.mem_map(DATA_BASE, REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    # Extract and load just the .text section
    code = get_text_section("./cb_wr_simple")
    mu.mem_write(CODE_BASE, code)

    # Initialize stack pointer (16-byte aligned - common in x86_64)
    mu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 16)

    # Initialize user data
    cache = L1DCache()
    tsc = {'value': 1000} # Mimics CPU timestamp counter
    user_data = {'cache': cache, 'log_file': log_file, 'tsc': tsc}

    # Add debug hooks
    mu.hook_add(UC_HOOK_CODE, hook_code, user_data)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_error, user_data)

    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, user_data)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, user_data)

    wr_write_1(mu, log_file)
    wr_read(mu, log_file)

    log_file.close()