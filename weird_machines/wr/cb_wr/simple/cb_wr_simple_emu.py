from unicorn import * # load basic unicorn constants
from unicorn.x86_const import * # load x86-specific constants
import struct
from elftools.elf.elffile import ELFFile

CODE_BASE = 0x401000
DATA_BASE = 0x402000 # wr_var is at 0x402000 (seen in mov instructions)
REGION_SIZE = 0x1000 # 4KB for each region
STACK_BASE = 0x0
STACK_SIZE = 1024*1024 # 1MB

def get_text_section(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        return text_section.data()

log_file = open('emulation_log.txt', 'w')

def hook_code(mu, address, size, user_data):
    log_file.write(f"Tracing instruction at 0x{address:x}, instruction size = 0x{size:x}\n")
    if address == CODE_BASE + 0x26 or address == CODE_BASE + 0x36:
        rip = mu.reg_read(UC_X86_REG_RIP)
        mu.reg_write(UC_X86_REG_RIP, rip + 1) # Skip the next instruction
        log_file.write(f"Skipping rdtscp instruction at 0x{address:x}\n")

def hook_error(uc, error, user_data):
    log_file.write(f"Error: {error}\n")
    return False

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

# Initialize stack pointer
mu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 1)

# Add debug hooks
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_INVALID, hook_error)

# Write to weird register
log_file.write("\nCalling write_wr(1)\n")
log_file.write(f"Running instructions from 0x{CODE_BASE:x} to 0x{CODE_BASE + 0x0f:x}\n")

# write 1
mu.reg_write(UC_X86_REG_EDI, 1) # Set first argument
mu.emu_start(CODE_BASE, CODE_BASE + 0x0f) # Stop at ret

# write 0
# mu.reg_write(UC_X86_REG_EDI, 0) # Set first argument
# mu.emu_start(CODE_BASE, CODE_BASE + 0x1b) # Stop at ret

# Read from weird register (call read_wr())
log_file.write("\nCalling read_wr()\n")
log_file.write(f"Running instructions from 0x{CODE_BASE + 0x1c:x} to 0x{CODE_BASE + 0x47:x}\n")
mu.emu_start(CODE_BASE + 0x1c, CODE_BASE + 0x47) # read_wr function
result = mu.reg_read(UC_X86_REG_AL) # Result is in AL
log_file.write(f"Result: {result}\n")

log_file.close()