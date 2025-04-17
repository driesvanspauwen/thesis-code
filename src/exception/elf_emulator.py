from unicorn import *
from unicorn.x86_const import *
import sys, os
from logger import Logger
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn

class ELFEmulator:
    def __init__(self, elf_path):
        self.elf_path = elf_path

        self.f = open(elf_path, 'rb')
        self.elf = ELFFile(self.f)

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        
        self.is_64_bit = self.elf.elfclass == 64
        output_dir = os.path.join("tmp", "elf_emulator")
        self.logger = Logger(os.path.join(output_dir, 'log.txt'), debug)
        print(f"ELF class: {'64-bit' if self.is_64_bit else '32-bit'}")

        self.mu = Uc(UC_ARCH_X86, UC_MODE_64 if self.is_64_bit else UC_MODE_32)

        self.base = 0
        for segment in self.elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                if self.base == 0 or segment.header.p_vaddr < self.base:
                    self.base = segment.header.p_vaddr & ~0xFFF  # Page align
        
        self.entry = self.elf.header.e_entry
        print(f"Entry point: 0x{self.entry:x}")
        print(f"Base address: 0x{self.base:x}")

        # Add debug hooks before mapping memory
        self._add_debug_hooks()
        
        self._map_segments()
        self._setup_stack()
        self._setup_tls()

    def _map_segments(self):
        print("Mapping segments:")
        for segment in self.elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':  # Only consider loadable segments
                # Calculate memory size (page-aligned)
                mem_start = segment.header.p_vaddr & ~0xFFF  # Page align
                mem_end = (segment.header.p_vaddr + segment.header.p_memsz + 0xFFF) & ~0xFFF
                mem_size = mem_end - mem_start

                # Determine segment permissions
                perm = 0
                if segment.header.p_flags & 0x1:  # PF_X - Execute
                    perm |= UC_PROT_EXEC
                if segment.header.p_flags & 0x2:  # PF_W - Write
                    perm |= UC_PROT_WRITE
                if segment.header.p_flags & 0x4:  # PF_R - Read
                    perm |= UC_PROT_READ
                    
                # Make sure we have at least read permission
                if perm == 0:
                    perm = UC_PROT_READ
                    
                # Map memory region used by segment
                print(f"  - Mapping segment at 0x{mem_start:x} - 0x{mem_end-1:x}, size: 0x{mem_size:x}")
                print(f"    Flags: {segment.header.p_flags}, Permissions: {perm}, Entry point in segment: {'Yes' if (segment.header.p_vaddr <= self.entry < segment.header.p_vaddr + segment.header.p_memsz) else 'No'}")
                
                try:
                    self.mu.mem_map(mem_start, mem_size, perm)
                    
                    # Map segment data
                    data = segment.data()
                    self.mu.mem_write(segment.header.p_vaddr, data)
                    self.logger.log(f"    Data written: 0x{len(data):x} bytes at 0x{segment.header.p_vaddr:x}")
                    
                    # Zero out uninitialized data
                    if segment.header.p_memsz > segment.header.p_filesz:
                        padding_size = segment.header.p_memsz - segment.header.p_filesz
                        padding_addr = segment.header.p_vaddr + segment.header.p_filesz
                        self.mu.mem_write(padding_addr, b'\x00' * padding_size)
                        self.logger.log(f"    Zeroed: 0x{padding_size:x} bytes at 0x{padding_addr:x}")
                except UcError as e:
                    self.logger.log(f"    Error mapping segment: {e}")
    
    def _setup_tls(self):
        """Set up Thread Local Storage (TLS)"""
        # Map a larger TLS memory region to accommodate negative offsets
        tls_size = 0x2000
        
        # Move the base a bit higher to allow for negative offsets
        self.tls_base = 0x7ffff7ffb000  # Adjusted to handle negative offsets
        
        try:
            self.mu.mem_map(self.tls_base - 0x1000, tls_size, UC_PROT_READ | UC_PROT_WRITE)
            self.mu.mem_write(self.tls_base - 0x1000, b'\x00' * tls_size)
            
            # Set FS base to point to our TLS region
            self.mu.reg_write(UC_X86_REG_FS_BASE, self.tls_base)
            
            self.logger.log(f"TLS mapped at 0x{self.tls_base-0x1000:x}, size: 0x{tls_size:x}")
        except UcError as e:
            self.logger.log(f"Error setting up TLS: {e}")

    def _setup_stack(self):
        if self.is_64_bit:
            self.stack_base = 0x7ffffffff000 - 0x100000
            self.stack_size = 0x100000  # 1 MB stack
        else:
            self.stack_base = 0xbf000000 - 0x100000
            self.stack_size = 0x100000  # 1 MB stack
        
        # Map stack memory
        self.mu.mem_map(self.stack_base, self.stack_size, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_write(self.stack_base, b'\x00' * self.stack_size)
        
        # Set stack pointer
        if self.is_64_bit:
            self.mu.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size - 0x100)
            self.mu.reg_write(UC_X86_REG_RBP, self.stack_base + self.stack_size - 0x100)
        else:
            self.mu.reg_write(UC_X86_REG_ESP, self.stack_base + self.stack_size - 0x100)
            self.mu.reg_write(UC_X86_REG_EBP, self.stack_base + self.stack_size - 0x100)
    
    def _add_debug_hooks(self):
        """Add hooks for debugging"""
        self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)

    def _hook_code(self, uc, address, size, user_data):
        """Code execution hook for debugging"""

        insn_bytes = uc.mem_read(address, size)
        for insn in self.cs.disasm(insn_bytes, address, 1):
            self.logger.log(f">>> Executing 0x{address:x}: {insn.mnemonic} {insn.op_str}")

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Invalid memory access hook"""
        ip = self.mu.reg_read(UC_X86_REG_RIP if self.is_64_bit else UC_X86_REG_EIP)
        access_map = {
            UC_MEM_WRITE: "WRITE",
            UC_MEM_READ: "READ",
            UC_MEM_FETCH: "FETCH",
            UC_MEM_READ_UNMAPPED: "READ_UNMAPPED",
            UC_MEM_WRITE_UNMAPPED: "WRITE_UNMAPPED",
            UC_MEM_FETCH_UNMAPPED: "FETCH_UNMAPPED",
            UC_MEM_WRITE_PROT: "WRITE_PROT",
            UC_MEM_READ_PROT: "READ_PROT",
            UC_MEM_FETCH_PROT: "FETCH_PROT",
        }
        access_type = access_map.get(access, f"UNKNOWN({access})")
        
        # Check if this is a TLS access
        if (address >> 32) == 0xffffffff:
            self.logger.log(f"TLS access at 0x{address:x}, setting up TLS")
            self._setup_tls()
            # Map the specific needed address if within a reasonable range
            if 0xfffffffffffa0 <= address <= 0xffffffffffffd0:
                try:
                    # Map just a small region around the accessed address
                    map_addr = address & ~0xFFF  # Page align
                    self.mu.mem_map(map_addr, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                    self.mu.mem_write(map_addr, b'\x00' * 0x1000)
                    self.logger.log(f"Mapped TLS region at 0x{map_addr:x}")
                    return True  # We handled this access
                except UcError as e:
                    self.logger.log(f"Failed to map TLS region: {e}")
        
        if access in (UC_MEM_WRITE, UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT):
            self.logger.log(f"Invalid {access_type} at 0x{address:x} (IP=0x{ip:x}), size={size}, value=0x{value:x}")
        else:
            self.logger.log(f"Invalid {access_type} at 0x{address:x} (IP=0x{ip:x}), size={size}")
        
        return False  # Return False to indicate we couldn't handle this access

    def emulate(self, start_addr=None, end_addr=None, timeout=0, count=0):
        """Start emulation"""
        start = start_addr if start_addr is not None else self.entry
        end = end_addr if end_addr is not None else start + 0x1000000  # Default to 16MB limit
        
        self.logger.log(f"Starting emulation at 0x{start:x}, ending at 0x{end:x}")
        
        # Map null page with no permissions to catch null pointer accesses
        try:
            self.mu.mem_map(0, 0x1000)  # 0 means no permissions
            self.logger.log("Mapped null page to catch null pointer accesses")
        except UcError as e:
            self.logger.log(f"Could not map null page: {e}")
            
        try:
            self.mu.emu_start(start, end, timeout=timeout, count=count)
        except UcError as e:
            if self.is_64_bit:
                rip = self.mu.reg_read(UC_X86_REG_RIP)
                self.logger.log(f"Error at RIP=0x{rip:x}: {e}")
            else:
                eip = self.mu.reg_read(UC_X86_REG_EIP)
                self.logger.log(f"Error at EIP=0x{eip:x}: {e}")
            
            # If we have an invalid read, try to dump memory around that location
            if "READ_UNMAPPED" in str(e) or "READ_PROT" in str(e):
                address = int(str(e).split("0x")[1].split(",")[0], 16)
                try:
                    # Try to read surrounding mapped memory
                    for offset in range(-0x20, 0x21, 0x10):
                        try:
                            data = self.mu.mem_read(address + offset, 0x10)
                            hex_str = ' '.join(f'{b:02x}' for b in data)
                            self.logger.log(f"Memory at 0x{address+offset:x}: {hex_str}")
                        except UcError:
                            self.logger.log(f"Memory at 0x{address+offset:x}: [unmapped]")
                except Exception as dump_err:
                    self.logger.log(f"Could not dump memory: {dump_err}")
            
            raise

    def add_syscall_hook(self):
        """Add syscall hook to handle system calls"""
        def hook_syscall(mu, user_data):
            if self.is_64_bit:
                syscall_num = mu.reg_read(UC_X86_REG_RAX)
                arg1 = mu.reg_read(UC_X86_REG_RDI)
                arg2 = mu.reg_read(UC_X86_REG_RSI)
                arg3 = mu.reg_read(UC_X86_REG_RDX)
                self.logger.log(f"Syscall: {syscall_num}, args: 0x{arg1:x}, 0x{arg2:x}, 0x{arg3:x}")
                # Handle syscalls here
            else:
                syscall_num = mu.reg_read(UC_X86_REG_EAX)
                arg1 = mu.reg_read(UC_X86_REG_EBX)
                arg2 = mu.reg_read(UC_X86_REG_ECX)
                arg3 = mu.reg_read(UC_X86_REG_EDX)
                self.logger.log(f"Syscall: {syscall_num}, args: 0x{arg1:x}, 0x{arg2:x}, 0x{arg3:x}")
                # Handle syscalls here
        
        self.mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    def __del__(self):
        if hasattr(self, 'f') and self.f:
            self.f.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf_file>")
        sys.exit(1)
    
    emu = ELFEmulator(sys.argv[1])
    emu.add_syscall_hook()
    try:
        emu.emulate()
    except Exception as e:
        print(f"Emulation failed: {e}")