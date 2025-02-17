from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
import struct
from typing import Optional, Tuple

class WeirdRegisterEmulator:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.base_addr = 0x400000  # Common base address for x64 binaries
        self.stack_addr = 0x7fffff000000
        self.stack_size = 0x21000
        
        # Initialize emulator
        self.setup_memory()
        self.load_binary()
        self.setup_hooks()
        
        # Track executed instructions for debugging
        self.instruction_trace = []
        
    def setup_memory(self):
        """Set up memory regions for code, data, and stack"""
        # Map stack memory
        self.emu.mem_map(self.stack_addr - self.stack_size, self.stack_size)
        self.emu.reg_write(UC_X86_REG_RSP, self.stack_addr - 0x1000)
        
    def load_binary(self):
        """Load the ELF binary into emulator memory"""
        with open(self.binary_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Load segments
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    # Calculate memory protection
                    prot = UC_PROT_NONE
                    if segment['p_flags'] & 0x1:  # Executable
                        prot |= UC_PROT_EXEC
                    if segment['p_flags'] & 0x2:  # Write
                        prot |= UC_PROT_WRITE
                    if segment['p_flags'] & 0x4:  # Read
                        prot |= UC_PROT_READ
                    
                    # Map memory for segment
                    size = segment['p_memsz']
                    addr = segment['p_vaddr']
                    
                    # Align address and size to 4KB pages
                    aligned_addr = addr & ~0xFFF
                    aligned_size = (size + 0xFFF) & ~0xFFF
                    
                    self.emu.mem_map(aligned_addr, aligned_size, prot)
                    
                    # Write segment data
                    data = segment.data()
                    if data:
                        self.emu.mem_write(addr, data)
        
        # Store entry point
        self.entry_point = elf['e_entry']
    
    def instruction_hook(self, uc, address, size, user_data):
        """Hook for tracing instructions"""
        # Read instruction bytes
        instruction = uc.mem_read(address, size)
        self.instruction_trace.append((address, instruction))
        
        # Handle CPUID instruction specially (needed for rdtscp)
        if instruction == b'\x0f\xa2':  # CPUID
            self.handle_cpuid(uc)
            
    def memory_hook(self, uc, access, address, size, value, user_data):
        """Hook for memory access"""
        if access == UC_MEM_WRITE:
            print(f"Memory write at 0x{address:x}, size: {size}, value: 0x{value:x}")
        else:
            print(f"Memory read at 0x{address:x}, size: {size}")
    
    def handle_cpuid(self, uc):
        """Handle CPUID instruction"""
        # Get input from EAX
        eax = uc.reg_read(UC_X86_REG_EAX)
        
        # Provide dummy CPUID results
        uc.reg_write(UC_X86_REG_EAX, 0)
        uc.reg_write(UC_X86_REG_EBX, 0)
        uc.reg_write(UC_X86_REG_ECX, 0)
        uc.reg_write(UC_X86_REG_EDX, 0)
        
    def setup_hooks(self):
        """Set up instruction and memory hooks"""
        self.emu.hook_add(UC_HOOK_CODE, self.instruction_hook)
        self.emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.memory_hook)
    
    def find_symbol(self, symbol_name: str) -> Optional[int]:
        """Find address of a symbol in the binary"""
        with open(self.binary_path, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name == symbol_name:
                        return sym['st_value']
        return None
    
    def run_weird_register_test(self):
        """Run the weird register test program"""
        try:
            # Find addresses of key functions
            main_addr = self.find_symbol('main')
            if not main_addr:
                raise Exception("Could not find main function")
            
            # Set up initial register state
            self.emu.reg_write(UC_X86_REG_RDI, 0)  # First argument
            
            # Run emulation
            print("Starting emulation...")
            self.emu.emu_start(main_addr, main_addr + 0x1000)
            
            # Get result from RAX
            result = self.emu.reg_read(UC_X86_REG_RAX)
            print(f"Emulation completed. Result: {result}")
            
            # Print instruction trace
            print("\nInstruction trace:")
            for addr, inst in self.instruction_trace:
                print(f"0x{addr:x}: {inst.hex()}")
                
        except UcError as e:
            print(f"Emulation failed: {e}")

if __name__ == "__main__":
    emulator = WeirdRegisterEmulator("cb_wr.bin")
    emulator.run_weird_register_test()