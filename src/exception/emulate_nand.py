from unicorn import *
from unicorn.x86_const import *
import sys, os
from logger import Logger
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn

class NANDEmulator:
    # Memory addresses from the disassembly/source code
    IN1_ADDR = 0x7040    # Address of in1 array
    IN2_ADDR = 0x6840    # Address of in2 array
    OUT_ADDR = 0x6040    # Address of out array
    TMP_REG1_ADDR = 0x5840
    TMP_REG2_ADDR = 0x5040
    TMP_REG3_ADDR = 0x4840
    TMP_REG4_ADDR = 0x4040

    # Function address
    NAND_GATE_START_ADDR = 0x13a0
    NAND_GATE_END_ADDR = 0x16ee


    def __init__(self, elf_path):
        self.elf_path = elf_path

        self.f = open(elf_path, "rb")
        self.elf = ELFFile(self.f)

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        output_dir = os.path.join("tmp", "elf_emulator")
        self.logger = Logger(os.path.join(output_dir, 'log.txt'))

        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)

        self.mu.hook_add(UC_HOOK_CODE, self._hook_code)

        self.map_segments()
        self.map_stack()
    
    def map_stack(self):
        self.logger.log("Mapping stack:")
        STACK_ADDR = 0x8000000
        STACK_SIZE = 0x10000
        self.mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x100)

    def map_segments(self):
        self.logger.log("Mapping segments:")
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
                self.logger.log(f"Mapping segment at 0x{mem_start:x} - 0x{mem_end-1:x}, size: 0x{mem_size:x}")
                self.logger.log(f"\tFlags: {segment.header.p_flags}, Permissions: {perm}, Entry point in segment: {'Yes' if (segment.header.p_vaddr <= self.NAND_GATE_START_ADDR < segment.header.p_vaddr + segment.header.p_memsz) else 'No'}")
                
                try:
                    self.mu.mem_map(mem_start, mem_size, perm)
                    
                    # Map segment data
                    data = segment.data()
                    self.mu.mem_write(segment.header.p_vaddr, data)
                    self.logger.log(f"\tData written: 0x{len(data):x} bytes at 0x{segment.header.p_vaddr:x}")
                    
                    # Zero out uninitialized data
                    if segment.header.p_memsz > segment.header.p_filesz:
                        padding_size = segment.header.p_memsz - segment.header.p_filesz
                        padding_addr = segment.header.p_vaddr + segment.header.p_filesz
                        self.mu.mem_write(padding_addr, b'\x00' * padding_size)
                        self.logger.log(f"\tZeroed: 0x{padding_size:x} bytes at 0x{padding_addr:x}")
                except UcError as e:
                    self.logger.log(f"\tError mapping segment: {e}")
    
    def _hook_code(self, uc, address, size, user_data):
        """Code execution hook for debugging"""

        insn_bytes = uc.mem_read(address, size)
        for insn in self.cs.disasm(insn_bytes, address, 1):
            self.logger.log(f">>> Executing 0x{address:x}: {insn.mnemonic} {insn.op_str}")

    def emulate(self):
        try:
            self.mu.emu_start(self.NAND_GATE_START_ADDR, self.NAND_GATE_END_ADDR)
        except UcError as e:
            self.logger.log(f"Emulation error: {e}")
            return False

if __name__ == "__main__":
    emulator = NANDEmulator("nand_test.elf")
    emulator.emulate()