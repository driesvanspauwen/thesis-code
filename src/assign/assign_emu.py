from unicorn import *
from unicorn.x86_const import *
from typing import List, Tuple, Optional, Set, Dict
import tempfile
import subprocess
import os
import struct
from logger import Logger

ASM_EXCEPTION_ASSIGN = """
BITS 64
DEFAULT REL

section .text
global _start

_start:
    ; Exception-based assign gate
    xor rdx, rdx         ; Set rdx to 0
    div rdx              ; Divide by zero to trigger exception
    
    ; Following instructions execute transiently
    mov rcx, [r14]       ; Load input value
    lea rdx, [r14 + rcx] ; Compute output address
    mov dl, [rdx]        ; Load from output address (leaks via cache)
"""

Checkpoint = Tuple[object, int, int, int]

def compile_asm(asm_code, output_bin="assign_gate.bin", output_obj="assign_gate.o", save_asm=True):
    # Save the assembly to a file
    asm_file = "assign_gate.asm"
    with open(asm_file, 'w') as f:
        f.write(asm_code)
    
    try:
        # Assemble using NASM
        subprocess.run(['nasm', '-f', 'elf64', asm_file, '-o', output_obj], check=True)
        
        # Extract binary code
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', output_obj, output_bin], check=True)
        
        print(f"Saved assembly to {asm_file}")
        print(f"Compiled object file to {output_obj}")
        print(f"Extracted binary to {output_bin}")
        
        with open(output_bin, 'rb') as f:
            machine_code = f.read()
        
        # objdump -d -M intel assign_gate.o
        return machine_code
    
    except subprocess.CalledProcessError as e:
        print(f"Compilation error: {e}")
        return None

class Executor():
    CODE_BASE = 0x1000
    DATA_BASE = 0x2000
    STACK_BASE = 0x3000
    REGION_SIZE = 0x1000

    machine_code = compile_asm(ASM_EXCEPTION_ASSIGN)
    logger = Logger('emulation_log.txt')
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    pending_fault_id: int = 0

    # instructions
    curr_instruction_addr: int = 0
    next_instruction_addr: int = 0

    # checkpointing
    checkpoints: List[Checkpoint]

    # speculation control
    in_speculation: bool = False
    nesting: int = 0
    speculation_window: int = 0
    previous_context = None
    MAX_SPEC_WINDOW = 250

    def __init__(self):
        self.setup()

    def setup(self):
        self.mu.mem_map(self.CODE_BASE, self.REGION_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.DATA_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.STACK_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        self.mu.mem_write(self.CODE_BASE, self.machine_code)
        
        # Setup register state
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.REGION_SIZE - 8)  # Stack pointer
        self.mu.reg_write(UC_X86_REG_R14, self.DATA_BASE)  # Base address

        # Add hooks
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.mem_access_hook, self)
        # self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
        self.mu.hook_add(UC_HOOK_CODE, self.instruction_hook, self)
        
        # Define exit address and fault handler address
        self.code_start_address = self.CODE_BASE
        
        self.code_exit_addr = self.CODE_BASE + len(self.machine_code)
        self.fault_handler_addr = self.code_exit_addr  # No fault handler in asm snippet

        self.checkpoints = []

    def exit_reached(self, address) -> bool:
        return address == self.code_exit_addr

    def checkpoint(self, emulator: Uc, next_instruction):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        spec_window = self.speculation_window
        self.checkpoints.append((context, next_instruction, flags, spec_window))
        self.in_speculation = True

    def speculate_fault(self, errno: int) -> int:
        # speculates only division by zero errors currently
        if not errno == 21:
            self.logger.log(f"Unhandled fault: {errno}")
            return 0
        
        self.checkpoint(self.mu, self.fault_handler_addr)

        self.mu.reg_write(UC_X86_REG_RAX, 0)
        self.mu.reg_write(UC_X86_REG_RDX, 0)

        return self.next_instruction_addr

    def handle_fault(self, errno: int) -> int:
        next_addr = self.speculate_fault(errno)
        if next_addr:
            return next_addr
    
    def instruction_hook(self, uc, address, size, user_data):
        if self.exit_reached(address):
            self.mu.emu_stop()
            return
        self.logger.log(f"Executing instruction at 0x{address:x}, instruction size = 0x{size:x}")
        self.curr_instruction_addr = address
        self.next_instruction_addr = address + size
        self.previous_context = self.mu.context_save()
        
        # this is in trace_instruction (start at X86FaultModelAbstract) but i just put it in instruction_hook
        if self.in_speculation:
            self.speculation_window += 1
            # rollback on a serializing instruction
            # if self.current_instruction.name in self.uc_target_desc.barriers:
            #     self.mu.emu_stop()

            # and on expired speculation window
            if self.speculation_window > self.MAX_SPEC_WINDOW:
                self.mu.emu_stop()

    def mem_access_hook(self, uc, access, address, size, value, user_data):
        self.logger.log(f"Memory access at 0x{address:x}, instruction size = 0x{size:x}")

    def rollback(self):
        pass

    def execute(self):
        self.logger.log("Starting emulation...")
        start_address = self.code_start_address
        while True:
            self.pending_fault_id = 0
            try:
                self.logger.log(f"(re)starting emulation with start address 0x{start_address:x}, exit address 0x{self.code_exit_addr:x}")
                self.mu.emu_start(start_address, self.code_exit_addr, timeout=10 * UC_SECOND_SCALE)
            except UcError as e:
                self.logger.log(f"Error interpreting instruction at 0x{self.curr_instruction_addr:x}: {e}")
                self.pending_fault_id = int(e.errno)

            if self.pending_fault_id:
                # workaround for a Unicorn bug: after catching an exception
                # we need to restore some pre-exception context. otherwise,
                # the emulator becomes corrupted
                self.mu.context_restore(self.previous_context)
                # another workaround, specifically for flags
                self.mu.reg_write(UC_X86_REG_EFLAGS, self.mu.reg_read(UC_X86_REG_EFLAGS))
            
                start_address = self.handle_fault(self.pending_fault_id)
                self.logger.log(f"Setting start address at 0x{start_address:x}")
                self.pending_fault_id = 0
                if start_address and start_address != self.code_exit_addr:
                    continue
            
            # i think this is called when instruction_hook stops emulation because spec window is exceeded
            # in our case probably unnecessary because when spec window is exceeded we dont have any more instructions
            if self.in_speculation:
                start_address = self.rollback()
                continue

if __name__ == "__main__":
    executor = Executor()
    executor.execute()