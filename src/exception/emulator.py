from unicorn import *
from unicorn.x86_const import *
from typing import List, Tuple, Optional, Set, Dict
from logger import Logger
from cache import L1DCache
from compiler import compile_asm
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
from interfaces import Insn
from reorder_buffer import ROB
import os
import traceback

Checkpoint = Tuple[object, int, int, int]

class Emulator():
    CODE_BASE = 0x1000
    DATA_BASE = 0x2000
    STACK_BASE = 0x3000
    REGION_SIZE = 0x1000

    def __init__(self, asm_code: str, gate_name: str, debug: bool = True):
        # initialize capstone
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        # initialize unicorn
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pending_fault_id: int = 0

        # cache
        self.cache = L1DCache()

        # rob
        self.rob = ROB()

        # logging & compilation
        self.gate_name = gate_name
        output_dir = os.path.join("output", gate_name)
        self.logger = Logger(os.path.join(output_dir, 'emulation_log.txt'), debug)
        self.machine_code = compile_asm(asm_code, output_dir=output_dir)

        # speculation
        self.in_speculation: bool = False

        # memory mappings
        self.mu.mem_map(self.CODE_BASE, self.REGION_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.DATA_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.STACK_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        self.mu.mem_write(self.CODE_BASE, self.machine_code)
        
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.REGION_SIZE - 8)  # Stack pointer

        # instructions
        self.current_pc: int = self.CODE_BASE
        self.curr_instruction: CsInsn
        self.curr_instruction_addr: int = 0
        self.next_instruction_addr: int = 0

        # hooks
        self.mu.hook_add(UC_HOOK_MEM_READ, self.mem_read_hook, self)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.mem_write_hook, self)
        # self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
        self.mu.hook_add(UC_HOOK_CODE, self.instruction_hook, self)
        
        # helper addresses
        self.code_start_address = self.CODE_BASE
        self.code_exit_addr = self.CODE_BASE + len(self.machine_code)
        self.fault_handler_addr = self.code_exit_addr  # No fault handler in asm snippet
    
    def mem_read_hook(self, uc, access, address, size, value, user_data):
        pass
    
    def mem_write_hook(self, uc, access, address, size, value, user_data):
        pass

    def instruction_hook(self, uc: Uc, address: int, size: int, user_data):
        pass

    def execute_cycle(self):
        # Fetch and decode next instruction if ROB has space
        if not self.rob.is_full():
            insn = self.disassemble_next_insn()
            if insn:
                self.rob.add_instruction(insn)
                self.current_pc += insn.size
        
        # Execute ready instructions
        executable = self.rob.get_executable_instructions()
        for idx, insn in enumerate(executable):
            exception = self.execute_instruction(insn)

            # todo: do something with exception
            self.rob.mark_executed(idx)

    def execute_insn(self, insn: Insn):
        self.current_insn = insn
        # saved_context = self.save_cpu_state()
        
        try:
            end_addr = insn.address + insn.size
            self.mu.emu_start(insn.address, end_addr, 0, 1)
            self.current_pc = self.mu.reg_read(UC_X86_REG_RIP)
            return None
        
        except Exception as e:
            # An exception occurred during execution
            print(f"Exception during execution: {e}")
            # self.restore_cpu_state(saved_context)
            return e
        
        finally:
            self.current_insn = None

    def disassemble_next_insn(self) -> Insn:
        """Disassemble the next instruction at current PC into internal Insn representation."""
        try:
            current_pc = self.mu.reg_read(UC_X86_REG_RIP)
            instruction_bytes = self.mu.mem_read(current_pc, 15)  # assuming instruction size of 15 bytes for x86)
            for cs_insn in self.cs.disasm(instruction_bytes, current_pc, 1):
                # disassemble and return 1 instruction
                return Insn(cs_insn)
        except Exception as e:
            print(f"Disassembly error at 0x{current_pc:x}: {e}")
        return None