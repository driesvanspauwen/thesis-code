from unicorn import *
from unicorn.x86_const import *
from typing import List, Tuple, Optional, Set, Dict
import os
from logger import Logger
from cache import L1DCache
from compiler import compile_asm

Checkpoint = Tuple[object, int, int, int]

class ExceptionEmulator():
    CODE_BASE = 0x1000
    DATA_BASE = 0x2000
    STACK_BASE = 0x3000
    REGION_SIZE = 0x1000

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    pending_fault_id: int = 0

    # instructions
    curr_instruction_addr: int = 0
    next_instruction_addr: int = 0

    # checkpointing
    checkpoints: List[Checkpoint] = []

    # cache
    cache = L1DCache()
    CACHE_HIT_CYCLES = 10     # Typical CPU cycles for L1 cache hit
    CACHE_MISS_CYCLES = 300   # Typical CPU cycles for memory 
    REGULAR_INSTR_CYCLES = 1  # Regular instruction timing
    
    # speculation control
    in_speculation: bool = False
    nesting: int = 0
    speculation_window: int = 0
    previous_context = None
    MAX_SPEC_WINDOW = 250

    def __init__(self, asm_code: str, gate_name: str):
        self.gate_name = gate_name
        output_dir = os.path.join("output", gate_name)

        self.machine_code = compile_asm(asm_code, output_dir=output_dir)
        self.logger = Logger(os.path.join(output_dir, 'emulation_log.txt'))

        # Map memory regions
        self.mu.mem_map(self.CODE_BASE, self.REGION_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.DATA_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.STACK_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        # Write machine code to memory
        self.mu.mem_write(self.CODE_BASE, self.machine_code)
        
        # Setup register state
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.REGION_SIZE - 8)  # Stack pointer

        # Add hooks
        self.mu.hook_add(UC_HOOK_MEM_READ, self.mem_read_hook, self)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.mem_write_hook, self)
        # self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
        self.mu.hook_add(UC_HOOK_CODE, self.instruction_hook, self)
        
        # Define exit address and fault handler address
        self.code_start_address = self.CODE_BASE
        self.code_exit_addr = self.CODE_BASE + len(self.machine_code)
        self.fault_handler_addr = self.code_exit_addr  # No fault handler in asm snippet

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

        # real processors cant rewrite these registers because they cant reorder instructions that might depend on this data
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
            self.speculation_window += self.REGULAR_INSTR_CYCLES
            # rollback on a serializing instruction
            # if self.current_instruction.name in self.uc_target_desc.barriers:
            #     self.mu.emu_stop()

            # and on expired speculation window
            if self.speculation_window > self.MAX_SPEC_WINDOW:
                self.mu.emu_stop()

    def mem_write_hook(self, uc, access, address, size, value, user_data):
        self.cache.write(address, value)
        self.logger.log(f"\tMemory write: address=0x{address:x}, size={size}, value={value}")

        if self.in_speculation:
            self.speculation_window += self.CACHE_HIT_CYCLES
            self.logger.log(f"\tCurrent speculation window size: {self.speculation_window}")

    def mem_read_hook(self, uc, access, address, size, value, user_data):
        is_hit = self.cache.read(address, uc)

        if self.in_speculation:
            if is_hit != None:
                self.speculation_window += self.CACHE_HIT_CYCLES - self.REGULAR_INSTR_CYCLES  # because we already added REGULAR_INSTR_CYCLES in instruction_hook
                self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE HIT, TSC += {self.CACHE_HIT_CYCLES}")
            else:
                self.speculation_window += self.CACHE_MISS_CYCLES - self.REGULAR_INSTR_CYCLES  # because we already added REGULAR_INSTR_CYCLES in instruction_hook
                self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE MISS, TSC += {self.CACHE_MISS_CYCLES}")

        self.logger.log(f"\tCurrent speculation window size: {self.speculation_window}")

    def rollback(self):
        pass

    def emulate(self):
        self.logger.log(f"Starting emulation of gate {self.gate_name}...")
        start_address = self.code_start_address
        while True:
            self.pending_fault_id = 0
            try:
                self.logger.log(f"(re)starting emulation with start address 0x{start_address:x}, exit address 0x{self.code_exit_addr:x}")
                self.mu.emu_start(start_address, self.code_exit_addr, timeout=10 * UC_SECOND_SCALE)
            except UcError as e:
                self.logger.log(f"\tError interpreting instruction at 0x{self.curr_instruction_addr:x}: {e}")
                self.pending_fault_id = int(e.errno)
            
            except Exception as e:
                print(f"Unhandled exception (stopping emulation): {e}")
                self.mu.emu_stop()
                break

            if self.pending_fault_id:
                # workaround for a Unicorn bug: after catching an exception
                # we need to restore some pre-exception context. otherwise,
                # the emulator becomes corrupted
                self.mu.context_restore(self.previous_context)
                # another workaround, specifically for flags
                self.mu.reg_write(UC_X86_REG_EFLAGS, self.mu.reg_read(UC_X86_REG_EFLAGS))
            
                start_address = self.handle_fault(self.pending_fault_id)
                self.logger.log(f"\tSetting start address at 0x{start_address:x}")
                self.pending_fault_id = 0
                if start_address and start_address != self.code_exit_addr:
                    continue
            
            # i think this is called when instruction_hook stops emulation because spec window is exceeded
            # in our case probably unnecessary because when spec window is exceeded we dont have any more instructions
            if self.in_speculation:
                start_address = self.rollback()
                continue