from unicorn import *
from unicorn.x86_const import *
from helper import *
from typing import List, Tuple, Optional, Set, Dict
from logger import Logger
from cache import L1DCache
from compiler import compile_asm
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
import os
import traceback

Checkpoint = Tuple[object, int, int, int]

class ExceptionEmulator():
    CODE_BASE = 0x1000
    DATA_BASE = 0x2000
    STACK_BASE = 0x3000
    REGION_SIZE = 0x1000

    # initialize capstone
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    # cache
    CACHE_MISS_CYCLES = 300   # Typical CPU cycles for memory
    REGULAR_INSTR_CYCLES = 1  # Regular instruction timing
    MAX_SPEC_WINDOW = 250

    def __init__(self, asm_code: str, gate_name: str, debug: bool = True):
        # initialize unicorn
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pending_fault_id: int = 0

        # cache
        self.cache = L1DCache()

        # speculation control
        self.in_speculation: bool = False
        self.speculation_depth: int = 0
        self.speculation_limit: int = 0
        self.previous_context = None

        # OoOE
        self.pending_registers: Dict[str, int] = {}
        self.pending_memory_loads = set()

        # instructions
        self.curr_insn: CsInsn
        self.curr_instruction_addr: int = 0
        self.next_insn_addr: int = 0

        # checkpointing
        self.checkpoints: List[Checkpoint] = []

        # logging & compilation
        self.gate_name = gate_name
        output_dir = os.path.join("output", gate_name)
        self.logger = Logger(os.path.join(output_dir, 'emulation_log.txt'), debug)
        self.machine_code = compile_asm(asm_code, output_dir=output_dir)

        # memory mappings
        self.mu.mem_map(self.CODE_BASE, self.REGION_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.DATA_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_map(self.STACK_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        self.mu.mem_write(self.CODE_BASE, self.machine_code)
        
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.REGION_SIZE - 8)  # Stack pointer

        # hooks
        self.mu.hook_add(UC_HOOK_MEM_READ, self.mem_read_hook, self)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.mem_write_hook, self)
        # self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
        self.mu.hook_add(UC_HOOK_CODE, self.instruction_hook, self)
        
        # helper addresses
        self.code_start_address = self.CODE_BASE
        self.code_exit_addr = self.CODE_BASE + len(self.machine_code)
        self.fault_handler_addr = self.code_exit_addr  # No fault handler in asm snippet

    def exit_reached(self, address) -> bool:
        return address == self.code_exit_addr

    def checkpoint(self, emulator: Uc, next_instruction):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        self.checkpoints.append((context, next_instruction, flags, self.speculation_depth))

    def speculate_fault(self, errno: int) -> int:
        # speculates only division by zero errors currently
        if not errno == 21:
            self.logger.log(f"Unhandled fault: {errno}")
            return 0
        
        self.checkpoint(self.mu, self.fault_handler_addr)
        
        self.in_speculation = True
        self.speculation_limit = self.MAX_SPEC_WINDOW
        regs_read, regs_written = self.curr_insn.regs_access()
        self.speculation_limit += self.get_max_cycle_wait_for_registers(regs_read)

        # real processors cant rewrite these registers because they cant reorder instructions that might depend on this data
        self.mu.reg_write(UC_X86_REG_RAX, 0)
        self.mu.reg_write(UC_X86_REG_RDX, 0)

        return self.next_insn_addr

    def handle_fault(self, errno: int) -> int:
        next_addr = self.speculate_fault(errno)
        if next_addr:
            return next_addr
    
    def skip_curr_insn(self) -> None:
        """Skips current instruction by directly jumping to the next one"""
        address = self.curr_insn.address
        size = self.curr_insn.size
        self.mu.reg_write(UC_X86_REG_RIP, address + size)

    def instruction_hook(self, uc: Uc, address: int, size: int, user_data):
        if self.exit_reached(address):
            self.mu.emu_stop()
            return
        
        insn_bytes = uc.mem_read(address, size)
        
        for insn in self.cs.disasm(insn_bytes, address, 1):
            self.curr_insn = insn
            self.next_insn_addr = address + size
            self.logger.log(f"Executing 0x{address:x}: {insn.mnemonic} {insn.op_str}")
            
            # Check if we should execute this instruction based on dependencies
            if not self.can_resolve_deps(insn):
                self.logger.log(f"\tSkipping instruction (resolving dependencies will exceed speculation limit)")
                self.skip_curr_insn()
                return

        self.previous_context = self.mu.context_save()
        
        # # this is in trace_instruction (start at X86FaultModelAbstract) but i just put it in instruction_hook
        # if self.in_speculation:
        #     self.speculation_depth += self.REGULAR_INSTR_CYCLES
        #     # rollback on a serializing instruction
        #     # if self.current_instruction.name in self.uc_target_desc.barriers:
        #     #     self.mu.emu_stop()

        #     # and on expired speculation window
        #     if self.speculation_depth > self.MAX_SPEC_WINDOW:
        #         self.mu.emu_stop()

    def mem_read_hook(self, uc: Uc, access, address: int, size: int, value, user_data):
        # not in speculation
        # if not self.in_speculation:
        #     is_hit = 
        #     self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, cached={is_hit is not None}")
        
        regs_read, regs_written = self.curr_insn.regs_access()

        # cache miss: add address and registers to pending
        if not self.cache.is_cached(address):
            self.pending_memory_loads.add(address)
            for reg in regs_written:
                self.pending_registers[reg] = self.CACHE_MISS_CYCLES
                if self.in_speculation:
                    if self.CACHE_MISS_CYCLES > self.speculation_limit:
                        self.logger.log(f"\tSkipping instruction (execution will exceed speculation limit)")
                        self.skip_curr_insn()
                else:
                    self.cache.read(address, uc)
            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE MISS")
        
        # cache hit: remove address and registers from pending
        else:
            self.cache.read(address, uc)
            self.pending_memory_loads.discard(address)
            for reg in regs_written:
                self.pending_registers.pop(reg, None)

            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE HIT")
        
        self._pretty_print_pending_state(indent=1)

    def mem_write_hook(self, uc, access, address, size, value, user_data):
        self.cache.write(address, value)

        self.logger.log(f"\tMemory write: address=0x{address:x}, size={size}")

    def rollback(self):
        pass
    
    def persist_pending_loads(self):
        """
        Persist pending memory loads to the cache.
        """
        self.logger.log("Persisting pending memory loads...")
        self._pretty_print_pending_state(indent=1)
        for address in self.pending_memory_loads:
            self.cache.write(address, self.mu.mem_read(address, self.cache.line_size))
        self.pending_memory_loads.clear()

    def can_resolve_deps(self, insn: CsInsn):
        """
        Determines if an instruction can resolve its dependencies within the speculative limit.
        """
        if not self.in_speculation:
            # only perform OOO execution in speculation
            return True
            
        regs_read, regs_written = insn.regs_access()
        # self.logger.log(f"\tRegs read: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_read]}")
        # self.logger.log(f"\tRegs written: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_written]}")

        # check if any read registers are pending
        max_cycle_wait = self.get_max_cycle_wait_for_registers(regs_read)
        self.logger.log(f"\tMaximum cycle wait: {max_cycle_wait}")

        # no dependencies
        if max_cycle_wait == 0:
            for reg in regs_written:
                self.pending_registers.pop(reg, None)

            return True

        # update resolve times for affected registers
        for reg in regs_written:
            self.pending_registers[reg] = max_cycle_wait

        return max_cycle_wait <= self.speculation_limit
    
    def get_max_cycle_wait_for_registers(self, regs_read):
        """
        Calculate the maximum cycle wait time for the given list of register dependencies. Checks both direct dependencies and aliased register dependencies.
        """
        max_cycle_wait = 0
        
        for reg_read in regs_read:
            # Check direct dependencies
            if reg_read in self.pending_registers:
                max_cycle_wait = max(max_cycle_wait, self.pending_registers[reg_read])
                continue
                
            # Check for aliasing dependencies
            for pending_reg, cycles in self.pending_registers.items():
                if registers_alias(reg_read, pending_reg):
                    max_cycle_wait = max(max_cycle_wait, cycles)
                    break
                    
        return max_cycle_wait

    
    def emulate(self):
        start_address = self.code_start_address
        while True:
            if start_address is None:
                self.finish_emulation()
                return
            self.pending_fault_id = 0
            try:
                if self.in_speculation:
                    self.logger.log(f"Entering speculative window with limit {self.speculation_limit}")
                self.logger.log(f"(re)starting emulation with start address 0x{start_address:x}, exit address 0x{self.code_exit_addr:x}")
                self.mu.emu_start(start_address, self.code_exit_addr, timeout=10 * UC_SECOND_SCALE)
            except UcError as e:
                self.logger.log(f"\tError interpreting instruction at 0x{self.curr_instruction_addr:x}: {e}")
                self.pending_fault_id = int(e.errno)
            
            except Exception as e:
                error_msg = f"Unhandled exception (stopping emulation): {e}"
                stack_trace = traceback.format_exc()
                self.logger.log(f"{error_msg}\n{stack_trace}")
                print(f"{error_msg}\n{stack_trace}")
                self.finish_emulation()
                return

            if self.pending_fault_id:
                # workaround for a Unicorn bug: after catching an exception
                # we need to restore some pre-exception context. otherwise,
                # the emulator becomes corrupted
                self.mu.context_restore(self.previous_context)
                # another workaround, specifically for flags
                self.mu.reg_write(UC_X86_REG_EFLAGS, self.mu.reg_read(UC_X86_REG_EFLAGS))
            
                start_address = self.handle_fault(self.pending_fault_id)

                self.pending_fault_id = 0
                if start_address and start_address != self.code_exit_addr:
                    self.logger.log(f"\tSetting start address at 0x{start_address:x}")
                    continue
            
            # i think this is called when instruction_hook stops emulation because spec window is exceeded
            # in our case probably unnecessary because when spec window is exceeded we dont have any more instructions
            if self.in_speculation:
                start_address = self.rollback()
                continue
    
    def finish_emulation(self):
        self.persist_pending_loads()
        self.mu.emu_stop()

    def _pretty_print_pending_state(self, indent=0):
        """
        Pretty prints the current state of pending memory loads and registers.
        """
        indent_str = "\t" * indent
        self.logger.log(f"{indent_str}Pending memory loads: {[f'0x{address:x}' for address in self.pending_memory_loads]}")
        
        # Update to show both register names and cycle counts
        reg_entries = [f"{self.cs.reg_name(reg_id)}:{cycles}" for reg_id, cycles in self.pending_registers.items()]
        self.logger.log(f"{indent_str}Pending registers: {reg_entries}")