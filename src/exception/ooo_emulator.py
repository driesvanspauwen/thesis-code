from capstone import CsInsn
from exception_emulator import ExceptionEmulator
from cache import L1DCache
from logger import Logger

class OOOEmulator(ExceptionEmulator):
    def __init__(self, asm_code: str, gate_name: str, debug: bool = True):
        super().__init__(asm_code, gate_name, debug)
        self.pending_registers = set()
        self.pending_memory_loads = set()

    def mem_read_hook(self, uc, access, address, size, value, user_data):
        if not self.in_speculation:
            is_hit = self.cache.read(address, uc)
            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, cached={is_hit is not None}")
            return
        
        regs_read, regs_written = self.curr_instruction.regs_access()

        # cache miss
        if not self.cache.is_cached(address):
            # Add address as pending memory load
            self.pending_memory_loads.add(address)

            # If register used to dereference address, set register to pending
            # TODO

            # Add receiving registers as pending registers
            for reg in regs_written:
                self.pending_registers.add(reg)
            
            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE MISS")
        
        # cache hit
        else:
            self.cache.read(address, uc)
            # Remove address from pending memory loads
            for reg in regs_written:
                self.pending_registers.discard(reg)

            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE HIT")

        self._pretty_print_pending_state(indent=1)

    def mem_write_hook(self, uc, access, address, size, value, user_data):
        self.cache.write(address, value)
        for reg in self.curr_instruction.regs_write:
            self.pending_registers.discard(reg)

        self.logger.log(f"\tMemory write: address=0x{address:x}, size={size}")
    
    def persist_pending_loads(self):
        """
        Persist pending memory loads to the cache.
        """
        self.logger.log("Persisting pending memory loads...")
        self._pretty_print_pending_state(indent=1)
        for address in self.pending_memory_loads:
            self.cache.write(address, self.mu.mem_read(address, self.cache.line_size))
        self.pending_memory_loads.clear()

    def should_skip(self, insn: CsInsn):
        """
        Determines if an instruction should be skipped based on register dependencies.
        """
        if not self.in_speculation:
            # only perform OOO execution in speculation
            return False
        
        read_from_pending = False
            
        regs_read, regs_written = insn.regs_access()
        # self.logger.log(f"\tRegs read: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_read]}")
        # self.logger.log(f"\tRegs written: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_written]}")
        
        # check if any read registers are pending
        for reg in regs_read:
            if reg in self.pending_registers:
                self.logger.log(f"\tSkipping instruction because there is a dependency on a pending register: {self.cs.reg_name(reg)}")
                read_from_pending = True
                break
        
        if read_from_pending:
            # if read from pending register, add written registers as pending
            for reg in regs_written:
                self.pending_registers.add(reg)
        else:
            # pending registers are overwritten so can be removed
            for reg in regs_written:
                self.pending_registers.discard(reg)
            

        return read_from_pending
    
    def _pretty_print_pending_state(self, indent=0):
        """
        Pretty prints the current state of pending memory loads and registers.
        """
        indent_str = "\t" * indent
        self.logger.log(f"{indent_str}Pending memory loads: {[f'0x{address:x}' for address in self.pending_memory_loads]}")
        self.logger.log(f"{indent_str}Pending registers: {[f'{self.cs.reg_name(reg_id)}' for reg_id in self.pending_registers]}")