from exception_emulator import ExceptionEmulator
from cache import L1DCache
from logger import Logger

class OOOEmulator(ExceptionEmulator):
    def __init__(self, asm_code: str, gate_name: str):
        super().__init__(asm_code, gate_name)
        self.pending_registers = set()
        self.pending_memory_loads = set()

    def mem_read_hook(self, uc, access, address, size, value, user_data):
        if not self.in_speculation:
            is_hit = self.cache.read(address, uc)
            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, cached={is_hit is not None}")
            return

        # Read address not cached
        if not self.cache.is_cached(address):
            # Add address as pending memory load
            self.pending_memory_loads.add(address)

            # Add receiving registers as pending registers
            _, regs_written = self.curr_instruction.regs_access()
            for reg in regs_written:
                self.pending_registers.add(reg)

            self.logger.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE MISS")
        
        # Read address cached
        else:
            self.cache.read(address, uc)

            # Remove address from pending memory loads
            for reg in self.curr_instruction.regs_write:
                self.pending_registers.discard(reg)

            # Remove receiving registers from pending registers
            _, regs_written = self.curr_instruction.regs_access()
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
            self.logger.log(f"\tPersisting memory load: address=0x{address:x}")
        self.pending_memory_loads.clear()

    def should_execute(self, insn):
        """
        Determines if an instruction should execute based on register dependencies.
        
        Args:
            insn: A Capstone instruction object
            
        Returns:
            bool: True if the instruction can execute, False if it should be skipped
        """
        # Check if we're not speculating - if not, always execute
        if not self.in_speculation:
            return True
            
        # Get registers read by this instruction
        regs_read, _ = insn.regs_access()
        
        # Check if any read registers are pending
        for reg in regs_read:
            if reg in self.pending_registers:
                self.logger.log(f"\tSkipping instruction (register dependency): {insn.mnemonic} {insn.op_str}")
                self.logger.log(f"\tPending register found: {self.cs.reg_name(reg)}")
                return False
        
        # # For memory reads, check if the address calculation uses pending registers
        # if insn.mnemonic in ['mov', 'movzx'] and any(op.type == 3 for op in insn.operands):  # Memory operand (type 3)
        #     # Check if this is a memory read operation
        #     mem_op = next((op for op in insn.operands if op.type == 3), None)
        #     if mem_op:
        #         # Check if base or index registers are pending
        #         base_reg = mem_op.mem.base
        #         index_reg = mem_op.mem.index
                
        #         if (base_reg and base_reg in self.pending_registers) or \
        #         (index_reg and index_reg in self.pending_registers):
        #             self.logger.log(f"\tSkipping instruction (memory address dependency): {insn.mnemonic} {insn.op_str}")
        #             return False
        
        return True
    
    def _pretty_print_pending_state(self, indent=0):
        """
        Pretty prints the current state of pending memory loads and registers.
        """
        indent_str = "\t" * indent
        self.logger.log(f"{indent_str}Pending memory loads: {[f'0x{address:x}' for address in self.pending_memory_loads]}")
        self.logger.log(f"{indent_str}Pending registers: {[f'{self.cs.reg_name(reg_id)}' for reg_id in self.pending_registers]}")