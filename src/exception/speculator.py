from exception_emulator import ExceptionEmulator
from cache import L1DCache

class Speculator:
    def __init__(self, cache: L1DCache):
        self.pending_registers = set()
        self.pending_memory_loads = set()
        # self.register_dependencies = {}
        # self.current_instruction = None
        self.is_speculating = False
        self.cache = cache

    def speculate_read(self, address, reg):
        if not self.is_speculating:
            return True

        if not self.cache.is_cached(address):
            self.pending_memory_loads.add(address)
            self.pending_registers.add(reg)
            return False
        
        if reg in self.pending_registers:
            self.pending_registers.remove(reg)

        return True

    def speculate_write(self, reg):
        if reg in self.pending_registers:
            self.pending_registers.remove(reg)
    
    def should_execute_instruction(self, instr_addr, opcode, source_regs):
        if not self.is_speculating:
            return True

        for reg in source_regs:
            if reg in self.pending_registers:
                return False
                
        return True