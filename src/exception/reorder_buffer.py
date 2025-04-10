from typing import Dict, List
from interfaces import Insn

class ROB:
    def __init__(self, max_size: int = 32):
        self.buffer: List[Insn] = []
        self.max_size: int = max_size
        self.register_status: Dict[int, Insn] = {}  # maps registers to latest instruction that writes to them
    
    def is_full(self):
        return len(self.buffer) >= self.max_size
    
    def is_empty(self):
        return len(self.buffer) == 0
    
    def add_instruction(self, insn: Insn):
        if self.is_full():
            return False

        # if insn uses registers affected by other pending insns, insn is not ready yet to execute
        insn.ready = self.insn_dependencies_resolved(insn)
        
        for reg in insn.regs_written:
            self.register_status[reg] = insn

        # add insn to ROB
        self.buffer.append(insn)
        return True
    
    def get_executable_instructions(self):
        executable = []
        for i, insn in enumerate(self.buffer):
            if insn.ready and not insn.executed:
                executable.append((i, insn))
        return executable

    def mark_executed(self, index):
        if 0 <= index < len(self.buffer):
            insn = self.buffer[index]
            insn.executed = True
            
            self.update_dependencies(insn)

    def insn_dependencies_resolved(self, insn: Insn) -> bool:
        for reg_read in insn.regs_read:
            if reg_read in self.register_status:
                dep_insn = self.register_status[reg_read]
                if not dep_insn.executed:
                    return False
        return True

    def update_dependencies(self, insn: Insn):
        for i, dep_insn in enumerate(self.buffer):
            for reg in dep_insn.regs_read:
                if reg in insn.regs_written:
                    # Dependent insn was waiting for register affected by executed instruction
                    if self.insn_dependencies_resolved(dep_insn):
                        dep_insn.ready = True
                        continue
    
    def commit(self, insn: Insn) -> Insn | None:
        if self.is_empty():
            return None
        
        insn = self.buffer[0]

        if not insn.executed:
            return None

        insn.committed = True

        # if insn is last writer to a register, remove it from register status map
        for reg in insn.regs_written:
            if self.register_status.get(reg) == insn:
                del self.register_status[reg]
        
        return insn