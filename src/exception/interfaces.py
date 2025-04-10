from capstone import CsInsn

class Insn(CsInsn):
    def __init__(self, cs_insn: CsInsn):
        # Copy all attributes from capstone instruction
        for key, value in cs_insn.__dict__.items():
            self.__dict__[key] = value
            
        # Add custom attributes
        self.executed = False
        self.ready = False
        self.committed = False
        self.regs_read, self.regs_written = self.regs_access()