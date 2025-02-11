"""
Disassembles x86-64 machine code represented as a byte string into assembly instructions
"""

from capstone import *
from emulator import *

cs = Cs(CS_ARCH_X86, CS_MODE_64)
code = cs.disasm(X86_CODE32_LOOP, 0x1000000)
for instr in code:
    print("0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))