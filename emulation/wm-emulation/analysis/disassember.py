"""
Disassembles x86-64 machine code represented as a byte string into assembly instructions
"""

from capstone import *
from emulator import *

cs = Cs(CS_ARCH_X86, CS_MODE_64)
for i in cs.disasm(X86_CODE32_LOOP, 0x1000000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))