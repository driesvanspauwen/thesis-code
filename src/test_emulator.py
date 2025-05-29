from unicorn import *
from unicorn.x86_const import *
from helper import *
from typing import List, Tuple, Dict, ByteString
from logger import Logger
from cache import L1DCache
from rsb import RSB
from read_timer import Timer
from loader import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
from capstone.x86 import *
import os
import traceback

Checkpoint = Tuple[object, int, int]  # context, next_insn_addr, flags

class MuWMEmulator():
    # initialize capstone
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    # cache
    CACHE_MISS_CYCLES = 300   # Typical CPU cycles for memory
    REGULAR_INSTR_CYCLES = 1  # Regular instruction timing
    MAX_SPEC_WINDOW = 250

    def __init__(self, gate_name: str, loader: Loader, debug: bool = True):
        # initialize unicorn
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pending_fault_id: int = 0

        # cache
        self.cache = L1DCache()

        # rsb
        self.rsb = RSB()

        # speculation control
        self.in_speculation: bool = False
        self.speculation_depth: int = 0
        self.speculation_limit: int = 0
        self.previous_context = None

        # OoOE
        self.pending_registers: Dict[str, int] = {}
        self.pending_memory_loads = set()

        # Timing (for rdtscp support)
        self.timer = Timer()

        # instructions
        self.curr_insn: CsInsn
        self.curr_insn_address: int = 0
        self.next_insn_addr: int = 0

        # checkpointing
        self.checkpoints: List[Checkpoint] = []
        self.store_logs: List[List[Tuple[int, ByteString]]] = []  # each entry is a list of (address, prev_value) tuples, one entry per checkpoint

        # logging & compilation
        self.gate_name = gate_name
        self.output_dir = os.path.join("output", gate_name)
        self.logger = Logger(os.path.join(self.output_dir, 'emulation_log.txt'), debug)
        
        # Helper addresses
        self.code_start_address: int
        self.code_exit_addr: int
        # self.fault_handler_addr: int
        self.data_start_addr: int

        # load code & map memory
        self.loader = loader
        self.loader.load(self)

        # hooks
        self.uc.hook_add(UC_HOOK_MEM_READ, self.mem_read_hook, self)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.mem_write_hook, self)
        # self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
        self.uc.hook_add(UC_HOOK_CODE, self.instruction_hook, self)

    def instruction_hook(self, uc: Uc, address: int, size: int, user_data):
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")
        print(f"Instruction hook at address: 0x{address:x}")
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")

    def mem_read_hook(self, uc: Uc, access, address: int, size: int, value, user_data):
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")
        print(f"Memory read hook at address: 0x{address:x}, size: {size}, value: {value}")
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")

    def mem_write_hook(self, uc: Uc, access, address: int, size: int, value, user_data):
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")
        print(f"Memory write hook at address: 0x{address:x}, size: {size}, value: {value}")
        print(f"EAX value: {uc.reg_read(UC_X86_REG_EAX)}")
    
    def emulate(self):
        start_address = self.code_start_address
        self.uc.emu_start(start_address, -1)


ASM_START = """
BITS 64
DEFAULT REL

section .text
global _start

_start:
"""

ASM_ACTUAL = """
; Trigger division by zero exception
mov eax, 42
add rax, 1
"""

def get_asm_exception_assign():
    return ASM_START + ASM_ACTUAL

def run_assign_asm():
    code = get_asm_exception_assign()
    loader = AsmLoader(code)
    emulator = MuWMEmulator('test', loader, False)
    emulator.emulate()

run_assign_asm()