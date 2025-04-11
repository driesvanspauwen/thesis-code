from capstone import CsInsn
from exception_emulator import ExceptionEmulator
from cache import L1DCache
from logger import Logger

class OOOEmulator(ExceptionEmulator):
    def __init__(self, asm_code: str, gate_name: str, debug: bool = True):
        super().__init__(asm_code, gate_name, debug)
        

    def mem_read_hook(self, uc, access, address, size, value, user_data):
        pass

    def mem_write_hook(self, uc, access, address, size, value, user_data):
        pass