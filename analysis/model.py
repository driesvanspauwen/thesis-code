from pathlib import Path
import unicorn as uni
from unicorn import Uc
from unicorn.x86_const import *
import json
from ruamel.yaml import YAML
yaml = YAML(typ='safe')

class CacheBasedWRModel:
    """Minimal model for emulating cache-based weird registers"""
    
    STACK_SIZE: int
    STACK: int 
    STACK_TOP: int
    STUB_ADDR = 0x1000

    def __init__(self, path, function_name):
        self.binary_path = Path(path)
        self.library = self.binary_path.name
        self.function_name = function_name
        self.dumps_path = Path.cwd() / 'dumps' / f'{self.library}'
        self._load_elf()
        self._mapped = set()
        self._segments = set()
        self.function_addr = self.elf['symtable'][function_name]['addr']
        self._load_program()

    def _load_elf(self):
        with (self.dumps_path / 'elf_info.yaml').open() as fp:
            self.elf = yaml.load(fp)

    @staticmethod
    def _aligndown(addr, alignment):
        return addr // alignment * alignment

    @staticmethod
    def _alignup(sz, alignment):
        return ((sz - 1) // alignment + 1) * alignment

    @staticmethod
    def mem_access_unmapped_hook(emulator: Uc, access: int, address: int, size: int, value: int, self) -> bool:
        # Map memory on-demand when accessed
        page = address & ~0xFFF  # Align to page size
        size = (size + 0xFFF) & ~0xFFF  # Round up to page size
        
        # Map the memory region with all permissions
        emulator.mem_map(page, size, uni.UC_PROT_ALL)
        
        # If this was a write access, perform the write
        if access == uni.UC_MEM_WRITE_UNMAPPED:
            emulator.mem_write(address, value.to_bytes(size, 'little'))
        
        return True

    def mem_map(self, start, size, perms=None):
        start = self._aligndown(start, 0x1000)
        end = self._alignup(start + size, 0x1000)
        size = end - start
        startn = start // 0x1000
        endn = end // 0x1000
        if not self._mapped.intersection(range(startn, endn)):
            if perms is not None:
                self.emulator.mem_map(start, size, perms)
            else:
                self.emulator.mem_map(start, size)
        else:
            for page in set(range(startn, endn)).difference(self._mapped):
                self.emulator.mem_map(page * 0x1000, 0x1000, perms)
        self._mapped.update(range(startn, endn))
        self._segments.add((start, start + size))

    def _load_program(self):
        self.emulator = Uc(uni.UC_ARCH_X86, uni.UC_MODE_64)
        
        self.emulator.hook_add(
            uni.UC_HOOK_MEM_WRITE_UNMAPPED | uni.UC_HOOK_MEM_READ_UNMAPPED,
            self.mem_access_unmapped_hook,
            self
        )
        self._import_dumps()

    def _import_dumps(self):
        blob = json.loads((self.dumps_path / 'dump_data.json').read_text())
        
        for start, end, size, offset, perms, file in blob['mappings']:
            if (path := (self.dumps_path / f'dump_{start:x}_{end:x}.bin')).is_file():
                if file == '[stack]':
                    self.STACK = end
                    self.STACK_SIZE = size
                    self.STACK_TOP = self.STACK - self.STACK_SIZE
                
                perm = 0
                if 'w' in perms: perm |= 2  # Write
                if 'r' in perms: perm |= 1  # Read
                if 'x' in perms: perm |= 4  # Execute
                
                data = path.read_bytes()
                self.mem_map(start, size, 7)
                self.emulator.mem_write(start, data)
                self.emulator.mem_protect(start, size, perm)

        # Write stub to call the function
        call_opcode = b"\xe8"
        relative_offset = self.function_addr - (self.STUB_ADDR + 5)
        stub = call_opcode + relative_offset.to_bytes(4, "little")
        self.mem_map(self.STUB_ADDR, 0x1000)
        self.emulator.mem_write(self.STUB_ADDR, stub)

    def run(self):
        try:
            self.emulator.emu_start(self.STUB_ADDR, self.STUB_ADDR + 5)
        except uni.UcError as e:
            print(f"Error: {e}")

    def reset(self):
        for start, end in self._segments:
            size = end - start 
            self.emulator.mem_unmap(start, size)
        self._mapped = set()
        self._segments = set()
        self._import_dumps()