#!/usr/bin/env python3
"""
Memory State Dumper for CPU Emulation Analysis

This tool dumps the memory state and register values of a running program using GDB,
which can be used to initialize CPU emulators (like Unicorn) for analyzing speculative
execution vulnerabilities.

Usage:
    python3 dumper.py <path_to_binary> <name_of_entry_function>
"""

import json
import re
import subprocess
import sys
from collections.abc import Mapping
from io import StringIO
from pathlib import Path

import pexpect  # For controlling GDB
import rich.pretty
import ruamel.yaml as yaml
from elftools.elf.elffile import ELFFile, SymbolTableSection
from ruamel.yaml import Representer
from ruamel.yaml.scalarint import HexInt

gdb = None  # Global GDB instance
output = []  # Stores GDB output

# Get binary and function to analyze from command line
library, function = sys.argv[1:]
library = Path(library)

# Create output directory for dumps - matching model.py path structure
outdir = Path.cwd() / 'dumps' / library.name
outdir.mkdir(parents=True, exist_ok=True)

def sanitize(s):
    """Clean up GDB output by removing ANSI escape sequences and carriage returns"""
    return re.sub(r'\x1b\[[^A-Za-z]*[A-Za-z]|\r', r'', s).strip()

def gdbstart():
    """Start GDB in quiet mode"""
    global gdb
    gdb = pexpect.spawn('gdb', ['-q'], timeout=2)
    res = gdb.expect([r'\(gdb\)', '<RET> for more'])
    output.append(gdb.before.decode())
    output.append(gdb.after.decode())

def gdbin(cmd):
    """Send command to GDB and capture output"""
    gdb.sendline(cmd)
    res = gdb.expect([r'\(gdb\)', '<RET> for more'])
    output.append(gdb.before.decode())
    if res:
        return gdbin('')

def gdbquit():
    """Cleanly exit GDB"""
    gdb.sendeof()
    gdb.expect(['will be killed', pexpect.EOF])

# Initialize GDB and set breakpoint
gdbstart()
gdbin(f'file {library}')  # Load binary
gdbin(f'b {function}')    # Set breakpoint at target function
gdbin('r')               # Run until breakpoint
gdbin('info proc mapping')  # Get memory mappings
gdbin('info reg')          # Get register values
gdbin('info reg fs_base')  # Get FS segment base register

# Parse GDB output to extract memory mappings and register values
state = "before"
lines = ''.join(map(sanitize, output)).splitlines()

mappings = []  # Store memory region information
regs = {}      # Store register values

def unhex(s):
    """Convert hex string to integer"""
    return int(s.removeprefix("0x"), 16)

# State machine to parse GDB output
for line in lines:
    print("line: {}".format(line))
    if state == "before":
        if "Start Addr" in line:
            state = "mappings"
            continue
    elif state == "mappings":
        try:
            # Parse memory mapping lines
            *nums, perms, file = re.match(r'\s*(0x[0-9a-f]+)' * 4 + r'\s*([rwxp-]+)\s*(.*)', line).groups()
            start, end, size, offset = map(unhex, nums)
        except AttributeError:
            if line.strip() and "rax" in line:  # Start of register section
                state = "regs"
            continue
        else:
            mappings.append((start, end, size, offset, perms, file))
    
    if state == "regs":
        try:
            # Parse register value lines
            name, hexval, *rest = re.match(r'(\w+)\s+(0x[0-9a-f]+)\s+(.*)', line).groups()
            val = unhex(hexval)
            regs[name] = val
        except (AttributeError, ValueError):
            continue

# Dump memory regions to files
for start, end, size, offset, perms, file in mappings:
    print(hex(start), hex(end), hex(size), hex(offset), file)
    gdbin(
        ' '.join(
            [
                'dump binary memory',
                str(outdir / f'dump_{start:x}_{end:x}.bin'),
                hex(start),
                hex(end),
            ]
        )
    )
    print(' ', 'wrote', str(outdir / f'dump_{start:x}_{end:x}.bin'))

# Save memory mapping and register information
(outdir / 'dump_data.json').write_text(
    (json.dumps(dict(mappings=mappings, regs=regs), indent=2))
)

# Extract symbol information using nm
nm = subprocess.check_output(
    [*'nm --ifunc-chars=ij -C -n -f sysv'.split(), library], text=True
).splitlines()

# Setup YAML dumper for ELF information
dumper = yaml.YAML()
dumper.representer.add_multi_representer(
    Mapping,
    lambda self, data: Representer.represent_dict(self, data.__dict__),
)

# Parse ELF binary information
fp = library.open('rb')  # leaving open on purpose
elf = ELFFile(fp)

# Extract symbol table
symtab = elf.get_section_by_name('.symtab')
symtable = {
    sym.name: dict(addr=HexInt(sym.entry.st_value), entry=sym.entry)
    for sym in symtab.iter_symbols()
    if sym.entry.st_value
}

# Extract segments and sections
segments = [dict(header=seg.header) for seg in elf.iter_segments()]
sections = {
    sec.name: dict(addr=HexInt(sec.header.sh_addr), header=sec.header)
    for sec in elf.iter_sections()
}

# Extract relocations
relocations = []
for sec in elf.iter_sections('SHT_RELA'):
    for entry in sec.iter_relocations():
        relocations.append(
            dict(
                addr=HexInt(entry['r_offset']),
                dest=HexInt(entry['r_addend']),
                entry=entry.entry,
            )
        )

# Combine all ELF information
elf_info = dict(
    segments=segments, sections=sections, relocations=relocations, symtable=symtable
)

# Save ELF information
with (outdir / 'elf_info.yaml').open('w') as fp:
    dumper.dump(elf_info, stream=fp)