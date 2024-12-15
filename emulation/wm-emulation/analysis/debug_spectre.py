#!/usr/bin/env python3
import sys
from pathlib import Path
import pexpect
import json
import re

def analyze_spectre():
    gdb = pexpect.spawn('gdb', ['-q', './input/spectre'])
    outdir = Path('analysis_output')
    outdir.mkdir(exist_ok=True)

    def gdbin(gdb, cmd):
        gdb.sendline(cmd)
        gdb.expect([r'\(gdb\)', '<RET> for more'])
        output = gdb.before.decode()
        # Clean ANSI escape codes
        output = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', output)
        return output

    def parse_registers(reg_output):
        registers = {}
        for line in reg_output.split('\n'):
            if match := re.match(r'(\w+)\s+(0x[0-9a-f]+)\s+(\d+)', line):
                reg, value_hex, value_dec = match.groups()
                registers[reg] = int(value_hex, 16)
        return registers

    # Set breakpoints
    print("Setting breakpoints")
    gdbin('b gate_function')
    gdbin('b run_gate')
    
    # Start execution
    print("Starting execution")
    gdbin('r')
    
    # Collect state
    print("Collecting state")
    info = {
        'registers': gdbin('info registers'),
        'memory_map': gdbin('info proc mapping'),
        'arrays': {
            'array1': gdbin('x/16bx &array1'),
            'array2': gdbin('x/16bx &array2'),
            'array_tmp': gdbin('x/16bx &array_tmp')
        }
    }
    
    # Save analysis results
    print("Saving analysis results in json")
    with open(outdir / 'analysis.json', 'w') as f:
        json.dump(info, f, indent=2)

    gdb.sendeof()

if __name__ == '__main__':
    print("Starting analysis")
    analyze_spectre()