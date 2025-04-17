import os
import subprocess
from unicorn import *
from unicorn.x86_const import *
from exception_emulator import ExceptionEmulator
import struct

def extract_nand_gate_code(binary_path):
    """Extract the NAND gate function code from the binary"""
    try:
        # Run objdump to get the disassembly
        result = subprocess.run(['objdump', '-d', binary_path], 
                                capture_output=True, text=True, check=True)
        
        # Look for the mangled name of nand_gate
        lines = result.stdout.split('\n')
        start_idx = None
        end_idx = None
        
        for i, line in enumerate(lines):
            if '_Z9nand_gatePhS_S_' in line and '<_Z9nand_gatePhS_S_>:' in line:
                start_idx = i
            elif start_idx is not None and '<' in line and '>:' in line:
                end_idx = i
                break
        
        if start_idx is None:
            print("NAND gate function not found")
            return None
        
        if end_idx is None:  # Function might be the last one
            end_idx = len(lines)
        
        # Extract the function code
        nand_gate_disasm = lines[start_idx:end_idx]
        print(f"Found NAND gate function (lines {start_idx}-{end_idx}):")
        
        # Extract the starting address and code
        if len(nand_gate_disasm) > 0:
            function_line = nand_gate_disasm[0]
            address_hex = function_line.split()[0].strip(':')
            start_address = int(address_hex, 16)
            
            code_bytes = bytearray()
            for line in nand_gate_disasm[1:]:  # Skip the function header
                parts = line.strip().split('\t')
                if len(parts) >= 3:
                    # Extract bytes from the middle column
                    byte_strings = parts[1].strip().split()
                    for byte_str in byte_strings:
                        if len(byte_str) == 2:  # Make sure it's a valid hex byte
                            code_bytes.append(int(byte_str, 16))
            
            return (start_address, bytes(code_bytes))
        
        return None
    
    except subprocess.CalledProcessError as e:
        print(f"Error extracting NAND gate code: {e}")
        return None

def run_nand_gate_in_emulator(binary_path, debug=True):
    """Run the NAND gate implementation in the extended Unicorn emulator"""
    # Extract the NAND gate function code
    result = extract_nand_gate_code(binary_path)
    if not result:
        print("Failed to extract NAND gate code")
        return
    
    start_address, code_bytes = result
    print(f"Extracted {len(code_bytes)} bytes of code starting at 0x{start_address:x}")
    
    # Create an instance of your ExceptionEmulator
    emulator = ExceptionEmulator("", "nand_gate_from_elf", debug)
    
    # Map the code into memory at the correct address
    # Making sure the address is page-aligned
    page_size = 0x1000
    code_addr = start_address & ~(page_size - 1)  # Align to page boundary
    
    # Make sure the memory region is mapped
    try:
        emulator.mu.mem_map(code_addr, page_size, UC_PROT_ALL)
    except UcError as e:
        if "map already exists" not in str(e):
            print(f"Error mapping memory: {e}")
            return
    
    # Write the code to memory
    offset = start_address - code_addr
    emulator.mu.mem_write(start_address, code_bytes)
    
    # Set up memory for inputs and outputs
    in1_addr = emulator.DATA_BASE
    in2_addr = emulator.DATA_BASE + 0x1000
    out_addr = emulator.DATA_BASE + 0x2000
    tmp1_addr = emulator.DATA_BASE + 0x3000
    tmp2_addr = emulator.DATA_BASE + 0x4000
    tmp3_addr = emulator.DATA_BASE + 0x5000
    tmp4_addr = emulator.DATA_BASE + 0x6000
    
    # Initialize memory
    emulator.mu.mem_write(in1_addr, b'\x00')
    emulator.mu.mem_write(in2_addr, b'\x00')
    emulator.mu.mem_write(out_addr, b'\x00')
    emulator.mu.mem_write(tmp1_addr, b'\x00')
    emulator.mu.mem_write(tmp2_addr, b'\x00')
    emulator.mu.mem_write(tmp3_addr, b'\x00')
    emulator.mu.mem_write(tmp4_addr, b'\x00')
    
    # Test with various input combinations
    results = []
    for in1_val in range(2):
        for in2_val in range(2):
            print(f"\nTesting NAND({in1_val}, {in2_val}):")
            
            # Set input values in cache
            if in1_val:
                emulator.cache.write(in1_addr, b'\x00')  # Set to cached
            else:
                emulator.mu.mem_write(in1_addr, b'\x00')  # Not cached
                
            if in2_val:
                emulator.cache.write(in2_addr, b'\x00')  # Set to cached
            else:
                emulator.mu.mem_write(in2_addr, b'\x00')  # Not cached
            
            # Make sure output is not cached
            emulator.mu.mem_write(out_addr, b'\x00')
            
            # Set up registers to pass arguments (x86-64 calling convention)
            emulator.mu.reg_write(UC_X86_REG_RDI, in1_addr)    # First argument (in1)
            emulator.mu.reg_write(UC_X86_REG_RSI, in2_addr)    # Second argument (in2)
            emulator.mu.reg_write(UC_X86_REG_RDX, out_addr)    # Third argument (out)
            
            # Run the function
            try:
                emulator.emulate()
            except Exception as e:
                print(f"Emulation error: {e}")
            
            # Check result
            result = emulator.cache.is_cached(out_addr)
            expected = not (in1_val and in2_val)
            
            results.append((in1_val, in2_val, result, expected))
            
            print(f"  NAND({in1_val}, {in2_val}) = {result}, Expected: {expected}")
    
    # Print summary
    print("\nNAND Gate Test Results:")
    print("----------------------")
    for in1_val, in2_val, result, expected in results:
        status = "✓" if result == expected else "✗"
        print(f"NAND({in1_val}, {in2_val}) = {result}, Expected: {expected} {status}")
    
    return results

if __name__ == "__main__":
    # Run the NAND gate ELF in the emulator
    run_nand_gate_in_emulator("nand_test.elf")