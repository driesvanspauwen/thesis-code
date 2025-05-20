def simulate_div_sequence():
   # Initialize registers with the values from the assembly
   rcx = 0x3a99
   rax = 0x54d3
   rdx = 0x1c98
   
   print(f"Initial values:")
   print(f"rcx = 0x{rcx:04x} ({rcx})")
   print(f"rax = 0x{rax:04x} ({rax})")
   print(f"rdx = 0x{rdx:04x} ({rdx})")
   print("\nExecuting division operations...")
   
   # The div instruction on x86 divides the composite dx:ax register by cx
   # For 16-bit div cx, it divides the 32-bit value in dx:ax by cx
   # Results: quotient in ax, remainder in dx
   
   for i in range(5):
       # Combine dx:ax to form the dividend
       dividend = (rdx << 16) | (rax & 0xFFFF)
       
       # Perform division
       quotient = dividend // rcx
       remainder = dividend % rcx
       
       # Update registers (truncate to 16 bits)
       rax = quotient & 0xFFFF
       rdx = remainder & 0xFFFF
       
       print(f"\nDivision {i+1}:")
       print(f"Dividend (dx:ax) = 0x{dividend:08x} ({dividend})")
       print(f"Divisor (cx) = 0x{rcx:04x} ({rcx})")
       print(f"Quotient (ax) = 0x{rax:04x} ({rax})")
       print(f"Remainder (dx) = 0x{rdx:04x} ({rdx})")
   
   print("\nFinal value that will be added to [rsp]:")
   print(f"rdx = 0x{rdx:04x} ({rdx})")
   
   # For completeness, also show the full 64-bit value of rdx 
   # (the upper bits are not affected by the 16-bit division)
   rdx_full = rdx & 0xFFFF  # Only the lower 16 bits are changed
   print(f"Full 64-bit rdx = 0x{rdx_full:016x}")
   
   return rdx

if __name__ == "__main__":
   final_rdx = simulate_div_sequence()
   print("\nSummary:")
   print(f"This code will add {final_rdx} (0x{final_rdx:x}) to the return address on the stack.")
   print(f"If the original return address was 0x2d02, the new return address will be 0x{0x2d02 + final_rdx:x}.")