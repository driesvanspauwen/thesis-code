## <write_wr>
`401000: 85 ff                test   edi,edi`
- Performs bitwise AND on `edi` - common way to check if register is 0
- edi is argument of `write_wr(int value)`

`401002: 74 0c                je     401010 <write_wr.flush>`
- jumps to write_wr.flush (function that sets WR to 0) if argument is 0

`401004: c7 04 25 00 20 40 00 mov    DWORD PTR ds:0x402000,0x2a`
`40100b: 2a 00 00 00`
-  Stores value 0x2a (42 in decimal) to the memory address 0x402000
- DWORD PTR indicates a 4-byte (32-bit) value is being stored
- ds: specifies the data segment.

## <write_wr.flush>
`401010: 48 8d 04 25 00 20 40 lea    rax,ds:0x402000`
- Load Effective Address - calculates address 0x402000 and stores it in the rax register

`401018:	0f ae 38             	clflush BYTE PTR [rax]`
- Cache Line Flush - flushes the cache line containing the address in rax from all levels of the cache hierarchy

## <read_wr>
`40101c: 53                   push   rbx`
`40101d: 55                   push   rbp`
- Save the rbx and rbp registers on the stack. These are callee-saved registers

`40101e: 48 83 ec 08          sub    rsp,0x8`
- Subtract 8 from the stack pointer, allocating 8 bytes of stack space

`401022: 48 8d 3c 24          lea    rdi,[rsp]`
- Load the address of the top of the stack into rdi

`401026: 0f 01 f9             rdtscp`
- Read Time-Stamp Counter and Processor ID 
- Gets the current CPU timestamp and stores it in edx:eax (lower 32 bits in eax and upper 32 bits in ebx)
- Stores the CPU ID/signature in ecx

`401029: 89 c3                mov    ebx,eax`
- Copy the lower 32 bits of the timestamp from eax to ebx

`40102b: 8b 04 25 00 20 40 00 mov    eax,DWORD PTR ds:0x402000`
- Load the 4-byte value at memory address 0x402000 into eax

`401032: 48 8d 3c 24          lea    rdi,[rsp]`
- Load the address of the top of the stack into rdi again

`401036: 0f 01 f9             rdtscp`
- Get another timestamp

`401039: 29 d8                sub    eax,ebx`
- Subtract first timestamp (ebx) from second timestamp (eax), storing difference in eax

`40103b: 83 f8 63             cmp    eax,0x63`
- Compare timestamp difference (eax) with 0x63 (99 in decimal) - sets flag for conditional instructions

`40103e: 0f 96 c0             setbe  al`
- Set al to 1 if below or equal (the timestamp difference is ≤ 99), otherwise set to 0

`401041: 48 83 c4 08          add    rsp,0x8`
- Add 8 to the stack pointer, deallocating the stack space.

`401045: 5d                   pop    rbp`
`401046: 5b                   pop    rbx`
- Restore callee-saved registers from the stack.