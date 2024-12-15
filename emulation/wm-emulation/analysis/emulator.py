from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import pickle

X86_CODE32 = b"\x41\x4a\x66\x0f\xef\xc1" # INC ecx; DEC edx; PXOR xmm0, xmm1
X86_CODE32_LOOP = b"\x41\x4a\xeb\xfe" # INC ecx; DEC edx; JMP self-loop
X86_CODE32_JUMP = b"\xeb\x02\x90\x90\x90\x90\x90\x90" # jmp 4; nop; nop; nop; nop; nop; nop
X86_CODE32_JMP_INVALID = b"\xe9\xe9\xee\xee\xee\x41\x4a" # JMP outside; INC ecx; DEC edx
X86_CODE32_MEM_READ = b"\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
X86_CODE32_MEM_WRITE = b"\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
X86_CODE64 = b"\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
X86_CODE32_INOUT = b"\x41\xE4\x3F\x4a\xE6\x46\x43" # INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
X86_CODE64_SYSCALL = b'\x0f\x05' # SYSCALL
X86_CODE16 = b'\x00\x00' # add   byte ptr [bx + si], al
X86_MMIO_CODE = b"\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00" # mov [0x20004], ecx; mov ecx, [0x20004]

# memory address where emulation starts
ADDRESS = 0x1000000

def test_x86_64():
    print("Emulate x86_64 code")
    try:
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_RAX, 0x71f3029efd49d41d)
        mu.reg_write(UC_X86_REG_RBX, 0xd87b45277f133ddb)
        mu.reg_write(UC_X86_REG_RCX, 0xab40d1ffd8afc461)
        mu.reg_write(UC_X86_REG_RDX, 0x919317b4a733f01)
        mu.reg_write(UC_X86_REG_RSI, 0x4c24e753a17ea358)
        mu.reg_write(UC_X86_REG_RDI, 0xe509a57d2571ce96)
        mu.reg_write(UC_X86_REG_R8, 0xea5b108cc2b9ab1f)
        mu.reg_write(UC_X86_REG_R9, 0x19ec097c8eb618c1)
        mu.reg_write(UC_X86_REG_R10, 0xec45774f00c5f682)
        mu.reg_write(UC_X86_REG_R11, 0xe17e9dbec8c074aa)
        mu.reg_write(UC_X86_REG_R12, 0x80f86a8dc0f6d457)
        mu.reg_write(UC_X86_REG_R13, 0x48288ca5671c5492)
        mu.reg_write(UC_X86_REG_R14, 0x595f72f6e4017f6e)
        mu.reg_write(UC_X86_REG_R15, 0x1efd97aea331cccc)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions in range [ADDRESS, ADDRESS+20]
        # mu.hook_add(UC_HOOK_CODE, hook_code64, None, ADDRESS, ADDRESS+20)

        # tracing all memory READ & WRITE access
        # mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
        # mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        # actually you can also use READ_WRITE to trace all memory access
        #mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        rax = mu.reg_read(UC_X86_REG_RAX)
        rbx = mu.reg_read(UC_X86_REG_RBX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        r8 = mu.reg_read(UC_X86_REG_R8)
        r9 = mu.reg_read(UC_X86_REG_R9)
        r10 = mu.reg_read(UC_X86_REG_R10)
        r11 = mu.reg_read(UC_X86_REG_R11)
        r12 = mu.reg_read(UC_X86_REG_R12)
        r13 = mu.reg_read(UC_X86_REG_R13)
        r14 = mu.reg_read(UC_X86_REG_R14)
        r15 = mu.reg_read(UC_X86_REG_R15)

        print(">>> RAX = 0x%x" %rax)
        print(">>> RBX = 0x%x" %rbx)
        print(">>> RCX = 0x%x" %rcx)
        print(">>> RDX = 0x%x" %rdx)
        print(">>> RSI = 0x%x" %rsi)
        print(">>> RDI = 0x%x" %rdi)
        print(">>> R8 = 0x%x" %r8)
        print(">>> R9 = 0x%x" %r9)
        print(">>> R10 = 0x%x" %r10)
        print(">>> R11 = 0x%x" %r11)
        print(">>> R12 = 0x%x" %r12)
        print(">>> R13 = 0x%x" %r13)
        print(">>> R14 = 0x%x" %r14)
        print(">>> R15 = 0x%x" %r15)


    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_x86_64()