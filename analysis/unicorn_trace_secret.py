"""Unicorn harness to trace Secret₃ by emulating FUN_100b3a60 (protocol builder).

Strategy: Hook the vtable call at RVA 0x0B3A76 that returns the credential object.
Instead of emulating the full credential construction, provide a fake credential object
with known values and trace what the function reads from it.

Then: hook SnakeOil at RVA 0x1B3E10 to capture the actual key used for encryption.
"""

import struct
import sys
import pefile
from unicorn import *
from unicorn.x86_const import *

DLL_PATH = "analysis/extracted/nngine.dll"
IMAGE_BASE = 0x10000000
STACK_BASE = 0x00100000
STACK_SIZE = 0x00100000
HEAP_BASE  = 0x00400000
HEAP_SIZE  = 0x00200000
STOP_ADDR  = 0x00DEAD00

# Addresses for fake objects
FAKE_CRED    = HEAP_BASE + 0x50000  # Fake credential object
FAKE_THIS    = HEAP_BASE + 0x60000  # Fake 'this' (param_1)
FAKE_PARAM2  = HEAP_BASE + 0x70000  # Fake param_2 (piVar8)
FAKE_PARAM3  = HEAP_BASE + 0x80000  # Fake param_3 (request struct)
FAKE_VTABLE  = HEAP_BASE + 0x90000  # Fake vtable
FAKE_CREDPROV = HEAP_BASE + 0xA0000 # Fake credential provider
FAKE_CREDPROV_VT = HEAP_BASE + 0xA1000
STUB_RET     = HEAP_BASE + 0xB0000  # Stub function that just returns

# Key RVAs
FUN_PROTOCOL_BUILDER = 0x0B3A60
VTABLE_CALL_ADDR = IMAGE_BASE + 0x0B3A76  # call [eax + 0x18]
SNAKEOIL_ADDR = IMAGE_BASE + 0x1B3E10
MALLOC_ADDR = IMAGE_BASE + 0x27E4F5  # FUN_1027e4f5 (malloc wrapper)

# Known values
TB_CODE = 3745651132643726
TB_SECRET = 3037636188661496
HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954


def load_dll(uc):
    pe = pefile.PE(DLL_PATH)
    image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
    uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
    uc.mem_write(IMAGE_BASE, pe.header[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    for section in pe.sections:
        va = IMAGE_BASE + section.VirtualAddress
        data = section.get_data()
        if data:
            uc.mem_write(va, data)


class HeapAllocator:
    def __init__(self, base, size):
        self.base = base
        self.ptr = base
        self.end = base + size

    def alloc(self, size):
        # Align to 8
        size = (size + 7) & ~7
        if self.ptr + size > self.end:
            raise MemoryError("Heap exhausted")
        addr = self.ptr
        self.ptr += size
        return addr


def main():
    print("=== Unicorn: Trace Secret₃ via protocol builder ===\n")

    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map memory regions
    uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)

    print("[1] Loading DLL...")
    load_dll(uc)

    heap = HeapAllocator(HEAP_BASE + 0xC0000, 0x40000)

    # Write a stub "ret" instruction at STUB_RET
    uc.mem_write(STUB_RET, b'\xC3')  # ret

    # Also write a "ret" that returns FAKE_CRED in eax
    STUB_RET_CRED = STUB_RET + 0x10
    # mov eax, FAKE_CRED; ret
    uc.mem_write(STUB_RET_CRED, b'\xB8' + struct.pack('<I', FAKE_CRED) + b'\xC3')

    # --- Set up fake credential object ---
    # Layout: +0x00=name_ptr, +0x10=Code_lo, +0x14=Code_hi, +0x18=???, +0x1C=Secret_lo, +0x20=Secret_hi
    # Fill with sentinel values so we can see what gets read
    SENTINEL_SECRET_LO = 0xDEADBEEF
    SENTINEL_SECRET_HI = 0xCAFEBABE
    SENTINEL_CODE_LO = TB_CODE & 0xFFFFFFFF
    SENTINEL_CODE_HI = (TB_CODE >> 32) & 0xFFFFFFFF

    cred_data = bytearray(0x30)
    # +0x10: Code
    struct.pack_into('<II', cred_data, 0x10, SENTINEL_CODE_LO, SENTINEL_CODE_HI)
    # +0x18: unknown field
    struct.pack_into('<I', cred_data, 0x18, 0x11111111)
    # +0x1C: Secret
    struct.pack_into('<II', cred_data, 0x1C, SENTINEL_SECRET_LO, SENTINEL_SECRET_HI)
    uc.mem_write(FAKE_CRED, bytes(cred_data))

    # --- Set up fake credential provider ---
    # this->field_0x1c = credential provider object
    # cred_provider->vtable[0] = vtable pointer
    # vtable[6] (+0x18) = function that returns credential object
    cred_prov_vt = bytearray(0x20)
    struct.pack_into('<I', cred_prov_vt, 0x18, STUB_RET_CRED)  # vtable[6] = return FAKE_CRED
    uc.mem_write(FAKE_CREDPROV_VT, bytes(cred_prov_vt))

    cred_prov = struct.pack('<I', FAKE_CREDPROV_VT)  # vtable pointer
    uc.mem_write(FAKE_CREDPROV, cred_prov)

    # --- Set up fake 'this' object (param_1 in thiscall) ---
    this_data = bytearray(0x90)
    struct.pack_into('<I', this_data, 0x1C, FAKE_CREDPROV)  # this->field_0x1c = cred provider
    # this->field_0x18 also needs a valid object for the error path
    struct.pack_into('<I', this_data, 0x18, FAKE_CREDPROV)
    # this->field_0x68 — used by FUN_101b41b0 (binary search array)
    fake_array = heap.alloc(0x20)
    uc.mem_write(fake_array, b'\x00' * 0x20)
    struct.pack_into('<I', this_data, 0x68, fake_array)
    # this->field_0x7c — used by FUN_101b41b0
    struct.pack_into('<I', this_data, 0x7C, 0)
    # this->field_0x80 needs a valid object too
    fake_obj80 = heap.alloc(0x20)
    fake_obj80_vt = heap.alloc(0x40)
    # vtable methods at +0x1c and +0x18 need to return non-zero (true)
    STUB_RET_1 = STUB_RET + 0x20
    uc.mem_write(STUB_RET_1, b'\xB8\x01\x00\x00\x00\xC3')  # mov eax, 1; ret
    for i in range(0, 0x40, 4):
        struct.pack_into('<I', bytearray(4), 0, STUB_RET_1)
        uc.mem_write(fake_obj80_vt + i, struct.pack('<I', STUB_RET_1))
    uc.mem_write(fake_obj80, struct.pack('<I', fake_obj80_vt))
    struct.pack_into('<I', this_data, 0x80, fake_obj80)
    uc.mem_write(FAKE_THIS, bytes(this_data))

    # --- Set up fake param_2 (piVar8) ---
    param2_data = bytearray(0x100)
    # param_2[0xf] (offset 0x3C) should NOT be 3 (to avoid error path)
    struct.pack_into('<I', param2_data, 0x3C, 0)
    # param_2[0x10] (offset 0x40) — flags byte
    param2_data[0x40] = 0
    # param_2 needs a vtable at [0] for various calls
    fake_p2_vt = heap.alloc(0x40)
    for i in range(0, 0x40, 4):
        uc.mem_write(fake_p2_vt + i, struct.pack('<I', STUB_RET))
    struct.pack_into('<I', param2_data, 0, fake_p2_vt)
    # param_2[0x48] (byte) — checked at 0x0B3B65
    param2_data[0x48] = 0
    uc.mem_write(FAKE_PARAM2, bytes(param2_data))

    # --- Set up fake param_3 (request struct) ---
    param3_data = bytearray(0x50)
    uc.mem_write(FAKE_PARAM3, bytes(param3_data))

    # --- Hook SnakeOil to capture the key ---
    snakeoil_calls = []

    def hook_snakeoil(uc, address, size, user_data):
        if address == SNAKEOIL_ADDR:
            esp = uc.reg_read(UC_X86_REG_ESP)
            # cdecl: [ret_addr] [src] [len] [dst] [key_lo] [key_hi]
            args = struct.unpack('<IIIIII', bytes(uc.mem_read(esp, 24)))
            ret_addr, src, length, dst, key_lo, key_hi = args
            seed = (key_hi << 32) | key_lo
            print(f"  SnakeOil called: src=0x{src:08X} len={length} dst=0x{dst:08X} key=0x{key_hi:08X}{key_lo:08X} ({seed})")
            snakeoil_calls.append((key_lo, key_hi, seed))

            if key_lo == SENTINEL_SECRET_LO and key_hi == SENTINEL_SECRET_HI:
                print("  >>> KEY IS SENTINEL SECRET — confirms Secret₃ is read from cred+0x1C/0x20")
            elif key_lo == SENTINEL_CODE_LO and key_hi == SENTINEL_CODE_HI:
                print("  >>> KEY IS CODE — query/body both use Code, not Secret!")

    uc.hook_add(UC_HOOK_CODE, hook_snakeoil, begin=SNAKEOIL_ADDR, end=SNAKEOIL_ADDR+1)

    # --- Hook malloc (FUN_1027e4f5) to return heap memory ---
    def hook_malloc(uc, address, size, user_data):
        if address == MALLOC_ADDR:
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr, alloc_size = struct.unpack('<II', bytes(uc.mem_read(esp, 8)))
            addr = heap.alloc(alloc_size)
            # Set eax = allocated address, then skip to ret
            uc.reg_write(UC_X86_REG_EAX, addr)
            uc.reg_write(UC_X86_REG_ESP, esp + 4)  # pop return address
            uc.reg_write(UC_X86_REG_EIP, ret_addr)  # jump to return address

    uc.hook_add(UC_HOOK_CODE, hook_malloc, begin=MALLOC_ADDR, end=MALLOC_ADDR+1)

    # --- Hook various functions that we need to stub ---
    stubs_hit = {}
    unmapped_reads = []

    def hook_generic_stub(uc, address, size, user_data):
        rva = address - IMAGE_BASE
        # List of functions to stub (return 0 or do nothing)
        stub_rvas = {
            0x1A9930,  # FUN_101a9930 — envelope serializer
            0x091DA0,  # FUN_10091da0
            0x1B8130,  # FUN_101b8130 — log cleanup
            0x091BF0,  # FUN_10091bf0 — envelope writer
            0x1B74E0,  # FUN_101b74e0 — sprintf/log
            0x1BAE20,  # FUN_101bae20 — log section
            0x1B8170,  # FUN_101b8170 — log end
            0x0B4600,  # FUN_100b4600 — debug dump
            0x0B4AD0,  # FUN_100b4ad0 — cleanup
            0x1BD8D0,  # FUN_101bd8d0
            0x1BD970,  # FUN_101bd970
            0x1BABB0,  # FUN_101babb0
            0x1B87C0,  # FUN_101b87c0
            0x27FA10,  # FUN_1027fa10 — memcpy
            0x1BAA50,  # FUN_101baa50
            0x1BDF30,  # FUN_101bdf30 — returns bool
            0x0935C0,  # FUN_100935c0
            0x0921D0,  # FUN_100921d0
            0x1B41B0,  # FUN_101b41b0 — binary search (needs array)
            0x1B45A0,  # FUN_101b45a0 — comparison
            0x1D2630,  # FUN_101d2630 — timestamp
            0x0312A0,  # FUN_100312a0
            0x056A10,  # FUN_10056a10
            0x0B4250,  # FUN_100b4250 — destructor
        }
        if rva in stub_rvas:
            if rva not in stubs_hit:
                stubs_hit[rva] = 0
            stubs_hit[rva] += 1
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
            uc.reg_write(UC_X86_REG_EAX, 0)
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            uc.reg_write(UC_X86_REG_EIP, ret_addr)

    # Add hooks for all stub functions
    for rva in [0x1A9930, 0x091DA0, 0x1B8130, 0x091BF0, 0x1B74E0, 0x1BAE20,
                0x1B8170, 0x0B4600, 0x0B4AD0, 0x1BD8D0, 0x1BD970, 0x1BABB0,
                0x1B87C0, 0x27FA10, 0x1BAA50, 0x1BDF30, 0x0935C0, 0x0921D0,
                0x1B41B0, 0x1B45A0, 0x1D2630, 0x0312A0, 0x056A10, 0x0B4250]:
        addr = IMAGE_BASE + rva
        uc.hook_add(UC_HOOK_CODE, hook_generic_stub, begin=addr, end=addr+1)

    # --- Hook __time64 ---
    TIME64_ADDR = IMAGE_BASE + 0x287E4D
    def hook_time64(uc, address, size, user_data):
        if address == TIME64_ADDR:
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
            # Return a fake timestamp in edx:eax
            uc.reg_write(UC_X86_REG_EAX, 0x12345678)
            uc.reg_write(UC_X86_REG_EDX, 0x00000060)
            uc.reg_write(UC_X86_REG_ESP, esp + 8)  # pop ret + 1 arg
            uc.reg_write(UC_X86_REG_EIP, ret_addr)

    uc.hook_add(UC_HOOK_CODE, hook_time64, begin=TIME64_ADDR, end=TIME64_ADDR+1)

    # --- Track memory reads from credential object ---
    def hook_mem_read(uc, access, address, size, value, user_data):
        if FAKE_CRED <= address < FAKE_CRED + 0x30:
            offset = address - FAKE_CRED
            data = bytes(uc.mem_read(address, size))
            val = int.from_bytes(data, 'little')
            print(f"  [MEM READ] cred+0x{offset:02X} ({size}B) = 0x{val:0{size*2}X}")

    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read, begin=FAKE_CRED, end=FAKE_CRED + 0x30)

    # --- Handle unmapped memory reads by mapping on demand ---
    def hook_unmapped(uc, access, address, size, value, user_data):
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            uc.mem_write(page, b'\x00' * 0x1000)
            unmapped_reads.append(address)
            if len(unmapped_reads) <= 20:
                eip = uc.reg_read(UC_X86_REG_EIP)
                print(f"  [UNMAPPED] 0x{address:08X} (EIP=0x{eip:08X} RVA 0x{eip-IMAGE_BASE:08X})")
            return True
        except:
            return False

    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped)

    # --- Run the function ---
    print("\n[2] Setting up thiscall: FUN_100b3a60(this, param2, param3, param4)")

    # thiscall: ecx = this, stack = [ret_addr, param2, param3, param4]
    esp = STACK_BASE + STACK_SIZE - 0x200
    stack = struct.pack('<IIII', STOP_ADDR, FAKE_PARAM2, FAKE_PARAM3, 0)
    uc.mem_write(esp, stack)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x100)
    uc.reg_write(UC_X86_REG_ECX, FAKE_THIS)

    entry = IMAGE_BASE + FUN_PROTOCOL_BUILDER
    print(f"    Entry: 0x{entry:08X}")
    print(f"    this=0x{FAKE_THIS:08X} param2=0x{FAKE_PARAM2:08X} param3=0x{FAKE_PARAM3:08X}")
    print(f"    Sentinel Secret: 0x{SENTINEL_SECRET_HI:08X}{SENTINEL_SECRET_LO:08X}")
    print(f"    Sentinel Code:   0x{SENTINEL_CODE_HI:08X}{SENTINEL_CODE_LO:08X}")

    print("\n[3] Running emulation...")
    try:
        uc.emu_start(entry, STOP_ADDR, timeout=30_000_000, count=500000)
        print("\n[4] Emulation completed normally")
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f"\n[4] Emulation stopped at EIP=0x{eip:08X} (RVA 0x{eip-IMAGE_BASE:08X}): {e}")

    print(f"\n[5] Results:")
    print(f"    SnakeOil calls: {len(snakeoil_calls)}")
    for i, (lo, hi, seed) in enumerate(snakeoil_calls):
        print(f"      [{i}] key=0x{hi:08X}{lo:08X} ({seed})")
    print(f"    Stubs hit: {dict(sorted(stubs_hit.items()))}")


if __name__ == "__main__":
    main()
