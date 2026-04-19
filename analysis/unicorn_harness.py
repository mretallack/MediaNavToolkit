"""Unicorn Engine harness for emulating nngine.dll x86-32 functions.

Loads the PE as a raw blob, maps sections, applies relocations,
and calls functions by setting up stack + arguments.
"""

import struct
import sys
import pefile
from unicorn import *
from unicorn.x86_const import *

DLL_PATH = "analysis/extracted/nngine.dll"

# Memory layout
IMAGE_BASE = 0x10000000
STACK_BASE = 0x00100000
STACK_SIZE = 0x00100000  # 1MB stack
HEAP_BASE  = 0x00400000
HEAP_SIZE  = 0x00100000  # 1MB heap
# Sentinel address — when EIP hits this, emulation stops (acts as return address)
STOP_ADDR  = 0x00DEAD00

# SnakeOil RVA and calling convention:
#   void __cdecl SnakeOil(uint8_t* src, int len, uint8_t* dst, uint32_t key_lo, uint32_t key_hi)
SNAKEOIL_RVA = 0x1B3E10


def load_dll(uc: Uc, path: str) -> int:
    """Parse PE, map sections into Unicorn memory, apply relocations. Returns image base."""
    pe = pefile.PE(path)
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    # Align to 4K page
    image_size = (image_size + 0xFFF) & ~0xFFF

    uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)

    # Write PE headers
    uc.mem_write(IMAGE_BASE, pe.header[:pe.OPTIONAL_HEADER.SizeOfHeaders])

    # Map sections
    for section in pe.sections:
        va = IMAGE_BASE + section.VirtualAddress
        data = section.get_data()
        if data:
            uc.mem_write(va, data)

    # Apply base relocations
    delta = IMAGE_BASE - pe.OPTIONAL_HEADER.ImageBase
    if delta != 0 and hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc.entries:
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    addr = IMAGE_BASE + entry.rva
                    val = struct.unpack('<I', uc.mem_read(addr, 4))[0]
                    uc.mem_write(addr, struct.pack('<I', (val + delta) & 0xFFFFFFFF))

    return IMAGE_BASE


def setup_stack(uc: Uc):
    """Map stack memory, set ESP to top."""
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    esp = STACK_BASE + STACK_SIZE - 0x100  # leave headroom
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp)
    return esp


def setup_heap(uc: Uc):
    """Map heap memory for data buffers."""
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)


def call_snakeoil(uc: Uc, src_data: bytes, key_lo: int, key_hi: int) -> bytes:
    """Emulate SnakeOil(src, len, dst, key_lo, key_hi) and return dst."""
    length = len(src_data)

    # Write src data to heap
    src_addr = HEAP_BASE
    dst_addr = HEAP_BASE + 0x10000
    uc.mem_write(src_addr, src_data)
    uc.mem_write(dst_addr, b'\x00' * length)

    # Set up stack: push args right-to-left (cdecl), then return address
    esp = STACK_BASE + STACK_SIZE - 0x100
    # Stack layout: [ret_addr] [src] [len] [dst] [key_lo] [key_hi]
    stack = struct.pack('<IIIIII', STOP_ADDR, src_addr, length, dst_addr, key_lo, key_hi)
    uc.mem_write(esp, stack)
    uc.reg_write(UC_X86_REG_ESP, esp)

    # Run from SnakeOil entry
    entry = IMAGE_BASE + SNAKEOIL_RVA
    try:
        uc.emu_start(entry, STOP_ADDR, timeout=10_000_000)  # 10s timeout
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f"Emulation error at EIP=0x{eip:08X}: {e}")
        raise

    return bytes(uc.mem_read(dst_addr, length))


def main():
    print("=== Unicorn Engine nngine.dll Harness ===\n")

    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # Map the sentinel page so EIP can land there
    uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)

    print("[1] Loading PE sections and applying relocations...")
    base = load_dll(uc, DLL_PATH)
    print(f"    DLL loaded at 0x{base:08X}")

    print("[2] Setting up stack and heap...")
    setup_stack(uc)
    setup_heap(uc)

    # Test 1: SnakeOil with zeros and tb_secret
    print("\n[3] Test: SnakeOil(zeros, tb_secret)")
    tb_secret = 3037636188661496
    key_lo = tb_secret & 0xFFFFFFFF         # 0xC9FB66F8
    key_hi = (tb_secret >> 32) & 0xFFFFFFFF  # 0x000ACAB6

    result = call_snakeoil(uc, bytes(8), key_lo, key_hi)
    expected = bytes.fromhex("bc755fbc32341970")
    print(f"    Result:   {result.hex()}")
    print(f"    Expected: {expected.hex()}")
    print(f"    Match: {result == expected}")

    if result != expected:
        print("\n*** SnakeOil validation FAILED — harness is broken ***")
        sys.exit(1)

    # Test 2: Decrypt 735 body (0x60 flow)
    print("\n[4] Test: Decrypt flow 735 body (0x60, tb_secret)")
    raw = open("analysis/flows_decoded/2026-04-16/735-senddevicestatus-req.bin", "rb").read()
    body = raw[18:]  # 0x60 body starts at offset 18
    decrypted = call_snakeoil(uc, body, key_lo, key_hi)
    if b"DaciaAutomotive" in decrypted:
        idx = decrypted.index(b"DaciaAutomotive")
        print(f"    ✓ DaciaAutomotive found at offset {idx}")
        print(f"    First 40 bytes: {decrypted[:40].hex()}")
    else:
        print(f"    ✗ DaciaAutomotive NOT found")
        print(f"    First 40 bytes: {decrypted[:40].hex()}")

    print("\n=== Harness validated ===")


if __name__ == "__main__":
    main()
