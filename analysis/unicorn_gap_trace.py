"""Unicorn: Trace gap area reads by emulating FUN_101b5a60 (SET reader).

Instead of the full reader (too complex), we set up a fake file stream
pointing to the decrypted FBL data and call the section-level reader
FUN_10109a90 on the gap area to see what fields it reads.

Actually, simpler approach: the gap area is read by the code AFTER the
SET header is parsed. Let me find what reads the gap by searching for
functions that take a stream + offset and read structured data.

Simplest approach: just read the gap header field by field using
FUN_100557f0 (read_u32) and FUN_10109c80 (read_u16) via Unicorn,
and annotate each read.
"""
import struct
import sys
from pathlib import Path
from unicorn import *
from unicorn.x86_const import *
import pefile

DLL_PATH = "analysis/extracted/nngine.dll"
XOR_TABLE_PATH = "analysis/xor_table_normal.bin"

IMAGE_BASE = 0x10000000
STACK_BASE = 0x00100000
STACK_SIZE = 0x00100000
HEAP_BASE  = 0x00400000
HEAP_SIZE  = 0x00800000
STOP_ADDR  = 0x00DEAD00

heap_ptr = HEAP_BASE + 0x200000

def load_dll(uc, path):
    pe = pefile.PE(path)
    image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
    uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
    uc.mem_write(IMAGE_BASE, pe.header[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    for section in pe.sections:
        va = IMAGE_BASE + section.VirtualAddress
        data = section.get_data()
        if data:
            uc.mem_write(va, data)
    delta = IMAGE_BASE - pe.OPTIONAL_HEADER.ImageBase
    if delta != 0 and hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc.entries:
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    addr = IMAGE_BASE + entry.rva
                    val = struct.unpack('<I', uc.mem_read(addr, 4))[0]
                    uc.mem_write(addr, struct.pack('<I', (val + delta) & 0xFFFFFFFF))


def decrypt_fbl(fbl_path):
    xor_table = Path(XOR_TABLE_PATH).read_bytes()
    data = Path(fbl_path).read_bytes()
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def make_stream(uc, stream_addr, data_addr, data_start, data_end, big_endian=False):
    """Create a stream object at stream_addr pointing to data."""
    stream = bytearray(0x40)
    struct.pack_into('<I', stream, 0x04, data_addr + data_start)  # current ptr
    struct.pack_into('<I', stream, 0x10, data_addr + data_end)    # end ptr
    struct.pack_into('<I', stream, 0x14, 1 if big_endian else 0)  # byte-swap flag
    struct.pack_into('<I', stream, 0x1c, 0)                       # no error
    uc.mem_write(stream_addr, bytes(stream))


def call_read_u32(uc, stream_addr, result_addr):
    """Call FUN_100557f0(stream, &result) -> reads one uint32."""
    esp = STACK_BASE + STACK_SIZE - 0x2000
    uc.reg_write(UC_X86_REG_ECX, stream_addr)
    stack = struct.pack('<II', STOP_ADDR, result_addr)
    uc.mem_write(esp, stack)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x100)
    uc.emu_start(IMAGE_BASE + 0x557f0, STOP_ADDR, timeout=1_000_000)
    return struct.unpack('<I', bytes(uc.mem_read(result_addr, 4)))[0]


def call_read_u16(uc, stream_addr, result_addr):
    """Call FUN_10109c80(stream, &result) -> reads one uint16."""
    esp = STACK_BASE + STACK_SIZE - 0x2000
    uc.reg_write(UC_X86_REG_ECX, stream_addr)
    stack = struct.pack('<II', STOP_ADDR, result_addr)
    uc.mem_write(esp, stack)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x100)
    uc.emu_start(IMAGE_BASE + 0x109c80, STOP_ADDR, timeout=1_000_000)
    return struct.unpack('<H', bytes(uc.mem_read(result_addr, 2)))[0]


def get_stream_pos(uc, stream_addr, data_addr):
    """Get current file offset from stream."""
    ptr = struct.unpack('<I', bytes(uc.mem_read(stream_addr + 4, 4)))[0]
    return ptr - data_addr


def main():
    fbl_path = sys.argv[1] if len(sys.argv) > 1 else "tools/maps/testdata/Vatican_osm.fbl"
    
    dec = decrypt_fbl(fbl_path)
    sec0 = struct.unpack_from('<I', dec, 0x048E)[0]
    
    print(f"=== Unicorn Gap Header Field Trace ===")
    print(f"File: {fbl_path}, {len(dec)} bytes, sec0=0x{sec0:04x}")
    
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
    load_dll(uc, DLL_PATH)
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    
    DATA_ADDR = HEAP_BASE
    uc.mem_write(DATA_ADDR, dec)
    
    STREAM_ADDR = HEAP_BASE + 0x100000
    RESULT_ADDR = HEAP_BASE + 0x110000
    
    # Read the gap header field by field, trying both LE and BE
    # The SET reader uses FUN_100557f0 which respects the byte-swap flag
    
    # First, read as LE (the default for most SET fields)
    print(f"\n--- Reading gap header as LE uint32 fields ---")
    make_stream(uc, STREAM_ADDR, DATA_ADDR, 0x04DE, sec0, big_endian=False)
    
    fields_le = []
    for i in range(32):
        pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
        if pos >= sec0:
            break
        uc.mem_write(RESULT_ADDR, b'\x00' * 8)
        val = call_read_u32(uc, STREAM_ADDR, RESULT_ADDR)
        fields_le.append((pos, val))
        print(f"  [{i:2d}] 0x{pos:04x}: {val:>12,} (0x{val:08x})")
    
    # Now try BE
    print(f"\n--- Reading gap header as BE uint32 fields ---")
    make_stream(uc, STREAM_ADDR, DATA_ADDR, 0x04DE, sec0, big_endian=True)
    
    fields_be = []
    for i in range(32):
        pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
        if pos >= sec0:
            break
        uc.mem_write(RESULT_ADDR, b'\x00' * 8)
        val = call_read_u32(uc, STREAM_ADDR, RESULT_ADDR)
        fields_be.append((pos, val))
        print(f"  [{i:2d}] 0x{pos:04x}: {val:>12,} (0x{val:08x})")
    
    # Now try reading the section header format (4 u32 + 2 u16)
    # using FUN_10109a90
    print(f"\n--- Reading gap as section header (FUN_10109a90) ---")
    make_stream(uc, STREAM_ADDR, DATA_ADDR, 0x04DE, sec0, big_endian=False)
    
    # FUN_10109a90 reads: 4 x read_u32, 2 x read_u16
    # Let's do it manually
    SECTION_HDR = HEAP_BASE + 0x120000
    uc.mem_write(SECTION_HDR, b'\x00' * 0x20)
    
    # Read 4 uint32s
    for j in range(4):
        pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
        val = call_read_u32(uc, STREAM_ADDR, SECTION_HDR + j*4)
        print(f"  u32[{j}] @ 0x{pos:04x}: {val:>12,} (0x{val:08x})")
    
    # Read 2 uint16s
    for j in range(2):
        pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
        val = call_read_u16(uc, STREAM_ADDR, SECTION_HDR + 16 + j*2)
        print(f"  u16[{j}] @ 0x{pos:04x}: {val:>6,} (0x{val:04x})")
    
    # Show where we are now
    pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
    print(f"\n  Stream position after section header: 0x{pos:04x}")
    print(f"  Remaining to sec0: {sec0 - pos} bytes")
    
    # Continue reading more fields
    print(f"\n--- Continuing to read uint32 fields ---")
    for i in range(20):
        pos = get_stream_pos(uc, STREAM_ADDR, DATA_ADDR)
        if pos >= sec0:
            break
        uc.mem_write(RESULT_ADDR, b'\x00' * 8)
        val = call_read_u32(uc, STREAM_ADDR, RESULT_ADDR)
        print(f"  [{i:2d}] 0x{pos:04x}: {val:>12,} (0x{val:08x})")


if __name__ == "__main__":
    main()
