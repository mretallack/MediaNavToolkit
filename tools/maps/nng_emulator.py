"""Unicorn harness for emulating FUN_1024a720 (byte-to-record converter).

Converts raw FBL section bytes into uint32 records by emulating the DLL's
parser function. Captures type 0x8003 records to extract road class indices.
"""
import struct
from pathlib import Path
from unicorn import *
from unicorn.x86_const import *
import pefile
import numpy as np

DLL_PATH = "analysis/extracted/nngine.dll"
XOR_TABLE_PATH = "analysis/xor_table_normal.bin"

IMAGE_BASE = 0x10000000
STACK_BASE = 0x00100000
STACK_SIZE = 0x00200000
HEAP_BASE  = 0x00400000
HEAP_SIZE  = 0x00800000  # 8MB heap
STOP_ADDR  = 0x00DEAD00

FUN_1024a720_RVA = 0x24a720


class NNGEmulator:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.heap_ptr = HEAP_BASE + 0x100000
        self._load_dll()
        self._setup_memory()

    def _load_dll(self):
        pe = pefile.PE(DLL_PATH)
        image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        self.uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
        self.uc.mem_write(IMAGE_BASE, pe.header[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for section in pe.sections:
            va = IMAGE_BASE + section.VirtualAddress
            data = section.get_data()
            if data:
                self.uc.mem_write(va, data)
        delta = IMAGE_BASE - pe.OPTIONAL_HEADER.ImageBase
        if delta != 0 and hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc.entries:
                    if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                        addr = IMAGE_BASE + entry.rva
                        val = struct.unpack('<I', self.uc.mem_read(addr, 4))[0]
                        self.uc.mem_write(addr, struct.pack('<I', (val + delta) & 0xFFFFFFFF))

    def _setup_memory(self):
        self.uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)

        # Hook malloc
        def hook_code(uc, address, size, user_data):
            rva = address - IMAGE_BASE
            if rva in (0x27e4f5, 0x27ea51):  # malloc
                esp = uc.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
                alloc_size = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
                result = self.heap_ptr
                self.heap_ptr += (alloc_size + 0xF) & ~0xF
                uc.mem_write(result, b'\x00' * min(alloc_size, 0x100000))
                uc.reg_write(UC_X86_REG_EAX, result)
                uc.reg_write(UC_X86_REG_ESP, esp + 4)
                uc.reg_write(UC_X86_REG_EIP, ret)
            elif rva in (0x2839d1, 0x210100, 0x27dfe8):  # free
                esp = uc.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
                uc.reg_write(UC_X86_REG_ESP, esp + 4)
                uc.reg_write(UC_X86_REG_EIP, ret)

        self.uc.hook_add(UC_HOOK_CODE, hook_code)

        def hook_mem(uc, access, address, size, value, user_data):
            try:
                uc.mem_map(address & ~0xFFF, 0x1000, UC_PROT_ALL)
            except:
                pass
            return True
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem)

    def alloc(self, size):
        result = self.heap_ptr
        self.heap_ptr += (size + 0xF) & ~0xF
        self.uc.mem_write(result, b'\x00' * size)
        return result

    def write(self, addr, data):
        self.uc.mem_write(addr, data)

    def read(self, addr, size):
        return bytes(self.uc.mem_read(addr, size))

    def read_u32(self, addr):
        return struct.unpack('<I', self.read(addr, 4))[0]

    def call(self, rva, *args, timeout=30_000_000):
        """Call a cdecl function with given arguments."""
        esp = STACK_BASE + STACK_SIZE - 0x4000
        stack = struct.pack('<I', STOP_ADDR)
        for arg in args:
            stack += struct.pack('<I', arg & 0xFFFFFFFF)
        self.uc.mem_write(esp, stack)
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp + 0x1000)
        self.uc.emu_start(IMAGE_BASE + rva, STOP_ADDR, timeout=timeout)
        return self.uc.reg_read(UC_X86_REG_EAX)


def extract_road_classes(section_data: bytes) -> list[int]:
    """Extract road class indices from FBL section data using DLL emulation.
    
    Returns list of road class indices (0-9) for each segment.
    """
    emu = NNGEmulator()

    # Write section data to heap
    data_addr = emu.alloc(len(section_data) + 16)
    emu.write(data_addr, section_data)
    data_end = data_addr + len(section_data)

    # Create output record buffer
    out_size = len(section_data) * 8  # generous
    out_addr = emu.alloc(out_size)

    # Create output pointer (param_3 points to a pointer that gets updated)
    out_ptr_addr = emu.alloc(4)
    emu.write(out_ptr_addr, struct.pack('<I', out_addr))

    # Create context object (param_4) - array of int32s
    # From decompiled code:
    # param_4[5] = ? 
    # param_4[7] = data start address
    # param_4[8] = data start address (current read position)
    # param_4[10] = ?
    # param_4[0x15] = error offset (written on error)
    # param_4[0x1E] = output buffer start
    # param_4[0x1F] = output buffer end
    # param_4[0x20] = max record count?
    ctx_addr = emu.alloc(0x100)
    emu.write(ctx_addr + 7*4, struct.pack('<I', data_addr))      # data start
    emu.write(ctx_addr + 8*4, struct.pack('<I', data_addr))      # current pos
    emu.write(ctx_addr + 0x1E*4, struct.pack('<I', out_addr))    # output start
    emu.write(ctx_addr + 0x1F*4, struct.pack('<I', out_addr + out_size))  # output end
    emu.write(ctx_addr + 0x20*4, struct.pack('<I', 0xFFFF))      # max records

    # param_1 = current read position in data
    # param_4[8] = end of data (the loop condition is param_1 < param_4[8])
    # param_4[7] = start of data
    # param_4[0x1E] = output buffer current pointer
    # param_4[0x1F] = output buffer end
    # param_4[0] = pointer to another object with field at +0x20 (max count)

    # Create a sub-object for param_4[0]
    sub_obj = emu.alloc(0x40)
    emu.write(sub_obj + 0x20, struct.pack('<I', 0xFFFF))  # max count

    emu.write(ctx_addr + 0*4, struct.pack('<I', sub_obj))        # param_4[0] = sub-object
    emu.write(ctx_addr + 7*4, struct.pack('<I', data_addr))      # data start
    emu.write(ctx_addr + 8*4, struct.pack('<I', data_end))       # data END
    emu.write(ctx_addr + 0x1E*4, struct.pack('<I', out_addr))    # output current
    emu.write(ctx_addr + 0x1F*4, struct.pack('<I', out_addr + out_size))  # output end

    # param_2 flags: bit 19 controls varint decoding
    flags = (1 << 19)  # enable varint decoding

    try:
        # param_1 = data_addr (current read position)
        result = emu.call(FUN_1024a720_RVA, data_addr, flags, out_ptr_addr, ctx_addr,
                         timeout=60_000_000)
        print(f"  FUN_1024a720 returned: 0x{result:08x}")
    except UcError as e:
        eip = emu.uc.reg_read(UC_X86_REG_EIP)
        print(f"  Error at RVA 0x{eip - IMAGE_BASE:06x}: {e}")
        result = 0

    # Read output records from context's output buffer
    # param_4[0x1E] was the start, it may have been advanced
    out_current = emu.read_u32(ctx_addr + 0x1E*4)
    n_records = (out_current - out_addr) // 4
    print(f"  Output: {n_records} uint32 records")

    # Scan for type 0x8003 records
    road_classes = []
    for i in range(n_records):
        val = emu.read_u32(out_addr + i * 4)
        if (val & 0xFFFF0000) == 0x80030000:
            idx = val & 0xFFFF
            road_classes.append(idx)

    return road_classes


if __name__ == "__main__":
    import sys

    xor_table = Path(XOR_TABLE_PATH).read_bytes()
    fbl_path = sys.argv[1] if len(sys.argv) > 1 else "tools/maps/testdata/Vatican_osm.fbl"

    raw = Path(fbl_path).read_bytes()
    d = np.frombuffer(raw, dtype=np.uint8)
    x = np.frombuffer(xor_table, dtype=np.uint8)
    dec = bytes(d ^ np.tile(x, (len(d) // len(x)) + 1)[: len(d)])

    sec4s = struct.unpack_from("<I", dec, 0x048E + 16)[0]
    sec4e = struct.unpack_from("<I", dec, 0x048E + 20)[0]
    sec4 = dec[sec4s:sec4e]

    name = Path(fbl_path).stem.replace("_osm", "")
    print(f"{name}: section 4 = {len(sec4)} bytes")

    classes = extract_road_classes(sec4)
    print(f"Road classes found: {len(classes)}")
    if classes:
        from collections import Counter
        frc_names = {0: 'motorway', 1: 'trunk', 2: 'primary', 3: 'secondary',
                     4: 'tertiary', 5: 'local_hi', 6: 'local_med', 7: 'local_lo',
                     8: 'pedestrian', 9: 'other'}
        dist = Counter(classes)
        for idx in sorted(dist.keys()):
            print(f"  Class {idx} ({frc_names.get(idx, '?'):>12s}): {dist[idx]}")
