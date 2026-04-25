"""Unicorn: Decode gap area by repeatedly calling FUN_10240e80 (tagged record reader).

Handles malloc/free stubs and vtable calls to keep emulation running.
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
HEAP_SIZE  = 0x00400000
STOP_ADDR  = 0x00DEAD00
STUB_BASE  = 0x00800000  # stubs for malloc/free/etc

SCALE = 2**23

heap_ptr = HEAP_BASE + 0x100000  # start allocating from here

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


def main():
    global heap_ptr
    fbl_path = sys.argv[1] if len(sys.argv) > 1 else "tools/maps/testdata/Vatican_osm.fbl"
    
    dec = decrypt_fbl(fbl_path)
    sec0 = struct.unpack_from('<I', dec, 0x048E)[0]
    
    # Get the ENTIRE gap area (not just bitstream) — start from right after section table
    # The tagged record reader might need the full gap data
    gap_data = dec[0x04DE:sec0]
    
    # Also try just the bitstream part
    bs_start = None
    for off in range(0x0580, min(0x0600, sec0)):
        if dec[off] == 0 and dec[off+1] == 0 and dec[off+2] == 0 and dec[off+3] != 0:
            window = dec[off+3:off+19]
            if len(set(window)) > 10:
                bs_start = off + 3
                break
    
    bitstream = dec[bs_start:sec0] if bs_start else gap_data
    
    print(f"=== Unicorn Gap Area Decoder ===")
    print(f"File: {fbl_path}")
    print(f"Gap: {len(gap_data)}B, Bitstream: {len(bitstream)}B")
    print(f"First byte: 0x{bitstream[0]:02x} (type={bitstream[0]&0x7F}, flag={bitstream[0]>>7})")
    
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
    uc.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL)
    
    load_dll(uc, DLL_PATH)
    
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    
    # Write bitstream to heap
    DATA_ADDR = HEAP_BASE
    uc.mem_write(DATA_ADDR, bitstream)
    
    # Create stream object
    STREAM_ADDR = HEAP_BASE + 0x50000
    
    # Write a RET stub at STUB_BASE for any function pointers we need
    uc.mem_write(STUB_BASE, b'\xc3')  # ret
    # Write a RET 4 stub (for __stdcall with 1 param)
    uc.mem_write(STUB_BASE + 0x10, b'\xc2\x04\x00')  # ret 4
    
    # Hook malloc (FUN_1027e4f5 and FUN_1027ea51)
    MALLOC_RVA_1 = 0x27e4f5
    MALLOC_RVA_2 = 0x27ea51
    
    def hook_code(uc, address, size, user_data):
        global heap_ptr
        rva = address - IMAGE_BASE
        
        # Hook malloc
        if rva == MALLOC_RVA_1 or rva == MALLOC_RVA_2:
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
            alloc_size = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
            
            # Allocate from our heap
            result = heap_ptr
            heap_ptr += (alloc_size + 0xF) & ~0xF  # align to 16
            uc.mem_write(result, b'\x00' * alloc_size)
            
            # Return: set EAX, pop return addr + 1 arg (cdecl: caller cleans)
            uc.reg_write(UC_X86_REG_EAX, result)
            uc.reg_write(UC_X86_REG_ESP, esp + 4)  # pop ret addr only (cdecl)
            uc.reg_write(UC_X86_REG_EIP, ret_addr)
        
        # Hook FUN_10210100 (some cleanup/free function)
        elif rva == 0x210100:
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            uc.reg_write(UC_X86_REG_EIP, ret_addr)
        
        # Stop on unmapped fetch
        elif address < IMAGE_BASE or address >= IMAGE_BASE + 0x400000:
            if address != STOP_ADDR and address >= 0x1000:
                # Probably a vtable call — just return
                esp = uc.reg_read(UC_X86_REG_ESP)
                ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
                uc.reg_write(UC_X86_REG_ESP, esp + 4)
                uc.reg_write(UC_X86_REG_EIP, ret_addr)
    
    uc.hook_add(UC_HOOK_CODE, hook_code)
    
    # Also hook unmapped memory reads to return 0
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        if access == UC_MEM_READ_UNMAPPED:
            # Map the page and fill with zeros
            page = address & ~0xFFF
            try:
                uc.mem_map(page, 0x1000, UC_PROT_ALL)
            except:
                pass
            return True
        return False
    
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
    
    # Now repeatedly call FUN_10240e80 to read records
    FUN_10240e80 = IMAGE_BASE + 0x240e80
    
    records = []
    max_records = 50
    
    for i in range(max_records):
        # Reset stream object
        stream = bytearray(0x40)
        # Calculate current data pointer
        consumed = sum(r.get('bytes', 0) for r in records)
        current_ptr = DATA_ADDR + consumed
        
        if consumed >= len(bitstream):
            print(f"\nAll data consumed after {i} records")
            break
        
        struct.pack_into('<I', stream, 0x04, current_ptr)
        struct.pack_into('<I', stream, 0x10, DATA_ADDR + len(bitstream))
        struct.pack_into('<I', stream, 0x1c, 0)
        uc.mem_write(STREAM_ADDR, bytes(stream))
        
        # Result buffer
        RESULT_ADDR = HEAP_BASE + 0x60000
        uc.mem_write(RESULT_ADDR, b'\x00' * 32)
        
        # Set up call
        esp = STACK_BASE + STACK_SIZE - 0x1000
        uc.reg_write(UC_X86_REG_ECX, STREAM_ADDR)
        stack_data = struct.pack('<II', STOP_ADDR, RESULT_ADDR)
        uc.mem_write(esp, stack_data)
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EBP, esp + 0x100)
        
        try:
            uc.emu_start(FUN_10240e80, STOP_ADDR, timeout=2_000_000)
        except UcError as e:
            eip = uc.reg_read(UC_X86_REG_EIP)
            print(f"\nRecord {i}: emulation error at RVA=0x{eip-IMAGE_BASE:06x}: {e}")
            break
        
        # Read result
        result = bytes(uc.mem_read(RESULT_ADDR, 16))
        rtype = struct.unpack_from('<I', result, 0)[0]
        rvalue = struct.unpack_from('<I', result, 4)[0]
        
        # Read new stream position
        new_stream = bytes(uc.mem_read(STREAM_ADDR, 0x20))
        new_ptr = struct.unpack_from('<I', new_stream, 0x04)[0]
        error = struct.unpack_from('<I', new_stream, 0x1c)[0]
        bytes_read = new_ptr - current_ptr
        
        record = {'type': rtype, 'value': rvalue, 'bytes': bytes_read, 'offset': consumed}
        records.append(record)
        
        # Interpret the record
        type_names = {0: 'END', 1: 'INT32', 2: 'COORD', 5: 'RAW8', 0x44: 'RAW8_PTR',
                      0x46: 'ARRAY', 0x47: 'GROUP'}
        tname = type_names.get(rtype, f'UNK_{rtype:02x}')
        
        extra = ""
        if rtype == 2:
            lon = rvalue / SCALE
            lat_raw = struct.unpack_from('<I', result, 8)[0]
            lat = struct.unpack_from('<i', result, 8)[0] / SCALE
            extra = f" ({lon:.6f}, {lat:.6f})"
        elif rtype == 1:
            extra = f" = {struct.unpack_from('<i', result, 4)[0]}"
        elif rtype == 0x44:
            # Raw 8 bytes — read from the pointer
            ptr = rvalue
            if ptr > 0:
                try:
                    raw = bytes(uc.mem_read(ptr, 8))
                    extra = f" = {raw.hex(' ')}"
                except:
                    extra = f" ptr=0x{ptr:08x}"
        
        print(f"  [{i:3d}] @{consumed:4d} +{bytes_read:2d}B type=0x{rtype:02x} ({tname:10s}) val=0x{rvalue:08x}{extra}")
        
        if error != 0:
            print(f"        Stream error: {error}")
            break
        
        if rtype == 0:  # END
            break
        
        if bytes_read <= 0:
            print(f"        No progress, stopping")
            break
    
    print(f"\nTotal records: {len(records)}")
    print(f"Total bytes consumed: {sum(r['bytes'] for r in records)}/{len(bitstream)}")


if __name__ == "__main__":
    main()
