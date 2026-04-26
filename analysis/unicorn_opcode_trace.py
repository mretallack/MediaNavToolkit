"""Unicorn: Emulate the DLL's opcode parser on Vatican section 4 data.

Feed the raw section 4 bytes to FUN_1025e228 (the counter/scanner function)
with param_4=1 (enable attribute extraction) and trace all memory writes
to capture the road class values it extracts."""
import struct
from pathlib import Path
import numpy as np
from unicorn import *
from unicorn.x86_const import *
from analysis.unicorn_harness import load_dll, setup_stack, setup_heap, IMAGE_BASE, STACK_BASE, STACK_SIZE, HEAP_BASE, STOP_ADDR

xor_table = Path('analysis/xor_table_normal.bin').read_bytes()
raw = Path('tools/maps/testdata/Vatican_osm.fbl').read_bytes()
d = np.frombuffer(raw, dtype=np.uint8)
x = np.frombuffer(xor_table, dtype=np.uint8)
dec = bytes(d ^ np.tile(x, (len(d) // len(x)) + 1)[:len(d)])

sec4_start = struct.unpack_from('<I', dec, 0x048E + 4*4)[0]
sec4_end = struct.unpack_from('<I', dec, 0x048E + 5*4)[0]
sec4 = dec[sec4_start:sec4_end]

print(f"Vatican section 4: {len(sec4)} bytes")

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(STOP_ADDR & ~0xFFF, 0x1000)
load_dll(uc, "analysis/extracted/nngine.dll")
setup_stack(uc)
setup_heap(uc)

# Write section 4 data
DATA_ADDR = HEAP_BASE + 0x50000
uc.mem_write(DATA_ADDR, sec4)

# FUN_1025e228 signature (from decompiled code):
# uint FUN_1025e228(byte *param_1, int param_2, int param_3, int param_4)
# param_1 = data pointer
# param_2 = ? (used for some comparisons)
# param_3 = ? (compared with record data)
# param_4 = flag (non-zero enables attribute extraction)
# Returns: segment count

FUN_1025e228 = IMAGE_BASE + 0x25e228

def hook_mem(uc, access, address, size, value, user_data):
    try:
        uc.mem_map(address & ~0xFFF, 0x1000)
    except:
        pass
    return True
uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem)

# Track data reads from section 4
reads = []
def hook_read(uc, access, address, size, value, user_data):
    if DATA_ADDR <= address < DATA_ADDR + len(sec4):
        offset = address - DATA_ADDR
        reads.append((offset, size))
uc.hook_add(UC_HOOK_MEM_READ, hook_read)

# Call with param_4=0 first (just count)
esp = STACK_BASE + STACK_SIZE - 0x2000
stack = struct.pack('<IIIII', STOP_ADDR, DATA_ADDR, 0, 0, 0)
uc.mem_write(esp, stack)
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

try:
    uc.emu_start(FUN_1025e228, STOP_ADDR, timeout=5_000_000)
    eax = uc.reg_read(UC_X86_REG_EAX)
    print(f"\nparam_4=0: EAX={eax} (segment count)")
    print(f"Data reads: {len(reads)}")
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    eax = uc.reg_read(UC_X86_REG_EAX)
    print(f"\nError at RVA 0x{eip-IMAGE_BASE:06x}: {e}")
    print(f"EAX={eax}, reads={len(reads)}")

# Now call with param_4=1 (enable attributes)
reads.clear()
stack = struct.pack('<IIIII', STOP_ADDR, DATA_ADDR, 0, 0, 1)
uc.mem_write(esp, stack)
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

try:
    uc.emu_start(FUN_1025e228, STOP_ADDR, timeout=5_000_000)
    eax = uc.reg_read(UC_X86_REG_EAX)
    print(f"\nparam_4=1: EAX={eax}")
    print(f"Data reads: {len(reads)}")
    
    # Show which bytes were read
    read_offsets = sorted(set(off for off, _ in reads))
    print(f"Unique offsets read: {len(read_offsets)}")
    print(f"First 20: {read_offsets[:20]}")
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    eax = uc.reg_read(UC_X86_REG_EAX)
    print(f"\nError at RVA 0x{eip-IMAGE_BASE:06x}: {e}")
    print(f"EAX={eax}, reads={len(reads)}")
    print(f"First 20 read offsets: {sorted(set(off for off, _ in reads))[:20]}")
