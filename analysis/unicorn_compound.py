"""Unicorn: trace the bitstream serializer with a minimal compound type.

Strategy: Create a fake data object that looks like a compound type with
one string field "ABC". Hook every bit-write function to trace the exact
encoding. Compare the output with the known input to derive encoding rules.
"""
import struct
from unicorn import *
from unicorn.x86_const import *

dll = open('analysis/extracted/nngine.dll', 'rb').read()
IB = 0x10000000

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)
uc.mem_map(0x1000000, 0x2000000)
uc.mem_map(0, 0x1000)
for a in [0x70000000, 0x77770000, 0xEFFFF000]:
    try: uc.mem_map(a, 0x10000); uc.mem_write(a, b'\xC3'*0x10000)
    except: pass
for va, raw, sz in [(0x1000, 0x400, 0x2ACE00), (0x2AE000, 0x2AD200, 0x5C200),
                     (0x30B000, 0x309400, 0x9200)]:
    uc.mem_write(IB + va, dll[raw:raw+sz])

hp = [0x1001000]
def ha(n):
    p = hp[0]; hp[0] += (n+15)&~15; uc.mem_write(p, b'\x00'*n); return p

stub_ptr = [IB + 0x3F0000]
uc.mem_write(IB + 0x3F0000, b'\x00' * 0x10000)
def alloc_stub(n):
    p = stub_ptr[0]; stub_ptr[0] += (n+15)&~15; return p

RET = alloc_stub(16); uc.mem_write(RET, b'\xC3')
END = alloc_stub(16); uc.mem_write(END, b'\xC3')
tls = ha(0x200); tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))
uc.mem_write(IB+0x312F68, struct.pack('<I', 0))
uc.mem_write(IB+0x312F6C, struct.pack('<I', 0xBB40E64E))

# IAT
for i in range(0, 0x2000, 4):
    off = 0x2AD200 + i
    if off+4 > len(dll): break
    v = struct.unpack_from('<I', dll, off)[0]
    if 0x10000 < v < 0x400000:
        no = 0x2AD200 + (v - 0x2AE000)
        if 0 < no < len(dll) - 50:
            try:
                nm = dll[no+2:no+50].split(b'\x00')[0].decode('ascii')
                if nm:
                    s = alloc_stub(16); uc.mem_write(s, b'\x31\xC0\xC2\x04\x00')
                    uc.mem_write(IB+0x2AE000+i, struct.pack('<I', s))
            except: pass

hooks = {}
def hm(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    n = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    uc.reg_write(UC_X86_REG_EAX, ha(max(n, 16))); uc.reg_write(UC_X86_REG_EIP, RET)
def hf(uc, a, s, u): uc.reg_write(UC_X86_REG_EIP, RET)
def hn(uc, a, s, u): uc.reg_write(UC_X86_REG_EAX, 1); uc.reg_write(UC_X86_REG_EIP, RET)
for rva, fn in [(0x27E4F5, hm), (0x2839F9, hm), (0x2839D1, hf), (0x27DFE8, hf), (0x283980, hn)]:
    hooks[IB+rva] = fn

# ============================================================
# Instead of building a fake compound type (complex), let me use
# an EXISTING type from the DLL — the UuidRO type (entry 2).
# UuidRO has: field[0]=String(4bit), field[1]=Int64
# This is a real compound type with leaf fields.
#
# I need to:
# 1. Create a data object with vtable[1] returning the UuidRO descriptor
# 2. Set the sub-objects at the field offsets with presence=1 and data
# 3. Call FUN_101a9930 and capture the output
# ============================================================

# UuidRO descriptor is at entry 2 of the descriptor table
# desc_va = 0x1030DE50 + 2*12 = 0x1030DE68
# [vtable=0x102D21CC, sub_desc=0x102CFECC, type_info=0x102CEA28]
UUID_DESC = 0x1030DE68

# Create vtable[1] stub that returns UUID_DESC
get_type_stub = alloc_stub(16)
uc.mem_write(get_type_stub, b'\xB8' + struct.pack('<I', UUID_DESC) + b'\xC3')

data_vtable = alloc_stub(64)
uc.mem_write(data_vtable + 0, struct.pack('<I', RET))  # vtable[0]
uc.mem_write(data_vtable + 4, struct.pack('<I', get_type_stub))  # vtable[1]

# Create data object
data_obj = ha(0x100)
uc.mem_write(data_obj, struct.pack('<I', data_vtable))

# UuidRO fields:
# field[0] at data_obj+0x8: String type (accessor returns data_obj+8)
# field[1] at data_obj+0x10: Int64 type (accessor returns data_obj+16)
#
# Each sub-object needs: [+0]=vtable, [+4]=presence_byte (1=present)
# For the string field, the data is a string pointer.
# For the int64 field, the data is an 8-byte value.

# Set presence bytes
uc.mem_write(data_obj + 0x8 + 4, b'\x01')  # field[0] present
uc.mem_write(data_obj + 0x10 + 4, b'\x01')  # field[1] present

# For the string field, we need the string data.
# The string accessor (vtable[0x20]) returns the string pointer.
# The string type vtable is at 0x102CE850.
# vtable[0x20] = FUN_101a2030 which returns arg[0].
# So the string data is at [sub_obj+0] = a pointer to the string.

# Create a string "ABC" (3 chars)
str_data = ha(16)
uc.mem_write(str_data, b'ABC\x00')

# The string sub-object at data_obj+0x8:
# [+0] = pointer to string data? Or vtable?
# Actually, the accessor returns data_obj+0x8, and the compound_serialize
# calls vtable[3] (serialize_value) on the field descriptor with this pointer.
# The serialize_value for strings calls vtable[0x2C] on the stream.
# vtable[0x2C] = FUN_101a3770 which calls vtable[0x10] with byte [eax].
# eax = the sub-object pointer from the accessor.
# So [eax] = the first byte of the string, [eax+1] = second byte, etc.

# Wait — the string serializer iterates over the string characters.
# The sub-object IS the string data directly.
# So data_obj+0x8 should point to the string bytes.
# But data_obj+0x8 also needs [+4]=presence byte.

# The accessor returns data_obj+0x8. The is_present check reads byte [ptr+4].
# The serialize_value reads [ptr+0] as the data.
# So: [data_obj+0x8+0] = string pointer or first char
#     [data_obj+0x8+4] = 1 (present)

# For the string type, the serialize_value (FUN_101a2040) does:
# push [esi+0xC]  ; field_count/length from type descriptor
# push [edx]      ; data value from sub-object[0]
# call [eax+0x2C] ; stream->vtable[0x2C]

# So [sub_obj+0] is the data value. For a string, this might be a pointer
# to the string, or the string length, or the first char.

# Let me just set it to a pointer to "ABC" and see what happens.
uc.mem_write(data_obj + 0x8, struct.pack('<I', str_data))  # [+0] = ptr to "ABC"
uc.mem_write(data_obj + 0x8 + 4, b'\x01')  # [+4] = present

# For int64 field at data_obj+0x10:
uc.mem_write(data_obj + 0x10, struct.pack('<Q', 0x1234567890ABCDEF))  # value
uc.mem_write(data_obj + 0x10 + 4, b'\x01')  # present (overwrites byte 4 of the value)
# Hmm, that overwrites part of the int64. Let me use a different layout.
# Actually the int64 value and presence byte might be at different offsets.
# The accessor returns data_obj+0x10. [ptr+4] = presence. [ptr+0] = value lo.
# For int64: [ptr+0]=lo32, [ptr+4]=hi32. But [ptr+4] is also the presence byte.
# This is a conflict. Let me check: the is_present function reads BYTE [ptr+4].
# If the int64 value has a non-zero byte at offset 4, it's "present".
# So presence is implicit — if the value is non-zero, it's present.

# Let me just set a non-zero value:
uc.mem_write(data_obj + 0x10, struct.pack('<Q', 0x0000000100000042))
# byte[4] = 0x01 (present), value = 0x42 in low byte

# Set up the output buffer
out_buf = ha(32)
uc.mem_write(out_buf + 16, struct.pack('<H', 0x0101))

# Hook bit-write functions
writes = []
def make_hook(name):
    def h(uc, addr, size, ud):
        esp = uc.reg_read(UC_X86_REG_ESP)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        if name == '1bit':
            bit = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0] & 0xFF
            pos = struct.unpack('<I', bytes(uc.mem_read(ecx+4, 4)))[0]
            writes.append(f'@{pos:4d} {name}({bit})')
        else:
            val = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
            nbits = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
            pos = struct.unpack('<I', bytes(uc.mem_read(ecx+4, 4)))[0]
            writes.append(f'@{pos:4d} {name}(0x{val:X}, {nbits}b)')
    return h

hooks[IB+0x1A9E80] = make_hook('1bit')
hooks[IB+0x1A8150] = make_hook('msb')
hooks[IB+0x1A8310] = make_hook('lsb')
hooks[IB+0x1A9A80] = make_hook('bitmap')

# FUN_1005c700 — stream ensure/write
def h_stream(uc, addr, size, ud):
    ecx = uc.reg_read(UC_X86_REG_ECX)
    esp = uc.reg_read(UC_X86_REG_ESP)
    nbytes = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    writes.append(f'      stream_ensure({nbytes}B)')
hooks[IB+0x05C700] = h_stream

def hook_unmapped(uc, access, address, size, value, ud):
    try: uc.mem_map(address&~0xFFF, 0x1000); uc.mem_write(address&~0xFFF, b'\x00'*0x1000); return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt = [0]
last_rvas = []
def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks: hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB+0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if IB <= address < IB+0x400000:
        last_rvas.append(address - IB)
        if len(last_rvas) > 20: last_rvas.pop(0)
    if cnt[0] > 500000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# Call FUN_101a9930
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, data_obj)
esp -= 4; uc.mem_write(esp, struct.pack('<I', out_buf))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)
cnt[0] = 0

try:
    uc.emu_start(IB+0x1A9930, END, timeout=60000000)
    print(f'Completed in {cnt[0]} instructions')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Error at RVA 0x{eip-IB:06X} after {cnt[0]} insns: {e}')
    print(f'Last RVAs: {["0x%06X" % r for r in last_rvas[-10:]]}')

print(f'\nBit writes ({len(writes)}):')
for w in writes:
    print(f'  {w}')

# Get output
ob = bytes(uc.mem_read(out_buf, 20))
data_ptr = struct.unpack_from('<I', ob, 0)[0]
data_len = struct.unpack_from('<I', ob, 8)[0]
print(f'\nOutput buffer: ptr=0x{data_ptr:08X} len={data_len}')
if data_ptr and 0 < data_len < 10000:
    data = bytes(uc.mem_read(data_ptr, data_len))
    print(f'Output ({data_len}B): {data.hex()}')
    bits = ''.join(format(b, '08b') for b in data)
    print(f'Bits: {bits}')
