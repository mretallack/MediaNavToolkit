"""Unicorn: run FUN_101b2c30 with SendDeviceStatusArg to capture SnakeOil keys.

Key fix: ALL stubs (vtable functions, data object) must be inside the DLL
address range (IB..IB+0x400000) because hook_code redirects everything
outside that range to RET.
"""
from unicorn import *
from unicorn.x86_const import *
import struct

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

# Heap allocator — allocate OUTSIDE DLL range (data only, not code)
hp = [0x1001000]
def ha(n):
    p = hp[0]; hp[0] += (n + 15) & ~15
    uc.mem_write(p, b'\x00' * n)
    return p

# Stub allocator — allocate INSIDE DLL range (for executable code)
stub_ptr = [IB + 0x3F0000]
uc.mem_write(IB + 0x3F0000, b'\x00' * 0x10000)
def alloc_stub(n):
    p = stub_ptr[0]; stub_ptr[0] += (n + 15) & ~15
    return p

RET = alloc_stub(16); uc.mem_write(RET, b'\xC3')
END = alloc_stub(16); uc.mem_write(END, b'\xC3')

# TLS
tls = ha(0x200); tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))
uc.mem_write(IB + 0x312F68, struct.pack('<I', 0))
uc.mem_write(IB + 0x312F6C, struct.pack('<I', 0xBB40E64E))

# IAT patching
hooks = {}
for i in range(0, 0x2000, 4):
    off = 0x2AD200 + i
    if off + 4 > len(dll): break
    v = struct.unpack_from('<I', dll, off)[0]
    if 0x10000 < v < 0x400000:
        no = 0x2AD200 + (v - 0x2AE000)
        if 0 < no < len(dll) - 50:
            try:
                nm = dll[no+2:no+50].split(b'\x00')[0].decode('ascii')
                if nm:
                    s = alloc_stub(16)
                    uc.mem_write(s, b'\x31\xC0\xC2\x04\x00')
                    uc.mem_write(IB + 0x2AE000 + i, struct.pack('<I', s))
            except: pass

# CRT hooks
def hm(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    n = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    uc.reg_write(UC_X86_REG_EAX, ha(max(n, 16))); uc.reg_write(UC_X86_REG_EIP, RET)
def hf(uc, a, s, u): uc.reg_write(UC_X86_REG_EIP, RET)
def hn(uc, a, s, u): uc.reg_write(UC_X86_REG_EAX, 1); uc.reg_write(UC_X86_REG_EIP, RET)
def hr(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    old = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    n = struct.unpack('<I', bytes(uc.mem_read(esp + 8, 4)))[0]
    p = ha(max(n, 16))
    if old:
        try: uc.mem_write(p, bytes(uc.mem_read(old, min(n, 4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX, p); uc.reg_write(UC_X86_REG_EIP, RET)

for rva, fn in [(0x27E4F5, hm), (0x2839F9, hr), (0x2839D1, hf), (0x27DFE8, hf), (0x283980, hn)]:
    hooks[IB + rva] = fn

# SnakeOil hook
snakeoil_calls = []
def h_snakeoil(uc, addr, size, ud):
    esp = uc.reg_read(UC_X86_REG_ESP)
    src = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    length = struct.unpack('<I', bytes(uc.mem_read(esp + 8, 4)))[0]
    key_lo = struct.unpack('<I', bytes(uc.mem_read(esp + 16, 4)))[0]
    key_hi = struct.unpack('<I', bytes(uc.mem_read(esp + 20, 4)))[0]
    key = key_lo | (key_hi << 32)
    plaintext = bytes(uc.mem_read(src, min(length, 256))) if src and 0 < length < 100000 else b''
    snakeoil_calls.append({'key': key, 'length': length, 'plaintext': plaintext[:64]})
    print(f'  SnakeOil #{len(snakeoil_calls)-1}: key=0x{key:016X} len={length}')
hooks[IB + 0x1B3E10] = h_snakeoil

# Unmapped memory
def hook_unmapped(uc, access, address, size, value, ud):
    try:
        uc.mem_map(address & ~0xFFF, 0x1000)
        uc.mem_write(address & ~0xFFF, b'\x00' * 0x1000)
        return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt = [0]
def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > 2000000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# ============================================================
# Step 1: Init serializer
# ============================================================
print("=== Step 1: Init serializer ===")
so = ha(64)
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, so)
esp -= 4; uc.mem_write(esp, struct.pack('<I', 1))
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)
cnt[0] = 0
try: uc.emu_start(IB + 0x1B2910, END, timeout=30000000)
except UcError as e: print(f'Init err: {e}')
print(f'OK: {cnt[0]} insns')

# ============================================================
# Step 2: Build data object (stubs INSIDE DLL range)
# ============================================================
print("\n=== Step 2: Build data object ===")

# vtable[1] stub: mov eax, 0x1030DE50; ret
get_type_stub = alloc_stub(16)
uc.mem_write(get_type_stub, b'\xB8' + struct.pack('<I', 0x1030DE50) + b'\xC3')

# vtable (inside DLL range)
data_vtable = alloc_stub(64)
uc.mem_write(data_vtable + 0, struct.pack('<I', RET))           # vtable[0]
uc.mem_write(data_vtable + 4, struct.pack('<I', get_type_stub)) # vtable[1]

# Data object (can be outside DLL range — it's data, not code)
data_obj = ha(0x1000)
uc.mem_write(data_obj, struct.pack('<I', data_vtable))

# The accessor functions return data_obj+offset, pointing to sub-objects.
# Each sub-object needs a vtable with vtable[1] returning its type descriptor.
# The type descriptor for each sub-object is the corresponding entry in the
# descriptor table at 0x1030DE50.
#
# Entry 0: AuthenticatedDelegationRO (top level)
#   field[0] at +0x8 -> DelegationRO (not in the 39 entries — it's a different type)
#   field[1] at +0x38 -> MessageDigestRO
#
# For now, let's just set up the top-level object and see how far we get.
# The sub-objects at +0x8 and +0x38 will have vtable=0 (NULL), which means
# vtable[1] will crash. But the serializer checks for NULL/presence first.

# The is_present check reads sub_obj[4]. If non-zero, field is present.
# Set presence=1 at every 8-byte boundary in the data object so all
# sub-objects are considered "present" by the serializer.
for offset in range(4, 0x1000, 8):
    uc.mem_write(data_obj + offset, b'\x01')

# Sub-objects need vtable[1] to return their type descriptor.
# The accessor returns data_obj+N, and [data_obj+N] is the vtable ptr.
# We need each sub-object's vtable[1] to return the correct descriptor.
# For now, make ALL sub-objects use the same top-level descriptor.
# This won't produce correct output but will trigger SnakeOil calls.
for offset in range(0, 0x1000, 8):
    uc.mem_write(data_obj + offset, struct.pack('<I', data_vtable))

# Re-set presence bytes (they got overwritten by vtable ptrs)
for offset in range(4, 0x1000, 8):
    uc.mem_write(data_obj + offset, b'\x01')

print(f'  data_obj=0x{data_obj:08X} (all sub-objects have vtable + presence=1)')
print(f'  vtable=0x{data_vtable:08X}')
print(f'  get_type_stub=0x{get_type_stub:08X}')

# ============================================================
# Step 3: Run FUN_101b2c30
# ============================================================
print("\n=== Step 3: Run binary serializer ===")

esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, so)
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))          # flags
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))          # descriptor = NULL
esp -= 4; uc.mem_write(esp, struct.pack('<I', data_obj))   # data_obj
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)
cnt[0] = 0

try:
    uc.emu_start(IB + 0x1B2C30, END, timeout=120000000)
    print(f'COMPLETED ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at RVA 0x{eip-IB:06X} after {cnt[0]} insns: {e}')

# ============================================================
# Results
# ============================================================
print(f'\n=== Results ===')
print(f'SnakeOil calls: {len(snakeoil_calls)}')
for i, call in enumerate(snakeoil_calls):
    print(f'  #{i}: key=0x{call["key"]:016X} len={call["length"]}')

# Check stream output
stream = struct.unpack('<I', bytes(uc.mem_read(so + 8, 4)))[0]
if stream:
    try:
        # Stream buffer has header at stream-0xC: [capacity, refcount, length]
        buf = bytes(uc.mem_read(stream - 0xC, 0xC))
        length = struct.unpack_from('<I', buf, 8)[0]
        print(f'\nOutput length: {length} bytes')
        if 0 < length < 100000:
            out = bytes(uc.mem_read(stream, min(length, 256)))
            print(f'Output: {out.hex()}')
    except Exception as ex:
        print(f'Stream read error: {ex}')
