"""Trace every memory read the serializer makes from the credential object.

This will tell us exactly which fields the serializer reads and in what order,
revealing the true serialized format.
"""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

TB_CODE = 3745651132643726
TB_SECRET = 3037636188661496
HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)
uc.mem_map(0x1000000, 0x2000000)
uc.mem_map(0, 0x1000)
for a in [0x70000000, 0x77770000, 0xEFFFF000]:
    try: uc.mem_map(a, 0x10000); uc.mem_write(a, b'\xC3'*0x10000)
    except: pass

for va, raw, sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB+va, dll[raw:raw+sz])

hp = [0x1001000]
def ha(n):
    p = hp[0]; hp[0] += (n+15) & ~15
    uc.mem_write(p, b'\x00'*n)
    return p

RET = 0x1000100; uc.mem_write(RET, b'\xC3')
END = 0x1000200; uc.mem_write(END, b'\xC3')
tls = ha(0x200); tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))
uc.mem_write(IB+0x312F68, struct.pack('<I', 0))
uc.mem_write(IB+0x312F6C, struct.pack('<I', 0xBB40E64E))

for i in range(0, 0x2000, 4):
    off = 0x2AD200 + i
    if off+4 > len(dll): break
    v = struct.unpack_from('<I', dll, off)[0]
    if 0x10000 < v < 0x400000:
        no = 0x2AD200 + (v - 0x2AE000)
        if 0 < no < len(dll)-50:
            try:
                nm = dll[no+2:no+50].split(b'\x00')[0].decode('ascii')
                if nm:
                    s = ha(16); uc.mem_write(s, b'\x31\xC0\xC2\x04\x00')
                    uc.mem_write(IB+0x2AE000+i, struct.pack('<I', s))
            except: pass

hooks = {}
def ah(rva, fn): hooks[IB+rva] = fn

def hm(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    n = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    uc.reg_write(UC_X86_REG_EAX, ha(max(n, 16)))
    uc.reg_write(UC_X86_REG_EIP, RET)

def hf(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EIP, RET)

def hr(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    old = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    n = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    p = ha(max(n, 16))
    if old:
        try: uc.mem_write(p, bytes(uc.mem_read(old, min(n, 4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, RET)

ah(0x27E4F5, hm); ah(0x2839F9, hr); ah(0x2839D1, hf); ah(0x27DFE8, hf)
ah(0x283980, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 1), uc.reg_write(UC_X86_REG_EIP, RET)))

# Build credential with SENTINEL values to trace reads
CRED_BASE = ha(0x80)
cd = bytearray(0x80)

# Use unique sentinel values for each field so we can identify reads
struct.pack_into('<I', cd, 0x00, IB+0x2B9590)  # vtable1
struct.pack_into('<I', cd, 0x04, 0xAA000004)    # sentinel
struct.pack_into('<I', cd, 0x08, IB+0x2B9580)   # vtable2
struct.pack_into('<I', cd, 0x0C, 0xAA00000C)    # sentinel
struct.pack_into('<I', cd, 0x10, 0x00000001)     # type = 1
struct.pack_into('<I', cd, 0x14, 0x00000001)     # flag
# Code = hu_code
struct.pack_into('<I', cd, 0x18, HU_CODE & 0xFFFFFFFF)   # Code_lo
struct.pack_into('<I', cd, 0x1C, (HU_CODE >> 32) & 0xFFFFFFFF)  # Code_hi
struct.pack_into('<I', cd, 0x20, 0x00000001)     # flag
# Agent = tb_code (from device manager)
struct.pack_into('<I', cd, 0x24, TB_CODE & 0xFFFFFFFF)   # Agent_lo
struct.pack_into('<I', cd, 0x28, (TB_CODE >> 32) & 0xFFFFFFFF)  # Agent_hi
struct.pack_into('<I', cd, 0x2C, 0xBB00002C)     # sentinel - unknown field from device mgr
struct.pack_into('<I', cd, 0x30, 0x69E37F31)     # timestamp
struct.pack_into('<I', cd, 0x34, 0xBB000034)     # sentinel
struct.pack_into('<I', cd, 0x38, IB+0x2B9588)    # vtable3
struct.pack_into('<I', cd, 0x3C, 0xBB00003C)     # sentinel
struct.pack_into('<I', cd, 0x40, 0x00000003)     # mode = 3
struct.pack_into('<I', cd, 0x44, 0x00000001)     # flag
uc.mem_write(CRED_BASE, bytes(cd))

print(f'Credential at 0x{CRED_BASE:08X}')
print(f'Credential+8 (vtable2) at 0x{CRED_BASE+8:08X}')

# Track reads from credential area
cred_reads = []
def hook_mem_read(uc, access, address, size, value, ud):
    if CRED_BASE <= address < CRED_BASE + 0x80:
        offset = address - CRED_BASE
        data = bytes(uc.mem_read(address, size))
        val = int.from_bytes(data, 'little')
        eip = uc.reg_read(UC_X86_REG_EIP)
        rva = eip - IB
        cred_reads.append((offset, size, val, rva))
uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

# Init serializer
so = ha(64)
uc.reg_write(UC_X86_REG_ECX, so)
esp = 0x5FF000
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp+0x200)

cnt = [0]
def hook_unmapped(uc, access, address, size, value, ud):
    try: uc.mem_map(address & ~0xFFF, 0x1000); uc.mem_write(address & ~0xFFF, b'\xC3'*0x1000); return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks and hooks[address]:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > 5000000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

try: uc.emu_start(IB+0x1B2910, END, timeout=30000000)
except UcError as e: print(f'Init err: {e}')

# Now serialize the credential
out_buf = ha(32)
uc.mem_write(out_buf + 16, struct.pack('<H', 0x0101))

esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, CRED_BASE + 8)  # vtable2 interface
esp -= 4; uc.mem_write(esp, struct.pack('<I', out_buf))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp+0x200)

cnt[0] = 0
cred_reads.clear()

print('\nRunning FUN_101a9930 (binary serializer)...')
try:
    uc.emu_start(IB+0x1A9930, END, timeout=120000000)
    print(f'COMPLETED ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at RVA 0x{eip-IB:X} after {cnt[0]}: {e}')

# Print credential reads
print(f'\n=== Credential reads ({len(cred_reads)} total) ===')
seen = set()
for offset, size, val, rva in cred_reads:
    key = (offset, size)
    if key not in seen:
        seen.add(key)
        label = ''
        if offset == 0x00: label = 'vtable1'
        elif offset == 0x08: label = 'vtable2'
        elif offset == 0x10: label = 'type'
        elif offset == 0x14: label = 'flag'
        elif offset == 0x18: label = 'Code_lo (hu_code)'
        elif offset == 0x1C: label = 'Code_hi (hu_code)'
        elif offset == 0x20: label = 'flag'
        elif offset == 0x24: label = 'Agent_lo (tb_code)'
        elif offset == 0x28: label = 'Agent_hi (tb_code)'
        elif offset == 0x2C: label = 'unknown (sentinel 0xBB00002C)'
        elif offset == 0x30: label = 'timestamp'
        elif offset == 0x34: label = 'sentinel'
        elif offset == 0x38: label = 'vtable3'
        elif offset == 0x40: label = 'mode'
        print(f'  +0x{offset:02X} ({size}B): 0x{val:08X}  {label}  (from RVA 0x{rva:X})')

# Read output
ob = bytes(uc.mem_read(out_buf, 20))
data_ptr = struct.unpack_from('<I', ob, 0)[0]
data_len = struct.unpack_from('<I', ob, 8)[0]
print(f'\nSerializer output: ptr=0x{data_ptr:08X} len={data_len}')
if data_ptr and 0 < data_len < 10000:
    data = bytes(uc.mem_read(data_ptr, data_len))
    print(f'Data ({data_len}B): {data.hex()}')
    
    # Compute HMAC with hu_secret
    h = hmac.new(b'\x00\x0E\xE8\x7C\x16\xB1\xE8\x12', data, hashlib.md5).digest()
    print(f'HMAC: {h.hex()}')
    print(f'Want: ad35bcc12654b893f7b5596a8057190c')
    print(f'Match: {h.hex() == "ad35bcc12654b893f7b5596a8057190c"}')
