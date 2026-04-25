"""Unicorn: serialize the DelegationRO object to produce the 16 variable bytes.

The chain body structure is:
  [0x58] presence byte (constant)
  [16B]  bitstream-encoded delegation (THIS IS WHAT WE GENERATE)
  [0xCD] separator (constant)
  [rest] device info (constant per USB, captured once)

The delegation object (0x58 bytes) has:
  [0x00] vtable = PTR_FUN_102b9590
  [0x04] Type presence = 1
  [0x08] vtable2 = PTR_FUN_102b9580
  [0x10] Type = 1 (TEMPORARY)
  [0x14] Delegator presence = 1
  [0x18] Delegator_lo = hu_code low 32 bits
  [0x1C] Delegator_hi = hu_code high 32 bits
  [0x20] Agent presence = 1
  [0x24] Agent_lo = tb_code low 32 bits (from credential +0x10)
  [0x28] Agent_hi = tb_code high 32 bits (from credential +0x14)
  [0x2C] Agent_extra = credential +0x18
  [0x30] Timestamp_lo
  [0x34] Timestamp_hi
  [0x38] vtable3 = PTR_FUN_102b9588
  [0x40] Mac Type = 3 (HMAC_MD5)
  [0x44] Mac presence = 1
  [0x48] Mac data ptr
  [0x4C] Mac data length (16)
  [0x50] Mac capacity
  [0x54] ?
"""
from unicorn import *
from unicorn.x86_const import *
import struct, hmac, hashlib, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

dll = open('analysis/extracted/nngine.dll', 'rb').read()
IB = 0x10000000

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4 * 1024 * 1024)
uc.mem_map(0x500000, 0x100000)
uc.mem_map(0x1000000, 0x2000000)
uc.mem_map(0, 0x1000)
for a in [0x70000000, 0x77770000, 0xEFFFF000]:
    try:
        uc.mem_map(a, 0x10000)
        uc.mem_write(a, b'\xC3' * 0x10000)
    except:
        pass

for va, raw, sz in [(0x1000, 0x400, 0x2ACE00), (0x2AE000, 0x2AD200, 0x5C200), (0x30B000, 0x309400, 0x9200)]:
    uc.mem_write(IB + va, dll[raw:raw + sz])

hp = [0x1001000]
def ha(n):
    p = hp[0]
    hp[0] += (n + 15) & ~15
    uc.mem_write(p, b'\x00' * n)
    return p

RET = 0x1000100
uc.mem_write(RET, b'\xC3')
END = 0x1000200
uc.mem_write(END, b'\xC3')

# TLS setup
tls = ha(0x200)
tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))

# Patch globals
uc.mem_write(IB + 0x312F68, struct.pack('<I', 0))
uc.mem_write(IB + 0x312F6C, struct.pack('<I', 0xBB40E64E))

# Patch IAT stubs
cnt = [0]
def hook_code(uc, addr, size, ud):
    cnt[0] += 1
    if cnt[0] > 500000:
        uc.emu_stop()

uc.hook_add(UC_HOOK_CODE, hook_code)

# Hook malloc/realloc/free
def hook_malloc(uc, addr, size, ud):
    esp = uc.reg_read(UC_X86_REG_ESP)
    n = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    p = ha(max(n, 16))
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0])
    uc.reg_write(UC_X86_REG_ESP, esp + 8)

malloc_stub = ha(16)
uc.mem_write(malloc_stub, b'\xC3')
uc.hook_add(UC_HOOK_CODE, hook_malloc, begin=malloc_stub, end=malloc_stub + 1)

# Patch IAT entries for malloc
for iat_rva in [0x30A0A4, 0x30A0A8]:
    uc.mem_write(IB + iat_rva, struct.pack('<I', malloc_stub))

# Hook realloc
def hook_realloc(uc, addr, size, ud):
    esp = uc.reg_read(UC_X86_REG_ESP)
    old = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    n = struct.unpack('<I', bytes(uc.mem_read(esp + 8, 4)))[0]
    p = ha(max(n, 16))
    if old:
        try:
            data = bytes(uc.mem_read(old, min(n, 4096)))
            uc.mem_write(p, data)
        except:
            pass
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0])
    uc.reg_write(UC_X86_REG_ESP, esp + 12)

realloc_stub = ha(16)
uc.mem_write(realloc_stub, b'\xC3')
uc.hook_add(UC_HOOK_CODE, hook_realloc, begin=realloc_stub, end=realloc_stub + 1)
uc.mem_write(IB + 0x30A0AC, struct.pack('<I', realloc_stub))

# Hook free (no-op)
free_stub = ha(16)
uc.mem_write(free_stub, b'\xC2\x04\x00')  # ret 4
uc.mem_write(IB + 0x30A0B0, struct.pack('<I', free_stub))

# Hook SnakeOil to capture field encryption
snakeoil_calls = []
def hook_snakeoil(uc, addr, size, ud):
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
    src = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
    length = struct.unpack('<I', bytes(uc.mem_read(esp + 8, 4)))[0]
    dst = struct.unpack('<I', bytes(uc.mem_read(esp + 12, 4)))[0]
    key_lo = struct.unpack('<I', bytes(uc.mem_read(esp + 16, 4)))[0]
    key_hi = struct.unpack('<I', bytes(uc.mem_read(esp + 20, 4)))[0]
    key64 = (key_hi << 32) | key_lo
    
    before = bytes(uc.mem_read(src, min(length, 64)))
    snakeoil_calls.append({
        'ret_rva': ret - IB,
        'len': length,
        'key': key64,
        'before': before,
    })

snakeoil_addr = IB + 0x1B3E10
uc.hook_add(UC_HOOK_CODE, hook_snakeoil, begin=snakeoil_addr, end=snakeoil_addr + 1)

# === Build the delegation object ===
# Credentials
hu_code = 0x000BF28569BACB7C
hu_secret = 0x000EE87C16B1E812
tb_code = 0x000D4EA65D36B98E
tb_secret = 0x000ACAB6C9FB66F8

# Compute HMAC
import time
timestamp = int(time.time()) & 0xFFFFFFFF
hmac_key = struct.pack('>Q', hu_secret)
hmac_data = b'\xC4' + struct.pack('>Q', hu_code) + struct.pack('>Q', tb_code) + struct.pack('>I', timestamp)
hmac_output = hmac.new(hmac_key, hmac_data, hashlib.md5).digest()

print(f'Timestamp: 0x{timestamp:08X}')
print(f'HMAC: {hmac_output.hex()}')

# Build delegation object (0x58 bytes)
deleg = ha(0x58)
obj = bytearray(0x58)

# Vtables
struct.pack_into('<I', obj, 0x00, IB + 0x2B9590)  # PTR_FUN_102b9590
struct.pack_into('<I', obj, 0x08, IB + 0x2B9580)  # PTR_FUN_102b9580
struct.pack_into('<I', obj, 0x38, IB + 0x2B9588)  # PTR_FUN_102b9588

# Type = TEMPORARY (1)
obj[0x05] = 1  # presence
struct.pack_into('<I', obj, 0x10, 1)  # Type value

# Delegator = hu_code
obj[0x15] = 1  # presence
struct.pack_into('<I', obj, 0x18, hu_code & 0xFFFFFFFF)
struct.pack_into('<I', obj, 0x1C, hu_code >> 32)

# Agent = tb_code
obj[0x21] = 1  # presence
struct.pack_into('<I', obj, 0x24, tb_code & 0xFFFFFFFF)
struct.pack_into('<I', obj, 0x28, tb_code >> 32)

# Timestamp
obj[0x31] = 1  # presence
# Convert Unix timestamp to Windows FILETIME (100ns intervals since 1601)
filetime = (timestamp + 11644473600) * 10000000
struct.pack_into('<I', obj, 0x30, filetime & 0xFFFFFFFF)
struct.pack_into('<I', obj, 0x34, filetime >> 32)

# Mac Type = HMAC_MD5 (3)
obj[0x45] = 1  # presence
struct.pack_into('<I', obj, 0x40, 3)

# Mac digest (16 bytes)
mac_buf = ha(16)
uc.mem_write(mac_buf, hmac_output)
struct.pack_into('<I', obj, 0x48, mac_buf)
struct.pack_into('<I', obj, 0x4C, 16)
struct.pack_into('<I', obj, 0x50, 16)

uc.mem_write(deleg, bytes(obj))

# Output buffer
out_buf = ha(32)
uc.mem_write(out_buf + 16, struct.pack('<H', 0x0101))

# Call FUN_101a9930 on the delegation object
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, deleg)
esp -= 4
uc.mem_write(esp, struct.pack('<I', out_buf))
esp -= 4
uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

print('\nEmulating FUN_101a9930 on delegation object...')
try:
    uc.emu_start(IB + 0x1A9930, END, timeout=120000000)
    print(f'COMPLETED ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at rva 0x{eip - IB:X} after {cnt[0]}: {e}')

# Read output
ob = bytes(uc.mem_read(out_buf, 20))
data_ptr = struct.unpack_from('<I', ob, 0)[0]
data_len = struct.unpack_from('<I', ob, 8)[0]
print(f'\nOutput: ptr=0x{data_ptr:08X} len={data_len}')

if data_ptr and 0 < data_len < 10000:
    data = bytes(uc.mem_read(data_ptr, data_len))
    print(f'Data ({data_len}B): {data.hex()}')
else:
    print(f'Buffer: {ob.hex()}')

# Print SnakeOil calls
print(f'\nSnakeOil calls: {len(snakeoil_calls)}')
for i, c in enumerate(snakeoil_calls):
    print(f'  [{i}] ret=0x{c["ret_rva"]:X} len={c["len"]} key=0x{c["key"]:016X} before={c["before"][:8].hex()}')
