"""Unicorn emulation of FUN_101a9930 (igo-binary serializer) on a credential object."""
from unicorn import *
from unicorn.x86_const import *
import struct, hmac, hashlib

dll = open('analysis/extracted/nngine.dll', 'rb').read()
IB = 0x10000000

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4 * 1024 * 1024)       # DLL
uc.mem_map(0x500000, 0x100000)          # Stack
uc.mem_map(0x1000000, 0x1000000)        # Heap
uc.mem_map(0x2000000, 0x10000)          # TEB/TLS

# Load DLL sections
for va, raw, sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB + va, dll[raw:raw+sz])

# Heap allocator
hp = [0x1001000]
def halloc(n):
    p = hp[0]; hp[0] += (n+15)&~15; uc.mem_write(p, b'\x00'*n); return p

RET = 0x1000100
uc.mem_write(RET, b'\xC3')

# TEB at 0x2000000, TLS array at 0x2001000, TLS slot at 0x2002000
TEB = 0x2000000
uc.mem_write(TEB + 0x2C, struct.pack('<I', 0x2001000))  # ThreadLocalStoragePointer
uc.mem_write(0x2001000, struct.pack('<I', 0x2002000))    # tls_array[0] = slot
uc.mem_write(0x2002000 + 0x28, struct.pack('<I', 0))     # slot+0x28 = 0 (init flag)

# _tls_index = 0
uc.mem_write(IB + 0x312F68, struct.pack('<I', 0))
# Security cookie
uc.mem_write(IB + 0x312F6C, struct.pack('<I', 0xBBBBBBBB))

# Hooks
hooks = {}
def add_hook(rva, fn): hooks[IB + rva] = fn

def h_malloc(uc,a,s,u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    n = struct.unpack('<I', bytes(uc.mem_read(esp+4,4)))[0]
    uc.reg_write(UC_X86_REG_EAX, halloc(max(n,16)))
    uc.reg_write(UC_X86_REG_EIP, RET)

def h_realloc(uc,a,s,u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    old = struct.unpack('<I', bytes(uc.mem_read(esp+4,4)))[0]
    n = struct.unpack('<I', bytes(uc.mem_read(esp+8,4)))[0]
    p = halloc(max(n,16))
    if old:
        try: uc.mem_write(p, bytes(uc.mem_read(old, min(n,4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, RET)

def h_nop(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX, 1); uc.reg_write(UC_X86_REG_EIP, RET)
def h_nop0(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX, 0); uc.reg_write(UC_X86_REG_EIP, RET)
def h_ecx(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX, uc.reg_read(UC_X86_REG_ECX)); uc.reg_write(UC_X86_REG_EIP, RET)
def h_free(uc,a,s,u): uc.reg_write(UC_X86_REG_EIP, RET)

add_hook(0x27E4F5, h_malloc)
add_hook(0x2839F9, h_realloc)
add_hook(0x2839D1, h_free)
add_hook(0x27DFE8, h_free)
add_hook(0x283980, h_nop)  # abort
add_hook(0x1BABB0, h_ecx)  # string init
add_hook(0x1B8130, h_nop)  # string release
add_hook(0x1BAA50, h_nop)  # string op
add_hook(0x27E41F, h_nop)  # InterlockedIncrement wrapper
add_hook(0x27E3D5, h_nop)  # InterlockedDecrement wrapper

# Hook for FS segment access (TLS)
def hook_mem_unmapped(uc, access, address, size, value, user_data):
    # FS segment reads go to TEB
    if 0x7FFD0000 <= address <= 0x7FFFFFFF:
        # Map it
        uc.mem_map(address & ~0xFFF, 0x1000)
        return True
    print(f'  Unmapped access at 0x{address:08X} (size={size})')
    return False

uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)

# Handle FS prefix instructions by hooking the specific TLS access pattern
# The code does: mov reg, fs:[0x2C] to get ThreadLocalStoragePointer
# In Unicorn without proper GDT, FS reads go to address 0 + offset
# We need to map address 0x2C area and put TLS pointer there
uc.mem_map(0, 0x1000)  # Map page 0 for FS:[offset] reads
uc.mem_write(0x2C, struct.pack('<I', 0x2001000))  # FS:[0x2C] = TLS array

cnt = [0]
def hook_code(uc, address, size, user_data):
    cnt[0] += 1
    if address in hooks:
        hooks[address](uc, address, size, user_data)
    if cnt[0] > 5000000:
        print(f'Timeout at 0x{address:08X}')
        uc.emu_stop()

uc.hook_add(UC_HOOK_CODE, hook_code)

# Build credential
cred = halloc(0x60)
cd = bytearray(0x60)
struct.pack_into('<I', cd, 0x00, IB+0x2B9590)
struct.pack_into('<I', cd, 0x08, IB+0x2B9580)
struct.pack_into('<I', cd, 0x38, IB+0x2B9588)
struct.pack_into('<I', cd, 0x10, 1); cd[0x14]=1
struct.pack_into('<I', cd, 0x18, 0x69BACB7C)
struct.pack_into('<I', cd, 0x1C, 0x000BF285)
cd[0x20]=1
struct.pack_into('<I', cd, 0x24, 0x5D36B98E)
struct.pack_into('<I', cd, 0x28, 0x000D4EA6)
struct.pack_into('<I', cd, 0x30, 0x69D4BA80)
struct.pack_into('<I', cd, 0x34, 1)
struct.pack_into('<I', cd, 0x40, 3); cd[0x44]=1
uc.mem_write(cred, bytes(cd))

# Output buffer
out_buf = halloc(32)
uc.mem_write(out_buf+16, struct.pack('<H', 0x0101))

# Call setup
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, cred + 8)
esp -= 4; uc.mem_write(esp, struct.pack('<I', out_buf))
esp -= 4; uc.mem_write(esp, struct.pack('<I', RET))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

print('Emulating FUN_101a9930...')
try:
    uc.emu_start(IB + 0x1A9930, RET, timeout=60000000)
    print(f'Done ({cnt[0]} insns)')
    r = bytes(uc.mem_read(out_buf, 20))
    dp = struct.unpack_from('<I', r, 0)[0]
    dl = struct.unpack_from('<I', r, 8)[0]
    print(f'ptr=0x{dp:08X} len={dl} buf={r.hex()}')
    if dp and 0 < dl < 10000:
        d = bytes(uc.mem_read(dp, dl))
        print(f'DATA ({dl}B): {d.hex()}')
        h = hmac.new(b'\x00\x0E\xE8\x7C\x16\xB1\xE8\x12', d, hashlib.md5).digest()
        print(f'HMAC: {h.hex()}')
        print(f'Want: ad35bcc12654b893f7b5596a8057190c')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'ERR at 0x{eip:08X} (rva 0x{eip-IB:X}) after {cnt[0]}: {e}')
    for n,r in [('EAX',UC_X86_REG_EAX),('ECX',UC_X86_REG_ECX),('ESP',UC_X86_REG_ESP)]:
        print(f'  {n}=0x{uc.reg_read(r):08X}')
