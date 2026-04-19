"""Unicorn emulation: initialize binary serializer, then serialize credential."""
from unicorn import *
from unicorn.x86_const import *
import struct, hmac, hashlib

dll = open('analysis/extracted/nngine.dll', 'rb').read()
IB = 0x10000000

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)  # stack
uc.mem_map(0x1000000, 0x2000000)  # heap (32MB)
uc.mem_map(0, 0x1000)  # FS segment

for va,raw,sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB+va, dll[raw:raw+sz])

hp=[0x1001000]
def ha(n):
    p=hp[0]; hp[0]+=(n+15)&~15
    uc.mem_write(p, b'\x00'*n)
    return p

RET=0x1000100; uc.mem_write(RET, b'\xC3')
END_ADDR=0x1000200; uc.mem_write(END_ADDR, b'\xC3')  # separate end address

# TLS
tls_slot = ha(0x200)
tls_array = ha(0x10)
uc.mem_write(tls_array, struct.pack('<I', tls_slot))
uc.mem_write(0x2C, struct.pack('<I', tls_array))
uc.mem_write(IB+0x312F68, struct.pack('<I', 0))
uc.mem_write(IB+0x312F6C, struct.pack('<I', 0xBB40E64E))  # default security cookie from binary

# Hooks
hooks = {}
def ah(rva, fn): hooks[IB+rva] = fn

def h_malloc(uc,a,s,u):
    esp=uc.reg_read(UC_X86_REG_ESP)
    n=struct.unpack('<I',bytes(uc.mem_read(esp+4,4)))[0]
    p=ha(max(n,16))
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, RET)

def h_realloc(uc,a,s,u):
    esp=uc.reg_read(UC_X86_REG_ESP)
    old=struct.unpack('<I',bytes(uc.mem_read(esp+4,4)))[0]
    n=struct.unpack('<I',bytes(uc.mem_read(esp+8,4)))[0]
    p=ha(max(n,16))
    if old:
        try: uc.mem_write(p, bytes(uc.mem_read(old, min(n,4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX, p)
    uc.reg_write(UC_X86_REG_EIP, RET)

def h_free(uc,a,s,u): uc.reg_write(UC_X86_REG_EIP, RET)
def h_nop1(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX, 1); uc.reg_write(UC_X86_REG_EIP, RET)
def h_nop0(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX, 0); uc.reg_write(UC_X86_REG_EIP, RET)

ah(0x27E4F5, h_malloc)
ah(0x2839F9, h_realloc)
ah(0x2839D1, h_free)
ah(0x27DFE8, h_free)

# Hook encoded pointer decode to return a no-op stub
def h_decode_ptr(uc,a,s,u):
    uc.reg_write(UC_X86_REG_EAX, RET)
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x29D7DD, h_decode_ptr)
ah(0x283980, h_nop1)  # abort

# Patch IAT for Windows API functions

# Scan IAT and patch ALL imports with ret stubs
import_stubs = {}
iat_base_va = 0x2AE000
for i in range(0, 0x2000, 4):
    off = 0x2AD200 + i
    if off + 4 > len(dll): break
    val = struct.unpack_from('<I', dll, off)[0]
    if val > 0x10000 and val < 0x400000:
        name_off = 0x2AD200 + (val - iat_base_va)
        if 0 < name_off < len(dll) - 50:
            try:
                name = dll[name_off+2:name_off+50].split(b'\x00')[0].decode('ascii')
                if name and len(name) > 1:
                    s = ha(16)
                    # Most Windows API functions are stdcall with varying arg counts
                    # Default: ret 4 (1 arg). Special cases below.
                    uc.mem_write(s, b'\x31\xC0\xC2\x04\x00')  # xor eax,eax; ret 4
                    import_stubs[name] = s
                    uc.mem_write(IB + iat_base_va + i, struct.pack('<I', s))
            except:
                pass

# Fix specific imports that need different ret sizes
for name, nargs in [('EnterCriticalSection',1),('LeaveCriticalSection',1),
                     ('InitializeCriticalSection',1),('DeleteCriticalSection',1),
                     ('Sleep',1),('TlsGetValue',1),('TlsSetValue',2),
                     ('GetCurrentThreadId',0),('HeapAlloc',3),('HeapFree',3),
                     ('HeapReAlloc',4),('GetProcessHeap',0),
                     ('VirtualAlloc',4),('VirtualFree',3)]:
    if name in import_stubs:
        s = import_stubs[name]
        ret_bytes = nargs * 4
        if name == 'GetProcessHeap':
            uc.mem_write(s, b'\xB8' + struct.pack('<I', 0xDEAD0000) + b'\xC3')  # mov eax, handle; ret
        elif name in ('HeapAlloc',):
            # HeapAlloc(hHeap, flags, size) -> ptr
            # We hook malloc instead, so this should redirect
            uc.mem_write(s, b'\x31\xC0\xC2' + struct.pack('<H', ret_bytes))
        else:
            uc.mem_write(s, b'\x31\xC0\xC2' + struct.pack('<H', ret_bytes))

print(f'Patched {len(import_stubs)} IAT entries')

def hook_unmapped(uc, access, address, size, value, ud):
    try:
        base = address & ~0xFFF
        uc.mem_map(base, 0x1000)
        uc.mem_write(base, b'\xC3' * 0x1000)
        return True
    except:
        return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

# Pre-map common high addresses
for addr in [0x70000000, 0x77770000, 0xEFFFF000]:
    try:
        uc.mem_map(addr, 0x10000)
        uc.mem_write(addr, b'\xC3' * 0x10000)
    except:
        pass

cnt = [0]
def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        # Outside DLL range — redirect to RET
        if address != RET and address != END_ADDR:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > 10000000:
        print(f'Timeout at 0x{address:08X}')
        uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# Step 1: Initialize the binary serializer via FUN_101b2910
# FUN_101b2910 is fastcall: ECX = serializer object
# It does ret 8, so it expects 8 bytes of stack args (2 dwords)
ser_obj = ha(64)  # serializer object on heap
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, ser_obj)
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)
# Push 2 dummy args + return address (ret 8 cleans 8 bytes after ret addr)
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))  # arg2
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))  # arg1
esp -= 4; uc.mem_write(esp, struct.pack('<I', END_ADDR))  # return addr
uc.reg_write(UC_X86_REG_ESP, esp)

print('Step 1: Initializing serializer (FUN_101b2910)...')
try:
    uc.emu_start(IB + 0x1B2910, END_ADDR, timeout=30000000)
    print(f'  Done ({cnt[0]} insns)')
    ser_data = bytes(uc.mem_read(ser_obj, 64))
    print(f'  Serializer: {ser_data[:32].hex()}')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'  ERR at rva 0x{eip-IB:X} after {cnt[0]}: {e}')
    for n,r in [('EAX',UC_X86_REG_EAX),('ECX',UC_X86_REG_ECX),('ESP',UC_X86_REG_ESP)]:
        print(f'    {n}=0x{uc.reg_read(r):08X}')

# Step 2: Build credential
cred = ha(0x60)
cd = bytearray(0x60)
struct.pack_into('<I', cd, 0x00, IB+0x2B9590)
struct.pack_into('<I', cd, 0x08, IB+0x2B9580)
struct.pack_into('<I', cd, 0x38, IB+0x2B9588)
struct.pack_into('<I', cd, 0x10, 1); cd[0x14] = 1
struct.pack_into('<I', cd, 0x18, 0x69BACB7C)
struct.pack_into('<I', cd, 0x1C, 0x000BF285)
cd[0x20] = 1
struct.pack_into('<I', cd, 0x24, 0x5D36B98E)
struct.pack_into('<I', cd, 0x28, 0x000D4EA6)
struct.pack_into('<I', cd, 0x2C, 1)  # Set device_mgr_extra to 1 (non-zero flag!)
struct.pack_into('<I', cd, 0x30, 0x69D4BA80)
struct.pack_into('<I', cd, 0x34, 1)
struct.pack_into('<I', cd, 0x40, 3)
cd[0x44] = 1
uc.mem_write(cred, bytes(cd))

# Step 3: Call FUN_101b2c30 to serialize
# void __thiscall FUN_101b2c30(int *param_1, int *param_2, int param_3, undefined1 param_4)
# param_1 = serializer (ECX, thiscall)
# param_2 = object to serialize (cred + 8 for vtable2)
# param_3 = version (0 = default)
# param_4 = flags (0)

cnt[0] = 0
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, ser_obj)
# Push args right-to-left: param_4, param_3, param_2, return_addr
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))  # param_4 = 0
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))  # param_3 = 0
esp -= 4; uc.mem_write(esp, struct.pack('<I', cred + 8))  # param_2 = cred vtable2
esp -= 4; uc.mem_write(esp, struct.pack('<I', END_ADDR))  # return addr
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

print(f'\nStep 2: Serializing credential (FUN_101b2c30)...')
try:
    uc.emu_start(IB + 0x1B2C30, END_ADDR, timeout=60000000)
    print(f'  Done ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'  ERR at rva 0x{eip-IB:X} after {cnt[0]}: {e}')

# Step 4: Read the serialized output
# The serializer stores output in its internal buffer.
# FUN_101bd970 returns the buffer data.
# The buffer is at ser_obj + 8 (the stream sub-object).
# Let me read the stream's data.

ser_data = bytes(uc.mem_read(ser_obj, 64))
print(f'  Serializer state: {ser_data[:32].hex()}')

# The stream is at ser_obj + 8. It has:
# [0] = vtable (should be 0x102D9154)
# [4] = data ptr
# [8] = data length
stream = ser_obj + 8
stream_data = bytes(uc.mem_read(stream, 32))
print(f'  Stream: {stream_data[:20].hex()}')

stream_vtable = struct.unpack_from('<I', stream_data, 0)[0]
stream_ptr = struct.unpack_from('<I', stream_data, 4)[0]
stream_len = struct.unpack_from('<I', stream_data, 8)[0]
print(f'  vtable=0x{stream_vtable:08X} ptr=0x{stream_ptr:08X} len={stream_len}')

if stream_ptr and 0 < stream_len < 10000:
    data = bytes(uc.mem_read(stream_ptr, stream_len))
    print(f'  DATA ({stream_len}B): {data.hex()}')
    h = hmac.new(b'\x00\x0E\xE8\x7C\x16\xB1\xE8\x12', data, hashlib.md5).digest()
    print(f'  HMAC: {h.hex()}')
    print(f'  Want: ad35bcc12654b893f7b5596a8057190c')
    print(f'  Match: {h.hex() == "ad35bcc12654b893f7b5596a8057190c"}')
elif stream_ptr:
    # Try reading more data
    raw = bytes(uc.mem_read(stream_ptr, 64))
    print(f'  Raw at stream_ptr: {raw.hex()}')
else:
    # Check if data is elsewhere in the serializer
    for off in range(0, 64, 4):
        val = struct.unpack_from('<I', ser_data, off)[0]
        if 0x1000000 < val < 0x2000000:
            try:
                d = bytes(uc.mem_read(val, 32))
                if any(b != 0 for b in d):
                    print(f'  ser_obj+{off}: ptr=0x{val:08X} data={d.hex()}')
            except:
                pass

# Scan heap for serialized data
print('\nScanning heap for serialized data...')
for addr in range(0x1001000, hp[0], 0x10):
    try:
        d = bytes(uc.mem_read(addr, 16))
        if any(b != 0 and b != 0xC3 for b in d):
            full = bytes(uc.mem_read(addr, min(64, hp[0] - addr)))
            first4 = struct.unpack_from('<I', full, 0)[0]
            if first4 in (IB+0x2B9590, IB+0x2B9580, IB+0x2B9588, IB+0x2D8D68, IB+0x2D9154, IB+0x2B90C0):
                continue
            print(f'  0x{addr:08X}: {full[:48].hex()}')
            for length in range(1, min(33, len(full)+1)):
                h = hmac.new(b'\x00\x0E\xE8\x7C\x16\xB1\xE8\x12', full[:length], hashlib.md5).digest()
                if h.hex() == 'ad35bcc12654b893f7b5596a8057190c':
                    print(f'  *** HMAC MATCH at length {length}! data={full[:length].hex()} ***')
    except:
        pass
