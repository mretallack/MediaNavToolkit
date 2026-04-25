"""Trace every byte written by the serializer to the output buffer."""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

TB_CODE = 3745651132643726
HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)
uc.mem_map(0x1000000, 0x2000000)
uc.mem_map(0, 0x1000)

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
    p = ha(max(n, 16))
    uc.reg_write(UC_X86_REG_EAX, p)
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

# Build credential with known values
CRED_BASE = ha(0x80)
cd = bytearray(0x80)
struct.pack_into('<I', cd, 0x00, IB+0x2B9590)
struct.pack_into('<I', cd, 0x08, IB+0x2B9580)
struct.pack_into('<I', cd, 0x10, 1)  # type
struct.pack_into('<I', cd, 0x14, 1)  # flag (Code present)
struct.pack_into('<I', cd, 0x18, HU_CODE & 0xFFFFFFFF)
struct.pack_into('<I', cd, 0x1C, (HU_CODE >> 32) & 0xFFFFFFFF)
struct.pack_into('<I', cd, 0x20, 1)  # flag (Agent present)
struct.pack_into('<I', cd, 0x24, TB_CODE & 0xFFFFFFFF)
struct.pack_into('<I', cd, 0x28, (TB_CODE >> 32) & 0xFFFFFFFF)
struct.pack_into('<I', cd, 0x2C, 1)  # flag (unknown present)
struct.pack_into('<I', cd, 0x30, 0x69E37F31)  # timestamp
struct.pack_into('<I', cd, 0x34, 1)  # flag (timestamp present)
struct.pack_into('<I', cd, 0x38, IB+0x2B9588)
struct.pack_into('<I', cd, 0x40, 3)  # mode
struct.pack_into('<I', cd, 0x44, 1)
uc.mem_write(CRED_BASE, bytes(cd))

# Track writes to the output buffer area
write_log = []

def hook_unmapped(uc, access, address, size, value, ud):
    try: uc.mem_map(address & ~0xFFF, 0x1000); uc.mem_write(address & ~0xFFF, b'\xC3'*0x1000); return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt = [0]
def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks and hooks[address]:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > 5000000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# Init serializer
so = ha(64)
uc.reg_write(UC_X86_REG_ECX, so)
esp = 0x5FF000
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))
esp -= 4; uc.mem_write(esp, struct.pack('<I', 0))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp+0x200)
try: uc.emu_start(IB+0x1B2910, END, timeout=30000000)
except UcError as e: print(f'Init err: {e}')

# Read the serializer's internal buffer pointer
# The serializer object has a stream at offset 8
# The stream has a buffer pointer
so_data = bytes(uc.mem_read(so, 64))
print(f'Serializer object:')
for i in range(0, 64, 4):
    v = struct.unpack_from('<I', so_data, i)[0]
    print(f'  +0x{i:02X}: 0x{v:08X}')

# Serialize
out_buf = ha(32)
uc.mem_write(out_buf + 16, struct.pack('<H', 0x0101))

esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, CRED_BASE + 8)
esp -= 4; uc.mem_write(esp, struct.pack('<I', out_buf))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp+0x200)
cnt[0] = 0

# Hook FUN_101a9e80 (write_1bit_lsb) to trace bit writes
bit_writes = []
def h_write_bit(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    # The bit value is in the first arg (after return addr)
    # Actually this is a thiscall - ECX = stream, param = bit value
    # Let me just trace the call
    bit_val = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    eip = uc.reg_read(UC_X86_REG_EIP)
    # Don't hook - let it run natively, just log
    bit_writes.append(bit_val)
# Don't hook - just trace

print(f'\nRunning serializer...')
try:
    uc.emu_start(IB+0x1A9930, END, timeout=120000000)
    print(f'COMPLETED ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at RVA 0x{eip-IB:X} after {cnt[0]}: {e}')

# Read output
ob = bytes(uc.mem_read(out_buf, 20))
data_ptr = struct.unpack_from('<I', ob, 0)[0]
data_len = struct.unpack_from('<I', ob, 8)[0]
print(f'\nOutput: ptr=0x{data_ptr:08X} len={data_len}')
if data_ptr and 0 < data_len < 10000:
    data = bytes(uc.mem_read(data_ptr, data_len))
    print(f'Data ({data_len}B): {data.hex()}')
    
    # Decode the bitstream
    print(f'\nBitstream analysis:')
    for i, b in enumerate(data):
        print(f'  Byte {i}: 0x{b:02X} = {b:08b}')
    
    # The first byte is the presence bitmap
    # Let's decode it
    pres = data[0]
    print(f'\nPresence byte: 0x{pres:02X} = {pres:08b}')
    
    # Try different HMAC computations
    hu_secret_be = bytes.fromhex('000ee87c16b1e812')
    
    # Standard format
    h = hmac.new(hu_secret_be, data, hashlib.md5).digest()
    print(f'\nHMAC of full data: {h.hex()}')
    print(f'Want: ad35bcc12654b893f7b5596a8057190c')
    
    # Try without presence byte
    h2 = hmac.new(hu_secret_be, data[1:], hashlib.md5).digest()
    print(f'HMAC without presence: {h2.hex()}')
    
    # Try with different presence bytes
    for p in [0xC4, 0x04, 0x84, 0x44, 0xC0, 0x40, 0x80, 0x00]:
        d = bytes([p]) + data[1:]
        h3 = hmac.new(hu_secret_be, d, hashlib.md5).digest()
        if h3.hex() == 'ad35bcc12654b893f7b5596a8057190c':
            print(f'MATCH with presence 0x{p:02X}!')
