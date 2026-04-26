"""Unicorn: Full emulation of FUN_10094390 (registration response handler)
with detailed tracing to understand why deserialization fails and what
the inner credential contains.
"""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()
deleg_resp = open('analysis/flows_decoded/2026-04-16/736-delegator-resp-decoded.bin', 'rb').read()

TB_CODE = 3745651132643726
TB_SECRET = 3037636188661496
HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)
uc.mem_map(0x1000000, 0x4000000)
uc.mem_map(0, 0x1000)
for a in [0x70000000, 0x77770000]:
    try: uc.mem_map(a, 0x10000); uc.mem_write(a, b'\xC3'*0x10000)
    except: pass

for va, raw, sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB+va, dll[raw:raw+sz])

hp = [0x1001000]
def ha(n):
    p = hp[0]; hp[0] += (n+15)&~15
    uc.mem_write(p, b'\x00'*n)
    return p

RET = 0x1000100; uc.mem_write(RET, b'\xC3')
END = 0x1000200; uc.mem_write(END, b'\xC3')
tls = ha(0x200); tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))
uc.mem_write(IB+0x312F68, struct.pack('<I', 0))
uc.mem_write(IB+0x312F6C, struct.pack('<I', 0xBB40E64E))

# Patch IAT
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
    uc.reg_write(UC_X86_REG_EAX, p); uc.reg_write(UC_X86_REG_EIP, RET)
def hf(uc, a, s, u): uc.reg_write(UC_X86_REG_EIP, RET)
def hr(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    old = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    n = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    p = ha(max(n, 16))
    if old:
        try: uc.mem_write(p, bytes(uc.mem_read(old, min(n, 4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX, p); uc.reg_write(UC_X86_REG_EIP, RET)

ah(0x27E4F5, hm); ah(0x2839F9, hr); ah(0x2839D1, hf); ah(0x27DFE8, hf)
ah(0x283980, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 1), uc.reg_write(UC_X86_REG_EIP, RET)))
ah(0x1B8130, hf)
ah(0x61C2D, hf)

obj_mgr = ha(32); obj_mgr_vt = ha(64)
for i in range(16): uc.mem_write(obj_mgr_vt + i*4, struct.pack('<I', RET))
uc.mem_write(obj_mgr, struct.pack('<I', obj_mgr_vt))
uc.mem_write(IB+0x326D38, struct.pack('<I', obj_mgr))
uc.mem_write(IB+0x316B18, struct.pack('<I', obj_mgr))

def hook_unmapped(uc, access, address, size, value, ud):
    try:
        uc.mem_map(address & ~0xFFF, 0x1000)
        uc.mem_write(address & ~0xFFF, b'\x00'*0x1000)
        return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

# Track calls to key functions
cnt = [0]
call_log = []

def hook_code(uc, address, size, ud):
    cnt[0] += 1
    rva = address - IB
    
    if address in hooks and hooks[address]:
        hooks[address](uc, address, size, ud)
        return
    
    # Track key function entries
    if rva == 0x1A99B0:  # FUN_101a99b0 (deserializer)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        call_log.append(f'FUN_101a99b0 (deserializer) ECX=0x{ecx:08X}')
    elif rva == 0xA4BE0:  # FUN_100a4be0 (inner cred creator)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        p2 = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
        call_log.append(f'FUN_100a4be0 (inner cred) ECX=0x{ecx:08X} param2=0x{p2:08X}')
        # Dump param_2 contents
        data = bytes(uc.mem_read(p2, 0x28))
        for j in range(0, 0x28, 4):
            v = struct.unpack_from('<I', data, j)[0]
            call_log.append(f'  param2+0x{j:02X}: 0x{v:08X}')
    elif rva == 0xA4750:  # FUN_100a4750 (inner cred allocator)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        call_log.append(f'FUN_100a4750 (alloc inner) ECX=0x{ecx:08X}')
    elif rva == 0xA4BB0:  # FUN_100a4bb0 (get inner[7])
        ecx = uc.reg_read(UC_X86_REG_ECX)
        val = struct.unpack('<I', bytes(uc.mem_read(ecx + 0x1c, 4)))[0]
        call_log.append(f'FUN_100a4bb0 ECX=0x{ecx:08X} -> [0x1C]=0x{val:08X}')
    
    if address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    
    if cnt[0] > 5000000: uc.emu_stop()

uc.hook_add(UC_HOOK_CODE, hook_code)

# Build device object
device_obj = ha(0x60)
uc.mem_write(device_obj, struct.pack('<I', IB + 0x2B9688))
uc.mem_write(device_obj + 0x38, struct.pack('<I', 0))
uc.mem_write(device_obj + 0x3C, struct.pack('<I', 0))

# Build param_2 (response context)
# FUN_10094390 reads: param_2+0x38 (char), param_2+0x30 (int len), param_2+0x2c (int data_ptr)
resp_data = ha(len(deleg_resp) + 16)
uc.mem_write(resp_data, deleg_resp)

param2 = ha(0x40)
uc.mem_write(param2 + 0x2C, struct.pack('<I', resp_data))
uc.mem_write(param2 + 0x30, struct.pack('<I', len(deleg_resp)))
uc.mem_write(param2 + 0x38, b'\x01')

# Call FUN_10094390
esp = 0x5FE800
uc.reg_write(UC_X86_REG_ECX, device_obj)
esp -= 4; uc.mem_write(esp, struct.pack('<I', param2))
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp)

cnt[0] = 0
try:
    uc.emu_start(IB + 0x94390, END, timeout=120000000)
    print(f'Completed ({cnt[0]} insns)')
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at RVA 0x{eip-IB:X} after {cnt[0]}: {e}')

ret = uc.reg_read(UC_X86_REG_EAX)
print(f'Return: {ret}')

inner_ptr = struct.unpack('<I', bytes(uc.mem_read(device_obj + 0x3C, 4)))[0]
print(f'device_obj[0xF] = 0x{inner_ptr:08X}')

print(f'\nCall log ({len(call_log)} entries):')
for entry in call_log:
    print(f'  {entry}')

if inner_ptr:
    print(f'\nInner credential at 0x{inner_ptr:08X}:')
    inner = bytes(uc.mem_read(inner_ptr, 0x28))
    for i in range(0, 0x28, 4):
        v = struct.unpack_from('<I', inner, i)[0]
        print(f'  +0x{i:02X}: 0x{v:08X}')
    
    val_1c = struct.unpack_from('<I', inner, 0x1C)[0]
    print(f'\n  inner[7] = 0x{val_1c:08X}')
    if 0x01000000 <= val_1c <= 0x05000000:
        print(f'  Looks like a heap pointer! Reading sub-object...')
        sub = bytes(uc.mem_read(val_1c, 0x30))
        for i in range(0, 0x30, 4):
            v = struct.unpack_from('<I', sub, i)[0]
            print(f'    sub+0x{i:02X}: 0x{v:08X}')
