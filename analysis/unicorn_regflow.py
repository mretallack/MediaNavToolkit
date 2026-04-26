"""Unicorn: Emulate FUN_101aa050 with proper device manager credential chain.

Goal: Find the correct HMAC input by properly populating the inner credential
chain that FUN_101aa050 reads from.

Chain: device_obj[0xF] -> inner_cred -> inner_cred[7] -> sub_obj -> sub_obj+0x10

The serialize3 script hardcoded tb_code at puVar9[9..10], but the real DLL
reads from the device manager chain. This script sets up the full chain
and captures the exact serialized bytes passed to HMAC-MD5.
"""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

# Known values
TB_CODE = 3745651132643726    # 0x000D4EA65D36B98E
TB_SECRET = 3037636188661496  # 0x000ACAB6C9FB66F8
HU_CODE = 3362879562238844    # 0x000BF28569BACB7C
HU_SECRET = 4196269328295954  # 0x000EE87C16B1E812

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()

# --- Setup Unicorn ---
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(IB, 4*1024*1024)
uc.mem_map(0x500000, 0x100000)  # stack
uc.mem_map(0x1000000, 0x2000000) # heap
uc.mem_map(0, 0x1000)           # TLS page

# Map DLL sections
for va, raw, sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB+va, dll[raw:raw+sz])

# Heap allocator
hp = [0x1001000]
def ha(n):
    p = hp[0]; hp[0] += (n+15) & ~15
    uc.mem_write(p, b'\x00'*n)
    return p

RET = 0x1000100; uc.mem_write(RET, b'\xC3')
END = 0x1000200; uc.mem_write(END, b'\xC3')

# TLS setup
tls = ha(0x200); tla = ha(0x10)
uc.mem_write(tla, struct.pack('<I', tls))
uc.mem_write(0x2C, struct.pack('<I', tla))

# Security cookie
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

# --- Hooks ---
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

ah(0x27E4F5, hm)   # malloc
ah(0x2839F9, hr)    # realloc
ah(0x2839D1, hf)    # free
ah(0x27DFE8, hf)    # free
ah(0x283980, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 1), uc.reg_write(UC_X86_REG_EIP, RET)))

# Hook FUN_101bad80 (string lookup) - no-op
def h_strlookup(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x1BAD80, h_strlookup)

# Hook FUN_101b8130 (cleanup) - no-op
ah(0x1B8130, h_strlookup)

# Hook FUN_10011dd0 (credential store lookup)
device_obj = None  # will be set up below
def h_lookup(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
    out_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    out_ref = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    # Write device_obj pointer and refcount
    uc.mem_write(out_ptr, struct.pack('<I', device_obj))
    uc.mem_write(out_ref, struct.pack('<I', 1))
    # Also set up refcount in the device object itself
    uc.mem_write(device_obj + 8, struct.pack('<I', 2))  # refcount
    uc.reg_write(UC_X86_REG_ESP, esp + 16)  # ret + 3 args (cdecl? or stdcall?)
    uc.reg_write(UC_X86_REG_EIP, ret)
ah(0x11DD0, h_lookup)

# Hook FUN_101d2630 (timer) - return known timestamp
TIMESTAMP = 0x69E37F31  # ~April 2026
def h_timer(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EAX, TIMESTAMP)
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x1D2630, h_timer)

# Hook FUN_100312a0 (handle getter) - return dummy
def h_handle(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EAX, ha(16))
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x312A0, h_handle)

# Hook FUN_10096700 (singleton constructor) - return ecx
def h_singleton(uc, a, s, u):
    ecx = uc.reg_read(UC_X86_REG_ECX)
    uc.reg_write(UC_X86_REG_EAX, ecx)
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x96700, h_singleton)

# Hook FUN_10157030 (check if HMAC result valid) - return true
def h_check(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EAX, 1)
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x157030, h_check)

# Hook FUN_10156c60 (get HMAC result buffer) - return pointer to HMAC output
hmac_result_buf = ha(32)
def h_gethmac(uc, a, s, u):
    uc.reg_write(UC_X86_REG_EAX, hmac_result_buf)
    uc.reg_write(UC_X86_REG_EIP, RET)
ah(0x156C60, h_gethmac)

# Capture HMAC-MD5 input
hmac_captures = []
def h_hmac(uc, a, s, u):
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
    out_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    key_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    key_len = struct.unpack('<I', bytes(uc.mem_read(esp+12, 4)))[0]
    data_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+16, 4)))[0]
    data_len = struct.unpack('<I', bytes(uc.mem_read(esp+20, 4)))[0]
    
    key = bytes(uc.mem_read(key_ptr, key_len))
    data = bytes(uc.mem_read(data_ptr, data_len))
    
    print(f'\n=== HMAC-MD5 CAPTURED ===')
    print(f'Key ({key_len}B): {key.hex()}')
    print(f'Data ({data_len}B): {data.hex()}')
    
    result = hmac.new(key, data, hashlib.md5).digest()
    print(f'Result: {result.hex()}')
    print(f'Want:   ad35bcc12654b893f7b5596a8057190c')
    print(f'Match:  {result.hex() == "ad35bcc12654b893f7b5596a8057190c"}')
    
    hmac_captures.append({'key': key, 'data': data, 'result': result})
    
    # Write result
    uc.mem_write(out_ptr, result)
    uc.mem_write(hmac_result_buf, result)
    
    uc.reg_write(UC_X86_REG_EAX, 1)
    uc.reg_write(UC_X86_REG_ESP, esp + 24)
    uc.reg_write(UC_X86_REG_EIP, ret)
ah(0x1AA3A0, h_hmac)

# Hook the serializer FUN_101a9930
ser_captures = []
def h_serialize(uc, a, s, u):
    """Hook FUN_101a9930 - capture the credential object being serialized."""
    ecx = uc.reg_read(UC_X86_REG_ECX)
    esp = uc.reg_read(UC_X86_REG_ESP)
    
    # Read the credential object (vtable2 interface, ECX = cred+8)
    cred_base = ecx - 8
    cred_data = bytes(uc.mem_read(cred_base, 0x60))
    
    print(f'\n=== SERIALIZER INPUT (cred at 0x{cred_base:08X}) ===')
    for i in range(0, min(len(cred_data), 0x58), 4):
        v = struct.unpack_from('<I', cred_data, i)[0]
        print(f'  +0x{i:02X} [{i//4:2d}]: 0x{v:08X}', end='')
        if i == 0x00: print(' vtable1', end='')
        elif i == 0x08: print(' vtable2', end='')
        elif i == 0x10: print(' type', end='')
        elif i == 0x18: print(f' Code_lo (hu_code_lo=0x{HU_CODE & 0xFFFFFFFF:08X})', end='')
        elif i == 0x1C: print(f' Code_hi (hu_code_hi=0x{(HU_CODE >> 32) & 0xFFFFFFFF:08X})', end='')
        elif i == 0x24: print(' Agent_lo (from device mgr)', end='')
        elif i == 0x28: print(' Agent_hi (from device mgr)', end='')
        elif i == 0x2C: print(' unknown field', end='')
        elif i == 0x30: print(' timestamp', end='')
        elif i == 0x38: print(' vtable3', end='')
        elif i == 0x40: print(' mode', end='')
        print()
    
    ser_captures.append(cred_data)
    # Don't hook - let it run natively
ah(0x1A9930, None)  # placeholder, we'll trace instead

# Unmapped memory handler
def hook_unmapped(uc, access, address, size, value, ud):
    try:
        uc.mem_map(address & ~0xFFF, 0x1000)
        uc.mem_write(address & ~0xFFF, b'\xC3' * 0x1000)
        return True
    except:
        return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt = [0]
def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks and hooks[address]:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > 5000000:
        uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)


def build_credential_chain(code_val, secret_val, label):
    """Build the device manager credential chain with given Code/Secret.
    
    Chain: device_obj[0xF] -> inner_cred -> inner_cred[7] -> sub_obj -> sub_obj+0x10
    
    FUN_100a4be0 creates inner_cred (0x28 bytes):
      [0] vtable PTR_FUN_102b02d4
      [1] presence byte
      [2] stream (from FUN_101baa50)
      [3] presence byte 2
      [4..5] Code (8 bytes)
      [6] unknown
      [7..8] Secret (8 bytes) -- BUT this might be a POINTER to sub-object
      [9] unknown
    
    FUN_100a4bb0 returns inner_cred[7] (value at offset 0x1C)
    FUN_101aa050 reads *(iVar5 + 0x10) from the returned value
    
    If inner_cred[7] is a raw value, *(value + 0x10) makes no sense.
    So inner_cred[7] must be a POINTER to a sub-object.
    """
    print(f'\n=== Building credential chain: {label} ===')
    print(f'  Code: {code_val} (0x{code_val:016X})')
    print(f'  Secret: {secret_val} (0x{secret_val:016X})')
    
    # Create sub-object that inner_cred[7] points to
    # This sub-object has Code at offset 0x10 and Secret at offset 0x1C
    sub_obj = ha(0x40)
    sub_data = bytearray(0x40)
    struct.pack_into('<I', sub_data, 0x00, IB + 0x2B02D4)  # vtable
    # The sub-object fields - we don't know the exact layout
    # But FUN_101aa050 reads *(iVar5 + 0x10) as 8 bytes
    # Let's try putting Code at offset 0x10
    struct.pack_into('<I', sub_data, 0x10, code_val & 0xFFFFFFFF)
    struct.pack_into('<I', sub_data, 0x14, (code_val >> 32) & 0xFFFFFFFF)
    struct.pack_into('<I', sub_data, 0x18, 1)  # unknown field
    struct.pack_into('<I', sub_data, 0x1C, secret_val & 0xFFFFFFFF)
    struct.pack_into('<I', sub_data, 0x20, (secret_val >> 32) & 0xFFFFFFFF)
    uc.mem_write(sub_obj, bytes(sub_data))
    
    # Create inner credential (0x28 bytes)
    inner_cred = ha(0x30)
    ic_data = bytearray(0x30)
    struct.pack_into('<I', ic_data, 0x00, IB + 0x2B02D4)  # vtable
    ic_data[0x04] = 1  # presence
    ic_data[0x0C] = 1  # presence 2
    struct.pack_into('<I', ic_data, 0x10, code_val & 0xFFFFFFFF)  # Code lo
    struct.pack_into('<I', ic_data, 0x14, (code_val >> 32) & 0xFFFFFFFF)  # Code hi
    struct.pack_into('<I', ic_data, 0x18, 1)  # unknown
    struct.pack_into('<I', ic_data, 0x1C, sub_obj)  # POINTER to sub-object
    struct.pack_into('<I', ic_data, 0x20, 0)  # high word (pointer is 32-bit)
    struct.pack_into('<I', ic_data, 0x24, 0)  # unknown
    uc.mem_write(inner_cred, bytes(ic_data))
    
    # Create device object (0x54 bytes)
    dev_obj = ha(0x60)
    do_data = bytearray(0x60)
    struct.pack_into('<I', do_data, 0x00, IB + 0x2B9688)  # vtable
    struct.pack_into('<I', do_data, 0x08, 2)  # refcount
    struct.pack_into('<I', do_data, 0x3C, inner_cred)  # [0xF] = inner credential ptr
    uc.mem_write(dev_obj, bytes(do_data))
    
    print(f'  device_obj at 0x{dev_obj:08X}')
    print(f'  inner_cred at 0x{inner_cred:08X}')
    print(f'  sub_obj at 0x{sub_obj:08X}')
    print(f'  device_obj[0xF] = 0x{inner_cred:08X}')
    print(f'  inner_cred[7] = 0x{sub_obj:08X} (pointer to sub_obj)')
    print(f'  sub_obj+0x10 = 0x{code_val & 0xFFFFFFFF:08X} 0x{(code_val >> 32) & 0xFFFFFFFF:08X}')
    
    return dev_obj


def run_test(code_val, secret_val, label):
    """Run FUN_101aa050 with given credential values."""
    global device_obj, cnt
    
    device_obj = build_credential_chain(code_val, secret_val, label)
    
    # Set up globals
    uc.mem_write(IB + 0x31445C, struct.pack('<I', 1))  # device manager singleton (non-zero)
    uc.mem_write(IB + 0x326D38, struct.pack('<I', ha(16)))  # global object manager
    
    # Set up object manager vtable
    obj_mgr = struct.unpack('<I', bytes(uc.mem_read(IB + 0x326D38, 4)))[0]
    obj_mgr_vtable = ha(32)
    uc.mem_write(obj_mgr, struct.pack('<I', obj_mgr_vtable))
    # vtable[2] (+0x08) = create method, vtable[7] (+0x1C) = destroy method
    for i in range(8):
        uc.mem_write(obj_mgr_vtable + i*4, struct.pack('<I', RET))
    
    # Prepare params: param_1 = &hu_code, param_2 = &hu_secret
    param1 = ha(8)
    param2 = ha(8)
    uc.mem_write(param1, struct.pack('<II', HU_CODE & 0xFFFFFFFF, (HU_CODE >> 32) & 0xFFFFFFFF))
    uc.mem_write(param2, struct.pack('<II', HU_SECRET & 0xFFFFFFFF, (HU_SECRET >> 32) & 0xFFFFFFFF))
    
    # Call FUN_101aa050(param_1, param_2)
    esp = 0x5FF000
    esp -= 4; uc.mem_write(esp, struct.pack('<I', param2))  # param_2
    esp -= 4; uc.mem_write(esp, struct.pack('<I', param1))  # param_1
    esp -= 4; uc.mem_write(esp, struct.pack('<I', END))      # return address
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x200)
    
    cnt[0] = 0
    hmac_captures.clear()
    
    print(f'\nRunning FUN_101aa050...')
    try:
        uc.emu_start(IB + 0x1AA050, END, timeout=30000000)
        print(f'COMPLETED ({cnt[0]} insns)')
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f'Crash at RVA 0x{eip-IB:X} after {cnt[0]} insns: {e}')
    
    # Read result
    result = uc.reg_read(UC_X86_REG_EAX)
    if result:
        print(f'\nCredential object at 0x{result:08X}:')
        cred = bytes(uc.mem_read(result, 0x58))
        for i in range(0, 0x58, 4):
            v = struct.unpack_from('<I', cred, i)[0]
            label_str = ''
            if i == 0x18: label_str = f' Code_lo'
            elif i == 0x1C: label_str = f' Code_hi'
            elif i == 0x24: label_str = f' Agent_lo (from chain)'
            elif i == 0x28: label_str = f' Agent_hi (from chain)'
            elif i == 0x30: label_str = f' timestamp'
            elif i == 0x40: label_str = f' mode'
            print(f'  +0x{i:02X}: 0x{v:08X}{label_str}')
    
    return hmac_captures


# Test 1: TB credentials in the chain (first registration)
print('='*60)
print('TEST 1: TB credentials in device manager chain')
print('='*60)
caps1 = run_test(TB_CODE, TB_SECRET, "TB credentials")

# Test 2: HU credentials in the chain (delegator response)
print('\n' + '='*60)
print('TEST 2: HU credentials in device manager chain')
print('='*60)
caps2 = run_test(HU_CODE, HU_SECRET, "HU credentials")

# Summary
print('\n' + '='*60)
print('SUMMARY')
print('='*60)
target = 'ad35bcc12654b893f7b5596a8057190c'
for i, caps in enumerate([caps1, caps2], 1):
    for j, c in enumerate(caps):
        match = c['result'].hex() == target
        print(f'Test {i} HMAC {j}: {c["result"].hex()} {"✓ MATCH!" if match else "✗ no match"}')
        print(f'  Key: {c["key"].hex()}')
        print(f'  Data ({len(c["data"])}B): {c["data"].hex()}')
