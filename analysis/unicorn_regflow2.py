"""Unicorn: Emulate FUN_10094390 (registration response handler) with real
delegator response data, then run FUN_101aa050 to get the correct HMAC.

This feeds the actual igo-binary delegator response into the DLL's own
deserializer, letting it populate the credential store correctly.
"""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()
deleg_resp = open('analysis/flows_decoded/2026-04-16/736-delegator-resp-decoded.bin', 'rb').read()

HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954
TB_CODE = 3745651132643726

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

# Hook FUN_101b8130 (string cleanup) - no-op
ah(0x1B8130, hf)

# Hook FUN_10061c2d (iterator step) - no-op, skip the loop
ah(0x61C2D, hf)

# Hook FUN_101babb0 (stream init) - let it run natively (it's needed for deserializer)
# Don't hook it

# Hook FUN_100a4750 (create inner credential container)
# This is complex - let it run natively but hook its dependencies
ah(0x5E8C0, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, ha(16)), uc.reg_write(UC_X86_REG_EIP, RET)))  # FUN_1005e8c0
ah(0x91A20, lambda uc,a,s,u: uc.reg_write(UC_X86_REG_EIP, RET))  # FUN_10091a20
ah(0x91100, lambda uc,a,s,u: uc.reg_write(UC_X86_REG_EIP, RET))  # FUN_10091100

# Global object manager
obj_mgr = ha(32)
obj_mgr_vt = ha(64)
for i in range(16):
    uc.mem_write(obj_mgr_vt + i*4, struct.pack('<I', RET))
uc.mem_write(obj_mgr, struct.pack('<I', obj_mgr_vt))
uc.mem_write(IB+0x326D38, struct.pack('<I', obj_mgr))

# Global singleton for credential store
uc.mem_write(IB+0x316B18, struct.pack('<I', obj_mgr))

def hook_unmapped(uc, access, address, size, value, ud):
    try:
        uc.mem_map(address & ~0xFFF, 0x1000)
        uc.mem_write(address & ~0xFFF, b'\xC3'*0x1000)
        return True
    except:
        return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt = [0]
max_insns = 500000
crash_info = [None]

def hook_code(uc, address, size, ud):
    cnt[0] += 1
    if address in hooks and hooks[address]:
        hooks[address](uc, address, size, ud)
    elif address < IB or address >= IB + 0x400000:
        if address != RET and address != END:
            uc.reg_write(UC_X86_REG_EIP, RET)
    if cnt[0] > max_insns:
        crash_info[0] = f'Instruction limit ({max_insns}) at RVA 0x{address-IB:X}'
        uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# ============================================================
# Step 1: Call FUN_10094390 with delegator response data
# ============================================================
print("=== Step 1: Emulate FUN_10094390 (registration response handler) ===")

# Build param_1 (device object, 0x54 bytes)
device_obj = ha(0x60)
dev_vt = IB + 0x2B9688  # device object vtable
uc.mem_write(device_obj, struct.pack('<I', dev_vt))
# device_obj[6] = param_1+6 used by FUN_100a4750 - set to some name data
uc.mem_write(device_obj + 0x18, b'\x00' * 16)  # name placeholder
# device_obj[0xE] = state (0 = initial)
uc.mem_write(device_obj + 0x38, struct.pack('<I', 0))
# device_obj[0xF] = inner credential (NULL initially)
uc.mem_write(device_obj + 0x3C, struct.pack('<I', 0))

# Build param_2 (response context)
# param_2 + 0x2c: data pointer
# param_2 + 0x30: data length
# param_2 + 0x38: char (non-zero = data present)
resp_ctx = ha(0x40)
resp_data = ha(len(deleg_resp) + 16)
uc.mem_write(resp_data, deleg_resp)
uc.mem_write(resp_ctx + 0x2C, struct.pack('<I', resp_data))
uc.mem_write(resp_ctx + 0x30, struct.pack('<I', len(deleg_resp)))
uc.mem_write(resp_ctx + 0x38, b'\x01')  # data present flag

print(f"  device_obj at 0x{device_obj:08X}")
print(f"  resp_ctx at 0x{resp_ctx:08X}")
print(f"  resp_data at 0x{resp_data:08X} ({len(deleg_resp)} bytes)")

# Call FUN_10094390(device_obj, resp_ctx)
# thiscall: ECX = device_obj (param_1), stack arg = resp_ctx (param_2)
esp = 0x5FF000
uc.reg_write(UC_X86_REG_ECX, device_obj)
esp -= 4; uc.mem_write(esp, struct.pack('<I', resp_ctx))  # param_2
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))        # return address
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

cnt[0] = 0
crash_info[0] = None

try:
    uc.emu_start(IB + 0x94390, END, timeout=60000000)
    if crash_info[0]:
        print(f"  STOPPED: {crash_info[0]}")
    else:
        print(f"  COMPLETED ({cnt[0]} insns)")
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f"  CRASH at RVA 0x{eip-IB:X} after {cnt[0]} insns: {e}")

# Read the result
eax = uc.reg_read(UC_X86_REG_EAX)
print(f"  Return value: {eax}")

# Check device_obj[0xF] (inner credential pointer)
inner_ptr = struct.unpack('<I', bytes(uc.mem_read(device_obj + 0x3C, 4)))[0]
print(f"  device_obj[0xF] = 0x{inner_ptr:08X}")

if inner_ptr:
    # Read inner credential (0x28 bytes)
    inner = bytes(uc.mem_read(inner_ptr, 0x30))
    print(f"\n  Inner credential at 0x{inner_ptr:08X}:")
    for i in range(0, 0x28, 4):
        v = struct.unpack_from('<I', inner, i)[0]
        label = ''
        if i == 0x00: label = 'vtable'
        elif i == 0x10: label = 'Code_lo?'
        elif i == 0x14: label = 'Code_hi?'
        elif i == 0x1C: label = 'Secret_lo? / sub_obj_ptr?'
        elif i == 0x20: label = 'Secret_hi?'
        print(f"    +0x{i:02X}: 0x{v:08X}  {label}")

    # Check if inner[7] (offset 0x1C) is a pointer
    sub_ptr = struct.unpack_from('<I', inner, 0x1C)[0]
    if 0x01000000 <= sub_ptr <= 0x02000000:
        print(f"\n  Sub-object at 0x{sub_ptr:08X}:")
        sub = bytes(uc.mem_read(sub_ptr, 0x30))
        for i in range(0, 0x30, 4):
            v = struct.unpack_from('<I', sub, i)[0]
            label = ''
            if i == 0x10: label = '<-- *(iVar5+0x10) = Agent field'
            elif i == 0x14: label = '<-- *(iVar5+0x14)'
            elif i == 0x18: label = '<-- *(iVar5+0x18)'
            print(f"      +0x{i:02X}: 0x{v:08X}  {label}")

        # Read the 8-byte value at sub_obj+0x10
        agent_lo = struct.unpack_from('<I', sub, 0x10)[0]
        agent_hi = struct.unpack_from('<I', sub, 0x14)[0]
        agent = agent_lo | (agent_hi << 32)
        print(f"\n  Agent value: 0x{agent:016X} = {agent}")
        print(f"  tb_code:     0x{TB_CODE:016X} = {TB_CODE}")
        print(f"  hu_code:     0x{HU_CODE:016X} = {HU_CODE}")
        if agent == TB_CODE: print("  Agent = tb_code")
        elif agent == HU_CODE: print("  Agent = hu_code")
        else: print(f"  Agent = UNKNOWN VALUE!")
else:
    print("  Inner credential is NULL - deserialization may have failed")
    # Dump the deserialized local variables area
    # They're on the stack - let's check what FUN_100a4be0 would have received
    print("  Checking stack area for deserialized data...")

# ============================================================
# Step 2: Run FUN_101aa050 with the populated device object
# ============================================================
if inner_ptr:
    print("\n=== Step 2: Emulate FUN_101aa050 (credential constructor) ===")

    # Set up device manager singleton
    uc.mem_write(IB + 0x31445C, struct.pack('<I', 1))

    # Hook FUN_10011dd0 to return our device_obj
    def h_lookup(uc, a, s, u):
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
        out_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
        out_ref = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
        uc.mem_write(out_ptr, struct.pack('<I', device_obj))
        uc.mem_write(out_ref, struct.pack('<I', 1))
        uc.mem_write(device_obj + 8, struct.pack('<I', 2))
        uc.reg_write(UC_X86_REG_ESP, esp + 16)
        uc.reg_write(UC_X86_REG_EIP, ret)
    ah(0x11DD0, h_lookup)

    ah(0x1BAD80, hf)  # string lookup
    ah(0x1D2630, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 0x69E37F31), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x312A0, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, ha(16)), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x96700, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, uc.reg_read(UC_X86_REG_ECX)), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x157030, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 1), uc.reg_write(UC_X86_REG_EIP, RET)))

    hmac_result_buf = ha(32)
    ah(0x156C60, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, hmac_result_buf), uc.reg_write(UC_X86_REG_EIP, RET)))

    # Capture HMAC
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
        result = hmac.new(key, data, hashlib.md5).digest()
        print(f"  HMAC key ({key_len}B): {key.hex()}")
        print(f"  HMAC data ({data_len}B): {data.hex()}")
        print(f"  HMAC result: {result.hex()}")
        print(f"  Want:        ad35bcc12654b893f7b5596a8057190c")
        print(f"  Match: {result.hex() == 'ad35bcc12654b893f7b5596a8057190c'}")
        uc.mem_write(out_ptr, result)
        uc.mem_write(hmac_result_buf, result)
        uc.reg_write(UC_X86_REG_EAX, 1)
        uc.reg_write(UC_X86_REG_ESP, esp + 24)
        uc.reg_write(UC_X86_REG_EIP, ret)
    ah(0x1AA3A0, h_hmac)

    param1 = ha(8)
    param2 = ha(8)
    uc.mem_write(param1, struct.pack('<II', HU_CODE & 0xFFFFFFFF, (HU_CODE >> 32) & 0xFFFFFFFF))
    uc.mem_write(param2, struct.pack('<II', HU_SECRET & 0xFFFFFFFF, (HU_SECRET >> 32) & 0xFFFFFFFF))

    esp = 0x5FF000
    esp -= 4; uc.mem_write(esp, struct.pack('<I', param2))
    esp -= 4; uc.mem_write(esp, struct.pack('<I', param1))
    esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

    cnt[0] = 0
    max_insns = 500000
    crash_info[0] = None

    try:
        uc.emu_start(IB + 0x1AA050, END, timeout=60000000)
        if crash_info[0]:
            print(f"  STOPPED: {crash_info[0]}")
        else:
            print(f"  COMPLETED ({cnt[0]} insns)")
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f"  CRASH at RVA 0x{eip-IB:X} after {cnt[0]} insns: {e}")
