"""Unicorn: Emulate FUN_10094390 with correct stack frame.

The key insight from disassembly:
- ECX for FUN_101babb0 = EBP-0x3C (stream object)
- ECX for FUN_101a99b0 = EBP-0x44 (deserialized object, vtable at [0])
- ECX for FUN_100a4be0 = device_obj[0x3C] (inner credential)
  with param = EBP-0x44 (deserialized object)

Stack layout (from EBP):
  -0x44: vtable PTR_FUN_102b02d4
  -0x40: presence byte 1
  -0x3C: stream vtable (set by FUN_101babb0)
  -0x38: presence byte 2
  -0x34: 8 bytes field (xmm0 zeroed)
  -0x2C: presence byte 3
  -0x28: 8 bytes field (xmm0 zeroed)
  -0x20: presence byte 4
  -0x1C: deserializer state (0)
  -0x18: data_ptr
  -0x14: data_ptr (current pos)
  -0x10: data_end
  -0x0C: 0
  -0x08: data_end
  -0x04: 1
"""
import struct, hmac, hashlib
from unicorn import *
from unicorn.x86_const import *

IB = 0x10000000
dll = open('analysis/extracted/nngine.dll', 'rb').read()
deleg_resp = open('analysis/flows_decoded/2026-04-16/736-delegator-resp-decoded.bin', 'rb').read()

HU_CODE = 3362879562238844
HU_SECRET = 4196269328295954

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
    uc.reg_write(UC_X86_REG_EAX, ha(max(n, 16))); uc.reg_write(UC_X86_REG_EIP, RET)
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
ah(0x61C2D, hf)  # iterator

obj_mgr = ha(32); obj_mgr_vt = ha(64)
for i in range(16): uc.mem_write(obj_mgr_vt + i*4, struct.pack('<I', RET))
uc.mem_write(obj_mgr, struct.pack('<I', obj_mgr_vt))
uc.mem_write(IB+0x326D38, struct.pack('<I', obj_mgr))
uc.mem_write(IB+0x316B18, struct.pack('<I', obj_mgr))

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
    if cnt[0] > 2000000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# ============================================================
# Step 1: Call FUN_10094390 with proper param_2
# ============================================================
print("=== Step 1: Emulate FUN_10094390 ===")

# Build device object
device_obj = ha(0x60)
uc.mem_write(device_obj, struct.pack('<I', IB + 0x2B9688))
uc.mem_write(device_obj + 0x38, struct.pack('<I', 0))  # state
uc.mem_write(device_obj + 0x3C, struct.pack('<I', 0))  # inner cred = NULL

# Build param_2 (the response context object)
# The function reads: param_2+0x38 (char), param_2+0x30 (int len), param_2+0x2c (int data_ptr)
resp_data = ha(len(deleg_resp) + 16)
uc.mem_write(resp_data, deleg_resp)

param2 = ha(0x40)
uc.mem_write(param2 + 0x2C, struct.pack('<I', resp_data))
uc.mem_write(param2 + 0x30, struct.pack('<I', len(deleg_resp)))
uc.mem_write(param2 + 0x38, b'\x01')

# Call: thiscall FUN_10094390(ECX=device_obj, param_2)
esp = 0x5FE800
uc.reg_write(UC_X86_REG_ECX, device_obj)
uc.reg_write(UC_X86_REG_EDI, device_obj)  # EDI = ECX (mov edi, ecx at 0x1009439E)
esp -= 4; uc.mem_write(esp, struct.pack('<I', param2))  # [ebp+8] = param_2
esp -= 4; uc.mem_write(esp, struct.pack('<I', END))      # return address
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, esp + 4)  # EBP will be set by push ebp; mov ebp, esp

cnt[0] = 0
try:
    uc.emu_start(IB + 0x94390, END, timeout=120000000)
    print(f"  Completed ({cnt[0]} insns)")
except UcError as e:
    eip = uc.reg_read(UC_X86_REG_EIP)
    print(f"  Crash at RVA 0x{eip-IB:X} after {cnt[0]}: {e}")

ret = uc.reg_read(UC_X86_REG_EAX)
print(f"  Return: {ret}")

inner_ptr = struct.unpack('<I', bytes(uc.mem_read(device_obj + 0x3C, 4)))[0]
print(f"  device_obj[0xF] = 0x{inner_ptr:08X}")

if inner_ptr:
    inner = bytes(uc.mem_read(inner_ptr, 0x30))
    print(f"\n  Inner credential (0x28 bytes):")
    for i in range(0, 0x28, 4):
        v = struct.unpack_from('<I', inner, i)[0]
        print(f"    +0x{i:02X}: 0x{v:08X}")

    # The key value: inner[7] at offset 0x1C
    val_1c = struct.unpack_from('<I', inner, 0x1C)[0]
    print(f"\n  inner[7] (offset 0x1C) = 0x{val_1c:08X}")
    if 0x01000000 <= val_1c <= 0x02000000:
        print(f"  Looks like a heap pointer! Reading sub-object...")
        sub = bytes(uc.mem_read(val_1c, 0x30))
        for i in range(0, 0x30, 4):
            v = struct.unpack_from('<I', sub, i)[0]
            label = ' <-- Agent field' if i == 0x10 else ''
            print(f"      +0x{i:02X}: 0x{v:08X}{label}")
        
        agent_lo = struct.unpack_from('<I', sub, 0x10)[0]
        agent_hi = struct.unpack_from('<I', sub, 0x14)[0]
        agent = agent_lo | (agent_hi << 32)
        print(f"\n  Agent = {agent} (0x{agent:016X})")
    else:
        print(f"  Not a pointer - raw value")
        # Maybe inner[7..8] is the raw Secret value
        val_20 = struct.unpack_from('<I', inner, 0x20)[0]
        secret = val_1c | (val_20 << 32)
        print(f"  As uint64: {secret} (0x{secret:016X})")

    # ============================================================
    # Step 2: Run FUN_101aa050
    # ============================================================
    print("\n=== Step 2: Emulate FUN_101aa050 ===")

    uc.mem_write(IB + 0x31445C, struct.pack('<I', 1))

    def h_lookup(uc, a, s, u):
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
        out_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
        out_ref = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
        uc.mem_write(out_ptr, struct.pack('<I', device_obj))
        uc.mem_write(out_ref, struct.pack('<I', 1))
        uc.mem_write(device_obj + 8, struct.pack('<I', 2))
        uc.reg_write(UC_X86_REG_ESP, esp + 16)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)
    ah(0x11DD0, h_lookup)
    ah(0x1BAD80, hf)
    ah(0x1D2630, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 0x69E37F31), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x312A0, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, ha(16)), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x96700, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, uc.reg_read(UC_X86_REG_ECX)), uc.reg_write(UC_X86_REG_EIP, RET)))
    ah(0x157030, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, 1), uc.reg_write(UC_X86_REG_EIP, RET)))

    hmac_buf = ha(32)
    ah(0x156C60, lambda uc,a,s,u: (uc.reg_write(UC_X86_REG_EAX, hmac_buf), uc.reg_write(UC_X86_REG_EIP, RET)))

    def h_hmac(uc, a, s, u):
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
        out = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
        kp = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
        kl = struct.unpack('<I', bytes(uc.mem_read(esp+12, 4)))[0]
        dp = struct.unpack('<I', bytes(uc.mem_read(esp+16, 4)))[0]
        dl = struct.unpack('<I', bytes(uc.mem_read(esp+20, 4)))[0]
        key = bytes(uc.mem_read(kp, kl))
        data = bytes(uc.mem_read(dp, dl))
        result = hmac.new(key, data, hashlib.md5).digest()
        print(f"  HMAC key ({kl}B): {key.hex()}")
        print(f"  HMAC data ({dl}B): {data.hex()}")
        print(f"  HMAC result: {result.hex()}")
        print(f"  Want:        ad35bcc12654b893f7b5596a8057190c")
        print(f"  MATCH: {result.hex() == 'ad35bcc12654b893f7b5596a8057190c'}")
        uc.mem_write(out, result)
        uc.mem_write(hmac_buf, result)
        uc.reg_write(UC_X86_REG_EAX, 1)
        uc.reg_write(UC_X86_REG_ESP, esp + 24)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)
    ah(0x1AA3A0, h_hmac)

    p1 = ha(8); p2 = ha(8)
    uc.mem_write(p1, struct.pack('<II', HU_CODE & 0xFFFFFFFF, (HU_CODE >> 32) & 0xFFFFFFFF))
    uc.mem_write(p2, struct.pack('<II', HU_SECRET & 0xFFFFFFFF, (HU_SECRET >> 32) & 0xFFFFFFFF))

    esp = 0x5FE800
    esp -= 4; uc.mem_write(esp, struct.pack('<I', p2))
    esp -= 4; uc.mem_write(esp, struct.pack('<I', p1))
    esp -= 4; uc.mem_write(esp, struct.pack('<I', END))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, esp + 0x200)

    cnt[0] = 0
    try:
        uc.emu_start(IB + 0x1AA050, END, timeout=60000000)
        print(f"  Completed ({cnt[0]} insns)")
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f"  Crash at RVA 0x{eip-IB:X} after {cnt[0]}: {e}")
else:
    print("\n  FAILED: Inner credential is NULL")
    print("  The deserializer did not populate the credential store")
    print("  Need to debug the deserializer further")
