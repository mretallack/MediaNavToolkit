"""Unicorn: serialize credential with proper format string hook."""
from unicorn import *
from unicorn.x86_const import *
import struct, hmac, hashlib, ctypes, re

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

for va,raw,sz in [(0x1000,0x400,0x2ACE00),(0x2AE000,0x2AD200,0x5C200),(0x30B000,0x309400,0x9200)]:
    uc.mem_write(IB+va, dll[raw:raw+sz])

hp=[0x1001000]
def ha(n): p=hp[0]; hp[0]+=(n+15)&~15; uc.mem_write(p,b'\x00'*n); return p

RET=0x1000100; uc.mem_write(RET,b'\xC3')
END=0x1000200; uc.mem_write(END,b'\xC3')
tls=ha(0x200); tla=ha(0x10)
uc.mem_write(tla,struct.pack('<I',tls))
uc.mem_write(0x2C,struct.pack('<I',tla))
uc.mem_write(IB+0x312F68,struct.pack('<I',0))
uc.mem_write(IB+0x312F6C,struct.pack('<I',0xBB40E64E))

# Patch IAT — with special handling for FileTimeToSystemTime
ft2st_stub = ha(256)
# FileTimeToSystemTime(FILETIME *ft, SYSTEMTIME *st) -> BOOL
# FILETIME: [lo:4B][hi:4B] = 100ns intervals since 1601-01-01
# SYSTEMTIME: [year:2B][month:2B][dow:2B][day:2B][hour:2B][min:2B][sec:2B][ms:2B]
# We implement this in x86 machine code that calls back to Python via a hook
uc.mem_write(ft2st_stub, b'\xC2\x08\x00')  # placeholder ret 8

def h_filetime_to_systemtime(uc, addr, size, ud):
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
    ft_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+4, 4)))[0]
    st_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    
    # Read FILETIME
    ft_lo = struct.unpack('<I', bytes(uc.mem_read(ft_ptr, 4)))[0]
    ft_hi = struct.unpack('<I', bytes(uc.mem_read(ft_ptr+4, 4)))[0]
    ft = ft_lo | (ft_hi << 32)
    
    # Convert FILETIME to datetime
    # FILETIME epoch: 1601-01-01 00:00:00 UTC
    # Unix epoch: 1970-01-01 00:00:00 UTC
    # Difference: 11644473600 seconds = 116444736000000000 in 100ns
    import datetime
    EPOCH_DIFF = 116444736000000000
    if ft > EPOCH_DIFF:
        unix_100ns = ft - EPOCH_DIFF
        unix_sec = unix_100ns // 10000000
        ms = (unix_100ns % 10000000) // 10000
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=unix_sec)
    else:
        # Before Unix epoch
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        ms = (ft % 10000) // 10
    
    # Write SYSTEMTIME
    st_data = struct.pack('<HHHHHHHH',
        dt.year, dt.month, dt.weekday(), dt.day,
        dt.hour, dt.minute, dt.second, ms)
    uc.mem_write(st_ptr, st_data)
    
    uc.reg_write(UC_X86_REG_EAX, 1)  # success
    uc.reg_write(UC_X86_REG_ESP, esp + 12)  # ret 8 (stdcall, 2 args)
    uc.reg_write(UC_X86_REG_EIP, ret_addr)

for i in range(0,0x2000,4):
    off=0x2AD200+i
    if off+4>len(dll): break
    v=struct.unpack_from('<I',dll,off)[0]
    if 0x10000<v<0x400000:
        no=0x2AD200+(v-0x2AE000)
        if 0<no<len(dll)-50:
            try:
                nm=dll[no+2:no+50].split(b'\x00')[0].decode('ascii')
                if nm: 
                    s=ha(16); uc.mem_write(s,b'\x31\xC0\xC2\x04\x00')
                    if nm == 'FileTimeToSystemTime':
                        s = ft2st_stub  # use our implementation
                    uc.mem_write(IB+0x2AE000+i,struct.pack('<I',s))
            except: pass

hooks={}
def ah(rva,fn): hooks[IB+rva]=fn

def hm(uc,a,s,u):
    esp=uc.reg_read(UC_X86_REG_ESP)
    n=struct.unpack('<I',bytes(uc.mem_read(esp+4,4)))[0]
    uc.reg_write(UC_X86_REG_EAX,ha(max(n,16))); uc.reg_write(UC_X86_REG_EIP,RET)
def hf(uc,a,s,u): uc.reg_write(UC_X86_REG_EIP,RET)
def hn(uc,a,s,u): uc.reg_write(UC_X86_REG_EAX,1); uc.reg_write(UC_X86_REG_EIP,RET)
def hr(uc,a,s,u):
    esp=uc.reg_read(UC_X86_REG_ESP)
    old=struct.unpack('<I',bytes(uc.mem_read(esp+4,4)))[0]
    n=struct.unpack('<I',bytes(uc.mem_read(esp+8,4)))[0]
    p=ha(max(n,16))
    if old:
        try: uc.mem_write(p,bytes(uc.mem_read(old,min(n,4096))))
        except: pass
    uc.reg_write(UC_X86_REG_EAX,p); uc.reg_write(UC_X86_REG_EIP,RET)

ah(0x27E4F5,hm); ah(0x2839F9,hr); ah(0x2839D1,hf); ah(0x27DFE8,hf); ah(0x283980,hn)
hooks[ft2st_stub] = h_filetime_to_systemtime

ser_obj = [0]  # will be set later

def read_cstr(ptr, maxlen=256):
    d = bytes(uc.mem_read(ptr, maxlen))
    return d.split(b'\x00')[0].decode('ascii', errors='replace')

def append_to_buf(text_bytes):
    sp = struct.unpack('<I', bytes(uc.mem_read(ser_obj[0]+8, 4)))[0]
    sl = struct.unpack('<I', bytes(uc.mem_read(sp-0xC, 4)))[0]
    if sl + len(text_bytes) < 4000:
        uc.mem_write(sp + sl, text_bytes + b'\x00')
        uc.mem_write(sp - 0xC, struct.pack('<I', sl + len(text_bytes)))

def h_fmt(uc, addr, size, ud):
    """Hook for FUN_101b2720: void (int ctx, char *fmt, ...)"""
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
    # [esp+4]=ctx, [esp+8]=fmt, [esp+12...]=varargs
    fmt_ptr = struct.unpack('<I', bytes(uc.mem_read(esp+8, 4)))[0]
    fmt = read_cstr(fmt_ptr)
    
    # Read up to 8 varargs as raw uint32
    va_base = esp + 12
    raw_args = [struct.unpack('<I', bytes(uc.mem_read(va_base+i*4, 4)))[0] for i in range(8)]
    
    # Parse format string and consume args
    result = b''
    ai = 0  # arg index
    i = 0
    while i < len(fmt):
        if fmt[i] != '%':
            result += fmt[i].encode(); i += 1; continue
        i += 1  # skip %
        if i >= len(fmt): break
        
        # Flags
        flags = ''
        while i < len(fmt) and fmt[i] in '-+ #0':
            flags += fmt[i]; i += 1
        
        # Width
        width = ''
        if i < len(fmt) and fmt[i] == '*':
            width = str(raw_args[ai]); ai += 1; i += 1
        else:
            while i < len(fmt) and fmt[i].isdigit():
                width += fmt[i]; i += 1
        
        # Precision
        prec = ''
        if i < len(fmt) and fmt[i] == '.':
            i += 1
            if i < len(fmt) and fmt[i] == '*':
                prec = str(raw_args[ai]); ai += 1; i += 1
            else:
                while i < len(fmt) and fmt[i].isdigit():
                    prec += fmt[i]; i += 1
        
        # Length modifier
        length = ''
        if i < len(fmt) and fmt[i] == 'I':
            if i+3 < len(fmt) and fmt[i+1:i+3] == '64':
                length = 'I64'; i += 3
        elif i < len(fmt) and fmt[i] == 'l':
            length = 'l'; i += 1
            if i < len(fmt) and fmt[i] == 'l':
                length = 'll'; i += 1
        
        # Conversion
        if i >= len(fmt): break
        conv = fmt[i]; i += 1
        
        if conv == '%':
            result += b'%'
        elif conv == 's':
            s = read_cstr(raw_args[ai]); ai += 1
            if prec:
                s = s[:int(prec)]
            result += s.encode()
        elif conv == 'd':
            if length == 'I64':
                lo = raw_args[ai]; ai += 1
                hi = raw_args[ai]; ai += 1
                val = ctypes.c_int64(lo | (hi << 32)).value
            else:
                val = ctypes.c_int32(raw_args[ai]).value; ai += 1
            fmt_spec = ''
            if '0' in flags and width:
                fmt_spec = f'0{width}'
            elif width:
                fmt_spec = width
            if prec:
                fmt_spec = f'.{prec}'
            result += format(val, fmt_spec or '').encode() if fmt_spec else str(val).encode()
        elif conv == 'u':
            if length == 'I64':
                lo = raw_args[ai]; ai += 1
                hi = raw_args[ai]; ai += 1
                val = lo | (hi << 32)
            else:
                val = raw_args[ai]; ai += 1
            result += str(val).encode()
    
    append_to_buf(result)
    uc.reg_write(UC_X86_REG_ESP, esp+4)  # cdecl: pop ret only
    uc.reg_write(UC_X86_REG_EIP, ret)

ah(0x1B2720, h_fmt)

# FUN_101b26a0 runs natively — it writes raw bytes to the stream
# Only FUN_101b2720 (format writer) is hooked

def hook_unmapped(uc,access,address,size,value,ud):
    try: uc.mem_map(address&~0xFFF,0x1000); uc.mem_write(address&~0xFFF,b'\xC3'*0x1000); return True
    except: return False
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

cnt=[0]
def hook_code(uc,address,size,ud):
    cnt[0]+=1
    if address in hooks: hooks[address](uc,address,size,ud)
    elif address<IB or address>=IB+0x400000:
        if address!=RET and address!=END:
            uc.reg_write(UC_X86_REG_EIP,RET)
    if cnt[0]>5000000: uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_code)

# Init serializer
so=ha(64); ser_obj[0]=so
esp=0x5FF000
uc.reg_write(UC_X86_REG_ECX,so)
esp-=4; uc.mem_write(esp,struct.pack('<I',0))
esp-=4; uc.mem_write(esp,struct.pack('<I',0))
esp-=4; uc.mem_write(esp,struct.pack('<I',END))
uc.reg_write(UC_X86_REG_ESP,esp); uc.reg_write(UC_X86_REG_EBP,esp+0x200)
cnt[0]=0
try: uc.emu_start(IB+0x1B2910, END, timeout=30000000)
except UcError as e: print(f'Init err: {e}')

# Build credential
cred=ha(0x60); cd=bytearray(0x60)
struct.pack_into('<I',cd,0x00,IB+0x2B9590)
struct.pack_into('<I',cd,0x08,IB+0x2B9580)
struct.pack_into('<I',cd,0x38,IB+0x2B9588)
struct.pack_into('<I',cd,0x10,1); cd[0x14]=1
struct.pack_into('<I',cd,0x18,0x69BACB7C); struct.pack_into('<I',cd,0x1C,0x000BF285)
cd[0x20]=1
struct.pack_into('<I',cd,0x24,0x5D36B98E); struct.pack_into('<I',cd,0x28,0x000D4EA6)
struct.pack_into('<I',cd,0x2C,1)
struct.pack_into('<I',cd,0x30,0x69D4BA80); struct.pack_into('<I',cd,0x34,1)
struct.pack_into('<I',cd,0x40,3); cd[0x44]=1
uc.mem_write(cred,bytes(cd))

# Serialize — call FUN_101a9930 (the HMAC serializer)
# thiscall: ECX = cred+8 (vtable2), stack arg = output buffer
# Output buffer: 20 bytes initialized to zeros with version=0x0101 at offset 16
out_buf = ha(32)
uc.mem_write(out_buf + 16, struct.pack('<H', 0x0101))

esp=0x5FF000
uc.reg_write(UC_X86_REG_ECX, cred+8)
# Push output buffer as arg, then return address
esp-=4; uc.mem_write(esp, struct.pack('<I', out_buf))
esp-=4; uc.mem_write(esp, struct.pack('<I', END))
uc.reg_write(UC_X86_REG_ESP, esp); uc.reg_write(UC_X86_REG_EBP, esp+0x200)
cnt[0]=0

try:
    uc.emu_start(IB+0x1A9930, END, timeout=120000000)
    print(f'COMPLETED ({cnt[0]} insns)')
except UcError as e:
    eip=uc.reg_read(UC_X86_REG_EIP)
    print(f'Crash at rva 0x{eip-IB:X} after {cnt[0]}: {e}')

ob = bytes(uc.mem_read(out_buf, 20))
data_ptr = struct.unpack_from('<I', ob, 0)[0]
data_len = struct.unpack_from('<I', ob, 8)[0]
print(f'\nOutput: ptr=0x{data_ptr:08X} len={data_len}')
print(f'Buffer: {ob.hex()}')
if data_ptr and 0 < data_len < 10000:
    data = bytes(uc.mem_read(data_ptr, data_len))
    print(f'Data ({data_len}B): {data.hex()}')
    try: print(f'ASCII: {data.decode("ascii")}')
    except: pass
    h = hmac.new(b'\x00\x0E\xE8\x7C\x16\xB1\xE8\x12', data, hashlib.md5).digest()
    print(f'\nHMAC: {h.hex()}')
    print(f'Want: ad35bcc12654b893f7b5596a8057190c')
    print(f'Match: {h.hex() == "ad35bcc12654b893f7b5596a8057190c"}')
