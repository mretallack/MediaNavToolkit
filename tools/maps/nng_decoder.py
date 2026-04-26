#!/usr/bin/env python3
"""NNG FBL section decoder.

Uses Unicorn emulation of the DLL's FUN_1024a720 as the reference decoder,
with a pure-Python fallback for environments without Unicorn.

The FBL section data is a regex-like pattern language (LF-separated lines).
Each line is decoded into uint32 records by the DLL's pattern compiler.
"""

import struct
from pathlib import Path

_DLL_PATH = Path(__file__).parent.parent.parent / "analysis" / "extracted" / "nngine.dll"
_XOR_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"


def decode_varint(data: bytes, pos: int):
    """Decode one UTF-8-like varint. Returns (value, new_pos)."""
    if pos >= len(data):
        return None, pos
    b0 = data[pos]
    if b0 <= 0xBF:
        return b0, pos + 1
    b1 = data[pos + 1] & 0x3F if pos + 1 < len(data) else 0
    if (b0 & 0x20) == 0:
        return ((b0 & 0x1F) << 6) | b1, pos + 2
    b2 = data[pos + 2] & 0x3F if pos + 2 < len(data) else 0
    if (b0 & 0x10) == 0:
        return (((b0 & 0x0F) << 6 | b1) << 6) | b2, pos + 3
    b3 = data[pos + 3] & 0x3F if pos + 3 < len(data) else 0
    if (b0 & 0x08) == 0:
        return ((((b0 & 0x07) << 6 | b1) << 6 | b2) << 6) | b3, pos + 4
    b4 = data[pos + 4] & 0x3F if pos + 4 < len(data) else 0
    if (b0 & 0x04) == 0:
        return (((((b0 & 0x03) << 6 | b1) << 6 | b2) << 6 | b3) << 6) | b4, pos + 5
    b5 = data[pos + 5] & 0x3F if pos + 5 < len(data) else 0
    return ((((((b0 & 0x01) << 6 | b1) << 6 | b2) << 6 | b3) << 6 | b4) << 6) | b5, pos + 6


def _decode_line_unicorn(line_data: bytes, dll_bytes: bytes = None):
    """Decode one line using Unicorn emulation of FUN_1024a720."""
    from unicorn import (
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_MODE_32,
        Uc,
        UcError,
    )
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

    if dll_bytes is None:
        dll_bytes = _DLL_PATH.read_bytes()

    dll = dll_bytes
    pe_sig_off = struct.unpack_from("<I", dll, 0x3C)[0]
    num_sections = struct.unpack_from("<H", dll, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", dll, pe_sig_off + 20)[0]
    sec_start = pe_sig_off + 24 + opt_hdr_size

    DLL_BASE = 0x10000000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    def rva_to_file(rva):
        for i in range(num_sections):
            off = sec_start + i * 40
            va = struct.unpack_from("<I", dll, off + 12)[0]
            vs = struct.unpack_from("<I", dll, off + 8)[0]
            ro = struct.unpack_from("<I", dll, off + 20)[0]
            if va <= rva < va + vs:
                return ro + (rva - va)
        return None

    for i in range(num_sections):
        off = sec_start + i * 40
        va = struct.unpack_from("<I", dll, off + 12)[0]
        vs = struct.unpack_from("<I", dll, off + 8)[0]
        rs = struct.unpack_from("<I", dll, off + 16)[0]
        ro = struct.unpack_from("<I", dll, off + 20)[0]
        addr = DLL_BASE + va
        size = ((vs + 0xFFF) // 0x1000) * 0x1000
        try:
            mu.mem_map(addr, size)
            mu.mem_write(addr, dll[ro : ro + rs])
        except:
            pass

    mu.mem_map(0x00100000, 0x100000)  # stack
    mu.mem_map(0x00200000, 0x1000)  # return
    mu.mem_write(0x00200000, b"\xcc")
    mu.mem_map(0x00300000, 0x200000)  # data

    LINE_ADDR = 0x00300000
    mu.mem_write(LINE_ADDR, line_data)
    OUTPUT_ADDR = 0x00340000

    fo = rva_to_file(0x2E5408)
    CCLASS_ADDR = 0x00390000
    mu.mem_write(CCLASS_ADDR, dll[fo : fo + 256])

    fo2 = rva_to_file(0x2E50C8)
    CTABLE_ADDR = 0x00391000
    mu.mem_write(CTABLE_ADDR, dll[fo2 : fo2 + 0x800])

    CTX_ADDR = 0x00392000
    ctx = bytearray(36)
    struct.pack_into("<I", ctx, 0, DLL_BASE + 0x243AC0)
    struct.pack_into("<I", ctx, 4, DLL_BASE + 0x243AD0)
    struct.pack_into("<I", ctx, 20, CTABLE_ADDR)
    struct.pack_into("<I", ctx, 24, 0xFFFFFFFF)
    struct.pack_into("<I", ctx, 28, 0x00020001)
    struct.pack_into("<I", ctx, 32, 0xFFFF)
    mu.mem_write(CTX_ADDR, bytes(ctx))

    P4_ADDR = 0x00380000
    p4 = bytearray(512)
    struct.pack_into("<I", p4, 0, CTX_ADDR)
    struct.pack_into("<I", p4, 4, CTABLE_ADDR)
    struct.pack_into("<I", p4, 16, CCLASS_ADDR)
    struct.pack_into("<I", p4, 20, OUTPUT_ADDR)
    struct.pack_into("<I", p4, 24, OUTPUT_ADDR)
    struct.pack_into("<I", p4, 28, LINE_ADDR)
    struct.pack_into("<I", p4, 32, LINE_ADDR + len(line_data))
    struct.pack_into("<I", p4, 40, 0x1000)
    struct.pack_into("<I", p4, 0x1E * 4, OUTPUT_ADDR)
    struct.pack_into("<I", p4, 0x1F * 4, OUTPUT_ADDR + 0x100000)
    struct.pack_into("<I", p4, 0x20 * 4, 0x100000)
    mu.mem_write(P4_ADDR, bytes(p4))

    esp = 0x001F0000
    mu.reg_write(UC_X86_REG_ESP, esp)
    stack = struct.pack("<IIIII", 0x00200000, LINE_ADDR, 0x480080, 0x003A0000, P4_ADDR)
    mu.mem_write(esp, stack)
    mu.mem_write(0x003A0000, struct.pack("<I", 0))

    count = [0]

    def hook_insn(uc, addr, size, _):
        count[0] += 1
        if count[0] >= 50_000_000:
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook_insn)

    def hook_mem(uc, access, addr, size, value, _):
        page = addr & ~0xFFF
        try:
            uc.mem_map(page, 0x1000)
            return True
        except:
            uc.emu_stop()
            return False

    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        hook_mem,
    )

    try:
        mu.emu_start(DLL_BASE + 0x24A720, 0x00200000, timeout=60_000_000)
    except UcError:
        pass

    out = mu.mem_read(OUTPUT_ADDR, 0x10000)
    records = []
    for i in range(0, len(out), 4):
        v = struct.unpack_from("<I", out, i)[0]
        if v == 0 and records:
            nxt = [
                struct.unpack_from("<I", out, i + j * 4)[0]
                for j in range(1, 4)
                if i + j * 4 < len(out)
            ]
            if all(x == 0 for x in nxt):
                break
        records.append(v)
    while records and records[-1] == 0:
        records.pop()
    return records


def decode_line(line_data: bytes, dll_bytes: bytes = None):
    """Decode one LF-separated line into uint32 records.

    Uses Unicorn emulation for accuracy.
    """
    return _decode_line_unicorn(line_data, dll_bytes)


def decode_section(section_data: bytes, dll_bytes: bytes = None):
    """Decode a full FBL section into records.

    The caller (FUN_10243ae0) processes the section data line-by-line,
    calling FUN_1024a720 once per LF-separated line. We replicate this
    by splitting on 0x0A and decoding each line independently.
    """
    if dll_bytes is None:
        dll_bytes = _DLL_PATH.read_bytes()
    lines = section_data.split(b"\x0a")
    all_records = []
    for line in lines:
        if not line:
            continue
        all_records.extend(decode_line(line, dll_bytes))
    return all_records


def decode_fbl_section(fbl_path, section_idx=4):
    """Decode a section from an FBL file."""
    import numpy as np

    xor = _XOR_PATH.read_bytes()
    raw = Path(fbl_path).read_bytes()
    d = np.frombuffer(raw, dtype=np.uint8)
    t = np.frombuffer(xor, dtype=np.uint8)
    dec = bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])

    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x49, 0x4B):
            table_start = off + 24
            break
    else:
        raise ValueError("Could not find section table")

    offsets = [struct.unpack_from("<I", dec, table_start + i * 4)[0] for i in range(20)]
    s = offsets[section_idx]
    e = (
        offsets[section_idx + 1]
        if section_idx + 1 < 20 and offsets[section_idx + 1] > s
        else len(dec)
    )
    if s == 0 or s >= len(dec):
        raise ValueError(f"Section {section_idx} not found")

    return decode_section(dec[s:e])


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Decode FBL section data")
    parser.add_argument("fbl_file")
    parser.add_argument("-s", "--section", type=int, default=4)
    parser.add_argument("-o", "--output")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    records = decode_fbl_section(args.fbl_file, args.section)
    if args.summary:
        from collections import Counter

        ctrl = [r for r in records if r >= 0x80000000]
        data = [r for r in records if r < 0x80000000]
        print(f"Total: {len(records)}, Control: {len(ctrl)}, Data: {len(data)}")
        for typ, cnt in Counter(r & 0xFFFF0000 for r in ctrl).most_common():
            print(f"  0x{typ:08x}: {cnt}")
    elif args.output:
        Path(args.output).write_text(json.dumps(records))
        print(f"Wrote {len(records)} records to {args.output}")
    else:
        for i, r in enumerate(records[:100]):
            print(f"[{i:5d}] {'0x%08x CTRL' % r if r >= 0x80000000 else str(r)}")
        if len(records) > 100:
            print(f"... ({len(records) - 100} more)")


if __name__ == "__main__":
    main()
