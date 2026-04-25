#!/usr/bin/env python3
"""Extract road class per segment from NNG .fbl map files.

Finds value 92 (backslash) markers in the varint stream and looks up
the following value in the DLL's road class table.

Usage:
    python tools/maps/fbl_road_class.py tools/maps/testdata/Monaco_osm.fbl
    python tools/maps/fbl_road_class.py tools/maps/testdata/Malta_osm.fbl -o malta_classes.csv
"""

import csv
import struct
import sys
from pathlib import Path as _P

sys.path.insert(0, str(_P(__file__).resolve().parent.parent.parent))
from pathlib import Path

import numpy as np

from tools.maps.nng_varint import SEGMENT_MARKERS, decode_varint

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
DLL_PATH = Path(__file__).parent.parent.parent / "analysis" / "extracted" / "nngine.dll"

RC_NAMES = {
    0: "motorway",
    1: "generic",
    2: "trunk",
    3: "primary",
    4: "tertiary",
    5: "local_hi",
    6: "local_med",
    7: "local_lo",
    8: "pedestrian",
    9: "other",
}


def _load_rc_table():
    import pefile

    pe = pefile.PE(str(DLL_PATH))
    dll = DLL_PATH.read_bytes()
    rva = 0x2E3480
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            fo = rva - section.VirtualAddress + section.PointerToRawData
            break
    table = {}
    for i in range(256):
        val = struct.unpack_from("<h", dll, fo + i * 2)[0]
        if val < 0:
            table[i] = -val
    return table


RC_TABLE = None


def get_rc_table():
    global RC_TABLE
    if RC_TABLE is None:
        RC_TABLE = _load_rc_table()
    return RC_TABLE


def decrypt(data, xor_table):
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


def extract_road_classes(sec4_data):
    """Extract (segment_index, byte_offset, road_class, road_class_name) tuples."""
    table = get_rc_table()
    results = []
    seg_idx = 0
    seg_start = 0
    current_rc = None
    pos = 0

    while pos < len(sec4_data):
        val, new_pos = decode_varint(sec4_data, pos)
        if val is None:
            break
        if val in SEGMENT_MARKERS:
            if seg_idx > 0 or current_rc is not None:
                results.append(
                    (
                        seg_idx,
                        seg_start,
                        current_rc,
                        (
                            RC_NAMES.get(current_rc, f"class_{current_rc}")
                            if current_rc is not None
                            else "unclassified"
                        ),
                    )
                )
            seg_idx += 1
            seg_start = pos
            current_rc = None
        if val == 92 and new_pos < len(sec4_data):
            nv, _ = decode_varint(sec4_data, new_pos)
            if nv is not None:
                if nv in table:
                    current_rc = table[nv]
                elif 48 <= nv <= 57:
                    current_rc = nv - 48
        pos = new_pos

    if seg_idx > 0:
        results.append(
            (
                seg_idx,
                seg_start,
                current_rc,
                (
                    RC_NAMES.get(current_rc, f"class_{current_rc}")
                    if current_rc is not None
                    else "unclassified"
                ),
            )
        )
    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_road_class.py <fbl_file> [-o output.csv]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)

    sec4s = struct.unpack_from("<I", dec, 0x048E + 16)[0]
    sec4e = struct.unpack_from("<I", dec, 0x048E + 20)[0]
    sec4 = dec[sec4s:sec4e]

    results = extract_road_classes(sec4)
    classified = sum(1 for _, _, rc, _ in results if rc is not None)
    print(f"{input_path.name}: {len(results)} segments, {classified} classified", file=sys.stderr)

    out = open(output_path, "w", newline="") if output_path else sys.stdout
    w = csv.writer(out)
    w.writerow(["segment", "byte_offset", "road_class", "road_class_name"])
    for seg, off, rc, name in results:
        w.writerow([seg, off, rc if rc is not None else "", name])
    if output_path:
        out.close()
        print(f"Wrote {len(results)} segments to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
