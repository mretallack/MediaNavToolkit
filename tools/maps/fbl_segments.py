#!/usr/bin/env python3
"""List all road segments in an NNG .fbl file with byte offsets and sizes.

Usage:
    python tools/maps/fbl_segments.py tools/maps/testdata/Monaco_osm.fbl
    python tools/maps/fbl_segments.py tools/maps/testdata/Malta_osm.fbl -o malta_segs.csv
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


def decrypt(data, xor_table):
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


def extract_segments(sec4_data):
    segments = []
    pos = 0
    seg_start = None
    seg_marker = None
    seg_idx = 0
    while pos < len(sec4_data):
        val, new_pos = decode_varint(sec4_data, pos)
        if val is None:
            break
        if val in SEGMENT_MARKERS:
            if seg_start is not None:
                segments.append((seg_idx, seg_start, pos, pos - seg_start, seg_marker))
                seg_idx += 1
            seg_start = pos
            seg_marker = val
        pos = new_pos
    if seg_start is not None:
        segments.append(
            (seg_idx, seg_start, len(sec4_data), len(sec4_data) - seg_start, seg_marker)
        )
    return segments


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_segments.py <fbl_file> [-o output.csv]", file=sys.stderr)
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

    segments = extract_segments(sec4)
    sizes = [s[3] for s in segments]
    print(
        f"{input_path.name}: {len(segments)} segments, "
        f"mean={np.mean(sizes):.0f}B, max={max(sizes)}B",
        file=sys.stderr,
    )

    out = open(output_path, "w", newline="") if output_path else sys.stdout
    w = csv.writer(out)
    w.writerow(["segment", "start_byte", "end_byte", "size", "marker_value"])
    for row in segments:
        w.writerow(row)
    if output_path:
        out.close()
        print(f"Wrote {len(segments)} segments to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
