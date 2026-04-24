#!/usr/bin/env python3
"""Analyse and compare headers of NNG map files.

Reads the first 64 bytes of each file and shows which bytes are constant
vs variable. Identifies magic bytes, type fields, and header structure.

Usage:
    python tools/maps/analyse_header.py tools/maps/testdata/
    python tools/maps/analyse_header.py file1.fbl file2.fpa file3.spc
"""
import math
import sys
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def read_header(path: Path, size: int = 64) -> bytes:
    return path.read_bytes()[:size]


def main():
    paths = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.is_dir():
            paths.extend(sorted(p.glob("*.*")))
        elif p.is_file():
            paths.append(p)

    if not paths:
        print("Usage: analyse_header.py <dir_or_files...>")
        sys.exit(1)

    # Filter to map files only
    exts = {".fbl", ".fpa", ".hnr", ".spc", ".poi", ".head"}
    paths = [p for p in paths if p.suffix in exts]

    headers = {}
    for p in paths:
        data = p.read_bytes()
        hdr = data[:64]
        headers[p.name] = hdr
        ent = shannon_entropy(data)
        print(f"{p.name:30s} {len(data):>10,d} B  entropy={ent:.3f}  magic={hdr[:8].hex()}")

    print()

    # Group by magic bytes
    by_magic = {}
    for name, hdr in headers.items():
        magic = hdr[:8].hex()
        by_magic.setdefault(magic, []).append(name)

    print("=== Magic Byte Groups ===")
    for magic, names in by_magic.items():
        print(f"  {magic}: {', '.join(names)}")

    print()

    # Compare headers within each magic group
    for magic, names in by_magic.items():
        if len(names) < 2:
            continue
        print(f"=== Header comparison for magic {magic} ===")
        hdrs = [headers[n] for n in names]
        min_len = min(len(h) for h in hdrs)

        print(f"{'Offset':<8s}", end="")
        for n in names:
            print(f"{n[:15]:>16s}", end="")
        print(f"{'  Constant?':>12s}")
        print("-" * (8 + 16 * len(names) + 12))

        for off in range(min_len):
            vals = [h[off] for h in hdrs]
            constant = len(set(vals)) == 1
            # Only show rows where values differ, or every 8th row
            if not constant or off < 16 or off % 8 == 0:
                print(f"0x{off:04X}  ", end="")
                for v in vals:
                    print(f"{v:02X}              ", end="")
                marker = "  ✓" if constant else "  ✗ DIFFERS"
                print(marker)

        print()

    # Show first 64 bytes side by side for the two smallest FBL files
    fbl_files = [n for n in headers if n.endswith(".fbl")]
    if len(fbl_files) >= 2:
        a, b = fbl_files[0], fbl_files[1]
        print(f"=== Byte-by-byte: {a} vs {b} ===")
        ha, hb = headers[a], headers[b]
        for off in range(0, min(len(ha), len(hb), 64), 16):
            chunk_a = ha[off : off + 16]
            chunk_b = hb[off : off + 16]
            diff = "".join("^" if chunk_a[i] != chunk_b[i] else " " for i in range(len(chunk_a)))
            print(f"  {off:04X} A: {chunk_a.hex()}")
            print(f"  {off:04X} B: {chunk_b.hex()}")
            print(f"       D: {diff}")
            print()


if __name__ == "__main__":
    main()
