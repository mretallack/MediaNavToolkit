#!/usr/bin/env python3
"""Show overview of all NNG map files in a directory or zip.

Outputs a summary table: country, file type, version, size, bounding box.

Usage:
    python tools/maps/map_overview.py tools/maps/testdata/
    python tools/maps/map_overview.py /path/to/extracted/map/files/
"""

import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
MAP_EXTENSIONS = {".fbl", ".fpa", ".hnr", ".poi", ".spc"}
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def get_info(dec: bytes, filename: str) -> dict:
    info = {"file": filename, "country": "", "type": "", "version": "", "bbox": ""}

    # Determine type from extension
    ext = Path(filename).suffix
    info["type"] = ext[1:].upper()

    # Extract country from UTF-16LE metadata
    for i in range(0x10, min(0x400, len(dec)) - 8):
        if dec[i] == ord("_") and dec[i + 1] == 0x00:
            code = ""
            j = i + 2
            while j < len(dec) - 1 and dec[j + 1] == 0x00 and dec[j] != ord("|"):
                code += chr(dec[j])
                j += 2
            if 2 <= len(code) <= 4 and code.isalpha():
                info["country"] = code
                break

    # Extract version — look for year pattern in UTF-16LE
    target = b"2\x000\x002\x005\x00.\x000"  # "2025.0" in UTF-16LE
    pos = dec.find(target, 0x200)
    if pos >= 0:
        ver = ""
        j = pos
        while j < len(dec) - 1 and dec[j + 1] == 0x00 and dec[j] >= 0x20 and dec[j] != ord("\\"):
            ver += chr(dec[j])
            j += 2
        info["version"] = ver.strip()

    # Bounding box (FBL only)
    if ext == ".fbl":
        for off in range(0x440, min(0x600, len(dec) - 20)):
            if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
                vals = struct.unpack_from("<4i", dec, off + 8)
                lon_min = vals[0] / SCALE
                lat_min = vals[3] / SCALE
                lon_max = vals[2] / SCALE
                lat_max = vals[1] / SCALE
                info["bbox"] = f"[{lon_min:.2f},{lat_min:.2f}]→[{lon_max:.2f},{lat_max:.2f}]"
                break

    return info


def main():
    if len(sys.argv) < 2:
        print("Usage: map_overview.py <directory>", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])

    files = sorted(f for f in input_path.rglob("*") if f.suffix in MAP_EXTENSIONS and f.is_file())

    if not files:
        print("No map files found.", file=sys.stderr)
        sys.exit(1)

    rows = []
    for f in files:
        data = f.read_bytes()
        dec = decrypt(data, xor_table)
        info = get_info(dec, f.name)
        info["size_kb"] = len(data) // 1024
        rows.append(info)

    # Print table
    print(f"{'Country':<6s} {'Type':<5s} {'Size':>8s} {'Version':<10s} {'Bbox':<40s} {'File'}")
    print("-" * 110)
    for r in sorted(rows, key=lambda x: (x["country"], x["type"])):
        print(
            f"{r['country']:<6s} {r['type']:<5s} {r['size_kb']:>6d} KB "
            f"{r['version']:<10s} {r['bbox']:<40s} {r['file']}"
        )

    # Summary
    countries = set(r["country"] for r in rows if r["country"])
    total_mb = sum(r["size_kb"] for r in rows) / 1024
    print(f"\n{len(rows)} files, {len(countries)} countries, {total_mb:.1f} MB total")


if __name__ == "__main__":
    main()
