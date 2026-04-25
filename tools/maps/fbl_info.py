#!/usr/bin/env python3
"""Show metadata from NNG map files (.fbl, .fpa, .hnr, .poi, .spc).

Decrypts the outer XOR layer and displays: format version, country,
map version, bounding box, copyright, and build info.

Usage:
    python tools/maps/fbl_info.py tools/maps/testdata/Vatican_osm.fbl
    python tools/maps/fbl_info.py tools/maps/testdata/
"""

import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
MAP_EXTENSIONS = {".fbl", ".fpa", ".hnr", ".poi", ".spc"}
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def extract_utf16_strings(dec: bytes, start: int, max_len: int = 1024) -> list[str]:
    """Extract UTF-16LE strings from decrypted data."""
    strings = []
    i = start
    while i < min(start + max_len, len(dec) - 1):
        if dec[i] >= 0x20 and dec[i + 1] == 0x00:
            chars = []
            j = i
            while j < len(dec) - 1 and dec[j + 1] == 0x00 and dec[j] >= 0x20:
                chars.append(chr(dec[j]))
                j += 2
            if len(chars) >= 3:
                strings.append("".join(chars))
            i = j + 2
        else:
            i += 1
    return strings


def show_info(path: Path, xor_table: bytes):
    data = path.read_bytes()
    dec = decrypt(data, xor_table)

    print(f"File: {path.name} ({len(data):,d} bytes)")

    # Check for SET format
    if dec[:3] == b"SET":
        version = f"{dec[4]}.{dec[5]}.{dec[6]}.{dec[7]}"
        data_offset = struct.unpack_from("<I", dec, 0x18)[0]
        file_size = struct.unpack_from("<I", dec, 0x1C)[0]
        print(f"  Format:  SET v{version}")
        print(f"  Size:    {file_size:,d} bytes")

        # Extract metadata strings
        strings = extract_utf16_strings(dec, data_offset)
        for s in strings:
            if "[nng]" in s:
                # Parse: [nng]#COUNTRY# version\n© copyright\n\n\n_CODE|version|||
                parts = s.split("\\n")
                for part in parts:
                    part = part.strip()
                    if part.startswith("[nng]"):
                        print(f"  Version: {part.replace('[nng]#COUNTRY# ', '')}")
                    elif part.startswith("©"):
                        print(f"  Copyright: {part}")
                    elif "|" in part and part.startswith("_"):
                        code = part.split("|")[0][1:]
                        ver = part.split("|")[1]
                        print(f"  Country: {code}")
                        print(f"  Map ver: {ver}")
            elif "<L>" in s:
                # Build info
                import re

                builds = re.findall(r'N="([^"]+)" V="([^"]+)"', s)
                for name, ver in builds:
                    print(f"  Build:   {name} v{ver}")

        # Bounding box — search for country code block
        for off in range(0x440, min(0x600, len(dec) - 20)):
            if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
                vals = struct.unpack_from("<4i", dec, off + 8)
                lon_min = vals[0] / SCALE
                lat_max = vals[1] / SCALE
                lon_max = vals[2] / SCALE
                lat_min = vals[3] / SCALE
                print(f"  Bbox:    [{lon_min:.4f}, {lat_min:.4f}] → [{lon_max:.4f}, {lat_max:.4f}]")
                break
    else:
        # Non-SET format (SPC, etc.)
        print(f"  Header:  {dec[:8].hex()}")
        strings = extract_utf16_strings(dec, 0x10)
        for s in strings:
            if "[nng]" in s:
                parts = s.split("\\n")
                for part in parts:
                    if "|" in part and part.strip().startswith("_"):
                        code = part.strip().split("|")[0][1:]
                        print(f"  Country: {code}")
            elif "©" in s:
                print(f"  Copyright: {s[:60]}")

    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_info.py <file_or_dir>")
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])

    files = []
    if input_path.is_dir():
        files = sorted(f for f in input_path.iterdir() if f.suffix in MAP_EXTENSIONS)
    elif input_path.is_file():
        files = [input_path]

    for f in files:
        show_info(f, xor_table)


if __name__ == "__main__":
    main()
