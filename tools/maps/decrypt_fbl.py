#!/usr/bin/env python3
"""Decrypt NNG map files (.fbl, .fpa, .hnr, .poi, .spc).

Uses the XOR table from nngine.dll (same as device.nng decryption).
Decryption: plaintext[i] = ciphertext[i] XOR xor_table[i % 4096]

Usage:
    python tools/maps/decrypt_fbl.py tools/maps/testdata/Vatican_osm.fbl
    python tools/maps/decrypt_fbl.py tools/maps/testdata/Vatican_osm.fbl -o vatican.dec
    python tools/maps/decrypt_fbl.py tools/maps/testdata/ -o decrypted/
"""

import math
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
MAP_EXTENSIONS = {".fbl", ".fpa", ".hnr", ".poi", ".spc"}


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def parse_set_header(dec: bytes) -> dict:
    """Parse the SET file header."""
    info = {}
    if dec[:3] == b"SET":
        info["format"] = "SET"
        info["version"] = f"{dec[4]}.{dec[5]}.{dec[6]}.{dec[7]}"
        info["file_size"] = struct.unpack_from("<I", dec, 0x1C)[0]
        info["data_offset"] = struct.unpack_from("<I", dec, 0x18)[0]

        # Extract UTF-16LE strings from data section
        data_off = info["data_offset"]
        if data_off < len(dec):
            # Find the metadata string
            i = data_off
            while i < min(data_off + 1024, len(dec) - 1):
                if dec[i] == ord("[") and dec[i + 1] == 0:
                    # Found start of UTF-16LE string
                    chars = []
                    j = i
                    while j < len(dec) - 1:
                        if dec[j + 1] == 0 and dec[j] >= 0x20:
                            chars.append(chr(dec[j]))
                        elif dec[j] == 0 and dec[j + 1] == 0:
                            break
                        else:
                            chars.append(chr(dec[j]))
                        j += 2
                    info["metadata"] = "".join(chars)
                    break
                i += 1
    return info


def main():
    if len(sys.argv) < 2:
        print("Usage: decrypt_fbl.py <file_or_dir> [-o output]")
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    files = []
    if input_path.is_dir():
        files = [f for f in sorted(input_path.iterdir()) if f.suffix in MAP_EXTENSIONS]
    elif input_path.is_file():
        files = [input_path]

    for f in files:
        data = f.read_bytes()
        dec = decrypt(data, xor_table)
        ent_before = shannon_entropy(data)
        ent_after = shannon_entropy(dec)
        info = parse_set_header(dec)

        print(f"{f.name}:")
        print(f"  Size: {len(data):,d} bytes")
        print(f"  Entropy: {ent_before:.3f} → {ent_after:.3f}")
        if info.get("format"):
            print(f"  Format: {info['format']} v{info.get('version', '?')}")
            print(f"  Data offset: {info.get('data_offset', '?')}")
            if info.get("metadata"):
                meta = info["metadata"][:120]
                print(f"  Metadata: {meta}")

        if output_path:
            if output_path.is_dir() or len(files) > 1:
                out_dir = output_path if output_path.is_dir() else output_path
                out_dir.mkdir(parents=True, exist_ok=True)
                out_file = out_dir / f"{f.stem}.dec{f.suffix}"
            else:
                out_file = output_path
            out_file.write_bytes(dec)
            print(f"  Written: {out_file}")
        print()


if __name__ == "__main__":
    main()
