#!/usr/bin/env python3
"""Replace section data in an existing FBL file.

Takes an existing FBL as a template and replaces one section's data
with new encoded records. Preserves the SET header and other sections.

Usage:
    python tools/maps/fbl_replace_section.py template.fbl -s 4 --records records.json -o output.fbl
"""

import json
import struct
import sys
from pathlib import Path

import numpy as np

_XOR_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


def replace_section(fbl_path: Path, section_idx: int, new_section_data: bytes, output_path: Path):
    """Replace a section in an FBL file with new data.

    Args:
        fbl_path: Path to template FBL file.
        section_idx: Section index to replace (0-19).
        new_section_data: New raw bytes for the section.
        output_path: Path to write the modified FBL file.
    """
    xor = _XOR_PATH.read_bytes()
    raw = fbl_path.read_bytes()
    dec = bytearray(decrypt(raw, xor))

    # Find section table
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x49, 0x4B):
            table_start = off + 24
            break
    else:
        raise ValueError("Could not find section table")

    offsets = [struct.unpack_from("<I", dec, table_start + i * 4)[0] for i in range(20)]

    old_start = offsets[section_idx]
    # Find end of section
    old_end = len(dec)
    for i in range(section_idx + 1, 20):
        if offsets[i] > old_start:
            old_end = offsets[i]
            break

    old_size = old_end - old_start
    new_size = len(new_section_data)
    size_diff = new_size - old_size

    # Build new file: header + sections before + new section + sections after
    new_dec = bytearray()
    new_dec.extend(dec[:old_start])
    new_dec.extend(new_section_data)
    new_dec.extend(dec[old_end:])

    # Update section offsets for sections after the replaced one
    for i in range(section_idx + 1, 20):
        if offsets[i] > old_start:
            new_offset = offsets[i] + size_diff
            struct.pack_into("<I", new_dec, table_start + i * 4, new_offset)

    # XOR encrypt and write
    encrypted = decrypt(bytes(new_dec), xor)  # XOR is symmetric
    output_path.write_bytes(encrypted)
    print(f"Wrote {len(encrypted)} bytes to {output_path}")
    print(f"Section {section_idx}: {old_size} → {new_size} bytes (diff={size_diff:+d})")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Replace FBL section data")
    parser.add_argument("template", help="Template FBL file")
    parser.add_argument("-s", "--section", type=int, default=4, help="Section index")
    parser.add_argument("--records", help="JSON file with uint32 records to encode")
    parser.add_argument("--raw", help="Raw bytes file for section data")
    parser.add_argument("-o", "--output", required=True, help="Output FBL file")
    args = parser.parse_args()

    if args.records:
        from tools.maps.nng_decoder import encode_records

        records = json.loads(Path(args.records).read_text())
        new_data = encode_records(records)
    elif args.raw:
        new_data = Path(args.raw).read_bytes()
    else:
        print("Error: specify --records or --raw", file=sys.stderr)
        sys.exit(1)

    replace_section(Path(args.template), args.section, new_data, Path(args.output))


if __name__ == "__main__":
    main()
