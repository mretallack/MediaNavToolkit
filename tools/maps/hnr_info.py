#!/usr/bin/env python3
"""Extract routing data from NNG .hnr (Historical Navigation Routing) files.

HNR files contain routing weights for road segments, organized as 256-byte
tiles with 64 entries each. Each entry has a 32-bit road segment identifier
and routing-specific weight data.

Usage:
    python tools/maps/hnr_info.py tools/maps/testdata/EuropeEconomic.hnr
    python tools/maps/hnr_info.py tools/maps/testdata/EuropeEconomic.hnr --stats
"""

import struct
import sys
from pathlib import Path

import numpy as np

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


def parse_hnr(dec: bytes):
    """Parse HNR file. Returns metadata dict and block info."""
    magic = dec[:4]
    if magic != b"HNRF":
        return None

    version = struct.unpack_from("<I", dec, 4)[0]
    meta_len = struct.unpack_from("<I", dec, 0x10)[0]
    metadata = dec[0x14 : 0x14 + meta_len * 2].decode("utf-16-le", errors="replace").rstrip("\x00")

    # Extract routing type from metadata
    routing_type = "Unknown"
    for line in metadata.replace("\\n", "\n").split("\n"):
        if "|" in line and line.startswith("~"):
            parts = line.split("|")
            if len(parts) >= 4:
                routing_type = parts[3].strip()

    # Read block counts
    counts = [struct.unpack_from("<I", dec, 0x0210 + i * 4)[0] >> 8 for i in range(384)]

    # Sanity check: if total exceeds 10M records, the >>8 interpretation is wrong
    # (Shortest variant uses a different format)
    total_check = sum(counts)
    if total_check > 10_000_000:
        counts = [struct.unpack_from("<I", dec, 0x0210 + i * 4)[0] for i in range(384)]

    pairs = [(counts[i * 2], counts[i * 2 + 1]) for i in range(192)]

    total_a = sum(a for a, b in pairs)
    total_b = sum(b for a, b in pairs)

    return {
        "version": version,
        "routing_type": routing_type,
        "metadata": metadata.split("\n")[0] if metadata else "",
        "pairs": pairs,
        "total_a": total_a,
        "total_b": total_b,
        "total_records": total_a + total_b,
        "total_segments": (total_a + total_b) * 64,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: hnr_info.py <hnr_file> [--stats]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    show_stats = "--stats" in sys.argv

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)
    info = parse_hnr(dec)

    if not info:
        print("Not a valid HNR file", file=sys.stderr)
        sys.exit(1)

    print(f"{input_path.name}: {info['routing_type']}", file=sys.stderr)
    print(f"  Version: {info['version']}", file=sys.stderr)
    print(f"  Regions: {len(info['pairs'])}", file=sys.stderr)
    print(f"  Records: {info['total_records']:,} ({info['total_a']:,} major + {info['total_b']:,} minor)", file=sys.stderr)
    print(f"  Segments: {info['total_segments']:,} ({info['total_a']*64:,} major + {info['total_b']*64:,} minor)", file=sys.stderr)

    if show_stats:
        print(f"\nRegion breakdown:", file=sys.stderr)
        for i, (a, b) in enumerate(info["pairs"]):
            if a + b > 0:
                ratio = a / b if b > 0 else 0
                print(f"  Region {i:3d}: major={a:>5} minor={b:>5} "
                      f"total={a+b:>5} ratio={ratio:.2f}", file=sys.stderr)


if __name__ == "__main__":
    main()
