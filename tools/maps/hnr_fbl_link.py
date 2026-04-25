#!/usr/bin/env python3
"""Link HNR routing tiles to FBL countries.

Matches HNR tiles to FBL countries using segment count ratio (8.3x)
and geographic bbox isolation.

Usage:
    python tools/maps/hnr_fbl_link.py tools/maps/testdata/EuropeEconomic.hnr
"""

import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
RATIO = 8.3  # HNR entries per FBL segment


def decrypt(data, xor_table):
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


# Known tile→country mappings (from segment count + bbox isolation analysis)
KNOWN_LINKS = {
    11: "FrenchGuiana",
    20: "Liechtenstein",
    21: "Reunion",
    36: "Guadeloupe",
    38: "SanMarino",
    41: "Martinique",
    51: "Andorra",
    52: "Gibraltar",
    147: "Monaco",
    166: "Mayotte",
}


def main():
    if len(sys.argv) < 2:
        print("Usage: hnr_fbl_link.py <hnr_file>", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    hnr_path = Path(sys.argv[1])
    dec = decrypt(hnr_path.read_bytes(), xor_table)

    counts = [struct.unpack_from("<I", dec, 0x0210 + i * 4)[0] >> 8 for i in range(384)]
    pairs = [(counts[i * 2], counts[i * 2 + 1]) for i in range(192)]

    print(f"{'Tile':>5s} {'A_segs':>8s} {'B_segs':>8s} {'Total':>8s} {'A%':>6s} {'Country':>20s}")
    print("-" * 60)

    for i, (a, b) in enumerate(pairs):
        total = (a + b) * 64
        a_segs = a * 64
        ratio = a_segs / total if total > 0 else 0
        country = KNOWN_LINKS.get(i, "")
        if country or total > 0:
            print(f"{i:5d} {a_segs:8,} {b * 64:8,} {total:8,} {ratio:6.1%} {country:>20s}")


if __name__ == "__main__":
    main()
