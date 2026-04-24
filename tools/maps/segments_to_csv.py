#!/usr/bin/env python3
"""Extract road segment metadata from NNG .fbl map files.

Finds junction coordinate pairs and the 12-byte segment metadata between them.
Outputs: from_lon, from_lat, to_lon, to_lat, road_type, shape_count, shape_offset.

Usage:
    python tools/maps/segments_to_csv.py tools/maps/testdata/Vatican_osm.fbl
    python tools/maps/segments_to_csv.py tools/maps/testdata/Vatican_osm.fbl -o segments.csv
"""

import csv
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def get_bbox(dec: bytes):
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48):
            vals = struct.unpack_from("<4i", dec, off + 8)
            return vals[0] / SCALE, vals[3] / SCALE, vals[2] / SCALE, vals[1] / SCALE
    return None


def get_country(dec: bytes) -> str:
    for off in range(0x440, min(0x600, len(dec) - 4)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48):
            return dec[off : off + 3].decode()
    return "UNK"


def is_coord(dec, off, bbox):
    if off + 8 > len(dec):
        return False
    lon = struct.unpack_from("<i", dec, off)[0] / SCALE
    lat = struct.unpack_from("<i", dec, off + 4)[0] / SCALE
    m = 0.01
    return (bbox[0] - m) < lon < (bbox[2] + m) and (bbox[1] - m) < lat < (bbox[3] + m)


def extract_segments(dec: bytes, bbox) -> list[dict]:
    """Find consecutive coordinate pairs with 12-byte metadata between them."""
    segments = []

    # Find all coordinate positions
    coord_positions = []
    off = 0x0400
    while off < len(dec) - 8:
        if is_coord(dec, off, bbox):
            lon = struct.unpack_from("<i", dec, off)[0] / SCALE
            lat = struct.unpack_from("<i", dec, off + 4)[0] / SCALE
            # Skip bbox corners
            if any(
                abs(lon - bbox[i]) < 0.0002 and abs(lat - bbox[j]) < 0.0002
                for i in (0, 2)
                for j in (1, 3)
            ):
                off += 4
                continue
            coord_positions.append((off, lon, lat))
            off += 8
        else:
            off += 1

    # Find pairs with exactly 12 bytes between them
    for i in range(len(coord_positions) - 1):
        off1, lon1, lat1 = coord_positions[i]
        off2, lon2, lat2 = coord_positions[i + 1]
        gap = off2 - (off1 + 8)

        if gap == 12:
            meta = dec[off1 + 8 : off2]
            road_type = meta[4]
            packed = struct.unpack_from("<I", meta, 8)[0]
            shape_count = packed >> 16
            shape_offset = packed & 0xFFFF

            segments.append(
                {
                    "from_lon": round(lon1, 6),
                    "from_lat": round(lat1, 6),
                    "to_lon": round(lon2, 6),
                    "to_lat": round(lat2, 6),
                    "road_type": road_type,
                    "shape_count": shape_count,
                    "shape_offset": shape_offset,
                }
            )

    return segments


def main():
    if len(sys.argv) < 2:
        print("Usage: segments_to_csv.py <fbl_file> [-o output.csv]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)
    bbox = get_bbox(dec)
    country = get_country(dec)

    if not bbox:
        print("No bounding box found", file=sys.stderr)
        sys.exit(1)

    segments = extract_segments(dec, bbox)
    print(f"{input_path.name}: {country}, {len(segments)} segments", file=sys.stderr)

    fieldnames = [
        "from_lon",
        "from_lat",
        "to_lon",
        "to_lat",
        "road_type",
        "shape_count",
        "shape_offset",
    ]
    out = open(output_path, "w", newline="") if output_path else sys.stdout
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(segments)
    if output_path:
        out.close()
        print(f"Wrote {len(segments)} segments to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
