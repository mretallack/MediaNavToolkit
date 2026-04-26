#!/usr/bin/env python3
"""Extract road curve coordinates from NNG .fbl map files as GeoJSON.

Decodes the section 1 bitstream which stores curve points as packed
[N-bit lon_offset][M-bit lat_offset] pairs relative to the bounding box
minimum, MSB-first. Bit widths are ceil(log2(bbox_range + 1)).

Small files use 68 00 02 record markers; larger files store points
as a flat bitstream. Use --all to extract from all sections (not just section 1).

Usage:
    python tools/maps/curves_to_geojson.py tools/maps/testdata/Vatican_osm.fbl
    python tools/maps/curves_to_geojson.py tools/maps/testdata/Monaco_osm.fbl --all
    python tools/maps/curves_to_geojson.py tools/maps/testdata/Vatican_osm.fbl -o curves.geojson
"""

import json
import math
import struct
import sys
from pathlib import Path

_XOR_LOCAL = Path(__file__).parent / "xor_key.bin"
_XOR_ANALYSIS = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
XOR_TABLE_PATH = _XOR_LOCAL if _XOR_LOCAL.exists() else _XOR_ANALYSIS
SCALE = 2**23
MARKER = b"\x68\x00\x02"
RECORD_HEADER = b"\x24\x8b\x18"


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    try:
        import numpy as np
        d = np.frombuffer(data, dtype=np.uint8)
        t = np.frombuffer(xor_table, dtype=np.uint8)
        return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])
    except ImportError:
        return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def get_bbox_raw(dec: bytes):
    """Return (lon_min, lat_min, lon_max, lat_max) as raw int32 values."""
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            vals = struct.unpack_from("<4i", dec, off + 8)
            return vals[0], vals[3], vals[2], vals[1]  # lon_min, lat_min, lon_max, lat_max
    return None


def get_country(dec: bytes) -> str:
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            return dec[off : off + 3].decode()
    return "UNK"


def get_section1(dec: bytes) -> bytes | None:
    """Extract section 1 data using the offset table."""
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            table_start = off + 24
            sec1_off = struct.unpack_from("<I", dec, table_start + 4)[0]
            sec2_off = struct.unpack_from("<I", dec, table_start + 8)[0]
            if 0 < sec1_off < len(dec) and sec1_off < sec2_off <= len(dec):
                return dec[sec1_off:sec2_off]
    return None


def bit_width(range_val: int) -> int:
    """Calculate bits needed to represent values 0..range_val."""
    if range_val <= 0:
        return 1
    return math.ceil(math.log2(range_val + 1))


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> int:
        val = 0
        for _ in range(n):
            byte_idx = self.pos >> 3
            bit_idx = 7 - (self.pos & 7)
            if byte_idx < len(self.data):
                val = (val << 1) | ((self.data[byte_idx] >> bit_idx) & 1)
            self.pos += 1
        return val


def decode_curve_points(
    sec1: bytes, bbox_lon_min: int, bbox_lat_min: int, lon_bits: int, lat_bits: int
) -> list[list[tuple[float, float]]]:
    """Decode section 1 bitstream into lists of (lon, lat) coordinate pairs."""
    bits_per_point = lon_bits + lat_bits
    has_markers = MARKER in sec1

    if has_markers:
        # Small files: records separated by 68 00 02 markers
        records = []
        i = 0
        while i < len(sec1):
            idx = sec1.find(MARKER, i)
            if idx == -1:
                records.append((i, sec1[i:]))
                break
            records.append((i, sec1[i:idx]))
            i = idx + len(MARKER)

        all_curves = []
        for ri, (offset, rec) in enumerate(records):
            if len(rec) < 4:
                continue
            # Header record: skip 2 zero bytes; data records: skip 3-byte header
            skip = 2 if ri == 0 else 3
            rec_data = rec[skip:]
            br = BitReader(rec_data)
            points = []
            while br.pos + bits_per_point <= len(rec_data) * 8:
                lon_rel = br.read(lon_bits)
                lat_rel = br.read(lat_bits)
                lon = (bbox_lon_min + lon_rel) / SCALE
                lat = (bbox_lat_min + lat_rel) / SCALE
                points.append((round(lon, 6), round(lat, 6)))
            if points:
                all_curves.append(points)
        return all_curves
    else:
        # Larger files: flat bitstream, no markers
        br = BitReader(sec1)
        points = []
        while br.pos + bits_per_point <= len(sec1) * 8:
            lon_rel = br.read(lon_bits)
            lat_rel = br.read(lat_bits)
            lon = (bbox_lon_min + lon_rel) / SCALE
            lat = (bbox_lat_min + lat_rel) / SCALE
            points.append((round(lon, 6), round(lat, 6)))
        return [points] if points else []


def to_geojson(curves: list[list[tuple[float, float]]], country: str) -> dict:
    features = []
    for ci, points in enumerate(curves):
        for pi, (lon, lat) in enumerate(points):
            features.append(
                {
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {"country": country, "record": ci, "point": pi},
                }
            )
    return {"type": "FeatureCollection", "features": features}


def main():
    if len(sys.argv) < 2:
        print("Usage: curves_to_geojson.py <fbl_file> [-o output.geojson]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)

    bbox = get_bbox_raw(dec)
    if not bbox:
        print("Could not find bounding box", file=sys.stderr)
        sys.exit(1)

    country = get_country(dec)
    sec1 = get_section1(dec)
    if not sec1:
        print("Could not find section 1", file=sys.stderr)
        sys.exit(1)

    lon_min, lat_min, lon_max, lat_max = bbox
    lon_bits = bit_width(lon_max - lon_min)
    lat_bits = bit_width(lat_max - lat_min)

    use_all = "--all" in sys.argv

    if use_all:
        # Extract from ALL sections using fbl_to_geojson logic
        from fbl_to_geojson import parse_fbl

        result = parse_fbl(dec)
        if not result:
            print("Could not parse FBL file", file=sys.stderr)
            sys.exit(1)
        _, _, _, _, all_sections = result
        curves = [pts for pts in all_sections.values()]
        total_points = sum(len(c) for c in curves)
        print(
            f"{input_path.name}: {country}, {lon_bits}+{lat_bits} bits, "
            f"ALL {len(all_sections)} sections, {total_points} points",
            file=sys.stderr,
        )
    else:
        curves = decode_curve_points(sec1, lon_min, lat_min, lon_bits, lat_bits)
        total_points = sum(len(c) for c in curves)
        print(
            f"{input_path.name}: {country}, {lon_bits}+{lat_bits} bits, "
            f"{len(curves)} records, {total_points} curve points",
            file=sys.stderr,
        )

    print(
        f"{input_path.name}: {country}, {lon_bits}+{lat_bits} bits, "
        f"{len(curves)} records, {total_points} curve points",
        file=sys.stderr,
    )

    geojson = to_geojson(curves, country)
    text = json.dumps(geojson, indent=2)

    if output_path:
        output_path.write_text(text)
        print(f"Wrote {total_points} points to {output_path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
