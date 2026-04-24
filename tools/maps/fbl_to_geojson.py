#!/usr/bin/env python3
"""Extract all coordinates from all sections of NNG .fbl map files as GeoJSON.

All sections use packed [N-bit lon][M-bit lat] bitstream encoding relative
to the bounding box minimum. Bit widths: ceil(log2(bbox_range + 1)).

Usage:
    python tools/maps/fbl_to_geojson.py tools/maps/testdata/Monaco_osm.fbl
    python tools/maps/fbl_to_geojson.py tools/maps/testdata/Monaco_osm.fbl -o monaco.geojson
"""

import json
import math
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23

SECTION_ROLES = {
    0: "marker", 1: "curves", 2: "boundary_a", 3: "boundary_b",
    4: "roads_main", 5: "roads_secondary", 6: "centroid", 7: "centroid",
    8: "roads_tertiary", 9: "marker", 10: "features", 11: "features",
    12: "features", 13: "features", 14: "features", 15: "labels",
    16: "areas", 17: "areas", 18: "extended",
}


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


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


def parse_fbl(dec: bytes):
    """Parse a decrypted FBL file. Returns (country, bbox, lon_bits, lat_bits, sections)."""
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48):
            country = dec[off : off + 3].decode()
            vals = struct.unpack_from("<4i", dec, off + 8)
            lon_min, lat_max, lon_max, lat_min = vals
            dlon = lon_max - lon_min
            dlat = lat_max - lat_min
            lon_bits = math.ceil(math.log2(dlon + 1)) if dlon > 0 else 1
            lat_bits = math.ceil(math.log2(dlat + 1)) if dlat > 0 else 1
            table_start = off + 24

            offsets = [struct.unpack_from("<I", dec, table_start + i * 4)[0] for i in range(20)]

            sections = {}
            for i in range(20):
                start = offsets[i]
                if start == 0 or start >= len(dec):
                    continue
                if i > 0 and start == offsets[i - 1]:
                    continue
                end = len(dec)
                for j in range(i + 1, 20):
                    if offsets[j] > start:
                        end = offsets[j]
                        break
                sec_data = dec[start:end]
                if len(sec_data) < 4:
                    continue

                br = BitReader(sec_data)
                points = []
                while br.pos + lon_bits + lat_bits <= len(sec_data) * 8:
                    lr = br.read(lon_bits)
                    latr = br.read(lat_bits)
                    lon = round((lon_min + lr) / SCALE, 6)
                    lat = round((lat_min + latr) / SCALE, 6)
                    points.append((lon, lat))
                if points:
                    sections[i] = points

            bbox = (
                round(lon_min / SCALE, 6), round(lat_min / SCALE, 6),
                round(lon_max / SCALE, 6), round(lat_max / SCALE, 6),
            )
            return country, bbox, lon_bits, lat_bits, sections
    return None


def to_geojson(country, sections):
    features = []
    for sec_idx, points in sorted(sections.items()):
        role = SECTION_ROLES.get(sec_idx, "unknown")
        for pi, (lon, lat) in enumerate(points):
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": {"section": sec_idx, "role": role, "point": pi, "country": country},
            })
    return {"type": "FeatureCollection", "features": features}


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_to_geojson.py <fbl_file> [-o output.geojson]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)
    result = parse_fbl(dec)
    if not result:
        print("Could not parse FBL file", file=sys.stderr)
        sys.exit(1)

    country, bbox, lon_bits, lat_bits, sections = result
    total = sum(len(pts) for pts in sections.values())

    print(f"{input_path.name}: {country}, {lon_bits}+{lat_bits} bits, "
          f"{len(sections)} sections, {total} points", file=sys.stderr)
    for idx in sorted(sections):
        role = SECTION_ROLES.get(idx, "unknown")
        print(f"  [{idx:2d}] {role:16s} {len(sections[idx]):6d} pts", file=sys.stderr)

    geojson = to_geojson(country, sections)
    text = json.dumps(geojson, indent=2)

    if output_path:
        output_path.write_text(text)
        print(f"Wrote {total} points to {output_path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
