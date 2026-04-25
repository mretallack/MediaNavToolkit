#!/usr/bin/env python3
"""Extract all coordinates from all sections of NNG .fbl map files as GeoJSON.

All sections use packed [N-bit lon][M-bit lat] bitstream encoding relative
to the bounding box minimum. Bit widths: ceil(log2(bbox_range + 1)).

Usage:
    python tools/maps/fbl_to_geojson.py tools/maps/testdata/Monaco_osm.fbl
    python tools/maps/fbl_to_geojson.py tools/maps/testdata/Monaco_osm.fbl -o monaco.geojson
    python tools/maps/fbl_to_geojson.py /tmp/uk.fbl --csv -o uk_coords.csv
"""

import csv
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
    try:
        import numpy as np
        d = np.frombuffer(data, dtype=np.uint8)
        t = np.frombuffer(xor_table, dtype=np.uint8)
        return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])
    except ImportError:
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


def decode_section(sec_data: bytes, lon_bits: int, lat_bits: int, lon_min: int, lat_min: int):
    """Decode packed bitstream into (lons, lats) arrays. Processes in chunks for large data."""
    try:
        import numpy as np
        bits_per_point = lon_bits + lat_bits
        n_points = (len(sec_data) * 8) // bits_per_point
        if n_points == 0:
            return [], []

        # Process in 1MB chunks to avoid OOM
        CHUNK = 1_000_000  # bytes
        lon_pow = (2 ** np.arange(lon_bits - 1, -1, -1)).astype(np.int64)
        lat_pow = (2 ** np.arange(lat_bits - 1, -1, -1)).astype(np.int64)
        all_lons, all_lats = [], []

        byte_offset = 0
        while byte_offset < len(sec_data):
            chunk = sec_data[byte_offset : byte_offset + CHUNK]
            chunk_points = (len(chunk) * 8) // bits_per_point
            if chunk_points == 0:
                break
            usable_bytes = (chunk_points * bits_per_point + 7) // 8
            bits = np.unpackbits(np.frombuffer(chunk[:usable_bytes], dtype=np.uint8))
            bits = bits[: chunk_points * bits_per_point].reshape(chunk_points, bits_per_point)
            lons = (bits[:, :lon_bits].astype(np.int64) @ lon_pow + lon_min) / SCALE
            lats = (bits[:, lon_bits:].astype(np.int64) @ lat_pow + lat_min) / SCALE
            all_lons.extend(np.round(lons, 6).tolist())
            all_lats.extend(np.round(lats, 6).tolist())
            # Advance by exact number of bytes consumed (may not align to byte boundary)
            byte_offset += (chunk_points * bits_per_point) // 8

        return all_lons, all_lats
    except ImportError:
        br = BitReader(sec_data)
        lons, lats = [], []
        while br.pos + lon_bits + lat_bits <= len(sec_data) * 8:
            lr = br.read(lon_bits)
            latr = br.read(lat_bits)
            lons.append(round((lon_min + lr) / SCALE, 6))
            lats.append(round((lat_min + latr) / SCALE, 6))
        return lons, lats


def parse_fbl(dec: bytes):
    """Parse a decrypted FBL file. Returns (country, bbox, lon_bits, lat_bits, section_ranges)."""
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            country = dec[off : off + 3].decode()
            vals = struct.unpack_from("<4i", dec, off + 8)
            lon_min, lat_max, lon_max, lat_min = vals
            dlon = lon_max - lon_min
            dlat = lat_max - lat_min
            lon_bits = math.ceil(math.log2(dlon + 1)) if dlon > 0 else 1
            lat_bits = math.ceil(math.log2(dlat + 1)) if dlat > 0 else 1
            table_start = off + 24

            offsets = [struct.unpack_from("<I", dec, table_start + i * 4)[0] for i in range(20)]

            section_ranges = {}
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
                if end - start >= 4:
                    section_ranges[i] = (start, end)

            # For large files, include data after the last section offset
            # (the section table only covers the first part of the file)
            last_offset = max((o for o in offsets if 0 < o < len(dec)), default=0)
            if last_offset > 0 and len(dec) - last_offset > 1024:
                # Check if there's significant data after the last section
                trailing = len(dec) - last_offset
                if trailing > max(end - start for start, end in section_ranges.values()):
                    section_ranges[19] = (last_offset, len(dec))

            bbox = (
                round(lon_min / SCALE, 6), round(lat_min / SCALE, 6),
                round(lon_max / SCALE, 6), round(lat_max / SCALE, 6),
            )
            return country, bbox, lon_bits, lat_bits, lon_min, lat_min, section_ranges
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
        print("Usage: fbl_to_geojson.py <fbl_file> [-o output] [--csv]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])
    use_csv = "--csv" in sys.argv
    sec_filter = None
    if "--sections" in sys.argv:
        sec_filter = set(int(x) for x in sys.argv[sys.argv.index("--sections") + 1].split(","))

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)
    result = parse_fbl(dec)
    if not result:
        print("Could not parse FBL file", file=sys.stderr)
        sys.exit(1)

    country, bbox, lon_bits, lat_bits, lon_min, lat_min, section_ranges = result

    # Count points per section
    total = 0
    sec_counts = {}
    for idx, (start, end) in sorted(section_ranges.items()):
        n = ((end - start) * 8) // (lon_bits + lat_bits)
        sec_counts[idx] = n
        total += n

    print(f"{input_path.name}: {country}, {lon_bits}+{lat_bits} bits, "
          f"{len(section_ranges)} sections, {total} points", file=sys.stderr)
    for idx in sorted(sec_counts):
        role = SECTION_ROLES.get(idx, "unknown")
        print(f"  [{idx:2d}] {role:16s} {sec_counts[idx]:6d} pts", file=sys.stderr)

    out = open(output_path, "w", newline="" if use_csv else None) if output_path else sys.stdout

    if use_csv:
        w = csv.writer(out)
        w.writerow(["section", "role", "longitude", "latitude"])
        for idx, (start, end) in sorted(section_ranges.items()):
            if sec_filter and idx not in sec_filter:
                continue
            role = SECTION_ROLES.get(idx, "unknown")
            lons, lats = decode_section(dec[start:end], lon_bits, lat_bits, lon_min, lat_min)
            for lon, lat in zip(lons, lats):
                w.writerow([idx, role, lon, lat])
    else:
        out.write('{"type":"FeatureCollection","features":[\n')
        first = True
        for idx, (start, end) in sorted(section_ranges.items()):
            if sec_filter and idx not in sec_filter:
                continue
            role = SECTION_ROLES.get(idx, "unknown")
            lons, lats = decode_section(dec[start:end], lon_bits, lat_bits, lon_min, lat_min)
            for pi, (lon, lat) in enumerate(zip(lons, lats)):
                if not first:
                    out.write(",\n")
                first = False
                out.write(json.dumps({
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {"section": idx, "role": role, "country": country},
                }))
        out.write("\n]}\n")

    if output_path:
        out.close()
        print(f"Wrote {total} points to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
