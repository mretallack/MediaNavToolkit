#!/usr/bin/env python3
"""Parse NNG .fbl map files and extract structured road network data.

Decodes the varint stream, identifies packed coordinate pairs,
road class markers, and segment boundaries.

Usage:
    python tools/maps/fbl_parse.py tools/maps/testdata/Monaco_osm.fbl
    python tools/maps/fbl_parse.py tools/maps/testdata/Monaco_osm.fbl --geojson -o monaco.geojson
    python tools/maps/fbl_parse.py tools/maps/testdata/Monaco_osm.fbl --csv -o monaco.csv
"""

import csv
import json
import math
import struct
import sys
from pathlib import Path

import numpy as np

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    d = np.frombuffer(data, dtype=np.uint8)
    t = np.frombuffer(xor_table, dtype=np.uint8)
    return bytes(d ^ np.tile(t, (len(d) // len(t)) + 1)[: len(d)])


def decode_varint(data: bytes, pos: int):
    """Decode one UTF-8-like varint. Returns (value, new_pos)."""
    if pos >= len(data):
        return None, pos
    b0 = data[pos]
    if b0 < 0x80:
        return b0, pos + 1
    if b0 < 0xC0:
        return b0, pos + 1
    if (b0 & 0xE0) == 0xC0:
        if pos + 1 >= len(data):
            return None, pos + 1
        return ((b0 & 0x1F) << 6) | (data[pos + 1] & 0x3F), pos + 2
    if (b0 & 0xF0) == 0xE0:
        if pos + 2 >= len(data):
            return None, pos + 1
        return (
            ((b0 & 0x0F) << 12) | ((data[pos + 1] & 0x3F) << 6) | (data[pos + 2] & 0x3F)
        ), pos + 3
    if (b0 & 0xF8) == 0xF0:
        if pos + 3 >= len(data):
            return None, pos + 1
        return (
            ((b0 & 0x07) << 18)
            | ((data[pos + 1] & 0x3F) << 12)
            | ((data[pos + 2] & 0x3F) << 6)
            | (data[pos + 3] & 0x3F)
        ), pos + 4
    if (b0 & 0xFC) == 0xF8:
        if pos + 4 >= len(data):
            return None, pos + 1
        return (
            ((b0 & 0x03) << 24)
            | ((data[pos + 1] & 0x3F) << 18)
            | ((data[pos + 2] & 0x3F) << 12)
            | ((data[pos + 3] & 0x3F) << 6)
            | (data[pos + 4] & 0x3F)
        ), pos + 5
    if (b0 & 0xFE) == 0xFC:
        if pos + 5 >= len(data):
            return None, pos + 1
        return (
            ((b0 & 0x01) << 30)
            | ((data[pos + 1] & 0x3F) << 24)
            | ((data[pos + 2] & 0x3F) << 18)
            | ((data[pos + 3] & 0x3F) << 12)
            | ((data[pos + 4] & 0x3F) << 6)
            | (data[pos + 5] & 0x3F)
        ), pos + 6
    return b0, pos + 1


def parse_fbl(fbl_path: Path):
    """Parse an FBL file and return structured data."""
    xor = XOR_TABLE_PATH.read_bytes()
    dec = decrypt(fbl_path.read_bytes(), xor)

    # Find bbox and section table
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x49, 0x4B):
            country = dec[off : off + 3].decode()
            lon_min, lat_max, lon_max, lat_min = struct.unpack_from("<4i", dec, off + 8)
            table_start = off + 24
            break
    else:
        raise ValueError("Could not find bbox in FBL file")

    dlon = lon_max - lon_min
    dlat = lat_max - lat_min
    lon_bits = math.ceil(math.log2(dlon + 1)) if dlon > 0 else 1
    lat_bits = math.ceil(math.log2(dlat + 1)) if dlat > 0 else 1

    # Read section offsets
    offsets = [struct.unpack_from("<I", dec, table_start + i * 4)[0] for i in range(20)]

    result = {
        "country": country,
        "bbox": {
            "lon_min": lon_min / SCALE,
            "lat_min": lat_min / SCALE,
            "lon_max": lon_max / SCALE,
            "lat_max": lat_max / SCALE,
        },
        "lon_bits": lon_bits,
        "lat_bits": lat_bits,
        "sections": {},
    }

    # Parse road sections (4, 5, 8)
    road_sections = {4: "roads_main", 5: "roads_secondary", 8: "roads_tertiary"}
    for sec_idx, sec_name in road_sections.items():
        sec_start = offsets[sec_idx]
        sec_end = offsets[sec_idx + 1] if sec_idx + 1 < 20 else 0
        if sec_start == 0 or sec_start >= len(dec):
            continue
        if sec_end <= sec_start:
            # Find next non-zero offset
            for j in range(sec_idx + 1, 20):
                if offsets[j] > sec_start:
                    sec_end = offsets[j]
                    break
            else:
                sec_end = len(dec)

        raw = dec[sec_start:sec_end]
        coords = extract_packed_coords(raw, lon_min, lat_min, lon_bits, lat_bits, dlon, dlat)
        result["sections"][sec_name] = {
            "size": len(raw),
            "coordinates": coords,
        }

    return result


def extract_packed_coords(data, lon_min, lat_min, lon_bits, lat_bits, dlon, dlat):
    """Extract packed coordinate pairs from a varint stream."""
    coords = []
    pos = 0
    while pos < len(data):
        val, new_pos = decode_varint(data, pos)
        if val is None:
            break

        lon_off = val >> lat_bits
        lat_off = val & ((1 << lat_bits) - 1)
        if lon_off > 0 and lat_off > 0 and lon_off <= dlon and lat_off <= dlat:
            lon = round((lon_min + lon_off) / SCALE, 6)
            lat = round((lat_min + lat_off) / SCALE, 6)
            coords.append((lon, lat))

        pos = new_pos
    return coords


def to_geojson(result):
    """Convert parsed FBL data to GeoJSON."""
    features = []
    for sec_name, sec_data in result["sections"].items():
        for i, (lon, lat) in enumerate(sec_data["coordinates"]):
            features.append(
                {
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {"section": sec_name, "index": i},
                }
            )
    return {"type": "FeatureCollection", "features": features}


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Parse NNG FBL map files")
    parser.add_argument("fbl_file", help="Path to .fbl file")
    parser.add_argument("--geojson", action="store_true", help="Output as GeoJSON")
    parser.add_argument("--csv", action="store_true", help="Output as CSV")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    result = parse_fbl(Path(args.fbl_file))

    if args.geojson:
        geojson = to_geojson(result)
        text = json.dumps(geojson, indent=2)
        if args.output:
            Path(args.output).write_text(text)
            print(f"Wrote {len(geojson['features'])} features to {args.output}")
        else:
            print(text)
    elif args.csv:
        rows = []
        for sec_name, sec_data in result["sections"].items():
            for i, (lon, lat) in enumerate(sec_data["coordinates"]):
                rows.append({"section": sec_name, "index": i, "lon": lon, "lat": lat})
        if args.output:
            with open(args.output, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["section", "index", "lon", "lat"])
                w.writeheader()
                w.writerows(rows)
            print(f"Wrote {len(rows)} rows to {args.output}")
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=["section", "index", "lon", "lat"])
            w.writeheader()
            w.writerows(rows)
    else:
        # Summary output
        print(f"Country: {result['country']}")
        print(
            f"Bbox: ({result['bbox']['lon_min']:.4f}, {result['bbox']['lat_min']:.4f}) - "
            f"({result['bbox']['lon_max']:.4f}, {result['bbox']['lat_max']:.4f})"
        )
        print(f"Bit widths: lon={result['lon_bits']}, lat={result['lat_bits']}")
        total_coords = 0
        for sec_name, sec_data in result["sections"].items():
            n = len(sec_data["coordinates"])
            total_coords += n
            print(f"  {sec_name}: {sec_data['size']:,} bytes, {n} coordinates")
        print(f"Total coordinates: {total_coords}")


if __name__ == "__main__":
    main()
