#!/usr/bin/env python3
"""Extract road junction coordinates from NNG .fbl map files as GeoJSON.

Scans decrypted .fbl files for full int32 coordinate pairs within the
bounding box and outputs them as a GeoJSON FeatureCollection.

Usage:
    python tools/maps/junctions_to_geojson.py tools/maps/testdata/Vatican_osm.fbl
    python tools/maps/junctions_to_geojson.py tools/maps/testdata/Vatican_osm.fbl -o vatican.geojson
"""

import json
import struct
import sys
from pathlib import Path

_XOR_LOCAL = Path(__file__).parent / "xor_key.bin"
_XOR_ANALYSIS = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
XOR_TABLE_PATH = _XOR_LOCAL if _XOR_LOCAL.exists() else _XOR_ANALYSIS
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def get_bbox(dec: bytes) -> tuple[float, float, float, float] | None:
    """Extract bounding box from the country block."""
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            vals = struct.unpack_from("<4i", dec, off + 8)
            return (
                vals[0] / SCALE,  # lon_min
                vals[3] / SCALE,  # lat_min
                vals[2] / SCALE,  # lon_max
                vals[1] / SCALE,  # lat_max
            )
    return None


def get_country(dec: bytes) -> str:
    """Extract country code."""
    for off in range(0x440, min(0x600, len(dec) - 4)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            return dec[off : off + 3].decode()
    return "UNK"


def extract_junctions(dec: bytes, bbox: tuple) -> list[tuple[float, float]]:
    """Find all full int32 coordinate pairs within the bounding box."""
    lon_min, lat_min, lon_max, lat_max = bbox
    # Expand bbox slightly for edge coordinates
    margin = 0.01
    coords = []
    seen = set()

    for off in range(0x0400, len(dec) - 8):
        lon = struct.unpack_from("<i", dec, off)[0] / SCALE
        lat = struct.unpack_from("<i", dec, off + 4)[0] / SCALE

        if (lon_min - margin) < lon < (lon_max + margin) and (lat_min - margin) < lat < (
            lat_max + margin
        ):
            # Skip bbox corner values themselves
            if abs(lon - lon_min) < 0.0001 and abs(lat - lat_max) < 0.0001:
                continue
            if abs(lon - lon_max) < 0.0001 and abs(lat - lat_min) < 0.0001:
                continue
            if abs(lon - lon_min) < 0.0001 and abs(lat - lat_min) < 0.0001:
                continue
            if abs(lon - lon_max) < 0.0001 and abs(lat - lat_max) < 0.0001:
                continue

            key = (round(lon, 5), round(lat, 5))
            if key not in seen:
                seen.add(key)
                coords.append((lon, lat))

    return coords


def to_geojson(coords: list[tuple[float, float]], country: str) -> dict:
    """Convert coordinate list to GeoJSON FeatureCollection."""
    features = []
    for i, (lon, lat) in enumerate(coords):
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [round(lon, 6), round(lat, 6)]},
                "properties": {"id": i, "country": country},
            }
        )
    return {"type": "FeatureCollection", "features": features}


def main():
    if len(sys.argv) < 2:
        print("Usage: junctions_to_geojson.py <fbl_file> [-o output.geojson]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)

    bbox = get_bbox(dec)
    if not bbox:
        print("Could not find bounding box", file=sys.stderr)
        sys.exit(1)

    country = get_country(dec)
    coords = extract_junctions(dec, bbox)

    print(f"{input_path.name}: {country}, bbox={bbox}, {len(coords)} junctions", file=sys.stderr)

    geojson = to_geojson(coords, country)
    text = json.dumps(geojson, indent=2)

    if output_path:
        output_path.write_text(text)
        print(f"Wrote {len(coords)} junctions to {output_path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
