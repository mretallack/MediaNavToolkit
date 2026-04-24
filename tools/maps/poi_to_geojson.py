#!/usr/bin/env python3
"""Extract POI coordinates from NNG .poi files as GeoJSON.

POI files use XOR table decryption (same as FBL) but a different container
format. Coordinates are stored as uint16 pairs scaled to the bounding box.

Usage:
    python tools/maps/poi_to_geojson.py tools/maps/testdata/Andorra_osm.poi
    python tools/maps/poi_to_geojson.py tools/maps/testdata/Andorra_osm.poi -o andorra_pois.geojson
"""

import json
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def extract_bbox_from_metadata(dec: bytes):
    """Extract country and bbox from the [nng] metadata string."""
    # Find _XXX|version pattern to get country code
    country = "UNK"
    for i in range(0x10, min(0x200, len(dec)) - 8):
        if dec[i] == ord("_") and dec[i + 1] == 0x00:
            code = ""
            j = i + 2
            while j < len(dec) - 1 and dec[j + 1] == 0x00 and dec[j] != ord("|"):
                code += chr(dec[j])
                j += 2
            if 2 <= len(code) <= 4:
                country = code
                break
    return country


def parse_poi(dec: bytes, lon_min, lat_min, lon_range, lat_range):
    """Parse POI section data into (name, lon, lat) tuples."""
    # Find section 1 (main POI data) from offset table at ~0x136
    offsets = []
    for i in range(0x136, min(0x180, len(dec) - 3), 4):
        v = struct.unpack_from("<I", dec, i)[0]
        if 0 < v < len(dec):
            offsets.append(v)
        else:
            break

    if len(offsets) < 2:
        return []

    # Use the second unique offset as section start, next different offset as end
    unique = sorted(set(offsets))
    sec_start = unique[1] if len(unique) > 1 else unique[0]
    sec_end = unique[2] if len(unique) > 2 else len(dec)
    sec = dec[sec_start:sec_end]

    pois = []
    current_name = None
    i = 0

    while i < len(sec) - 1:
        if sec[i] == 0 and sec[i + 1] == 0:
            if i + 4 < len(sec) and sec[i + 2] >= 0x20 and sec[i + 3] == 0:
                j = i + 2
                name = ""
                while j < len(sec) - 1 and sec[j + 1] == 0 and sec[j] >= 0x20:
                    name += chr(sec[j])
                    j += 2
                current_name = name
                i = j + 2
                continue
            i += 2
            continue

        if i + 3 < len(sec):
            v1 = struct.unpack_from("<H", sec, i)[0]
            v2 = struct.unpack_from("<H", sec, i + 2)[0]
            lon = lon_min + (v1 / 65535.0) * lon_range
            lat = lat_min + (v2 / 65535.0) * lat_range
            if lon_min - 0.1 < lon < lon_min + lon_range + 0.1 and lat_min - 0.1 < lat < lat_min + lat_range + 0.1:
                pois.append((current_name or "", round(lon, 6), round(lat, 6)))
            i += 4
        else:
            i += 1

    return pois


def main():
    if len(sys.argv) < 2:
        print("Usage: poi_to_geojson.py <poi_file> [-o output.geojson]", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)
    country = extract_bbox_from_metadata(dec)

    # Hardcoded bbox lookup (from FBL files) — extend as needed
    BBOXES = {
        "AND": (1.4079, 42.4323, 0.33, 0.2023),
        "VAT": (12.4466, 41.9004, 0.0111, 0.0069),
        "MON": (7.4094, 43.5362, 0.2216, 0.2156),
    }

    if country not in BBOXES:
        print(f"Unknown country {country} — bbox not available", file=sys.stderr)
        sys.exit(1)

    lon_min, lat_min, lon_range, lat_range = BBOXES[country]
    pois = parse_poi(dec, lon_min, lat_min, lon_range, lat_range)

    print(f"{input_path.name}: {country}, {len(pois)} POIs", file=sys.stderr)

    features = [
        {
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {"name": name, "country": country},
        }
        for name, lon, lat in pois
    ]
    geojson = {"type": "FeatureCollection", "features": features}
    text = json.dumps(geojson, indent=2)

    if output_path:
        output_path.write_text(text)
        print(f"Wrote {len(pois)} POIs to {output_path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
