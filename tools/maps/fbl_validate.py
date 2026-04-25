#!/usr/bin/env python3
"""Validate FBL road class extraction against OpenStreetMap data.

Queries OSM Overpass API for roads in the FBL's bounding box and compares
the road class distribution.

Usage:
    python tools/maps/fbl_validate.py tools/maps/testdata/Andorra_osm.fbl
"""

import json
import math
import struct
import subprocess
import sys
from pathlib import Path as _P

sys.path.insert(0, str(_P(__file__).resolve().parent.parent.parent))
from pathlib import Path

import numpy as np

from tools.maps.fbl_road_class import RC_NAMES, decrypt, extract_road_classes

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23

OSM_TO_RC = {
    "motorway": 0,
    "motorway_link": 0,
    "trunk": 2,
    "trunk_link": 2,
    "primary": 3,
    "primary_link": 3,
    "secondary": 4,
    "secondary_link": 4,
    "tertiary": 4,
    "tertiary_link": 4,
    "unclassified": 5,
    "residential": 6,
    "living_street": 7,
    "service": 7,
    "pedestrian": 8,
    "footway": 8,
    "path": 9,
    "steps": 8,
    "track": 9,
    "cycleway": 9,
}


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_validate.py <fbl_file>", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)

    # Get bbox
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            country = dec[off : off + 3].decode()
            vals = struct.unpack_from("<4i", dec, off + 8)
            bbox = (vals[0] / SCALE, vals[3] / SCALE, vals[2] / SCALE, vals[1] / SCALE)
            break

    # Extract FBL road classes
    sec4s = struct.unpack_from("<I", dec, 0x048E + 16)[0]
    sec4e = struct.unpack_from("<I", dec, 0x048E + 20)[0]
    fbl_results = extract_road_classes(dec[sec4s:sec4e])
    fbl_classes = {}
    for _, _, rc, name in fbl_results:
        if rc is not None and rc <= 9:
            fbl_classes[rc] = fbl_classes.get(rc, 0) + 1

    # Query OSM
    print(
        f"{country} bbox: ({bbox[0]:.2f},{bbox[1]:.2f})-({bbox[2]:.2f},{bbox[3]:.2f})",
        file=sys.stderr,
    )
    query = f'[out:json][timeout:30];(way["highway"]({bbox[1]:.4f},{bbox[0]:.4f},{bbox[3]:.4f},{bbox[2]:.4f}););out tags;'
    result = subprocess.run(
        ["curl", "-s", "https://overpass-api.de/api/interpreter", "-d", f"data={query}"],
        capture_output=True,
        text=True,
    )
    try:
        osm = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Failed to query OSM", file=sys.stderr)
        sys.exit(1)

    osm_classes = {}
    for el in osm.get("elements", []):
        hw = el.get("tags", {}).get("highway", "")
        rc = OSM_TO_RC.get(hw)
        if rc is not None:
            osm_classes[rc] = osm_classes.get(rc, 0) + 1

    # Compare
    print(f"\n{'Road Class':>15s} {'FBL':>6s} {'OSM':>6s} {'Match':>6s}")
    print("-" * 40)
    for rc in sorted(set(list(fbl_classes.keys()) + list(osm_classes.keys()))):
        fbl_n = fbl_classes.get(rc, 0)
        osm_n = osm_classes.get(rc, 0)
        name = RC_NAMES.get(rc, f"class_{rc}")
        match = "✓" if (fbl_n > 0) == (osm_n > 0) else "✗"
        print(f"{name:>15s} {fbl_n:>6d} {osm_n:>6d} {match:>6s}")

    fbl_total = sum(fbl_classes.values())
    osm_total = sum(osm_classes.values())
    print(f"{'TOTAL':>15s} {fbl_total:>6d} {osm_total:>6d}")


if __name__ == "__main__":
    main()
