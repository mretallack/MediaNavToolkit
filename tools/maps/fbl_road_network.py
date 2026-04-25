#!/usr/bin/env python3
"""Export FBL road network as GeoJSON with road class properties.

Combines coordinate extraction with road class extraction to produce
a GeoJSON file where each point has a road_class property.

Usage:
    python tools/maps/fbl_road_network.py tools/maps/testdata/Monaco_osm.fbl -o monaco.geojson
"""

import json
import math
import struct
import sys
from pathlib import Path as _P

sys.path.insert(0, str(_P(__file__).resolve().parent.parent.parent))
from pathlib import Path

import numpy as np

from tools.maps.fbl_road_class import RC_NAMES, decrypt, extract_road_classes
from tools.maps.nng_varint import SEGMENT_MARKERS, decode_varint

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23

RC_COLORS = {
    0: "#e31a1c",
    1: "#999999",
    2: "#ff7f00",
    3: "#fdbf6f",
    4: "#b2df8a",
    5: "#cccccc",
    6: "#dddddd",
    7: "#eeeeee",
    8: "#6a3d9a",
    9: "#aaaaaa",
}


def main():
    if len(sys.argv) < 2:
        print("Usage: fbl_road_network.py <fbl_file> -o output.geojson", file=sys.stderr)
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    data = input_path.read_bytes()
    dec = decrypt(data, xor_table)

    # Get bbox
    for off in range(0x440, min(0x600, len(dec) - 20)):
        if dec[off : off + 3].isalpha() and dec[off + 3] in (0x40, 0x48, 0x4B):
            country = dec[off : off + 3].decode()
            vals = struct.unpack_from("<4i", dec, off + 8)
            lon_min, lat_max, lon_max, lat_min = vals
            break

    N = math.ceil(math.log2(lon_max - lon_min + 1)) if lon_max > lon_min else 1
    M = math.ceil(math.log2(lat_max - lat_min + 1)) if lat_max > lat_min else 1

    # Get section 4 coordinates
    sec4s = struct.unpack_from("<I", dec, 0x048E + 16)[0]
    sec4e = struct.unpack_from("<I", dec, 0x048E + 20)[0]
    sec4 = dec[sec4s:sec4e]

    # Extract road classes
    rc_results = extract_road_classes(sec4)
    rc_map = {seg: (rc, name) for seg, _, rc, name in rc_results}

    # Decode coordinates from section 4 using numpy
    bits = np.unpackbits(np.frombuffer(sec4, dtype=np.uint8))
    bpp = N + M
    n_pts = len(bits) // bpp
    if n_pts == 0:
        print("No coordinates found", file=sys.stderr)
        sys.exit(1)

    bits = bits[: n_pts * bpp].reshape(n_pts, bpp)
    lon_pow = (2 ** np.arange(N - 1, -1, -1)).astype(np.int64)
    lat_pow = (2 ** np.arange(M - 1, -1, -1)).astype(np.int64)
    lons = np.round((bits[:, :N].astype(np.int64) @ lon_pow + lon_min) / SCALE, 6)
    lats = np.round((bits[:, N:].astype(np.int64) @ lat_pow + lat_min) / SCALE, 6)

    # Assign road class to coordinate points (approximate: distribute evenly)
    n_segs = len(rc_results)
    pts_per_seg = n_pts // max(n_segs, 1)

    features = []
    for i in range(n_pts):
        seg_idx = min(i // max(pts_per_seg, 1), n_segs - 1) + 1
        rc, rc_name = rc_map.get(seg_idx, (None, "unclassified"))
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [float(lons[i]), float(lats[i])]},
                "properties": {
                    "country": country,
                    "segment": int(seg_idx),
                    "road_class": rc,
                    "road_class_name": rc_name,
                    "color": RC_COLORS.get(rc, "#999999"),
                },
            }
        )

    geojson = {"type": "FeatureCollection", "features": features}

    name = input_path.stem.replace("_osm", "")
    classified = sum(1 for _, _, rc, _ in rc_results if rc is not None)
    print(f"{name}: {n_pts} points, {n_segs} segments, {classified} classified", file=sys.stderr)

    if output_path:
        with open(output_path, "w") as f:
            json.dump(geojson, f)
        print(f"Wrote {n_pts} features to {output_path}", file=sys.stderr)
    else:
        json.dump(geojson, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
