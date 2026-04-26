#!/usr/bin/env python3
"""NNG map data model and OSM-to-FBL converter.

Converts OpenStreetMap PBF data into NNG .fbl map files by:
1. Reading OSM ways/nodes for a bounding box
2. Building an NNG road network model
3. Encoding as FBL section data (varint stream)
4. Writing to an FBL file using an existing file as template

Usage:
    python tools/maps/osm_to_fbl.py input.osm.pbf --bbox 7.41,43.54,7.63,43.75 \\
        --template tools/maps/testdata/Monaco_osm.fbl -o output.fbl
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

SCALE = 2**23

# OSM highway tag → NNG road class mapping
OSM_TO_NNG_CLASS = {
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
    "unclassified": 1,
    "residential": 5,
    "living_street": 6,
    "service": 7,
    "pedestrian": 8,
    "footway": 8,
    "cycleway": 8,
    "path": 9,
    "track": 9,
}


@dataclass
class Coord:
    lon: float
    lat: float

    def to_int(self) -> tuple[int, int]:
        return round(self.lon * SCALE), round(self.lat * SCALE)


@dataclass
class RoadSegment:
    """A road segment between two junctions."""

    road_class: int  # 0-9
    coords: list[Coord]  # shape points (first=start junction, last=end junction)
    name: str = ""
    oneway: bool = False
    speed_limit: int = 0  # km/h, 0=unknown


@dataclass
class RoadNetwork:
    """Complete road network for one map tile."""

    country: str  # 3-letter code
    bbox: tuple[float, float, float, float]  # lon_min, lat_min, lon_max, lat_max
    segments: list[RoadSegment] = field(default_factory=list)

    @property
    def lon_min_int(self) -> int:
        return round(self.bbox[0] * SCALE)

    @property
    def lat_min_int(self) -> int:
        return round(self.bbox[1] * SCALE)

    @property
    def lon_max_int(self) -> int:
        return round(self.bbox[2] * SCALE)

    @property
    def lat_max_int(self) -> int:
        return round(self.bbox[3] * SCALE)

    @property
    def lon_bits(self) -> int:
        d = self.lon_max_int - self.lon_min_int
        return math.ceil(math.log2(d + 1)) if d > 0 else 1

    @property
    def lat_bits(self) -> int:
        d = self.lat_max_int - self.lat_min_int
        return math.ceil(math.log2(d + 1)) if d > 0 else 1


# ── OSM PBF reader ──────────────────────────────────────────────────────────


def read_osm_pbf(pbf_path: str, bbox: tuple[float, float, float, float]) -> RoadNetwork:
    """Read OSM PBF file and extract road network within bbox.

    Requires the `osmium` package: pip install osmium
    """
    import osmium

    lon_min, lat_min, lon_max, lat_max = bbox
    nodes: dict[int, Coord] = {}
    segments: list[RoadSegment] = []

    class NodeHandler(osmium.SimpleHandler):
        def node(self, n):
            if lon_min <= n.location.lon <= lon_max and lat_min <= n.location.lat <= lat_max:
                nodes[n.id] = Coord(n.location.lon, n.location.lat)

    class WayHandler(osmium.SimpleHandler):
        def way(self, w):
            highway = w.tags.get("highway")
            if highway not in OSM_TO_NNG_CLASS:
                return
            coords = []
            for n in w.nodes:
                if n.ref in nodes:
                    coords.append(nodes[n.ref])
            if len(coords) < 2:
                return
            segments.append(
                RoadSegment(
                    road_class=OSM_TO_NNG_CLASS[highway],
                    coords=coords,
                    name=w.tags.get("name", ""),
                    oneway=w.tags.get("oneway") == "yes",
                    speed_limit=(
                        int(w.tags.get("maxspeed", "0").split()[0])
                        if w.tags.get("maxspeed", "").split()[0].isdigit()
                        else 0
                    ),
                )
            )

    NodeHandler().apply_file(pbf_path)
    WayHandler().apply_file(pbf_path)

    country = "OSM"  # Default; caller can override
    return RoadNetwork(country=country, bbox=bbox, segments=segments)


def read_osm_xml(xml_path: str, bbox: tuple[float, float, float, float]) -> RoadNetwork:
    """Read OSM XML file (for small areas / testing)."""
    import xml.etree.ElementTree as ET

    lon_min, lat_min, lon_max, lat_max = bbox
    tree = ET.parse(xml_path)
    root = tree.getroot()

    nodes: dict[int, Coord] = {}
    for node in root.iter("node"):
        lon = float(node.get("lon", 0))
        lat = float(node.get("lat", 0))
        if lon_min <= lon <= lon_max and lat_min <= lat <= lat_max:
            nodes[int(node.get("id"))] = Coord(lon, lat)

    segments: list[RoadSegment] = []
    for way in root.iter("way"):
        tags = {t.get("k"): t.get("v") for t in way.iter("tag")}
        highway = tags.get("highway")
        if highway not in OSM_TO_NNG_CLASS:
            continue
        coords = []
        for nd in way.iter("nd"):
            ref = int(nd.get("ref"))
            if ref in nodes:
                coords.append(nodes[ref])
        if len(coords) < 2:
            continue
        segments.append(
            RoadSegment(
                road_class=OSM_TO_NNG_CLASS[highway],
                coords=coords,
                name=tags.get("name", ""),
                oneway=tags.get("oneway") == "yes",
            )
        )

    return RoadNetwork(country="OSM", bbox=bbox, segments=segments)


# ── FBL section encoder ─────────────────────────────────────────────────────


def encode_varint(val: int) -> bytes:
    """Encode value as UTF-8-like varint."""
    if val < 0x80:
        return bytes([val])
    if val < 0x800:
        return bytes([0xC0 | (val >> 6), 0x80 | (val & 0x3F)])
    if val < 0x10000:
        return bytes([0xE0 | (val >> 12), 0x80 | ((val >> 6) & 0x3F), 0x80 | (val & 0x3F)])
    if val < 0x200000:
        return bytes(
            [
                0xF0 | (val >> 18),
                0x80 | ((val >> 12) & 0x3F),
                0x80 | ((val >> 6) & 0x3F),
                0x80 | (val & 0x3F),
            ]
        )
    if val < 0x4000000:
        return bytes(
            [
                0xF8 | (val >> 24),
                0x80 | ((val >> 18) & 0x3F),
                0x80 | ((val >> 12) & 0x3F),
                0x80 | ((val >> 6) & 0x3F),
                0x80 | (val & 0x3F),
            ]
        )
    return bytes(
        [
            0xFC | (val >> 30),
            0x80 | ((val >> 24) & 0x3F),
            0x80 | ((val >> 18) & 0x3F),
            0x80 | ((val >> 12) & 0x3F),
            0x80 | ((val >> 6) & 0x3F),
            0x80 | (val & 0x3F),
        ]
    )


def network_to_records(net: RoadNetwork) -> list[int]:
    """Convert a RoadNetwork to uint32 records for FBL section 4.

    Coordinates are encoded as bbox offsets to fit in 31 bits.
    Structure: for each segment, emit data values then control markers.
    """
    records: list[int] = []
    current_class = -1
    lon_min = net.lon_min_int
    lat_min = net.lat_min_int

    for seg in net.segments:
        # Road class change
        if seg.road_class != current_class:
            records.append(0x80030000 | seg.road_class)
            current_class = seg.road_class

        # Encode coordinates as data values FIRST
        for coord in seg.coords:
            lon_int, lat_int = coord.to_int()
            lon_off = max(0, lon_int - lon_min)
            lat_off = max(0, lat_int - lat_min)
            records.append(lon_off & 0x7FFFFFFF)
            records.append(lat_off & 0x7FFFFFFF)

        # Then road segment marker (generates 0x80330000 after data)
        records.append(0x80330000)

        # Separator between segments
        records.append(0x80090000)

    # End marker
    records.append(0x80000000)
    return records


def records_to_bytes(records: list[int]) -> bytes:
    """Encode records as raw FBL section bytes.

    Data records go inside \\Q...\\E quote blocks.
    Control records are encoded as metacharacters AFTER closing the quote.
    The DLL's regex engine generates control records from metacharacters
    that follow data tokens.
    """
    out = bytearray()
    in_quote = False

    def open_quote():
        nonlocal in_quote
        if not in_quote:
            out.append(0x5C)  # \Q
            out.append(0x51)
            in_quote = True

    def close_quote():
        nonlocal in_quote
        if in_quote:
            out.append(0x5C)  # \E
            out.append(0x45)
            in_quote = False

    _CTRL_META = {
        0x80090000: 0x5E,  # ^
        0x80330000: 0x2B,  # +
        0x80160000: 0x24,  # $
        0x80010000: 0x7C,  # |
        0x80170000: 0x2E,  # .
    }

    for r in records:
        if r >= 0x80000000:
            typ = r & 0xFFFF0000
            if r == 0x80000000:
                close_quote()
                out.append(0x0A)
            elif typ in _CTRL_META:
                close_quote()
                out.append(_CTRL_META[typ])
            elif typ in (0x80030000, 0x80180000):
                close_quote()
                out.append(0x5C)
                out.extend(encode_varint(r & 0xFFFF))
            # Other control: skip
        else:
            open_quote()
            out.extend(encode_varint(r))

    close_quote()
    return bytes(out)


# ── FBL file writer ──────────────────────────────────────────────────────────


def write_fbl(
    template_path: str,
    output_path: str,
    network: RoadNetwork,
    section_idx: int = 4,
):
    """Write an FBL file using a template and new road network data.

    Args:
        template_path: Existing FBL file to use as template.
        output_path: Output FBL file path.
        network: Road network data to encode.
        section_idx: Section to replace (default 4 = roads_main).
    """
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from tools.maps.fbl_replace_section import replace_section

    records = network_to_records(network)
    section_bytes = records_to_bytes(records)
    replace_section(Path(template_path), section_idx, section_bytes, Path(output_path))
    return len(records)


# ── CLI ──────────────────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Convert OSM data to NNG FBL map file")
    parser.add_argument("osm_file", help="OSM PBF or XML file")
    parser.add_argument(
        "--bbox",
        required=True,
        help="Bounding box: lon_min,lat_min,lon_max,lat_max",
    )
    parser.add_argument("--template", required=True, help="Template FBL file")
    parser.add_argument("-o", "--output", required=True, help="Output FBL file")
    parser.add_argument("--country", default="OSM", help="3-letter country code")
    parser.add_argument("--section", type=int, default=4, help="Section to replace")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    args = parser.parse_args()

    bbox = tuple(float(x) for x in args.bbox.split(","))
    assert len(bbox) == 4, "bbox must be lon_min,lat_min,lon_max,lat_max"

    osm_path = args.osm_file
    if osm_path.endswith(".pbf"):
        network = read_osm_pbf(osm_path, bbox)
    else:
        network = read_osm_xml(osm_path, bbox)

    network.country = args.country

    if args.stats:
        from collections import Counter

        class_dist = Counter(s.road_class for s in network.segments)
        print(f"Country: {network.country}")
        print(f"Bbox: {network.bbox}")
        print(f"Segments: {len(network.segments)}")
        print(f"Road classes: {dict(class_dist.most_common())}")
        total_coords = sum(len(s.coords) for s in network.segments)
        print(f"Total coordinates: {total_coords}")

    n_records = write_fbl(args.template, args.output, network, args.section)
    print(f"Wrote {n_records} records to {args.output}")


if __name__ == "__main__":
    main()
