#!/usr/bin/env python3
"""Generate a complete NNG FBL map file from scratch.

No template needed — builds the entire SET container including header,
metadata, section table, and all sections.
"""

import math
import struct
from pathlib import Path

import numpy as np

SCALE = 2**23
_XOR_LOCAL = Path(__file__).parent / "xor_key.bin"
_XOR_ANALYSIS = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
_XOR_PATH = _XOR_LOCAL if _XOR_LOCAL.exists() else _XOR_ANALYSIS

# SET header copyright text (from real FBL files)
_COPYRIGHT = (
    b"Nihil esset incerti, nisi obcuris voluptate hominum, nihil fallacis "
    b"ratione to commitorium. Ita mali salvam a societ rem per. si steret "
    b"in sua liceat atque eius rei fructum percipere, quem poteum, ut opti"
    b"mi statim."
)


def _encode_varint(val: int) -> bytes:
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


def _encode_section(segments, bbox_ints):
    """Encode road segments into FBL section bytes."""
    lon_min, lat_min = bbox_ints
    out = bytearray()
    in_quote = False
    current_class = -1

    def _open():
        nonlocal in_quote
        if not in_quote:
            out.extend(b"\x5c\x51")
            in_quote = True

    def _close():
        nonlocal in_quote
        if in_quote:
            out.extend(b"\x5c\x45")
            in_quote = False

    for seg in segments:
        if seg.road_class != current_class:
            _close()
            out.append(0x5C)
            out.extend(_encode_varint(seg.road_class))
            current_class = seg.road_class

        _open()
        for coord in seg.coords:
            lon_off = max(0, round(coord.lon * SCALE) - lon_min)
            lat_off = max(0, round(coord.lat * SCALE) - lat_min)
            out.extend(_encode_varint(lon_off & 0x7FFFFFFF))
            out.extend(_encode_varint(lat_off & 0x7FFFFFFF))

        _close()
        out.append(0x2B)  # + road marker
        out.append(0x5E)  # ^ separator

    _close()
    out.append(0x0A)  # LF end
    return bytes(out)


def build_fbl(
    country: str, bbox: tuple, segments: list, xor_path: str | Path | None = None
) -> bytes:
    """Build a complete FBL file from scratch.

    Args:
        country: 3-letter country code (e.g. "MON")
        bbox: (lon_min, lat_min, lon_max, lat_max) in degrees
        segments: list of RoadSegment objects
        xor_path: path to XOR key file

    Returns:
        Encrypted FBL file bytes ready to write to disk.
    """
    if xor_path is None:
        xor_path = _XOR_PATH
    xor = Path(xor_path).read_bytes()

    lon_min = round(bbox[0] * SCALE)
    lat_min = round(bbox[1] * SCALE)
    lon_max = round(bbox[2] * SCALE)
    lat_max = round(bbox[3] * SCALE)

    # Split segments by road class into sections
    sec4 = [s for s in segments if s.road_class <= 3]
    sec5 = [s for s in segments if 4 <= s.road_class <= 6]
    sec8 = [s for s in segments if s.road_class >= 7]

    bbox_ints = (lon_min, lat_min)
    sec4_data = _encode_section(sec4, bbox_ints) if sec4 else b"\x0a"
    sec5_data = _encode_section(sec5, bbox_ints) if sec5 else b"\x0a"
    sec8_data = _encode_section(sec8, bbox_ints) if sec8 else b"\x0a"

    # Empty sections for the rest
    sec0_data = b"\x00\x00"  # marker
    sec1_data = b"\x00"  # curves (empty)
    sec2_data = b"\x00" * 2  # boundary_a
    sec3_data = b"\x00" * 2  # boundary_b
    sec6_data = b""  # centroid (empty)
    sec7_data = b"\x00" * 2  # centroid
    sec9_data = b"\x00\x00"  # marker
    sec10_data = b"\x00" * 2  # features
    sec11_data = b"\x00" * 2  # features
    sec12_data = b"\x00" * 2  # features
    sec13_data = b"\x00" * 2  # features
    sec14_data = b"\x00" * 2  # features
    sec15_data = b"\x00" * 2  # labels
    sec16_data = b""  # areas (empty)
    sec17_data = b"\x00" * 2  # areas

    all_sections = [
        sec0_data,
        sec1_data,
        sec2_data,
        sec3_data,
        sec4_data,
        sec5_data,
        sec6_data,
        sec7_data,
        sec8_data,
        sec9_data,
        sec10_data,
        sec11_data,
        sec12_data,
        sec13_data,
        sec14_data,
        sec15_data,
        sec16_data,
        sec17_data,
    ]

    # --- Build header ---
    header = bytearray()

    # SET magic + version
    header.extend(b"SET\x00")
    header.extend(struct.pack("<I", 0x20070604))  # version/date

    # Hash placeholder + section count
    header.extend(struct.pack("<I", 0))  # hash (filled later)
    header.extend(struct.pack("<I", 1))  # section count

    # File size placeholder
    header.extend(struct.pack("<I", 0))  # filled later

    # Padding
    header.extend(b"\x00" * 4)

    # Data offset + total size placeholder
    header.extend(struct.pack("<I", 0x200))  # data starts at 512
    header.extend(struct.pack("<I", 0))  # total size

    # Copyright text (padded to offset 0x200)
    header.extend(_COPYRIGHT)
    while len(header) < 0x200:
        header.extend(b"\x00")

    # --- Gap area (minimal) ---
    gap = bytearray()
    # Padding to reach country code position (~0x476 from file start)
    # The gap area has coordinate data; we'll use minimal padding
    while len(header) + len(gap) < 0x440:
        gap.extend(b"\x00")

    # Country code + type byte
    country_bytes = country.encode("ascii")[:3].ljust(3, b"\x00")
    gap.extend(country_bytes)
    gap.append(0x48)  # type byte

    # Padding before bbox
    gap.extend(b"\x00" * 4)

    # Bbox: lon_min, lat_max, lon_max, lat_min
    gap.extend(struct.pack("<4i", lon_min, lat_max, lon_max, lat_min))

    # Section offset table (20 entries)
    # Calculate offsets
    table_pos = len(header) + len(gap)
    data_start = table_pos + 20 * 4

    offsets = []
    pos = data_start
    for sec_data in all_sections:
        offsets.append(pos)
        pos += len(sec_data)
    # Pad to 20 entries
    while len(offsets) < 20:
        offsets.append(0)

    for off in offsets:
        gap.extend(struct.pack("<I", off))

    # --- Assemble file ---
    fbl = bytearray()
    fbl.extend(header)
    fbl.extend(gap)

    # Write sections
    for sec_data in all_sections:
        fbl.extend(sec_data)

    # Update file size in header
    struct.pack_into("<I", fbl, 0x10, len(fbl))

    # XOR encrypt
    d = np.frombuffer(bytes(fbl), dtype=np.uint8).copy()
    t = np.frombuffer(xor, dtype=np.uint8)
    d ^= np.tile(t, (len(d) // len(t)) + 1)[: len(d)]
    return bytes(d)
