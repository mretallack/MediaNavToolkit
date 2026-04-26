"""NNG varint decoder and FBL section parser.

The NNG map format uses UTF-8-like variable-length integer encoding.
This module decodes the varint stream and extracts road class information.
"""

import struct


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one varint from data at pos. Returns (value, new_pos)."""
    if pos >= len(data):
        return None, pos
    b0 = data[pos]
    if b0 < 0x80:
        return b0, pos + 1
    if b0 < 0xC0:
        # Continuation byte — shouldn't be first byte
        return b0, pos + 1
    if (b0 & 0xE0) == 0xC0:  # 110xxxxx = 2-byte
        if pos + 1 >= len(data):
            return b0, pos + 1
        return ((b0 & 0x1F) << 6) | (data[pos + 1] & 0x3F), pos + 2
    if (b0 & 0xF0) == 0xE0:  # 1110xxxx = 3-byte
        if pos + 2 >= len(data):
            return b0, pos + 1
        return (((b0 & 0x0F) << 6 | (data[pos + 1] & 0x3F)) << 6 |
                (data[pos + 2] & 0x3F)), pos + 3
    if (b0 & 0xF8) == 0xF0:  # 11110xxx = 4-byte
        if pos + 3 >= len(data):
            return b0, pos + 1
        return ((((b0 & 0x07) << 6 | (data[pos + 1] & 0x3F)) << 6 |
                 (data[pos + 2] & 0x3F)) << 6 | (data[pos + 3] & 0x3F)), pos + 4
    if (b0 & 0xFC) == 0xF8:  # 111110xx = 5-byte
        if pos + 4 >= len(data):
            return b0, pos + 1
        return (((((b0 & 0x03) << 6 | (data[pos + 1] & 0x3F)) << 6 |
                  (data[pos + 2] & 0x3F)) << 6 | (data[pos + 3] & 0x3F)) << 6 |
                (data[pos + 4] & 0x3F)), pos + 5
    if (b0 & 0xFE) == 0xFC:  # 1111110x = 6-byte
        if pos + 5 >= len(data):
            return b0, pos + 1
        return ((((((b0 & 0x01) << 6 | (data[pos + 1] & 0x3F)) << 6 |
                   (data[pos + 2] & 0x3F)) << 6 | (data[pos + 3] & 0x3F)) << 6 |
                  (data[pos + 4] & 0x3F)) << 6 | (data[pos + 5] & 0x3F)), pos + 6
    return b0, pos + 1


def decode_all_varints(data: bytes) -> list[int]:
    """Decode entire byte stream as varints. Returns list of values."""
    values = []
    pos = 0
    while pos < len(data):
        val, pos = decode_varint(data, pos)
        if val is None:
            break
        values.append(val)
    return values


# Segment marker values in the varint stream
SEGMENT_MARKERS = {6, 98, 99, 100, 101, 102, 103}  # 0x06, 0x62-0x67


def count_segments(data: bytes) -> int:
    """Count road segments in section data."""
    return sum(1 for v in decode_all_varints(data) if v in SEGMENT_MARKERS)


def _test():
    """Unit tests for varint decoder."""
    # 1-byte values
    assert decode_varint(b'\x00', 0) == (0, 1)
    assert decode_varint(b'\x7f', 0) == (127, 1)

    # 2-byte values
    assert decode_varint(b'\xc0\x80', 0) == (0, 2)  # minimal 2-byte
    assert decode_varint(b'\xc2\x80', 0) == (128, 2)
    assert decode_varint(b'\xdf\xbf', 0) == (2047, 2)

    # 3-byte values
    assert decode_varint(b'\xe0\xa0\x80', 0) == (2048, 2 + 1)  # wait, let me recalc
    # E0 = 1110_0000, A0 = 10_100000, 80 = 10_000000
    # value = (0 << 12) | (0x20 << 6) | 0 = 0x800 = 2048
    v, p = decode_varint(b'\xe0\xa0\x80', 0)
    assert v == 2048, f"Expected 2048, got {v}"
    assert p == 3

    # Edge: value 127 (1-byte)
    assert decode_varint(b'\x7f', 0) == (127, 1)

    # Edge: value 128 (2-byte: C2 80)
    v, p = decode_varint(b'\xc2\x80', 0)
    assert v == 128, f"Expected 128, got {v}"

    # Sequence
    vals = decode_all_varints(b'\x00\x7f\xc2\x80')
    assert vals == [0, 127, 128], f"Got {vals}"

    print("All varint tests passed!")


if __name__ == "__main__":
    _test()
