"""Tests for NNG map format tools."""
import struct
from pathlib import Path

import numpy as np
import pytest

# Paths
TEST_DATA = Path(__file__).parent / "data"
TESTDATA_MAPS = Path(__file__).parent.parent / "tools" / "maps" / "testdata"
XOR_TABLE = Path(__file__).parent.parent / "analysis" / "xor_table_normal.bin"


def _decrypt(fbl_path):
    xor = XOR_TABLE.read_bytes()
    raw = Path(fbl_path).read_bytes()
    d = np.frombuffer(raw, dtype=np.uint8)
    x = np.frombuffer(xor, dtype=np.uint8)
    return bytes(d ^ np.tile(x, (len(d) // len(x)) + 1)[: len(d)])


def _get_sec4(dec):
    s = struct.unpack_from("<I", dec, 0x048E + 16)[0]
    e = struct.unpack_from("<I", dec, 0x048E + 20)[0]
    return dec[s:e]


# ── nng_varint tests ──


class TestVarintDecoder:
    def test_single_byte(self):
        from tools.maps.nng_varint import decode_varint
        assert decode_varint(b"\x00", 0) == (0, 1)
        assert decode_varint(b"\x7f", 0) == (127, 1)

    def test_two_byte(self):
        from tools.maps.nng_varint import decode_varint
        v, p = decode_varint(b"\xc2\x80", 0)
        assert v == 128
        assert p == 2

    def test_three_byte(self):
        from tools.maps.nng_varint import decode_varint
        v, p = decode_varint(b"\xe0\xa0\x80", 0)
        assert v == 2048
        assert p == 3

    def test_decode_all(self):
        from tools.maps.nng_varint import decode_all_varints
        vals = decode_all_varints(b"\x00\x7f\xc2\x80")
        assert vals == [0, 127, 128]

    def test_segment_count_vatican(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.nng_varint import count_segments
        dec = _decrypt(TESTDATA_MAPS / "Vatican_osm.fbl")
        sec4 = _get_sec4(dec)
        assert count_segments(sec4) == 81


# ── fbl_road_class tests ──


class TestRoadClass:
    @pytest.fixture(autouse=True)
    def _skip_no_dll(self):
        dll = Path("analysis/extracted/nngine.dll")
        if not dll.exists():
            pytest.skip("nngine.dll not available")

    def test_vatican_has_road_classes(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.fbl_road_class import extract_road_classes
        dec = _decrypt(TESTDATA_MAPS / "Vatican_osm.fbl")
        sec4 = _get_sec4(dec)
        results = extract_road_classes(sec4)
        classified = [r for r in results if r[2] is not None]
        assert len(classified) >= 2

    def test_monaco_has_trunk(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.fbl_road_class import extract_road_classes
        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        results = extract_road_classes(sec4)
        classes = {r[2] for r in results if r[2] is not None}
        assert 2 in classes  # trunk

    def test_malta_has_motorway(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.fbl_road_class import extract_road_classes
        dec = _decrypt(TESTDATA_MAPS / "Malta_osm.fbl")
        sec4 = _get_sec4(dec)
        results = extract_road_classes(sec4)
        classes = {r[2] for r in results if r[2] is not None}
        assert 0 in classes  # motorway


# ── fbl_segments tests ──


class TestSegments:
    def test_vatican_segment_count(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.fbl_segments import extract_segments
        dec = _decrypt(TESTDATA_MAPS / "Vatican_osm.fbl")
        sec4 = _get_sec4(dec)
        segs = extract_segments(sec4)
        assert len(segs) == 81

    def test_segments_have_positive_size(self):
        if not TESTDATA_MAPS.exists():
            pytest.skip("test data not available")
        from tools.maps.fbl_segments import extract_segments
        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        segs = extract_segments(sec4)
        assert all(s[3] > 0 for s in segs)
