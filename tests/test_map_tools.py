"""Tests for NNG map format tools."""

import struct
import sys
from pathlib import Path

import numpy as np
import pytest

# Add project root to path so tools.maps imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

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


# ── fbl_parse tests ──────────────────────────────────────────────────────────


class TestFblParse:
    """Tests for the FBL parser (packed coordinate extraction)."""

    def test_parse_monaco(self):
        from tools.maps.fbl_parse import parse_fbl

        r = parse_fbl(TESTDATA_MAPS / "Monaco_osm.fbl")
        assert r["country"] == "MON"
        assert 7.4 < r["bbox"]["lon_min"] < 7.5
        assert r["lon_bits"] == 21
        assert r["lat_bits"] == 21
        assert "roads_main" in r["sections"]
        assert len(r["sections"]["roads_main"]["coordinates"]) > 200

    def test_parse_vatican(self):
        from tools.maps.fbl_parse import parse_fbl

        r = parse_fbl(TESTDATA_MAPS / "Vatican_osm.fbl")
        assert r["country"] == "VAT"
        assert len(r["sections"]["roads_main"]["coordinates"]) > 50

    def test_parse_all_files(self):
        from tools.maps.fbl_parse import parse_fbl

        for f in TESTDATA_MAPS.glob("*.fbl"):
            r = parse_fbl(f)
            total = sum(len(s["coordinates"]) for s in r["sections"].values())
            assert total > 0, f"{f.name}: no coordinates"

    def test_coordinates_in_bbox(self):
        from tools.maps.fbl_parse import parse_fbl

        r = parse_fbl(TESTDATA_MAPS / "Monaco_osm.fbl")
        bbox = r["bbox"]
        for sec_data in r["sections"].values():
            for lon, lat in sec_data["coordinates"]:
                assert bbox["lon_min"] - 0.01 <= lon <= bbox["lon_max"] + 0.01
                assert bbox["lat_min"] - 0.01 <= lat <= bbox["lat_max"] + 0.01

    def test_packed_coord_decoding(self):
        """Verify packed coordinate pair decoding formula."""
        from tools.maps.fbl_parse import decode_varint

        # Monaco: lon_bits=21, lat_bits=21
        # Value 31710617 should decode to a valid Monaco coordinate
        lon_min = 62154560
        lat_min = 365208000
        val = 31710617
        lat_bits = 21
        lon_off = val >> lat_bits
        lat_off = val & ((1 << lat_bits) - 1)
        lon = (lon_min + lon_off) / (2**23)
        lat = (lat_min + lat_off) / (2**23)
        assert 7.3 < lon < 7.7
        assert 43.5 < lat < 43.8

    def test_geojson_output(self):
        from tools.maps.fbl_parse import parse_fbl, to_geojson

        r = parse_fbl(TESTDATA_MAPS / "Vatican_osm.fbl")
        gj = to_geojson(r)
        assert gj["type"] == "FeatureCollection"
        assert len(gj["features"]) > 0
        assert gj["features"][0]["geometry"]["type"] == "Point"
