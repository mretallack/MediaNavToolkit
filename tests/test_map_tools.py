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

# Skip entire module if test data not available (CI doesn't have FBL files)
_HAS_MAP_DATA = XOR_TABLE.exists() and TESTDATA_MAPS.exists() and any(TESTDATA_MAPS.glob("*.fbl"))
pytestmark = pytest.mark.skipif(
    not _HAS_MAP_DATA, reason="Map test data not available (analysis/ or testdata/)"
)

# Check if Unicorn + DLL are available (needed for decoder tests)
_DLL_PATH = Path(__file__).parent.parent / "analysis" / "extracted" / "nngine.dll"
try:
    import unicorn  # noqa: F401

    _HAS_UNICORN = _DLL_PATH.exists()
except ImportError:
    _HAS_UNICORN = False

_skip_unicorn = pytest.mark.skipif(not _HAS_UNICORN, reason="Unicorn or nngine.dll not available")


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


# ── nng_decoder tests ────────────────────────────────────────────────────────


class TestNngDecoder:
    """Tests for the NNG section decoder (Unicorn-based)."""

    def test_varint_decode_single_byte(self):
        from tools.maps.nng_decoder import decode_varint

        assert decode_varint(b"\x00", 0) == (0, 1)
        assert decode_varint(b"\x7f", 0) == (127, 1)
        assert decode_varint(b"\xbf", 0) == (0xBF, 1)

    def test_varint_decode_multi_byte(self):
        from tools.maps.nng_decoder import decode_varint

        # 2-byte: 0xC0-0xDF
        assert decode_varint(b"\xc2\x80", 0) == (0x80, 2)
        # 3-byte
        val, pos = decode_varint(b"\xe0\xa0\x80", 0)
        assert pos == 3
        # 5-byte: Monaco's first value
        val, pos = decode_varint(b"\xf9\xb8\xfd\xb6\x99", 0)
        assert val == 31710617
        assert pos == 5

    @_skip_unicorn
    def test_decode_line_monaco_line0(self):
        """Decode Monaco section 4 first line and check record count."""
        from tools.maps.nng_decoder import decode_line

        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        # First line (up to first 0x0A)
        first_line = sec4.split(b"\x0a")[0]
        records = decode_line(first_line)
        # First line produces ~76 records
        assert len(records) > 30
        # Should have control records
        ctrl = [r for r in records if r >= 0x80000000]
        assert len(ctrl) >= 1

    @_skip_unicorn
    def test_decode_section_monaco(self):
        """Full Monaco section 4 decode."""
        from tools.maps.nng_decoder import decode_section

        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        records = decode_section(sec4)
        assert len(records) > 3000
        # Check control record types
        ctrl_types = set(r & 0xFFFF0000 for r in records if r >= 0x80000000)
        assert 0x80000000 in ctrl_types  # END

    @_skip_unicorn
    def test_decode_has_road_class(self):
        """Check that road class records are present."""
        from tools.maps.nng_decoder import decode_section

        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        records = decode_section(sec4)
        # Road class records: 0x80030000 (Unicorn) or 0x80180000 (Python)
        road_class = [r for r in records if (r & 0xFFFF0000) in (0x80030000, 0x80180000)]
        assert len(road_class) >= 1  # Monaco has road class records

    @_skip_unicorn
    def test_decode_vatican(self):
        """Decode Vatican section 4."""
        from tools.maps.nng_decoder import decode_section

        dec = _decrypt(TESTDATA_MAPS / "Vatican_osm.fbl")
        sec4 = _get_sec4(dec)
        records = decode_section(sec4)
        assert len(records) > 10

    def test_encode_varint_roundtrip(self):
        from tools.maps.nng_decoder import decode_varint, encode_varint

        for val in [0, 1, 127, 128, 2047, 2048, 65535, 1000000, 31710617]:
            enc = encode_varint(val)
            dec, _ = decode_varint(enc, 0)
            assert dec == val, f"Roundtrip failed: {val} → {enc.hex()} → {dec}"

    @_skip_unicorn
    def test_encode_records_roundtrip(self):
        """Encode records and decode back — should match."""
        from tools.maps.nng_decoder import decode_line, encode_records

        dec = _decrypt(TESTDATA_MAPS / "Monaco_osm.fbl")
        sec4 = _get_sec4(dec)
        line0 = sec4.split(b"\x0a")[0]
        original = decode_line(line0)
        encoded = encode_records(original)
        roundtrip = decode_line(encoded)
        orig_data = [r for r in original if r != 0x80000000]
        rt_data = [r for r in roundtrip if r != 0x80000000]
        assert orig_data == rt_data

    def test_encode_control_records(self):
        """Control records should encode to metacharacters."""
        from tools.maps.nng_decoder import encode_records

        records = [42, 0x80090000, 99, 0x80000000]
        encoded = encode_records(records)
        assert b"\x5e" in encoded  # ^ for separator
        assert b"\x0a" in encoded  # LF for end

    def test_xor_roundtrip(self):
        """XOR encrypt then decrypt should return original."""
        from tools.maps.nng_decoder import xor_encrypt

        original = b"Hello, NNG map format!"
        encrypted = xor_encrypt(original)
        assert encrypted != original
        decrypted = xor_encrypt(encrypted)
        assert decrypted == original

    @_skip_unicorn
    def test_osm_to_fbl_roundtrip(self):
        """OSM XML → records → bytes → decode should preserve structure."""
        from tools.maps.nng_decoder import decode_line
        from tools.maps.osm_to_fbl import (
            Coord,
            RoadNetwork,
            RoadSegment,
            network_to_records,
            records_to_bytes,
        )

        net = RoadNetwork(
            country="TST",
            bbox=(7.41, 43.53, 7.63, 43.75),
            segments=[
                RoadSegment(
                    road_class=3,
                    coords=[Coord(7.42, 43.73), Coord(7.43, 43.74)],
                ),
                RoadSegment(
                    road_class=5,
                    coords=[Coord(7.50, 43.60), Coord(7.51, 43.61)],
                ),
            ],
        )
        records = network_to_records(net)
        raw = records_to_bytes(records)
        decoded = decode_line(raw)
        # Should have 2 road segment markers
        road_markers = [r for r in decoded if r == 0x80330000]
        assert len(road_markers) == 2
        # Should have coordinate data
        data = [r for r in decoded if r < 0x80000000]
        assert len(data) > 4  # At least 4 coord values + 2 class values
