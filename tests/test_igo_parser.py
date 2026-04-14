"""Tests for igo-binary parser.

Test data from decrypted mitmproxy captures.
"""

from medianav_toolbox.igo_parser import (
    IgoBinaryReader,
    parse_boot_response,
    parse_register_response,
)

# Decrypted boot response (first 100 bytes — contains index and mobile entries)
BOOT_RESPONSE = bytes.fromhex(
    "8080698f050d00015180060305696e646578003068747470733a2f2f"
    "7a697070792e6e6176696578747261732e636f6d2f73657276696365"
    "732f696e6465782f7265737401066d6f62696c6500296874747073"
    "3a2f2f7777772e6e617669657874726173"
)

# Decrypted registration response
REG_RESPONSE = bytes.fromhex(
    "80e0fb86acd6eba8f54a93c4286ce077d06c"
    "000d4ea65d36b98e"
    "000acab6c9fb66f8"
    "000000012c00000000"
)


class TestIgoBinaryReader:
    def test_read_string(self):
        # length=5, "hello", null terminator
        data = b"\x05hello\x00"
        r = IgoBinaryReader(data)
        assert r.read_string() == "hello"
        assert r.pos == 7

    def test_read_string_no_null(self):
        data = b"\x03abc"
        r = IgoBinaryReader(data)
        assert r.read_string() == "abc"

    def test_read_uint64_be(self):
        data = b"\x00\x0d\x4e\xa6\x5d\x36\xb9\x8e"
        r = IgoBinaryReader(data)
        assert r.read_uint64_be() == 0x000D4EA65D36B98E


class TestParseBootResponse:
    def test_returns_dict(self):
        result = parse_boot_response(BOOT_RESPONSE)
        assert isinstance(result, dict)

    def test_has_index(self):
        result = parse_boot_response(BOOT_RESPONSE)
        assert "index" in result
        assert "zippy.naviextras.com" in result["index"]

    def test_index_url(self):
        result = parse_boot_response(BOOT_RESPONSE)
        assert result["index"] == "https://zippy.naviextras.com/services/index/rest"


class TestParseRegisterResponse:
    def test_extracts_name(self):
        result = parse_register_response(REG_RESPONSE)
        assert result["name"] == "FB86ACD6EBA8F54A93C4286CE077D06C"

    def test_extracts_code(self):
        result = parse_register_response(REG_RESPONSE)
        assert result["code"] == 0x000D4EA65D36B98E

    def test_extracts_secret(self):
        result = parse_register_response(REG_RESPONSE)
        assert result["secret"] == 0x000ACAB6C9FB66F8

    def test_extracts_max_age(self):
        result = parse_register_response(REG_RESPONSE)
        assert result["max_age"] == 300
