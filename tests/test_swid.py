"""Tests for SWID generation."""

from medianav_toolbox.swid import CROCKFORD, _to_crockford_base32, compute_swid


class TestCrockfordBase32:
    def test_all_zeros(self):
        result = _to_crockford_base32(b"\x00" * 10)
        assert result == "0000000000000000"

    def test_output_length(self):
        result = _to_crockford_base32(b"\xff" * 10)
        assert len(result) == 16

    def test_all_chars_valid(self):
        result = _to_crockford_base32(b"\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd")
        assert all(c in CROCKFORD for c in result)


class TestComputeSwid:
    def test_format(self):
        swid = compute_swid("test123")
        assert swid.startswith("CK-")
        parts = swid.split("-")
        assert len(parts) == 5
        assert all(len(p) == 4 for p in parts[1:])
        assert parts[0] == "CK"

    def test_deterministic(self):
        assert compute_swid("abc") == compute_swid("abc")

    def test_different_serials_different_swids(self):
        assert compute_swid("serial1") != compute_swid("serial2")

    def test_valid_crockford_chars(self):
        swid = compute_swid("myserial")
        chars = swid.replace("CK-", "").replace("-", "")
        assert all(c in CROCKFORD for c in chars)
