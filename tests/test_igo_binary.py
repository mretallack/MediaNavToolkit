"""Tests for api/igo_binary.py."""

from pathlib import Path

import pytest

from medianav_toolbox.api.igo_binary import (
    decode_boot_response,
    decode_model_list_response,
    encode_request_header,
)

DATA_DIR = Path(__file__).parent / "data"


def test_decode_boot_response_real():
    """Decode the real v3 boot response."""
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    assert len(entries) == 6


def test_decode_boot_response_entry_fields():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    for e in entries:
        assert "version" in e
        assert "name" in e
        assert "location" in e
        assert e["location"].startswith("https://")


def test_decode_boot_response_has_index():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    names = [e["name"] for e in entries]
    assert "index" in names


def test_decode_boot_response_has_register():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    names = [e["name"] for e in entries]
    assert "register" in names


def test_decode_boot_response_invalid_header():
    with pytest.raises(ValueError, match="Invalid"):
        decode_boot_response(b"\x00\x01\x02\x03")


def test_decode_boot_response_too_short():
    with pytest.raises(ValueError):
        decode_boot_response(b"\x80\x80")


def test_encode_request_header():
    hdr = encode_request_header()
    assert hdr[:2] == b"\x80\x80"
    assert len(hdr) == 4


def test_decode_model_list_response():
    data = (DATA_DIR / "model_list_response.bin").read_bytes()
    version = decode_model_list_response(data)
    assert version is not None
    assert "." in version  # e.g. "3.857"
