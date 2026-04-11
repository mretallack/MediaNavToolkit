"""Tests for device.py — device.nng parsing, XOR decode, USB detection."""

import struct
from pathlib import Path

import pytest

from medianav_toolbox.device import (
    detect_drive,
    parse_device_nng,
    parse_stm_file,
    read_device_status,
    read_installed_content,
    validate_drive,
    xor_decode,
)
from medianav_toolbox.models import ContentType

DATA_DIR = Path(__file__).parent / "data"


# --- XOR decode ---


def test_xor_decode_word_aligned():
    """XOR decode operates on 32-bit words, not bytes."""
    table = b"\x01\x00\x00\x00" * 1024  # table of all 1s (as uint32)
    data = b"\x05\x00\x00\x00"  # single word = 5
    result = xor_decode(data, table)
    # (1 ^ 5) - 0 = 4
    assert struct.unpack("<I", result)[0] == 4


def test_xor_decode_table_wraps():
    """XOR table index wraps at 0x3ff (1024 entries)."""
    table = bytes(range(256)) * 16  # 4096 bytes
    data = b"\x00" * 8  # 2 words
    result = xor_decode(data, table)
    assert len(result) == 8


def test_xor_decode_with_normal_table():
    """XOR decode with the real normal table produces non-zero output."""
    data = b"\xaa\xbb\xcc\xdd" * 4
    result = xor_decode(data)  # uses default normal table
    assert result != data  # should be different after XOR


# --- device.nng parsing ---


def test_parse_device_nng_appcid():
    """Extracts APPCID=0x42000B53 from real device.nng at offset 0x5C."""
    device = parse_device_nng(DATA_DIR / "device.nng")
    assert device.appcid == 0x42000B53


def test_parse_device_nng_brand_md5():
    """BrandMD5 is extracted and is a 32-char hex string."""
    device = parse_device_nng(DATA_DIR / "device.nng")
    assert len(device.brand_md5) == 32
    assert all(c in "0123456789abcdef" for c in device.brand_md5)


def test_parse_device_nng_raw_data():
    """Raw data is preserved for pass-through to API."""
    device = parse_device_nng(DATA_DIR / "device.nng")
    assert len(device.raw_data) == 268


def test_parse_device_nng_too_small(tmp_path):
    """Raises ValueError for truncated device.nng."""
    small = tmp_path / "device.nng"
    small.write_bytes(b"\x00" * 10)
    with pytest.raises(ValueError, match="too small"):
        parse_device_nng(small)


def test_parse_device_nng_drive_path():
    """Drive path points to USB root (3 levels up from device.nng)."""
    device = parse_device_nng(DATA_DIR / "device.nng")
    # DATA_DIR/device.nng → drive_path = DATA_DIR/../../../ (tests root)
    assert device.drive_path.is_dir()


# --- USB drive validation ---


def test_validate_drive_valid(tmp_path):
    ns = tmp_path / "NaviSync"
    ns.mkdir()
    (ns / "license").mkdir()
    (ns / "license" / "device.nng").write_bytes(b"\x00" * 268)
    (ns / "device_status.ini").write_text("freesize = 100\n")
    assert validate_drive(tmp_path) == []


def test_validate_drive_missing_navisync(tmp_path):
    errors = validate_drive(tmp_path)
    assert any("NaviSync" in e for e in errors)


def test_validate_drive_missing_device_nng(tmp_path):
    ns = tmp_path / "NaviSync"
    ns.mkdir()
    (ns / "license").mkdir()
    (ns / "device_status.ini").write_text("freesize = 100\n")
    errors = validate_drive(tmp_path)
    assert any("device.nng" in e for e in errors)


def test_detect_drive_invalid(tmp_path):
    assert detect_drive(tmp_path) is None


# --- device_status.ini ---


def test_read_device_status():
    info = read_device_status(DATA_DIR.parent.parent / "analysis" / "usb_drive" / "disk")
    assert info.free_space == 2312216576
    assert info.total_space == 4407054336
    assert info.os_version == "6.0.12.2.1166_r2"
    assert "store_md5_files" in info.capabilities


# --- .stm parsing ---


def test_parse_stm_file():
    stm = parse_stm_file(DATA_DIR / "UnitedKingdom.fbl.stm")
    assert stm.content_id == 7341211
    assert stm.header_id == 117863961
    assert stm.size == 109490688
    assert stm.timestamp == 1580666002
    assert stm.purpose == "shadow"


def test_read_installed_content():
    usb = DATA_DIR.parent.parent / "analysis" / "usb_drive" / "disk"
    content = read_installed_content(usb)
    assert len(content) > 0
    types = {c.content_type for c in content}
    assert ContentType.MAP in types
    assert ContentType.POI in types


def test_stm_content_type_from_dir(tmp_path):
    """Content type is inferred from parent directory name."""
    content = tmp_path / "NaviSync" / "content" / "speedcam"
    content.mkdir(parents=True)
    stm = content / "test.spc.stm"
    stm.write_text("purpose = shadow\nsize = 100\ncontent_id = 1\nheader_id = 2\ntimestamp = 3\n")
    result = parse_stm_file(stm)
    assert result.content_type == ContentType.SPEEDCAM
