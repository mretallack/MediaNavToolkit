"""Tests for fingerprint.py."""

from pathlib import Path

from medianav_toolbox.fingerprint import (
    encode_fingerprint,
    fingerprint_md5,
    read_fingerprint,
    save_fingerprint,
    validate_fingerprint,
)


def test_read_fingerprint_not_found(tmp_path):
    (tmp_path / "NaviSync" / "save").mkdir(parents=True)
    assert read_fingerprint(tmp_path) is None


def test_save_and_read_fingerprint(tmp_path):
    data = b"test fingerprint data"
    save_fingerprint(tmp_path, data)
    result = read_fingerprint(tmp_path)
    assert result == data


def test_encode_fingerprint():
    assert encode_fingerprint(b"\xab\xcd") == "abcd"


def test_fingerprint_md5():
    md5 = fingerprint_md5(b"test")
    assert len(md5) == 32
    assert md5 == "098F6BCD4621D373CADE4E832627B4F6"


def test_validate_fingerprint_valid(tmp_path):
    ns = tmp_path / "NaviSync"
    ns.mkdir()
    (ns / "device_checksum.md5").write_text("abc")
    (ns / "device_status.ini").write_text("freesize = 100\n")
    assert validate_fingerprint(tmp_path) == []


def test_validate_fingerprint_missing_checksum(tmp_path):
    ns = tmp_path / "NaviSync"
    ns.mkdir()
    (ns / "device_status.ini").write_text("freesize = 100\n")
    errors = validate_fingerprint(tmp_path)
    assert any("checksum" in e.lower() for e in errors)
