"""Tests for license parsing and installation."""

import hashlib
import struct
import tempfile
from pathlib import Path

import pytest

from medianav_toolbox.catalog import License, parse_licenses_response
from medianav_toolbox.installer import install_license


def _build_licenses_response(entries: list[tuple[str, str, bytes]]) -> bytes:
    """Build a fake licenses response from (swid, fname, lyc_data) tuples."""
    buf = bytearray()
    buf.append(0x40)  # presence
    buf.extend(struct.pack(">H", len(entries)))
    for swid, fname, lyc_data in entries:
        buf.append(0xC0)
        buf.extend(struct.pack(">I", 1776169153))  # timestamp
        buf.extend(struct.pack(">I", 3600))  # expiry
        swid_bytes = swid.encode("ascii")
        buf.append(len(swid_bytes))
        buf.extend(swid_bytes)
        fname_bytes = fname.encode("ascii")
        buf.append(len(fname_bytes))
        buf.extend(fname_bytes)
        buf.extend(struct.pack(">I", len(lyc_data)))
        buf.extend(lyc_data)
    return bytes(buf)


class TestParseLicensesResponse:
    def test_empty_response(self):
        assert parse_licenses_response(b"") == []
        assert parse_licenses_response(b"\x00\x00\x00") == []

    def test_zero_count(self):
        assert parse_licenses_response(b"\x40\x00\x00") == []

    def test_single_entry(self):
        lyc = b"\x02\x00\x00\x00\xd0" + b"\xaa" * 203
        resp = _build_licenses_response(
            [
                ("CW-AAAA-BBBB-CCCC-DDDD-EEEE", "Test_License.lyc", lyc),
            ]
        )
        result = parse_licenses_response(resp)
        assert len(result) == 1
        assert result[0].swid == "CW-AAAA-BBBB-CCCC-DDDD-EEEE"
        assert result[0].lyc_file == "Test_License.lyc"
        assert result[0].lyc_data == lyc
        assert result[0].timestamp == 1776169153
        assert result[0].expiry == 3600

    def test_multiple_entries(self):
        entries = [
            ("CW-1111-2222-3333-4444-5555", "Map_UK.lyc", b"\x01" * 100),
            ("CW-AAAA-BBBB-CCCC-DDDD-EEEE", "Lang_Update.lyc", b"\x02" * 50),
            ("CW-XXXX-YYYY-ZZZZ-WWWW-VVVV", "Config.lyc", b"\x03" * 25),
        ]
        resp = _build_licenses_response(entries)
        result = parse_licenses_response(resp)
        assert len(result) == 3
        for i, (swid, fname, data) in enumerate(entries):
            assert result[i].swid == swid
            assert result[i].lyc_file == fname
            assert result[i].lyc_data == data

    def test_real_decoded_response(self):
        """Parse the actual captured response if available."""
        path = Path("analysis/flows_decoded/2026-04-16/740-licenses-resp-decoded.bin")
        if not path.exists():
            pytest.skip("Decoded response not available")
        data = path.read_bytes()
        result = parse_licenses_response(data)
        assert len(result) == 3
        assert result[0].lyc_file == "LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc"
        assert len(result[0].lyc_data) == 2280
        assert result[1].lyc_file == "Renault_Dacia_ULC2_Language_Update.lyc"
        assert len(result[1].lyc_data) == 728
        assert result[2].lyc_file == "Renault_Dacia_Global_Config_update.lyc"
        assert len(result[2].lyc_data) == 472


class TestInstallLicense:
    def test_install_creates_files(self, tmp_path):
        usb = tmp_path
        (usb / "NaviSync" / "license").mkdir(parents=True)
        lyc_data = b"license content here"
        install_license(usb, "test.lyc", lyc_data)

        lyc_path = usb / "NaviSync" / "license" / "test.lyc"
        md5_path = usb / "NaviSync" / "license" / "test.lyc.md5"
        assert lyc_path.read_bytes() == lyc_data
        assert md5_path.read_text() == hashlib.md5(lyc_data).hexdigest().upper()

    def test_install_overwrites_existing(self, tmp_path):
        usb = tmp_path
        lic_dir = usb / "NaviSync" / "license"
        lic_dir.mkdir(parents=True)
        (lic_dir / "old.lyc").write_bytes(b"old data")

        new_data = b"new license data"
        install_license(usb, "old.lyc", new_data)
        assert (lic_dir / "old.lyc").read_bytes() == new_data

    def test_install_creates_license_dir(self, tmp_path):
        usb = tmp_path
        lyc_data = b"data"
        install_license(usb, "new.lyc", lyc_data)
        assert (usb / "NaviSync" / "license" / "new.lyc").exists()

    def test_md5_matches_content(self, tmp_path):
        usb = tmp_path
        lyc_data = b"\x02\x00\x00\x00\xd0" + b"\xff" * 200
        install_license(usb, "check.lyc", lyc_data)
        md5_text = (usb / "NaviSync" / "license" / "check.lyc.md5").read_text()
        assert md5_text == hashlib.md5(lyc_data).hexdigest().upper()


class TestValidateInstalledLicenses:
    """Validate that installed .lyc files match the server response."""

    def test_roundtrip(self, tmp_path):
        """Parse response → install → verify files match."""
        entries = [
            ("CW-1111-2222-3333-4444-5555", "Map.lyc", b"\xaa" * 500),
            ("CW-AAAA-BBBB-CCCC-DDDD-EEEE", "Lang.lyc", b"\xbb" * 200),
        ]
        resp = _build_licenses_response(entries)
        licenses = parse_licenses_response(resp)

        usb = tmp_path
        for lic in licenses:
            install_license(usb, lic.lyc_file, lic.lyc_data)

        # Validate
        lic_dir = usb / "NaviSync" / "license"
        for lic in licenses:
            lyc_path = lic_dir / lic.lyc_file
            md5_path = lic_dir / f"{lic.lyc_file}.md5"
            assert lyc_path.exists(), f"{lic.lyc_file} not installed"
            assert lyc_path.read_bytes() == lic.lyc_data
            assert md5_path.read_text() == hashlib.md5(lic.lyc_data).hexdigest().upper()
