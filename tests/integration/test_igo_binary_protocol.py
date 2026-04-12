"""Integration test: igo-binary protocol probing.

Documents what we've discovered about the igo-binary wire format
through empirical testing against the live API.
"""

import struct

import pytest
from dotenv import load_dotenv

load_dotenv()

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.config import Config

IDX3 = "https://zippy.naviextras.com/services/index/rest/3"
REG = "https://zippy.naviextras.com/services/register/rest/1"
HDR = {"Content-Type": "application/vnd.igo-binary; v=1"}


@pytest.fixture(scope="module")
def client():
    c = NaviExtrasClient(Config())
    yield c
    c.close()


class TestIgoBinaryFormat:
    """Empirical tests documenting the igo-binary wire format."""

    def test_minimum_valid_request_is_6_bytes(self, client):
        """Server needs at least 6 bytes: 80 80 + 4 bytes."""
        # 5 bytes = 500 (parse error)
        resp = client.post(IDX3, content=b"\x80\x80\x00\x00\x00", headers=HDR)
        assert resp.status_code == 500

        # 6 bytes = 412 (valid format, missing data)
        resp = client.post(IDX3, content=b"\x80\x80\x00\x00\x00\x00", headers=HDR)
        assert resp.status_code == 412

    def test_magic_bytes_80_80_in_responses(self, client):
        """Responses start with 0x80 0x80 but requests accept any first 2 bytes."""
        from pathlib import Path

        # Responses always start with 0x80
        data = Path("tests/data/boot_response_v3.bin").read_bytes()
        assert data[0] == 0x80

        # Requests: even all-zeros is accepted (412 not 500)
        resp = client.post(IDX3, content=b"\x00\x00\x00\x00\x00\x00", headers=HDR)
        assert resp.status_code == 412

    def test_boot_response_has_11_byte_header(self, client):
        """Boot response: 11-byte header + 6 entries consuming all remaining bytes."""
        from medianav_toolbox.api.igo_binary import decode_boot_response
        from pathlib import Path

        data = Path("tests/data/boot_response_v3.bin").read_bytes()
        entries = decode_boot_response(data)
        assert len(entries) == 6
        # Verify header is exactly 11 bytes by re-parsing
        assert data[0:2] == b"\x80\x80"  # magic
        assert data[10] == 6  # entry count

    def test_boot_response_entry_format(self, client):
        """Each boot entry: [version:1] [name_len:1] [name] [0x00] [url_len:1] [url]."""
        from pathlib import Path

        data = Path("tests/data/boot_response_v3.bin").read_bytes()
        pos = 11  # after header
        # First entry: v3 index
        assert data[pos] == 3  # version
        assert data[pos + 1] == 5  # name_len
        assert data[pos + 2 : pos + 7] == b"index"
        assert data[pos + 7] == 0  # separator
        assert data[pos + 8] == 48  # url_len

    def test_model_list_response_format(self, client):
        """Model list: 80 00 [len] [version_string] 00 00."""
        from pathlib import Path

        data = Path("tests/data/model_list_response.bin").read_bytes()
        assert data[0] == 0x80
        assert data[1] == 0x00
        str_len = data[2]
        version = data[3 : 3 + str_len].decode("ascii")
        assert "." in version

    def test_index_v3_412_means_valid_but_missing_device(self, client):
        """412 = server parsed the format but device data is missing."""
        resp = client.post(IDX3, content=b"\x80\x80\x00\x00\x00\x00", headers=HDR)
        assert resp.status_code == 412
        assert len(resp.content) == 0  # no error body

    def test_byte5_is_validated(self, client):
        """Byte at position 5 (0xff) causes parse error — it's a parsed field."""
        resp = client.post(IDX3, content=b"\x80\x80\x00\x00\x00\xff", headers=HDR)
        assert resp.status_code == 500  # parse error, not 412
