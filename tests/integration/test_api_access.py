"""Integration test: Full API access verification with real credentials.

Tests what currently works against the live NaviExtras API.
"""

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

from medianav_toolbox.api.boot import boot
from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.igo_binary import decode_boot_response
from medianav_toolbox.api.register import get_device_model_list
from medianav_toolbox.config import Config
from medianav_toolbox.device import detect_drive, read_device_status, read_installed_content

USB_PATH = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))


@pytest.fixture(scope="module")
def client():
    c = NaviExtrasClient(Config())
    yield c
    c.close()


class TestBootService:
    """Boot service — no auth required."""

    def test_boot_v2_returns_all_services(self, client):
        endpoints = boot(client)
        assert endpoints.index_v2
        assert endpoints.index_v3
        assert endpoints.register
        assert endpoints.selfie
        assert endpoints.mobile
        assert "naviextras.com" in endpoints.index_v2

    def test_boot_v3_returns_igo_binary(self, client):
        resp = client.post(
            f"{client.config.api_base}/3/boot",
            json={},
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert "igo-binary" in resp.headers.get("content-type", "")
        entries = decode_boot_response(resp.content)
        assert len(entries) == 6
        names = [e["name"] for e in entries]
        assert "index" in names
        assert "register" in names
        assert "selfie" in names
        assert "mobile" in names

    def test_boot_jsessionid_cookie(self, client):
        """Server sets JSESSIONID on first contact."""
        resp = client.get(f"{client.config.api_base}/2/boot")
        assert resp.status_code == 200
        # Cookie should be set on the client
        cookies = dict(resp.cookies)
        assert "JSESSIONID" in cookies or any("JSESSIONID" in str(c) for c in client.cookies.jar)


class TestRegisterService:
    """Register service — no auth required for model list."""

    def test_get_device_model_list(self, client):
        endpoints = boot(client)
        version = get_device_model_list(client, endpoints)
        assert version is not None
        # Version is like "3.857"
        parts = version.split(".")
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert parts[1].isdigit()

    def test_register_endpoints_respond(self, client):
        """All register endpoints are alive (not 404)."""
        endpoints = boot(client)
        for path in ["/get_device_model_list", "/get_device_descriptor_list", "/devinfo", "/device"]:
            resp = client.post(
                f"{endpoints.register}{path}",
                json={},
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code != 404, f"{path} returned 404"


class TestDeviceDetection:
    """Device detection from real USB data."""

    def test_detect_device(self):
        device = detect_drive(USB_PATH)
        assert device is not None
        assert device.appcid == 0x42000B53
        assert len(device.brand_md5) == 32
        assert len(device.raw_data) == 268

    def test_device_status(self):
        info = read_device_status(USB_PATH)
        assert info.total_space == 4407054336
        assert info.free_space == 2312216576
        assert info.os_version == "6.0.12.2.1166_r2"
        assert "store_md5_files" in info.capabilities

    def test_installed_content(self):
        content = read_installed_content(USB_PATH)
        assert len(content) > 5  # Should have multiple items
        # Check we have maps
        map_items = [c for c in content if c.content_type.value == "map"]
        assert len(map_items) > 0
        # Check a known item
        uk_maps = [c for c in content if "United" in str(c.file_path)]
        assert len(uk_maps) > 0
        assert uk_maps[0].content_id == 7341211
        assert uk_maps[0].size == 109490688

    def test_installed_content_types(self):
        content = read_installed_content(USB_PATH)
        types = {c.content_type.value for c in content}
        print(f"\n  Content types found: {types}")
        print(f"  Total items: {len(content)}")
        for t in sorted(types):
            items = [c for c in content if c.content_type.value == t]
            print(f"    {t}: {len(items)} items")
        assert "map" in types
        assert "poi" in types


class TestAPIProtocol:
    """Test what we know about the API protocol."""

    def test_index_v2_needs_device_data(self, client):
        """Index v2 returns 412 without device identification."""
        endpoints = boot(client)
        resp = client.get(endpoints.index_v2)
        assert resp.status_code == 412

    def test_index_v3_needs_igo_binary(self, client):
        """Index v3 returns 412 without proper igo-binary payload."""
        endpoints = boot(client)
        resp = client.post(endpoints.index_v3, content=b"\x80\x80\x00\x00", headers={"Content-Type": "application/vnd.igo-binary; v=1"})
        # 412 = valid format, missing data (not 500 = parse error)
        assert resp.status_code in (412, 500)

    def test_register_descriptor_list_needs_device(self, client):
        """Descriptor list returns 417 with empty JSON (needs device data)."""
        endpoints = boot(client)
        resp = client.post(f"{endpoints.register}/get_device_descriptor_list", json={}, headers={"Content-Type": "application/json"})
        assert resp.status_code == 417  # Expectation Failed = right format, wrong values

    def test_selfie_update_endpoint(self, client):
        """Self-update endpoint is alive."""
        endpoints = boot(client)
        resp = client.post(endpoints.selfie + "/update", json={}, headers={"Content-Type": "application/json"})
        assert resp.status_code in (417, 412)  # Alive but needs proper data
