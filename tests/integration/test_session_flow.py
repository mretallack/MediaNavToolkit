"""Integration test: full session flow against live NaviExtras API.

Flow: boot → login → senddrives → sendfingerprint → getprocess

Uses real device values from USB drive (toolbox.md §21.5).
All market calls send igo-binary to the index v3 endpoint.
"""

import httpx
import pytest

from medianav_toolbox.api.igo_binary import (
    decode_boot_response,
    encode_get_process,
    encode_login,
    encode_send_drives,
    encode_send_fingerprint,
)

# --- Device values from USB drive (toolbox.md §21.5) ---
BRAND = "DaciaAutomotive"
DEVICE_TYPE = "DaciaToolbox"
APPCID = 0x42000B53
VERSION_MAJOR = 5
VERSION_MINOR = 28

# --- Endpoints ---
BOOT_URL = "https://zippy.naviextras.com/services/index/rest"
IGO_CT = {"Content-Type": "application/vnd.igo-binary; v=1"}
UA = {"User-Agent": "WinHTTP ToolBox/1.0"}


@pytest.fixture(scope="module")
def client():
    with httpx.Client(timeout=30, headers=UA) as c:
        yield c


class TestFullSessionFlow:
    """Test the complete market call session flow against the live API."""

    def test_01_boot_v3_from_saved_response(self):
        """Verify we can decode the saved boot response for service URLs."""
        from pathlib import Path

        data = Path("tests/data/boot_response_v3.bin").read_bytes()
        entries = decode_boot_response(data)
        names = [e["name"] for e in entries]
        assert "index" in names
        assert "register" in names

        # Extract index v3 URL
        index_entries = [e for e in entries if e["name"] == "index" and e["version"] == "3"]
        assert len(index_entries) >= 1
        url = index_entries[0]["location"]
        assert "naviextras.com" in url

    def test_02_model_list_confirms_api_alive(self, client):
        """Register endpoint still responds — confirms API connectivity."""
        r = client.post(
            "https://zippy.naviextras.com/services/register/rest/1/get_device_model_list",
            content=b"{}",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 200
        assert len(r.content) > 0

    def test_03_login_igo_binary_format_accepted(self, client):
        """LOGIN payload is parsed by server (not 500 = format error)."""
        data = encode_login(
            username="",
            password="",
            brand=BRAND,
            device_type=DEVICE_TYPE,
            appcid=APPCID,
            device_id=0,
            version_major=VERSION_MAJOR,
            version_minor=VERSION_MINOR,
        )
        r = client.post(f"{BOOT_URL}/3", content=data, headers=IGO_CT)
        # 412 = format valid, device data insufficient
        # 200 = success (unlikely without full session)
        # 500 = format error (BAD — means our encoding is wrong)
        assert r.status_code != 500, f"Server rejected igo-binary format: {r.status_code}"
        assert r.status_code in (200, 412), f"Unexpected status: {r.status_code}"

    def test_04_send_drives_format_accepted(self, client):
        """SEND_DRIVES payload is parsed by server."""
        data = encode_send_drives(drive_count=0, drive_id=0)
        r = client.post(f"{BOOT_URL}/3", content=data, headers=IGO_CT)
        assert r.status_code != 500, f"Server rejected SEND_DRIVES format: {r.status_code}"

    def test_05_send_fingerprint_format_accepted(self, client):
        """SEND_FINGERPRINT payload is parsed by server."""
        data = encode_send_fingerprint()
        r = client.post(f"{BOOT_URL}/3", content=data, headers=IGO_CT)
        assert r.status_code != 500, f"Server rejected SEND_FINGERPRINT format: {r.status_code}"

    @pytest.mark.xfail(reason="Uses response-format encoder, not wire protocol with SnakeOil")
    def test_06_get_process_format_accepted(self, client):
        """GET_PROCESS payload is parsed by server."""
        data = encode_get_process()
        r = client.post(f"{BOOT_URL}/3", content=data, headers=IGO_CT)
        assert r.status_code != 500, f"Server rejected GET_PROCESS format: {r.status_code}"

    @pytest.mark.xfail(reason="Uses response-format encoder, not wire protocol with SnakeOil")
    def test_07_full_session_flow(self, client):
        """Full session: login → senddrives → sendfingerprint → getprocess.

        Each call should be accepted (not 500). We track JSESSIONID across calls.
        """
        base = f"{BOOT_URL}/3"
        results = {}

        # Step 1: LOGIN
        login_data = encode_login(
            username="",
            password="",
            brand=BRAND,
            device_type=DEVICE_TYPE,
            appcid=APPCID,
            device_id=0,
            version_major=VERSION_MAJOR,
            version_minor=VERSION_MINOR,
        )
        r = client.post(base, content=login_data, headers=IGO_CT)
        results["login"] = r.status_code
        jsessionid = r.cookies.get("JSESSIONID")

        # Build headers with session cookie for subsequent calls
        session_headers = dict(IGO_CT)
        if jsessionid:
            session_headers["Cookie"] = f"JSESSIONID={jsessionid}"

        # Step 2: SEND_DRIVES
        drives_data = encode_send_drives(drive_count=0, drive_id=0)
        r = client.post(base, content=drives_data, headers=session_headers)
        results["senddrives"] = r.status_code

        # Step 3: SEND_FINGERPRINT
        fp_data = encode_send_fingerprint()
        r = client.post(base, content=fp_data, headers=session_headers)
        results["sendfingerprint"] = r.status_code

        # Step 4: GET_PROCESS
        gp_data = encode_get_process()
        r = client.post(base, content=gp_data, headers=session_headers)
        results["getprocess"] = r.status_code

        # All calls should be format-valid (not 500)
        for call, status in results.items():
            assert status != 500, f"{call} returned 500 (format error)"

        # Report results
        print(f"\nSession flow results: {results}")
        if jsessionid:
            print(f"JSESSIONID captured: {jsessionid[:20]}...")
