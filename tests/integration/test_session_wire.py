"""Integration test: full session flow against live NaviExtras API.

Captures responses as fixtures for offline unit tests.
Run with: pytest tests/integration/test_session_wire.py -v -m integration
"""

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

from medianav_toolbox.session import run_session

USB_PATH = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))
USERNAME = os.environ.get("NAVIEXTRAS_USER", "")
PASSWORD = os.environ.get("NAVIEXTRAS_PASS", "")
FIXTURES_DIR = Path(__file__).parent.parent / "data" / "fixtures"


@pytest.fixture(scope="module")
def session_result():
    """Run the full session flow once and share across tests."""
    if not USERNAME or not PASSWORD:
        pytest.skip("NAVIEXTRAS_USER/PASS not set")
    if not USB_PATH.exists():
        pytest.skip(f"USB path not found: {USB_PATH}")

    result = run_session(USB_PATH, USERNAME, PASSWORD)

    # Save fixtures for offline tests
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    fixture = {
        "steps": result["steps"],
        "errors": result["errors"],
        "fingerprint_status": result.get("fingerprint_status"),
        "getprocess_status": result.get("getprocess_status"),
    }
    if result.get("endpoints"):
        ep = result["endpoints"]
        fixture["endpoints"] = {
            "index_v3": ep.index_v3,
            "register": ep.register,
            "selfie": ep.selfie,
        }
    if result.get("getprocess_body"):
        fixture["getprocess_body_hex"] = result["getprocess_body"].hex()

    (FIXTURES_DIR / "session_flow.json").write_text(json.dumps(fixture, indent=2))

    return result


@pytest.mark.integration
class TestSessionFlow:
    def test_boot_succeeds(self, session_result):
        assert "boot" in session_result["steps"]
        assert session_result["endpoints"].index_v3

    def test_register_succeeds(self, session_result):
        assert "register" in session_result["steps"]
        creds = session_result["device_creds"]
        assert creds.code != 0
        assert creds.secret != 0
        assert len(creds.name) == 16

    def test_login_succeeds(self, session_result):
        assert "login" in session_result["steps"]
        assert session_result["session"].is_authenticated

    def test_login_has_jsessionid(self, session_result):
        assert session_result["session"].jsessionid is not None

    def test_fingerprint_succeeds(self, session_result):
        assert "sendfingerprint" in session_result["steps"]
        assert session_result["fingerprint_status"] == 200

    def test_getprocess_succeeds(self, session_result):
        assert "getprocess" in session_result["steps"]
        assert session_result["getprocess_status"] == 200

    def test_no_errors(self, session_result):
        assert session_result["errors"] == []
