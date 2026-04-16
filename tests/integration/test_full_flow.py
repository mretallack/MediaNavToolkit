"""Integration test: full session flow + catalog retrieval against live API.

Captures responses as fixtures for offline tests.
Run with: pytest tests/integration/test_full_flow.py -v -m integration
"""

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv()

from medianav_toolbox.catalog import (
    parse_catalog_html,
    parse_managecontent_html,
    parse_senddevicestatus_response,
    parse_update_selection,
)
from medianav_toolbox.session import MARKET_BASE, TOOLBOX_UA, _wire_headers, run_session

USB_PATH = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))
USERNAME = os.environ.get("NAVIEXTRAS_USER", "")
PASSWORD = os.environ.get("NAVIEXTRAS_PASS", "")
FIXTURES_DIR = Path(__file__).parent.parent / "data" / "fixtures"


@pytest.fixture(scope="module")
def session_result():
    if not USERNAME or not PASSWORD:
        pytest.skip("NAVIEXTRAS_USER/PASS not set")
    if not USB_PATH.exists():
        pytest.skip(f"USB path not found: {USB_PATH}")
    return run_session(USB_PATH, USERNAME, PASSWORD)


@pytest.mark.integration
class TestFullSessionFlow:
    def test_all_steps_complete(self, session_result):
        assert "boot" in session_result["steps"]
        assert "login" in session_result["steps"]
        assert "sendfingerprint" in session_result["steps"]
        assert "getprocess" in session_result["steps"]

    def test_no_errors(self, session_result):
        assert session_result["errors"] == []

    def test_login_authenticated(self, session_result):
        assert session_result["session"].is_authenticated

    def test_fingerprint_accepted(self, session_result):
        assert session_result["fingerprint_status"] == 200

    def test_getprocess_ok(self, session_result):
        assert session_result["getprocess_status"] == 200


@pytest.mark.integration
class TestCatalogRetrieval:
    """Test catalog retrieval via the web endpoints (uses JSESSIONID from login)."""

    @pytest.fixture(scope="class")
    def catalog_html(self, session_result):
        """Fetch catalog list page using the authenticated session."""
        from medianav_toolbox.api.client import NaviExtrasClient
        from medianav_toolbox.config import Config

        jsid = session_result["session"].jsessionid
        if not jsid:
            pytest.skip("No JSESSIONID")

        with NaviExtrasClient(Config()) as client:
            resp = client.get(
                f"{MARKET_BASE.replace('/rest', '')}/toolbox/cataloglist",
                headers={
                    "User-Agent": TOOLBOX_UA,
                    "Cookie": f"JSESSIONID={jsid}",
                },
            )
            if resp.status_code != 200:
                pytest.skip(f"Catalog returned {resp.status_code}")
            return resp.text

    def test_catalog_has_items(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        assert len(items) > 5

    def test_catalog_has_maps(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        maps = [i for i in items if "Map" in i.name]
        assert len(maps) > 0


@pytest.mark.integration
class TestContentSelection:
    """Test content selection and size estimation against live API."""

    def test_get_content_tree(self, session_result):
        from medianav_toolbox.content import get_content_tree

        jsid = session_result["session"].jsessionid
        if not jsid:
            pytest.skip("No JSESSIONID")

        from medianav_toolbox.api.client import NaviExtrasClient
        from medianav_toolbox.config import Config

        with NaviExtrasClient(Config()) as client:
            nodes = get_content_tree(client._client, jsid)
            assert len(nodes) > 5
            # Should have UK map
            uk = [n for n in nodes if "United Kingdom" in n.name]
            assert len(uk) >= 1

    def test_select_and_get_sizes(self, session_result):
        from medianav_toolbox.content import get_content_tree, select_content

        jsid = session_result["session"].jsessionid
        if not jsid:
            pytest.skip("No JSESSIONID")

        from medianav_toolbox.api.client import NaviExtrasClient
        from medianav_toolbox.config import Config

        with NaviExtrasClient(Config()) as client:
            nodes = get_content_tree(client._client, jsid)
            all_ids = [n.content_id for n in nodes]
            sizes, indicator = select_content(client._client, jsid, all_ids)
            assert len(sizes) > 0
            assert indicator["fullSize"] > 0

            # Deselect to clean up
            select_content(client._client, jsid, [])
