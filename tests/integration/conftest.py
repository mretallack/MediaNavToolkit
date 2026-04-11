"""Integration test fixtures — real API and real USB data."""

import os
import time
from pathlib import Path

import pytest

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.auth import load_credentials
from medianav_toolbox.config import Config
from medianav_toolbox.models import Credentials

# Skip all integration tests if no credentials
_has_creds = bool(os.environ.get("NAVIEXTRAS_USER"))


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
            # Only skip API tests (not device/e2e) when no credentials
            needs_api = (
                "live" in item.name
                and "device" not in item.name
                and "end_to_end" not in str(item.fspath)
            )
            if not _has_creds and needs_api:
                item.add_marker(pytest.mark.skip(reason="No NAVIEXTRAS_USER in env"))


@pytest.fixture(scope="session")
def credentials():
    return load_credentials()


@pytest.fixture(scope="session")
def live_client():
    client = NaviExtrasClient(Config(max_retries=2, http_timeout=30))
    yield client
    client.close()


@pytest.fixture(scope="session")
def real_usb_path():
    p = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))
    if not (p / "NaviSync").is_dir():
        pytest.skip("No real USB data available")
    return p


@pytest.fixture(autouse=True)
def rate_limit():
    """1 second delay between integration tests to be polite to the API."""
    yield
    time.sleep(1)
