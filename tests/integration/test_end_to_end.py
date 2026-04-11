"""Integration tests — end-to-end flow (no actual download/install)."""

from medianav_toolbox import Toolbox


def test_full_detect_and_boot(real_usb_path):
    """Boot + detect device — no login required."""
    with Toolbox(usb_path=str(real_usb_path)) as tb:
        device = tb.detect_device()
        assert device.appcid == 0x42000B53

        endpoints = tb.boot()
        assert endpoints.index_v2
        assert endpoints.register


def test_installed_catalog(real_usb_path):
    """Read installed catalog from real USB."""
    with Toolbox(usb_path=str(real_usb_path)) as tb:
        catalog = tb.catalog()
        assert len(catalog) > 0
        assert all(c.installed for c in catalog)
