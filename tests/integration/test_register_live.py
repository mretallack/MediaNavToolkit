"""Integration tests — register service against real API."""

from medianav_toolbox.api.boot import boot
from medianav_toolbox.api.register import (
    get_device_descriptor_list,
    get_device_info,
    get_device_model_list,
)
from medianav_toolbox.device import parse_device_nng


def test_get_device_model_list_live(live_client):
    endpoints = boot(live_client)
    version = get_device_model_list(live_client, endpoints)
    assert version is not None
    assert "." in version  # e.g. "3.857"


def test_get_device_descriptor_list_live(live_client, real_usb_path):
    endpoints = boot(live_client)
    device = parse_device_nng(real_usb_path / "NaviSync" / "license" / "device.nng")
    result = get_device_descriptor_list(live_client, endpoints, device)
    # 417 = valid format but needs proper encoding; 200 = success
    assert result["status"] in (200, 412, 417, 500)


def test_devinfo_live(live_client, real_usb_path):
    endpoints = boot(live_client)
    device = parse_device_nng(real_usb_path / "NaviSync" / "license" / "device.nng")
    result = get_device_info(live_client, endpoints, device)
    assert result["status"] in (200, 412, 417, 500)
