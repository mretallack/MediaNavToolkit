"""Integration tests — device parsing with real USB data."""

from medianav_toolbox.device import (
    detect_drive,
    parse_device_nng,
    read_device_status,
    read_installed_content,
)
from medianav_toolbox.models import ContentType


def test_parse_real_device_nng(real_usb_path):
    device = parse_device_nng(real_usb_path / "NaviSync" / "license" / "device.nng")
    assert device.appcid == 0x42000B53
    assert len(device.raw_data) == 268


def test_read_real_usb_structure(real_usb_path):
    content = read_installed_content(real_usb_path)
    assert len(content) > 0
    types = {c.content_type for c in content}
    assert ContentType.MAP in types


def test_detect_real_drive(real_usb_path):
    device = detect_drive(real_usb_path)
    assert device is not None
    assert device.appcid == 0x42000B53


def test_read_real_device_status(real_usb_path):
    info = read_device_status(real_usb_path)
    assert info.total_space > 0
    assert info.os_version
