"""Tests for api/catalog.py."""

from pathlib import Path

from medianav_toolbox.api.catalog import build_catalog, get_installed_catalog
from medianav_toolbox.models import ContentType, DownloadItem, InstalledContent, ProcessInfo

USB_PATH = Path(__file__).parent.parent / "analysis" / "usb_drive" / "disk"


def test_build_catalog_marks_installed():
    installed = [
        InstalledContent(
            content_id=100,
            header_id=1,
            size=1000,
            timestamp=0,
            purpose="shadow",
            file_path=Path("x"),
            content_type=ContentType.MAP,
        )
    ]
    process = ProcessInfo(
        downloads=[
            DownloadItem(
                content_id=100, url="https://x/map.fbl", target_path="/map/UK.fbl", size=2000
            ),
            DownloadItem(
                content_id=200, url="https://x/poi.poi", target_path="/poi/FR.poi", size=500
            ),
        ]
    )
    catalog = build_catalog(process, installed)
    assert len(catalog) == 2
    assert catalog[0].installed is True
    assert catalog[0].is_update is True
    assert catalog[1].installed is False


def test_build_catalog_infers_type():
    process = ProcessInfo(
        downloads=[
            DownloadItem(content_id=1, url="x", target_path="/map/UK.fbl", size=100),
            DownloadItem(content_id=2, url="x", target_path="/poi/FR.poi", size=100),
            DownloadItem(content_id=3, url="x", target_path="/speedcam/EU.spc", size=100),
        ]
    )
    catalog = build_catalog(process, [])
    assert catalog[0].content_type == ContentType.MAP
    assert catalog[1].content_type == ContentType.POI
    assert catalog[2].content_type == ContentType.SPEEDCAM


def test_build_catalog_empty():
    catalog = build_catalog(ProcessInfo(), [])
    assert catalog == []


def test_get_installed_catalog():
    if not USB_PATH.exists():
        return  # skip if no USB data
    catalog = get_installed_catalog(USB_PATH)
    assert len(catalog) > 0
    assert all(c.installed for c in catalog)
    names = [c.name for c in catalog]
    assert any("United" in n for n in names)
