"""Tests for installer.py."""

from pathlib import Path

from medianav_toolbox.installer import ContentInstaller
from medianav_toolbox.models import ContentItem, ContentType


def _make_usb(tmp_path):
    (tmp_path / "NaviSync" / "content").mkdir(parents=True)
    return tmp_path


def _item(name="TestMap", ctype=ContentType.MAP, cid=100, size=1000):
    return ContentItem(
        content_id=cid, name=name, content_type=ctype, size=size, timestamp=1700000000
    )


def test_install_writes_stm(tmp_path):
    usb = _make_usb(tmp_path)
    inst = ContentInstaller(usb)
    result = inst.install([_item()], [tmp_path / "dummy.dat"])
    assert result.installed_count == 1
    stm_files = list((usb / "NaviSync" / "content" / "map").glob("*.stm"))
    assert len(stm_files) == 1


def test_install_stm_content(tmp_path):
    usb = _make_usb(tmp_path)
    inst = ContentInstaller(usb)
    inst.install([_item(name="UK", cid=42, size=9999)], [tmp_path / "dummy.dat"])
    stm = (usb / "NaviSync" / "content" / "map" / "UK.fbl.stm").read_text()
    assert "content_id = 42" in stm
    assert "size = 9999" in stm
    assert "purpose = shadow" in stm


def test_install_writes_update_checksum(tmp_path):
    usb = _make_usb(tmp_path)
    inst = ContentInstaller(usb)
    inst.install([_item()], [tmp_path / "dummy.dat"])
    checksum = usb / "update_checksum.md5"
    assert checksum.exists()
    assert len(checksum.read_text()) == 32  # MD5 hex


def test_install_check_space(tmp_path):
    usb = _make_usb(tmp_path)
    inst = ContentInstaller(usb)
    assert inst.check_space(1) is True
    assert inst.check_space(10**18) is False  # 1 exabyte


def test_install_preserves_existing(tmp_path):
    usb = _make_usb(tmp_path)
    existing = usb / "NaviSync" / "content" / "map"
    existing.mkdir(parents=True, exist_ok=True)
    (existing / "OldMap.fbl.stm").write_text("purpose = shadow\nsize = 500\n")
    inst = ContentInstaller(usb)
    inst.install([_item(name="NewMap")], [tmp_path / "dummy.dat"])
    assert (existing / "OldMap.fbl.stm").exists()
    assert (existing / "NewMap.fbl.stm").exists()


def test_install_content_type_dirs(tmp_path):
    usb = _make_usb(tmp_path)
    inst = ContentInstaller(usb)
    items = [
        _item(name="A", ctype=ContentType.MAP, cid=1),
        _item(name="B", ctype=ContentType.POI, cid=2),
        _item(name="C", ctype=ContentType.SPEEDCAM, cid=3),
    ]
    inst.install(items, [tmp_path / "d"] * 3)
    assert (usb / "NaviSync" / "content" / "map" / "A.fbl.stm").exists()
    assert (usb / "NaviSync" / "content" / "poi" / "B.poi.stm").exists()
    assert (usb / "NaviSync" / "content" / "speedcam" / "C.spc.stm").exists()
