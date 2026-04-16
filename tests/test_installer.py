"""Tests for content installer."""

from pathlib import Path

import pytest

from medianav_toolbox.installer import (
    InstallItem,
    check_space,
    compute_md5,
    install_content,
    install_license,
    write_stm,
    write_update_checksum,
)


def test_write_stm(tmp_path):
    stm = tmp_path / "test.fbl.stm"
    write_stm(stm, 109490688, 7341211, 117863961)
    text = stm.read_text()
    assert "purpose = shadow" in text
    assert "size = 109490688" in text
    assert "content_id = 7341211" in text
    assert "header_id = 117863961" in text
    assert "timestamp = " in text
    assert "md5" not in text


def test_write_stm_with_md5(tmp_path):
    stm = tmp_path / "test.zip.stm"
    write_stm(stm, 124146, 1090520534, 1514622542, md5="EAC5E8CCCC4A28792251535B55A7B182")
    text = stm.read_text()
    assert "md5 = EAC5E8CCCC4A28792251535B55A7B182" in text


def test_compute_md5(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"hello world")
    assert compute_md5(f) == "5EB63BBBE01EEED093CB22BB8F5ACDC3"


def test_install_content_with_file(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()
    src = tmp_path / "UnitedKingdom.fbl"
    src.write_bytes(b"map data here")

    items = [
        InstallItem(filename="UnitedKingdom.fbl", subdir="map", content_id=7341211, source_path=src)
    ]
    errors = install_content(usb, items)

    assert errors == []
    assert (usb / "NaviSync" / "content" / "map" / "UnitedKingdom.fbl").exists()
    stm = usb / "NaviSync" / "content" / "map" / "UnitedKingdom.fbl.stm"
    assert stm.exists()
    text = stm.read_text()
    assert "size = 13" in text
    assert "content_id = 7341211" in text


def test_install_content_zip_has_md5(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()
    src = tmp_path / "Lang_English-uk.zip"
    src.write_bytes(b"zip content")

    items = [
        InstallItem(
            filename="Lang_English-uk.zip", subdir="lang", content_id=1090520530, source_path=src
        )
    ]
    errors = install_content(usb, items)

    assert errors == []
    stm = usb / "NaviSync" / "content" / "lang" / "Lang_English-uk.zip.stm"
    assert "md5 = " in stm.read_text()


def test_install_content_stm_only(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()

    items = [InstallItem(filename="France.fbl", subdir="map", content_id=6816923)]
    errors = install_content(usb, items)

    assert errors == []
    stm = usb / "NaviSync" / "content" / "map" / "France.fbl.stm"
    assert stm.exists()
    assert "size = 0" in stm.read_text()


def test_install_license(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()

    install_license(usb, "test.lyc", b"license data")

    assert (usb / "NaviSync" / "license" / "test.lyc").read_bytes() == b"license data"
    md5_file = usb / "NaviSync" / "license" / "test.lyc.md5"
    assert md5_file.exists()
    assert len(md5_file.read_text()) == 32


def test_write_update_checksum(tmp_path):
    usb = tmp_path / "usb"
    content = usb / "NaviSync" / "content" / "map"
    content.mkdir(parents=True)
    (content / "test.fbl.stm").write_text("purpose = shadow\nsize = 100\n")

    path = write_update_checksum(usb)

    assert path == usb / "update_checksum.md5"
    assert path.exists()
    assert len(path.read_text()) == 32


def test_check_space(tmp_path):
    ok, free = check_space(tmp_path, 1)
    assert ok is True
    assert free > 0
