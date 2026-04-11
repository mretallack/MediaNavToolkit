"""Tests for download.py."""

import hashlib
from pathlib import Path

import httpx
import respx

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.config import Config
from medianav_toolbox.download import DownloadManager
from medianav_toolbox.models import DownloadItem


def _cfg(tmp_path):
    return Config(cache_dir=tmp_path / "cache", max_retries=1, http_timeout=5)


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


@respx.mock
def test_download_one(tmp_path):
    content = b"hello world"
    respx.get("https://dl.example.com/file.dat").mock(
        return_value=httpx.Response(200, content=content)
    )
    cfg = _cfg(tmp_path)
    item = DownloadItem(
        content_id=1,
        url="https://dl.example.com/file.dat",
        target_path="file.dat",
        size=len(content),
    )
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        path = dm.download_one(item)
    assert path.exists()
    assert path.read_bytes() == content


@respx.mock
def test_download_md5_verify(tmp_path):
    content = b"test data"
    md5 = _md5(content)
    respx.get("https://dl.example.com/f.dat").mock(
        return_value=httpx.Response(200, content=content)
    )
    cfg = _cfg(tmp_path)
    item = DownloadItem(
        content_id=2,
        url="https://dl.example.com/f.dat",
        target_path="f.dat",
        size=len(content),
        md5=md5,
    )
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        path = dm.download_one(item)
    assert dm.verify_md5(path, md5)


@respx.mock
def test_download_md5_mismatch(tmp_path):
    content = b"bad data"
    respx.get("https://dl.example.com/f.dat").mock(
        return_value=httpx.Response(200, content=content)
    )
    cfg = _cfg(tmp_path)
    item = DownloadItem(
        content_id=3,
        url="https://dl.example.com/f.dat",
        target_path="f.dat",
        size=len(content),
        md5="0000000000000000",
    )
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        try:
            dm.download_one(item)
            assert False, "Should have raised"
        except ValueError as e:
            assert "MD5 mismatch" in str(e)


@respx.mock
def test_download_cache_hit(tmp_path):
    content = b"cached"
    md5 = _md5(content)
    cfg = _cfg(tmp_path)
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cfg.cache_dir / "4_f.dat"
    cached.write_bytes(content)
    route = respx.get("https://dl.example.com/f.dat").mock(
        return_value=httpx.Response(200, content=b"new")
    )
    item = DownloadItem(
        content_id=4,
        url="https://dl.example.com/f.dat",
        target_path="f.dat",
        size=len(content),
        md5=md5,
    )
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        path = dm.download_one(item)
    assert path.read_bytes() == content  # served from cache
    assert route.call_count == 0  # no HTTP request made


@respx.mock
def test_download_concurrent(tmp_path):
    respx.get("https://dl.example.com/a.dat").mock(return_value=httpx.Response(200, content=b"aaa"))
    respx.get("https://dl.example.com/b.dat").mock(return_value=httpx.Response(200, content=b"bbb"))
    cfg = _cfg(tmp_path)
    items = [
        DownloadItem(
            content_id=10, url="https://dl.example.com/a.dat", target_path="a.dat", size=3
        ),
        DownloadItem(
            content_id=11, url="https://dl.example.com/b.dat", target_path="b.dat", size=3
        ),
    ]
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        paths = dm.download_all(items)
    assert len(paths) == 2
    assert all(p.exists() for p in paths)


@respx.mock
def test_download_progress_callback(tmp_path):
    content = b"x" * 100
    respx.get("https://dl.example.com/f.dat").mock(
        return_value=httpx.Response(200, content=content)
    )
    cfg = _cfg(tmp_path)
    item = DownloadItem(
        content_id=5, url="https://dl.example.com/f.dat", target_path="f.dat", size=100
    )
    calls = []
    with NaviExtrasClient(cfg) as client:
        dm = DownloadManager(cfg, client)
        dm.download_one(item, progress_cb=lambda done, total: calls.append((done, total)))
    assert len(calls) > 0
    assert calls[-1][0] == 100


def test_clear_cache(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)
    (cfg.cache_dir / "test.dat").write_bytes(b"x")
    dm = DownloadManager.__new__(DownloadManager)
    dm.config = cfg
    dm.clear_cache()
    assert cfg.cache_dir.exists()
    assert list(cfg.cache_dir.iterdir()) == []
