"""Unit tests for download manager."""

import hashlib
from pathlib import Path

import pytest

from medianav_toolbox.download import DownloadManager
from medianav_toolbox.models import DownloadItem


@pytest.fixture
def tmp_cache(tmp_path):
    return tmp_path / "cache"


class TestDownloadManager:
    def test_verify_md5_correct(self, tmp_cache):
        tmp_cache.mkdir()
        test_file = tmp_cache / "test.bin"
        test_file.write_bytes(b"hello world")
        expected = hashlib.md5(b"hello world").hexdigest()

        from unittest.mock import MagicMock

        from medianav_toolbox.config import Config

        config = Config()
        config.cache_dir = tmp_cache
        dm = DownloadManager(config, MagicMock())
        assert dm.verify_md5(test_file, expected)

    def test_verify_md5_wrong(self, tmp_cache):
        tmp_cache.mkdir()
        test_file = tmp_cache / "test.bin"
        test_file.write_bytes(b"hello world")

        from unittest.mock import MagicMock

        from medianav_toolbox.config import Config

        config = Config()
        config.cache_dir = tmp_cache
        dm = DownloadManager(config, MagicMock())
        assert not dm.verify_md5(test_file, "0" * 32)

    def test_cache_hit_skips_download(self, tmp_cache):
        tmp_cache.mkdir()
        test_file = tmp_cache / "123_map.bin"
        data = b"cached content"
        test_file.write_bytes(data)
        md5 = hashlib.md5(data).hexdigest()

        from unittest.mock import MagicMock

        from medianav_toolbox.config import Config

        config = Config()
        config.cache_dir = tmp_cache
        client = MagicMock()
        dm = DownloadManager(config, client)

        item = DownloadItem(
            content_id="123",
            url="http://example.com/map.bin",
            target_path="map.bin",
            size=len(data),
            md5=md5,
        )
        result = dm.download_one(item)
        assert result == test_file
        # Client should NOT have been called (cache hit)
        client.get.assert_not_called()

    def test_clear_cache(self, tmp_cache):
        tmp_cache.mkdir()
        (tmp_cache / "file1.bin").write_bytes(b"data")
        (tmp_cache / "file2.bin").write_bytes(b"data")

        from unittest.mock import MagicMock

        from medianav_toolbox.config import Config

        config = Config()
        config.cache_dir = tmp_cache
        dm = DownloadManager(config, MagicMock())
        dm.clear_cache()
        assert tmp_cache.exists()
        assert len(list(tmp_cache.iterdir())) == 0
