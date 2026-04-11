"""Download manager with cache, resume, and MD5 verification.

Ref: toolbox.md §9 (download manager), §9.1 (cache path), §9.5 (MD5 verification)
"""

import hashlib
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.config import Config
from medianav_toolbox.models import DownloadItem


class DownloadManager:
    def __init__(self, config: Config, client: NaviExtrasClient):
        self.config = config
        self._client = client
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)

    def download_one(self, item: DownloadItem, progress_cb: Callable | None = None) -> Path:
        """Download a single item to cache. Resumes partial downloads. Verifies MD5."""
        dest = self.config.cache_dir / f"{item.content_id}_{Path(item.target_path).name}"

        # Cache hit — skip if file exists and MD5 matches
        if dest.exists() and item.md5 and self.verify_md5(dest, item.md5):
            return dest

        # Resume support
        headers = {}
        mode = "wb"
        existing_size = 0
        partial = dest.with_suffix(dest.suffix + ".part")
        if partial.exists():
            existing_size = partial.stat().st_size
            headers["Range"] = f"bytes={existing_size}-"
            mode = "ab"

        resp = self._client.get(item.url, headers=headers)
        if resp.status_code == 416:  # Range not satisfiable — file complete
            if partial.exists():
                partial.rename(dest)
            return dest

        with open(partial, mode) as f:
            downloaded = existing_size
            f.write(resp.content)
            downloaded += len(resp.content)
            if progress_cb:
                progress_cb(downloaded, item.size)

        # Rename partial to final
        partial.rename(dest)

        # MD5 verification
        if item.md5 and not self.verify_md5(dest, item.md5):
            dest.unlink()
            raise ValueError(f"MD5 mismatch for {item.content_id}: expected {item.md5}")

        return dest

    def download_all(
        self, items: list[DownloadItem], progress_cb: Callable | None = None
    ) -> list[Path]:
        """Download multiple items concurrently."""
        results: list[Path] = []
        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_downloads) as pool:
            futures = {pool.submit(self.download_one, item, progress_cb): item for item in items}
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def verify_md5(self, path: Path, expected: str) -> bool:
        """Verify file MD5 matches expected hash."""
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest().lower() == expected.lower()

    def clear_cache(self) -> None:
        """Remove all cached downloads."""
        if self.config.cache_dir.exists():
            shutil.rmtree(self.config.cache_dir)
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)
