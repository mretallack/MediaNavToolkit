"""Content file downloader — fetch map files from NaviExtras CDN.

The download protocol (discovered 2026-07-16):
1. Server confirms content selection via web API
2. sendfilecontent triggers server-side preparation
3. SSE event fires with process UUID
4. getprocess returns encrypted manifest with CDN URLs + MD5 checksums
5. Files are downloaded from download.naviextras.com (unauthenticated CDN)
6. sendprocessstatus reports progress per file

The CDN requires no authentication — URLs are the only access control.
Files support HTTP Range headers for resume.

URL pattern: https://download.naviextras.com/content/{type}/{format}/{region}/{version}/{build_date}/{filename}
"""

import hashlib
import json
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

CDN_HOST = "https://download.naviextras.com"


@dataclass
class DownloadFile:
    """A file to download from the CDN."""

    url: str
    filename: str
    md5: str = ""
    size: int = 0
    content_type: str = ""  # map, speedcam, global_cfg, etc.


def parse_getprocess_manifest(data: bytes, secret: int) -> list[DownloadFile]:
    """Parse the encrypted getprocess response to extract CDN download URLs.

    Args:
        data: Raw wire response from getprocess (starts with 01 00 C2)
        secret: Device secret for SnakeOil decryption

    Returns:
        List of DownloadFile entries with URLs and MD5 checksums
    """
    from medianav_toolbox.protocol import parse_response

    if len(data) < 10:
        return []

    decrypted = parse_response(data, secret)
    if len(decrypted) < 50:
        return []

    # Extract URLs with MD5 checksums
    # Format in manifest: URL followed by space and 32-char hex MD5
    raw_urls = re.findall(rb"https://download\.naviextras\.com/[^\x00-\x1f\x80-\xff]+", decrypted)

    files = []
    seen = set()
    for raw in raw_urls:
        s = raw.decode("ascii")
        parts = s.split(" ")
        if len(parts) >= 2 and len(parts[-1]) == 32:
            url = parts[0]
            md5 = parts[-1]
        else:
            url = s
            md5 = ""

        fname = url.rsplit("/", 1)[-1]
        if fname in seen:
            continue
        seen.add(fname)

        # Determine content type from URL path
        content_type = "unknown"
        if "/content/map/" in url:
            content_type = "map"
        elif "/content/speedcam/" in url:
            content_type = "speedcam"
        elif "/content/global_cfg/" in url:
            content_type = "global_cfg"
        elif "/content/poi/" in url:
            content_type = "poi"

        files.append(DownloadFile(url=url, filename=fname, md5=md5, content_type=content_type))

    return files


def load_manifest_from_file(path: Path) -> list[DownloadFile]:
    """Load a previously saved manifest JSON file."""
    data = json.loads(path.read_text())
    return [
        DownloadFile(
            url=entry["url"],
            filename=entry["filename"],
            md5=entry.get("md5", ""),
            size=entry.get("size", 0),
        )
        for entry in data
    ]


def download_file(
    url: str,
    output_path: Path,
    expected_md5: str = "",
    progress_cb: Callable[[str, int, int], None] | None = None,
    chunk_size: int = 1024 * 1024,  # 1MB chunks
) -> bool:
    """Download a single file from the CDN with resume support and MD5 verification.

    Args:
        url: CDN URL to download
        output_path: Local path to save the file
        expected_md5: Expected MD5 hash (verified after download)
        progress_cb: Optional callback(filename, bytes_downloaded, total_bytes)
        chunk_size: Download chunk size (default 1MB)

    Returns:
        True if download succeeded and MD5 matches
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if file already exists and is complete
    if output_path.exists() and expected_md5:
        existing_md5 = _md5_file(output_path)
        if existing_md5 == expected_md5.upper():
            if progress_cb:
                progress_cb(
                    output_path.name, output_path.stat().st_size, output_path.stat().st_size
                )
            return True

    # Support resume via Range header
    resume_pos = 0
    if output_path.exists():
        resume_pos = output_path.stat().st_size

    headers = {"User-Agent": "DaciaAutomotive-Toolbox-2026041167"}
    if resume_pos > 0:
        headers["Range"] = f"bytes={resume_pos}-"

    with httpx.Client(timeout=httpx.Timeout(30.0, read=300.0), follow_redirects=True) as client:
        with client.stream("GET", url, headers=headers) as resp:
            if resp.status_code == 416:
                # Range not satisfiable — file already complete
                return True
            if resp.status_code not in (200, 206):
                raise RuntimeError(f"Download failed: HTTP {resp.status_code} for {url}")

            total = int(resp.headers.get("content-length", 0))
            if resp.status_code == 206:
                total += resume_pos
            elif resp.status_code == 200:
                resume_pos = 0  # Server doesn't support range, start fresh

            mode = "ab" if resp.status_code == 206 else "wb"
            downloaded = resume_pos

            with open(output_path, mode) as f:
                for chunk in resp.iter_bytes(chunk_size=chunk_size):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb:
                        progress_cb(output_path.name, downloaded, total)

    # Verify MD5
    if expected_md5:
        actual_md5 = _md5_file(output_path)
        if actual_md5 != expected_md5.upper():
            output_path.unlink()
            raise RuntimeError(
                f"MD5 mismatch for {output_path.name}: "
                f"expected {expected_md5}, got {actual_md5}"
            )

    return True


def download_files(
    files: list[DownloadFile],
    output_dir: Path,
    progress_cb: Callable[[str, int, int], None] | None = None,
    filter_names: list[str] | None = None,
) -> list[Path]:
    """Download multiple files from the CDN.

    Args:
        files: List of DownloadFile entries
        output_dir: Directory to save downloaded files
        progress_cb: Optional progress callback
        filter_names: If set, only download files whose names contain one of these strings

    Returns:
        List of successfully downloaded file paths
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []

    for entry in files:
        if filter_names:
            if not any(f.lower() in entry.filename.lower() for f in filter_names):
                continue

        output_path = output_dir / entry.filename
        try:
            success = download_file(
                url=entry.url,
                output_path=output_path,
                expected_md5=entry.md5,
                progress_cb=progress_cb,
            )
            if success:
                downloaded.append(output_path)
        except Exception as e:
            if progress_cb:
                progress_cb(entry.filename, -1, 0)
            # Continue with other files

    return downloaded


def _md5_file(path: Path) -> str:
    """Compute MD5 hex of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()
