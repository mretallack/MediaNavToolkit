"""Content file downloader — fetch files from Naviextras via getprocess polling.

The download protocol:
1. confirm_selection (REST) — tell server what to update
2. getprocess (wire, with SWIDs) — server returns file manifest
3. getprocess (wire, polling) — server streams file data
4. Repeat step 3 until complete

The manifest is a binary structure listing files with content IDs,
filenames, cache paths, sizes, and timestamps.
"""

import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ManifestEntry:
    """A file entry from the getprocess manifest."""

    content_id: str
    filename: str
    cache_path: str = ""


def parse_manifest(data: bytes) -> list[ManifestEntry]:
    """Parse the getprocess manifest response into file entries.

    The manifest is a binary structure with length-prefixed strings
    for content IDs, filenames, and cache paths.
    """
    if len(data) < 10:
        return []

    entries = []
    current: dict[str, str] = {}
    pos = 6  # Skip 4-byte header + 2-byte marker

    while pos < len(data) - 2:
        b = data[pos]

        # Length-prefixed ASCII string
        if 1 <= b <= 0x7F and pos + b < len(data):
            s = data[pos + 1 : pos + 1 + b]
            if all(0x20 <= c <= 0x7E for c in s):
                text = s.decode("ascii")
                if "/" in text and len(text) > 10:
                    current["cache_path"] = text
                elif "." in text and len(text) > 3:
                    current["filename"] = text
                elif text.isdigit() and len(text) >= 5:
                    if current.get("filename"):
                        entries.append(
                            ManifestEntry(
                                content_id=current.get("content_id", ""),
                                filename=current["filename"],
                                cache_path=current.get("cache_path", ""),
                            )
                        )
                        current = {}
                    current["content_id"] = text
                pos += 1 + b
                continue
        pos += 1

    if current.get("filename"):
        entries.append(
            ManifestEntry(
                content_id=current.get("content_id", ""),
                filename=current["filename"],
                cache_path=current.get("cache_path", ""),
            )
        )

    # Deduplicate and filter out .md5 files
    seen: set[tuple[str, str]] = set()
    result = []
    for e in entries:
        if e.filename.endswith(".md5"):
            continue
        key = (e.content_id, e.filename)
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


def download_content(
    client,
    creds,
    session,
    swids: list[str],
    output_dir: Path,
    max_polls: int = 100,
    poll_interval: float = 2.0,
    progress_cb=None,
):
    """Download content files via getprocess polling.

    Args:
        client: NaviExtrasClient instance
        creds: DeviceCredentials
        session: Session with jsessionid
        swids: License SWIDs to include in getprocess
        output_dir: Directory to write downloaded files
        max_polls: Maximum number of getprocess polls
        poll_interval: Seconds between polls
        progress_cb: Optional callback(filename, bytes_received, total_bytes)

    Returns:
        List of downloaded file paths
    """
    from medianav_toolbox.igo_serializer import build_credential_block
    from medianav_toolbox.protocol import SVC_MARKET, build_request, parse_response
    from medianav_toolbox.wire_codec import build_getprocess_body

    output_dir.mkdir(parents=True, exist_ok=True)

    def _call_getprocess(body=b""):
        cred_block = build_credential_block(creds.name)
        query = bytes([0xC3, 0x20]) + cred_block
        wire = build_request(
            query=query,
            body=body,
            service_minor=SVC_MARKET,
            code=creds.code,
            secret=creds.secret,
        )
        headers = {"User-Agent": "DaciaAutomotive-Toolbox-2026041167"}
        if session.jsessionid:
            headers["Cookie"] = f"JSESSIONID={session.jsessionid}"
        resp = client.post(
            "https://dacia-ulc.naviextras.com/rest/1/getprocess",
            content=wire,
            headers=headers,
            timeout=120.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"getprocess returned {resp.status_code}")
        if len(resp.content) <= 4:
            return b""
        return parse_response(resp.content, creds.secret)

    # Step 1: Call getprocess with SWIDs to get manifest
    gp_body = build_getprocess_body(swids) if swids else b""
    manifest_data = _call_getprocess(gp_body)

    if not manifest_data:
        return []

    manifest = parse_manifest(manifest_data)
    if not manifest:
        # Response might be file data directly, save it
        if len(manifest_data) > 100:
            out = output_dir / "getprocess_response.bin"
            out.write_bytes(manifest_data)
            return [out]
        return []

    downloaded = []

    # Step 2: Poll getprocess for file data
    for poll in range(max_polls):
        time.sleep(poll_interval)

        chunk = _call_getprocess()
        if not chunk:
            break  # No more data

        # The response is raw file data. We need to figure out which file
        # it belongs to. For now, save sequentially.
        out = output_dir / f"chunk_{poll:04d}.bin"
        out.write_bytes(chunk)
        downloaded.append(out)

        if progress_cb:
            progress_cb(f"chunk_{poll}", len(chunk), 0)

    return downloaded
