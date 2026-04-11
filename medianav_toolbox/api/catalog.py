"""Content catalog — compare server catalog with installed content.

Ref: toolbox.md §5.4 (index response), §19.1 step 5 (market calls)
"""

from pathlib import Path

from medianav_toolbox.device import read_installed_content
from medianav_toolbox.models import (
    ContentItem,
    ContentType,
    DeviceInfo,
    InstalledContent,
    ProcessInfo,
)


def build_catalog(
    process: ProcessInfo,
    installed: list[InstalledContent],
) -> list[ContentItem]:
    """Build catalog by comparing server process info with installed content.

    Marks items as installed/update based on content_id matching.
    """
    installed_ids = {c.content_id for c in installed}

    items = []
    for dl in process.downloads:
        is_installed = dl.content_id in installed_ids
        items.append(
            ContentItem(
                content_id=dl.content_id,
                name=dl.target_path.rsplit("/", 1)[-1] if "/" in dl.target_path else dl.target_path,
                content_type=_infer_type(dl.target_path),
                size=dl.size,
                is_update=is_installed,
                installed=is_installed,
            )
        )
    return items


def get_installed_catalog(usb_path: Path) -> list[ContentItem]:
    """Build catalog of currently installed content from USB .stm files."""
    installed = read_installed_content(usb_path)
    return [
        ContentItem(
            content_id=c.content_id,
            name=c.file_path.stem.replace(".fbl", "")
            .replace(".poi", "")
            .replace(".spc", "")
            .replace(".zip", ""),
            content_type=c.content_type,
            size=c.size,
            timestamp=c.timestamp,
            installed=True,
        )
        for c in installed
    ]


def _infer_type(path: str) -> ContentType:
    """Infer content type from file path."""
    p = path.lower()
    if "/map/" in p or p.endswith(".fbl"):
        return ContentType.MAP
    if "/poi/" in p or p.endswith(".poi"):
        return ContentType.POI
    if "/speedcam/" in p or p.endswith(".spc"):
        return ContentType.SPEEDCAM
    if "/voice/" in p or p.endswith(".zip"):
        return ContentType.VOICE
    return ContentType.UNKNOWN
