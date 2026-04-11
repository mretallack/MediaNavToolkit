"""Content installer — write downloaded content to USB drive.

Ref: toolbox.md §11 (content installation), §20 (installation details)
"""

import hashlib
import shutil
from pathlib import Path
from typing import Callable

from medianav_toolbox.models import ContentItem, ContentType, InstallResult

# Map content type to USB subdirectory
_TYPE_DIR = {
    ContentType.MAP: "map",
    ContentType.POI: "poi",
    ContentType.SPEEDCAM: "speedcam",
    ContentType.VOICE: "voice",
    ContentType.LANG: "lang",
    ContentType.TMC: "tmc",
    ContentType.GLOBAL_CFG: "global_cfg",
}

# Map content type to .stm file extension
_TYPE_EXT = {
    ContentType.MAP: ".fbl.stm",
    ContentType.POI: ".poi.stm",
    ContentType.SPEEDCAM: ".spc.stm",
    ContentType.VOICE: ".zip.stm",
    ContentType.LANG: ".zip.stm",
}


class ContentInstaller:
    def __init__(self, usb_path: Path):
        self.usb_path = usb_path
        self.content_dir = usb_path / "NaviSync" / "content"

    def install(
        self,
        items: list[ContentItem],
        files: list[Path],
        progress_cb: Callable | None = None,
    ) -> InstallResult:
        """Install content items to USB drive."""
        errors = []
        installed = 0

        for item, src in zip(items, files):
            try:
                self._install_one(item, src)
                installed += 1
                if progress_cb:
                    progress_cb(installed, len(items))
            except Exception as e:
                errors.append(f"{item.name}: {e}")

        if installed > 0:
            self.write_update_checksum()

        return InstallResult(success=len(errors) == 0, installed_count=installed, errors=errors)

    def _install_one(self, item: ContentItem, src: Path) -> None:
        """Install a single content item."""
        subdir = _TYPE_DIR.get(item.content_type, "unknown")
        dest_dir = self.content_dir / subdir
        dest_dir.mkdir(parents=True, exist_ok=True)
        self.write_stm_file(item, dest_dir)

    def write_stm_file(self, item: ContentItem, dest_dir: Path) -> Path:
        """Create/update .stm shadow metadata file. Ref: toolbox.md §20.1."""
        ext = _TYPE_EXT.get(item.content_type, ".stm")
        stm_path = dest_dir / f"{item.name}{ext}"
        stm_path.write_text(
            f"purpose = shadow\n"
            f"size = {item.size}\n"
            f"content_id = {item.content_id}\n"
            f"header_id = 0\n"
            f"timestamp = {item.timestamp}\n"
        )
        return stm_path

    def write_update_checksum(self) -> Path:
        """Write update_checksum.md5 to signal head unit. Ref: toolbox.md §20.2."""
        # Compute MD5 of all .stm files
        h = hashlib.md5()
        for stm in sorted(self.content_dir.rglob("*.stm")):
            h.update(stm.read_bytes())
        checksum_path = self.usb_path / "update_checksum.md5"
        checksum_path.write_text(h.hexdigest())
        return checksum_path

    def check_space(self, required_bytes: int) -> bool:
        """Check if USB has enough free space."""
        stat = shutil.disk_usage(self.usb_path)
        return stat.free >= required_bytes
