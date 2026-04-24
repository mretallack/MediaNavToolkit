"""Content installer — write downloaded content to USB drive.

The head unit's synctool reads content from the USB drive when inserted.
The update process:
1. Write content files to NaviSync/content/{type}/
2. Write .stm shadow files with metadata (size, content_id, timestamp, md5)
3. Update .lyc license files in NaviSync/license/
4. Write update_checksum.md5 to trigger synctool

USB layout:
  NaviSync/content/map/{Country}.fbl         — map data
  NaviSync/content/map/{Country}.fbl.stm     — shadow metadata
  NaviSync/content/poi/{Country}.poi         — POI data
  NaviSync/content/poi/{Country}.poi.stm     — shadow metadata
  NaviSync/content/lang/Lang_{Name}.zip      — language pack
  NaviSync/content/lang/Lang_{Name}.zip.stm  — shadow metadata
  NaviSync/license/{name}.lyc                — license file
  NaviSync/license/{name}.lyc.md5            — license checksum
  NaviSync/device_checksum.md5               — device checksum
  update_checksum.md5                        — triggers synctool

.stm format (INI):
  purpose = shadow
  size = {file_size_bytes}
  content_id = {content_id}
  header_id = {header_id}
  timestamp = {unix_timestamp}
  md5 = {md5_hex}              (optional, present for zip files)

Ref: toolbox.md §8 (USB structure), synctool_log.txt
"""

import hashlib
import shutil
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class InstallItem:
    """A content item to install on the USB drive."""

    filename: str  # e.g. "UnitedKingdom.fbl", "Lang_English-uk.zip"
    subdir: str  # e.g. "map", "lang", "poi", "speedcam", "tmc", "voice", "global_cfg"
    content_id: int
    header_id: int = 0
    source_path: Path | None = None  # path to downloaded file (None = stm-only update)


def write_stm(dest: Path, size: int, content_id: int, header_id: int, md5: str = "") -> None:
    """Write a .stm shadow metadata file."""
    lines = [
        "purpose = shadow",
        f"size = {size}",
        f"content_id = {content_id}",
        f"header_id = {header_id}",
        f"timestamp = {int(time.time())}",
    ]
    if md5:
        lines.append(f"md5 = {md5}")
    dest.write_text("\n".join(lines) + "\n")


def compute_md5(path: Path) -> str:
    """Compute MD5 hex digest of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def install_content(usb_path: Path, items: list[InstallItem]) -> list[str]:
    """Install content items to USB drive.

    Returns list of error messages (empty = success).
    """
    content_dir = usb_path / "NaviSync" / "content"
    errors = []

    for item in items:
        try:
            dest_dir = content_dir / item.subdir
            dest_dir.mkdir(parents=True, exist_ok=True)

            if item.source_path and item.source_path.exists():
                # Copy content file
                dest_file = dest_dir / item.filename
                shutil.copy2(item.source_path, dest_file)
                size = dest_file.stat().st_size
                md5 = compute_md5(dest_file) if item.filename.endswith(".zip") else ""
            else:
                # STM-only update (no content file to copy)
                size = 0
                md5 = ""

            # Write .stm
            stm_path = dest_dir / f"{item.filename}.stm"
            write_stm(stm_path, size, item.content_id, item.header_id, md5)

        except Exception as e:
            errors.append(f"{item.filename}: {e}")

    return errors


def install_license(usb_path: Path, lyc_name: str, lyc_data: bytes) -> None:
    """Install a license file, its MD5 checksum, and its STM shadow."""
    license_dir = usb_path / "NaviSync" / "license"
    license_dir.mkdir(parents=True, exist_ok=True)

    lyc_path = license_dir / lyc_name
    lyc_path.write_bytes(lyc_data)

    md5 = hashlib.md5(lyc_data).hexdigest().upper()
    (license_dir / f"{lyc_name}.md5").write_text(md5)

    # Write .lyc.stm shadow — tells synctool to copy this license
    (license_dir / f"{lyc_name}.stm").write_text('purpose="copy"\n')


def write_update_checksum(usb_path: Path) -> Path:
    """Write update_checksum.md5 to trigger the head unit's synctool.

    The synctool checks for this file on USB insertion. If present,
    it processes the update and then deletes the file.
    """
    content_dir = usb_path / "NaviSync" / "content"
    h = hashlib.md5()
    for stm in sorted(content_dir.rglob("*.stm")):
        h.update(stm.read_bytes())
    checksum_path = usb_path / "update_checksum.md5"
    checksum_path.write_text(h.hexdigest().upper())
    return checksum_path


def write_device_checksum(usb_path: Path) -> None:
    """Update NaviSync/device_checksum.md5 from all .stm files in content/."""
    content_dir = usb_path / "NaviSync" / "content"
    h = hashlib.md5()
    for stm in sorted(content_dir.rglob("*.stm")):
        h.update(stm.read_bytes())
    checksum_path = usb_path / "NaviSync" / "device_checksum.md5"
    try:
        checksum_path.unlink(missing_ok=True)
    except OSError:
        pass
    checksum_path.write_text(h.hexdigest().upper())


def write_content_stms(usb_path: Path) -> list[str]:
    """Write directory-level .stm files for content subdirectories.

    The Win32 Toolbox writes map.stm, poi.stm, speedcam.stm in the
    content/ directory with purpose="delete" to tell synctool to
    replace the content on the head unit.

    Returns list of written STM paths.
    """
    content_dir = usb_path / "NaviSync" / "content"
    written = []
    for subdir in ["map", "poi", "speedcam"]:
        sub_path = content_dir / subdir
        if not sub_path.exists():
            continue
        file_stms = list(sub_path.glob("*.stm"))
        if not file_stms:
            continue
        stm_path = content_dir / f"{subdir}.stm"
        if stm_path.exists():
            continue
        stm_path.write_text('purpose="delete"\n')
        written.append(str(stm_path))
    return written


def check_space(usb_path: Path, required_bytes: int) -> tuple[bool, int]:
    """Check if USB has enough free space. Returns (ok, free_bytes)."""
    stat = shutil.disk_usage(usb_path)
    return stat.free >= required_bytes, stat.free
