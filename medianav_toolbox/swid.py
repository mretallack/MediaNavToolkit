"""SWID (Software ID) generation.

The SWID identifies the machine running the Toolbox. It's derived from
the drive serial number via: MD5("SPEEDx{serial}CAM") → Crockford base32.

Format: CK-XXXX-XXXX-XXXX-XXXX (16 Crockford base32 chars from first 10 MD5 bytes)

Ref: toolbox.md §4 (SWID), FUN_100bd380 (salt+MD5), FUN_100bd450 (get serial)
"""

import hashlib
import subprocess
from pathlib import Path

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _to_crockford_base32(data: bytes) -> str:
    """Encode 10 bytes as 16 Crockford base32 characters (80 bits → 16×5 bits)."""
    val = int.from_bytes(data[:10], "big")
    chars = []
    for _ in range(16):
        chars.append(CROCKFORD[val & 0x1F])
        val >>= 5
    return "".join(reversed(chars))


def compute_swid(drive_serial: str) -> str:
    """Compute SWID from a drive serial string.

    Args:
        drive_serial: drive serial number (e.g. from lsblk or /dev/disk/by-id/)

    Returns:
        SWID string like "CK-153G-PF9R-KB6D-W8B0"
    """
    salted = f"SPEEDx{drive_serial}CAM"
    md5 = hashlib.md5(salted.encode()).digest()
    encoded = _to_crockford_base32(md5[:10])
    return f"CK-{encoded[:4]}-{encoded[4:8]}-{encoded[8:12]}-{encoded[12:16]}"


def get_drive_serial(drive_path: str | Path) -> str | None:
    """Get the serial number of the drive containing the given path.

    Tries (in order):
    1. lsblk --nodeps -no SERIAL for the device
    2. /dev/disk/by-id/ symlink parsing

    Returns:
        Serial string, or None if not detectable
    """
    drive_path = Path(drive_path)

    # Find the block device for this path
    device = _find_block_device(drive_path)
    if not device:
        return None

    # Strip partition number to get the base device
    base_device = _strip_partition(device)

    # Try lsblk
    serial = _serial_from_lsblk(base_device)
    if serial:
        return serial

    # Try /dev/disk/by-id/
    return _serial_from_by_id(base_device)


def _find_block_device(path: Path) -> str | None:
    """Find the block device for a mount point using findmnt."""
    try:
        result = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _strip_partition(device: str) -> str:
    """Strip partition number: /dev/sda1 → /dev/sda, /dev/nvme0n1p1 → /dev/nvme0n1."""
    if "nvme" in device and "p" in device.split("nvme")[-1]:
        return device.rsplit("p", 1)[0]
    return device.rstrip("0123456789")


def _serial_from_lsblk(device: str) -> str | None:
    """Get serial via lsblk."""
    try:
        result = subprocess.run(
            ["lsblk", "--nodeps", "-no", "SERIAL", device],
            capture_output=True,
            text=True,
            timeout=5,
        )
        serial = result.stdout.strip()
        if serial:
            return serial
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _serial_from_by_id(device: str) -> str | None:
    """Get serial from /dev/disk/by-id/ symlinks."""
    by_id = Path("/dev/disk/by-id")
    if not by_id.exists():
        return None
    device_name = Path(device).name
    for link in by_id.iterdir():
        if link.is_symlink() and link.resolve().name == device_name:
            # Format: usb-Vendor_Model_SERIAL-0:0 or ata-Model_SERIAL
            name = link.name
            parts = name.rsplit("_", 1)
            if len(parts) == 2:
                serial = parts[1].split("-")[0]
                if serial and len(serial) >= 4:
                    return serial
    return None
