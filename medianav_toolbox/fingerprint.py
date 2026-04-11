"""Fingerprint read/write/encode for MediaNav devices.

Ref: toolbox.md §12 (fingerprint management)
"""

import hashlib
from pathlib import Path


def read_fingerprint(usb_path: Path) -> bytes | None:
    """Read fingerprint data from USB drive. Returns None if not found."""
    fp_dir = usb_path / "NaviSync" / "save"
    # Fingerprint could be in various locations; check common ones
    for name in ["fingerprint.dat", "fingerprint.xml"]:
        fp_path = fp_dir / name
        if fp_path.is_file():
            return fp_path.read_bytes()
    return None


def save_fingerprint(usb_path: Path, data: bytes, filename: str = "fingerprint.dat") -> Path:
    """Write fingerprint data to USB drive."""
    fp_dir = usb_path / "NaviSync" / "save"
    fp_dir.mkdir(parents=True, exist_ok=True)
    fp_path = fp_dir / filename
    fp_path.write_bytes(data)
    return fp_path


def encode_fingerprint(data: bytes) -> str:
    """Encode fingerprint for API transmission (hex-encoded)."""
    return data.hex()


def fingerprint_md5(data: bytes) -> str:
    """Compute MD5 of fingerprint data."""
    return hashlib.md5(data).hexdigest().upper()


def validate_fingerprint(usb_path: Path) -> list[str]:
    """Validate fingerprint files on USB. Returns list of errors.

    Ref: toolbox.md §7.4 (synctool fingerprint validation)
    """
    errors = []
    ns = usb_path / "NaviSync"

    if not (ns / "device_checksum.md5").is_file():
        errors.append("Missing device checksum file")

    if not (ns / "device_status.ini").is_file():
        errors.append("Missing drive info file")

    return errors
