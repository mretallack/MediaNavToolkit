"""Build senddevicestatus body from live USB contents.

Scans the USB drive and builds the binary body that the server expects,
including MD5 hashes of all files in NaviSync/license/ and NaviSync/CONTENT/.

The body format (D8 02, bitmask 1F40):
  [4B header] [device_info] [00] [content_version_block] [file_entries] [trailer]

Ref: captured run16 bodies, agent-comms.txt analysis
"""

import hashlib
import struct
import time
from pathlib import Path

from medianav_toolbox.device import parse_device_nng, read_device_status
from medianav_toolbox.wire_codec import encode_int32, encode_int64, encode_string


def _md5_file(path: Path) -> str:
    """Compute MD5 hex of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _file_ts_ms(path: Path) -> int:
    """Get file modification time as epoch milliseconds."""
    return int(path.stat().st_mtime * 1000)


def _encode_file_entry(md5: str, fname: str, mount: str, path: str,
                       size: int, ts_ms: int) -> bytes:
    """Encode an 0xA0 file entry."""
    return (
        b"\xa0"
        + encode_string(md5)
        + encode_string(fname)
        + encode_string(mount)
        + encode_string(path)
        + encode_int64(size)
        + encode_int64(ts_ms)
        + encode_int64(ts_ms)
    )


def _encode_dir_entry(name: str, mount: str, path: str, ts_ms: int) -> bytes:
    """Encode a 0x22 directory entry."""
    return (
        b"\x22"
        + encode_string(name)
        + encode_string(mount)
        + encode_string(path)
        + encode_int64(0)
        + encode_int64(ts_ms)
        + encode_int64(ts_ms)
    )


def _encode_e0_entry(md5_content: str, md5_file: str, fname: str,
                     mount: str, path: str, size: int, ts_ms: int) -> bytes:
    """Encode an 0xE0 file entry (content MD5 + file MD5)."""
    return (
        b"\xe0"
        + encode_string(md5_content)
        + b"\x08\xa0"
        + encode_string(md5_file)
        + encode_string(fname)
        + encode_string(mount)
        + encode_string(path)
        + encode_int64(size)
        + encode_int64(ts_ms)
        + encode_int64(ts_ms)
    )


def build_live_senddevicestatus(usb_path: Path, variant: int = 0x02,
                                uniq_id_override: str = "",
                                drive_path: str = "E:\\") -> bytes:
    """Build senddevicestatus body from live USB contents.

    Args:
        usb_path: path to USB root
        variant: 0x02 for D8 02 (RECOGNIZED, bitmask 1F40)
                 0x03 for D8 03 (REGISTERED, bitmask 1E40)
        uniq_id_override: if set, use this instead of device.nng brand_md5
    """
    device = parse_device_nng(usb_path / "NaviSync" / "license" / "device.nng")
    status = read_device_status(usb_path)

    # Header
    bitmask = b"\x1f\x40" if variant == 0x02 else b"\x1e\x40"
    header = bytes([0xd8, variant]) + bitmask

    # Device info — values from device.nng and captured traffic
    # SWID, IMEI, serial come from the head unit (constant for this device)
    swid = "CK-A80R-YEC3-MYXL-18LN"
    imei = "32483158423731362D42323938353431"
    version = "9.12.179.821558"
    first_use = 0x63AAF600
    serial = "UU1DJF00869579646"
    uniq_id = uniq_id_override or device.brand_md5.upper()

    device_info = (
        encode_string("DaciaAutomotive")
        + encode_string("DaciaAutomotiveDeviceCY20_ULC4dot5")
        + encode_string(swid)
        + encode_string(imei)
        + encode_string(version)
        + encode_int32(first_use)
        + b"\x00\x00\x00\x00"
        + encode_int32(device.appcid)
        + encode_string(serial)
    )
    # UniqId is only present for variant=0x02 (bitmask 1F40, bit 0 set)
    if variant == 0x02:
        device_info += encode_string(uniq_id)

    # Content version block — use value from device_status or default
    content_ver = 46475  # from captured traffic
    separator = b"\x00"
    content_block = (
        b"\x01"
        + struct.pack("<H", content_ver)
        + b"\x00\x00"
        + b"\x00\x01\x00\x00\x00\x00"
    )

    # Scan files
    entries = b""
    license_dir = usb_path / "NaviSync" / "license"
    content_dir = usb_path / "NaviSync" / "content"

    # brand.txt — E0 entry with content MD5 and file MD5
    brand_file = content_dir / "brand.txt"
    if brand_file.exists():
        # Content MD5 = overall device checksum from device_checksum.md5
        checksum_file = usb_path / "NaviSync" / "device_checksum.md5"
        if checksum_file.exists():
            md5_content = checksum_file.read_text().strip()
        else:
            md5_content = _md5_file(brand_file)
        md5_file = _md5_file(brand_file)
        entries += _encode_e0_entry(
            md5_content, md5_file, "brand.txt", "primary",
            "NaviSync/CONTENT", brand_file.stat().st_size,
            _file_ts_ms(brand_file),
        )

    # license directory entry
    if license_dir.exists():
        entries += _encode_dir_entry(
            "license", "primary", "NaviSync", _file_ts_ms(license_dir)
        )

    # All files in NaviSync/license/ — device.nng first, then others sorted
    if license_dir.exists():
        device_nng = license_dir / "device.nng"
        if device_nng.exists():
            entries += _encode_file_entry(
                _md5_file(device_nng), "device.nng", "primary", "NaviSync/license",
                device_nng.stat().st_size, _file_ts_ms(device_nng),
            )
        for f in sorted(license_dir.iterdir()):
            if f.is_file() and f.name != "device.nng":
                entries += _encode_file_entry(
                    _md5_file(f), f.name, "primary", "NaviSync/license",
                    f.stat().st_size, _file_ts_ms(f),
                )

    # Trailer
    info_str = f"{int(time.time())}_{1}"
    trailer = (
        b"\x01\x00"
        + encode_string("primary")
        + encode_int64(status.total_space)
        + encode_int64(status.free_space)
        + encode_int64(0)  # minfree
        + b"\x00\x00\x00\x00\x00\x00"  # padding
        + b"\x10\x00"  # blocksize 4096
        + encode_string(drive_path)
        + encode_string(info_str)
    )

    return header + device_info + separator + content_block + entries + trailer
