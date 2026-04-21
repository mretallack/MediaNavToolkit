"""USB device detection, device.nng parsing, and XOR decoding.

Ref: toolbox.md §7 (device recognition), §21 (XOR tables), §22 (XOR decode)
"""

import struct
from importlib import resources
from pathlib import Path

from medianav_toolbox.models import ContentType, DeviceInfo, DriveInfo, InstalledContent

# Brand index mapping (toolbox.md §7.6, from synctool log)
BRAND_MAP = {
    0: "dacia",
    1: "renault",
    2: "opel",
    3: "avtovaz",
    4: "vauxhall",
    5: "fiat",
    6: "nissan",
    7: "renault_trucks",
    8: "renault_samsung_motors",
    10: "datsun",
}

# Content type inferred from directory name
_DIR_TO_TYPE = {
    "map": ContentType.MAP,
    "poi": ContentType.POI,
    "speedcam": ContentType.SPEEDCAM,
    "voice": ContentType.VOICE,
    "lang": ContentType.LANG,
    "tmc": ContentType.TMC,
    "global_cfg": ContentType.GLOBAL_CFG,
    "userdata": ContentType.USERDATA,
}


def _load_xor_table(name: str = "xor_table_normal.bin") -> bytes:
    """Load a bundled XOR table."""
    return resources.files("medianav_toolbox.data").joinpath(name).read_bytes()


def xor_decode(data: bytes, table: bytes | None = None) -> bytes:
    """XOR decode using NNG algorithm (toolbox.md line 453922).

    Operates on 32-bit words: decoded = (table[i & 0x3ff] ^ word[i]) - iVar7
    First chunk uses iVar7=0.
    """
    if table is None:
        table = _load_xor_table()

    xor_words = struct.unpack("<1024I", table)

    # Pad data to 4-byte boundary
    padded = data + b"\x00" * ((-len(data)) % 4)
    words = list(struct.unpack(f"<{len(padded) // 4}I", padded))
    num_words = (len(data) + 3) // 4

    decoded = []
    for i in range(num_words):
        val = (xor_words[i & 0x3FF] ^ words[i]) & 0xFFFFFFFF
        decoded.append(val)

    return struct.pack(f"<{len(decoded)}I", *decoded)[: len(data)]


def parse_device_nng(path: Path) -> DeviceInfo:
    """Parse device.nng and extract device identity fields.

    Ref: toolbox.md §7.6 (recognition flow)
    - APPCID at offset 0x5C (little-endian uint32) in RAW data
    - BrandMD5 at offset 0x40 (16 bytes, XOR-encoded)
    - NNGE marker at offset 0x50
    """
    raw = path.read_bytes()
    if len(raw) < 0x60:
        raise ValueError(f"device.nng too small: {len(raw)} bytes (expected >= 96)")

    # APPCID is in the raw (un-XOR'd) data at offset 0x5C
    appcid = struct.unpack_from("<I", raw, 0x5C)[0]

    # BrandMD5 is the 16 bytes at offset 0x40, XOR-encoded
    # We XOR-decode just that section to get the brand identifier
    table = _load_xor_table()
    brand_raw = raw[0x40:0x50]
    xor_words = struct.unpack("<1024I", table)
    brand_words = struct.unpack("<4I", brand_raw)
    # Offset into XOR table: 0x40 / 4 = 16 words in
    brand_decoded = []
    for i in range(4):
        idx = (i + 0x10) & 0x3FF
        brand_decoded.append((xor_words[idx] ^ brand_words[i]) & 0xFFFFFFFF)
    brand_md5 = struct.pack("<4I", *brand_decoded).hex()

    return DeviceInfo(
        appcid=appcid,
        brand_md5=brand_md5,
        drive_path=path.parent.parent.parent,  # NaviSync/license/device.nng → USB root
        raw_data=raw,
    )


def validate_drive(usb_path: Path) -> list[str]:
    """Check USB drive has required MediaNav files. Returns list of errors."""
    errors = []
    ns = usb_path / "NaviSync"
    if not ns.is_dir():
        errors.append("Missing NaviSync/ directory")
        return errors
    if not (ns / "license" / "device.nng").is_file():
        errors.append("Missing NaviSync/license/device.nng")
    if not (ns / "device_status.ini").is_file():
        errors.append("Missing NaviSync/device_status.ini")
    return errors


def detect_drive(usb_path: Path) -> DeviceInfo | None:
    """Detect and parse a MediaNav USB drive. Returns None if not valid."""
    errors = validate_drive(usb_path)
    if errors:
        return None
    return parse_device_nng(usb_path / "NaviSync" / "license" / "device.nng")


def read_device_status(usb_path: Path) -> DriveInfo:
    """Parse NaviSync/device_status.ini."""
    ini_path = usb_path / "NaviSync" / "device_status.ini"
    data: dict[str, str] = {}
    for line in ini_path.read_text().splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            data[key.strip()] = val.strip().strip('"')

    caps = [c.strip() for c in data.get("capabilities", "").split(",") if c.strip()]
    return DriveInfo(
        drive_path=usb_path,
        free_space=int(data.get("freesize", 0)),
        total_space=int(data.get("totalsize", 0)),
        os_version=data.get("os_version", ""),
        os_build=data.get("os_build_version", ""),
        capabilities=caps,
    )


def parse_stm_file(path: Path) -> InstalledContent:
    """Parse a .stm shadow/metadata file."""
    data: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            data[key.strip()] = val.strip()

    # Infer content type from parent directory name
    parent_name = path.parent.name.lower()
    ctype = _DIR_TO_TYPE.get(parent_name, ContentType.UNKNOWN)

    return InstalledContent(
        content_id=int(data.get("content_id", 0)),
        header_id=int(data.get("header_id", 0)),
        size=int(data.get("size", 0)),
        timestamp=int(data.get("timestamp", 0)),
        purpose=data.get("purpose", ""),
        file_path=path,
        content_type=ctype,
    )


def read_installed_content(usb_path: Path) -> list[InstalledContent]:
    """Scan all .stm files on the USB drive."""
    content_dir = usb_path / "NaviSync" / "content"
    if not content_dir.is_dir():
        return []
    return [parse_stm_file(p) for p in sorted(content_dir.rglob("*.stm"))]


def scan_device_files(usb_path: Path) -> list:
    """Scan NaviSync directory and return DeviceFileEntry list for senddevicestatus.

    Scans: NaviSync/CONTENT/brand.txt, NaviSync/license/ directory and all files in it.
    Returns entries with MD5 hashes, sizes, and modification timestamps.
    """
    import hashlib

    from medianav_toolbox.wire_codec import DeviceFileEntry

    entries = []
    navisync = usb_path / "NaviSync"
    if not navisync.is_dir():
        return entries

    # brand.txt
    brand_txt = navisync / "CONTENT" / "brand.txt"
    if brand_txt.is_file():
        data = brand_txt.read_bytes()
        md5 = hashlib.md5(data).hexdigest().upper()
        mtime_ms = int(brand_txt.stat().st_mtime * 1000)
        entries.append(
            DeviceFileEntry(
                md5=md5,
                filename="brand.txt",
                mount="primary",
                path="NaviSync/CONTENT",
                size=len(data),
                modified_ms=mtime_ms,
            )
        )

    # license directory + files
    license_dir = navisync / "license"
    if license_dir.is_dir():
        mtime_ms = int(license_dir.stat().st_mtime * 1000)
        entries.append(
            DeviceFileEntry(
                md5="",
                filename="license",
                mount="primary",
                path="NaviSync",
                size=0,
                modified_ms=mtime_ms,
            )
        )
        for f in sorted(license_dir.iterdir()):
            if f.is_file():
                data = f.read_bytes()
                md5 = hashlib.md5(data).hexdigest().upper()
                mtime_ms = int(f.stat().st_mtime * 1000)
                ctime_ms = int(f.stat().st_ctime * 1000)
                entries.append(
                    DeviceFileEntry(
                        md5=md5,
                        filename=f.name,
                        mount="primary",
                        path="NaviSync/license",
                        size=len(data),
                        modified_ms=mtime_ms,
                        created_ms=ctime_ms,
                    )
                )

    return entries


def compute_overall_md5(usb_path: Path) -> str:
    """Compute the overall MD5 for senddevicestatus from NaviSync files."""
    import hashlib

    h = hashlib.md5()
    navisync = usb_path / "NaviSync"
    if not navisync.is_dir():
        return ""
    for f in sorted(navisync.rglob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest().upper()
