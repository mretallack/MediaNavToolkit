"""Data models for the MediaNav Toolbox library.

Ref: design.md §5, §6, §7
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ContentType(Enum):
    MAP = "map"
    POI = "poi"
    SPEEDCAM = "speedcam"
    VOICE = "voice"
    LANG = "lang"
    TMC = "tmc"
    GLOBAL_CFG = "global_cfg"
    USERDATA = "userdata"
    UNKNOWN = "unknown"


# --- Device ---


@dataclass
class DeviceInfo:
    """Parsed device identity from device.nng. Ref: toolbox.md §7, §21."""

    appcid: int
    brand_md5: str
    sku_ids: list[int] = field(default_factory=list)
    device_id: int | None = None
    device_name: str | None = None
    drive_path: Path = field(default_factory=Path)
    raw_data: bytes = b""


@dataclass
class InstalledContent:
    """Parsed .stm shadow file from USB. Ref: toolbox.md §20."""

    content_id: int
    header_id: int
    size: int
    timestamp: int
    purpose: str
    file_path: Path
    content_type: ContentType


@dataclass
class DriveInfo:
    """USB drive info from device_status.ini."""

    drive_path: Path
    free_space: int = 0
    total_space: int = 0
    os_version: str = ""
    os_build: str = ""
    capabilities: list[str] = field(default_factory=list)


# --- API ---


@dataclass
class ServiceEndpoints:
    """Service URLs from boot response. Ref: toolbox.md §5."""

    index_v2: str = ""
    index_v3: str = ""
    register: str = ""
    selfie: str = ""
    mobile: str = ""


@dataclass
class Credentials:
    """NaviExtras account credentials."""

    username: str = ""
    password: str = ""


@dataclass
class Session:
    """Authenticated session state. Ref: toolbox.md §17.1."""

    jsessionid: str | None = None
    device_auth_token: str | None = None
    is_authenticated: bool = False


@dataclass
class ContentItem:
    """A content item from the catalog."""

    content_id: int
    name: str
    content_type: ContentType
    size: int = 0
    timestamp: int = 0
    is_update: bool = False
    installed: bool = False


@dataclass
class DownloadItem:
    """A file to download."""

    content_id: int
    url: str
    target_path: str
    size: int = 0
    md5: str = ""


@dataclass
class ProcessInfo:
    """Response from GET_PROCESS market call. Ref: toolbox.md §6.1."""

    process_id: int = 0
    downloads: list[DownloadItem] = field(default_factory=list)
    total_size: int = 0


@dataclass
class RegisterResult:
    success: bool = False
    device_id: int | None = None
    message: str = ""


@dataclass
class InstallResult:
    success: bool = False
    installed_count: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class SyncResult:
    success: bool = False
    installed_count: int = 0
    downloaded_bytes: int = 0
    errors: list[str] = field(default_factory=list)
