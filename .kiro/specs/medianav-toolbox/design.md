# Design: MediaNav Toolbox Python Library

> **Reverse engineering reference:** See [toolbox.md](toolbox.md) for detailed Ghidra decompilation traces, line references, and binary format analysis.

---

## 1. Library Architecture

The library (`medianav_toolbox`) is designed as a Python package that can be used programmatically or via CLI. All functionality is exposed through the library API first; the CLI is a thin wrapper.

```
┌──────────────────────────────────────────────────────────────┐
│                        CLI (click)                           │
│  detect │ login │ catalog │ download │ install │ sync        │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│                  medianav_toolbox (public API)                │
│                                                              │
│  Toolbox(usb_path, username, password)                       │
│    .boot()          → ServiceEndpoints                       │
│    .login()         → Session                                │
│    .detect_device() → DeviceInfo                             │
│    .register()      → RegisterResult                         │
│    .catalog()       → list[ContentItem]                      │
│    .download()      → list[Path]                             │
│    .install()       → InstallResult                          │
│    .sync()          → SyncResult  (full pipeline)            │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│                    Internal Modules                           │
│                                                              │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────────┐ │
│  │ device.py  │ │ auth.py    │ │ api/                     │ │
│  │ XOR decode │ │ Credentials│ │  boot.py   register.py   │ │
│  │ device.nng │ │ Session    │ │  market.py catalog.py    │ │
│  │ .stm parse │ │ JSESSIONID │ │  igo_binary.py           │ │
│  └────────────┘ └────────────┘ └──────────────────────────┘ │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────────┐ │
│  │fingerprint │ │ download.py│ │ installer.py             │ │
│  │  .py       │ │ Cache      │ │ USB layout               │ │
│  │ Read/write │ │ Resume     │ │ .stm/.md5 files          │ │
│  │ Encode     │ │ MD5 verify │ │ update_checksum.md5      │ │
│  └────────────┘ └────────────┘ └──────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## 2. Module Structure

```
medianav_toolbox/
├── __init__.py              # Public API: Toolbox class (calls load_dotenv())
├── __main__.py              # python -m medianav_toolbox
├── cli.py                   # Click CLI commands
├── config.py                # Config defaults from plugin.dll (→ toolbox.md §2.2)
├── models.py                # Dataclasses: DeviceInfo, ContentItem, DriveInfo, etc.
├── auth.py                  # Login credentials, session management, JSESSIONID
├── device.py                # USB detection, device.nng parsing, XOR decode (→ toolbox.md §21)
├── fingerprint.py           # Fingerprint read/write/encode (→ toolbox.md §12)
├── api/
│   ├── __init__.py
│   ├── client.py            # HTTP client, retry, cookies (→ toolbox.md §4, §17)
│   ├── igo_binary.py        # igo-binary encoder/decoder (→ toolbox.md §23)
│   ├── boot.py              # Boot service discovery (→ toolbox.md §5)
│   ├── register.py          # Device registration (→ toolbox.md §8)
│   ├── market.py            # Market API calls (→ toolbox.md §6, §16)
│   └── catalog.py           # Content catalog (→ toolbox.md §5.4)
├── download.py              # Download manager with cache (→ toolbox.md §9)
└── installer.py             # Content installation to USB (→ toolbox.md §11, §20)

# Project root
.env.example                 # Template: NAVIEXTRAS_USER, NAVIEXTRAS_PASS, NAVIEXTRAS_USB_PATH
.env                         # Actual credentials (in .gitignore, never committed)
.gitignore                   # Includes .env, __pycache__, venv/, download_cache/
```

## 3. Authentication & Login

> Ref: toolbox.md §6.1 (LOGIN market call), §17.1 (auth modes), §2.2 (config)

The original Windows app requires a naviextras.com user account. The app supports two auth modes discovered in the decompiled code (toolbox.md line 119102):

- **`full-auth`** — Username + password authentication (default for LOGIN)
- **`device-auth`** — Device-only authentication (for subsequent calls after login)

### 3.1 Credentials

```python
@dataclass
class Credentials:
    username: str          # naviextras.com email
    password: str          # naviextras.com password
```

Credentials can be provided via (in priority order):
1. Constructor arguments
2. `.env` file in project root (loaded via `python-dotenv`)
3. Environment variables: `NAVIEXTRAS_USER`, `NAVIEXTRAS_PASS`
4. Interactive prompt (CLI only)

A `.env.example` file is provided in the repo:
```ini
NAVIEXTRAS_USER=<email>
NAVIEXTRAS_PASS=<password>
NAVIEXTRAS_USB_PATH=/media/usb
```

`.env` is in `.gitignore` — never committed. The library calls `load_dotenv()` on init to pick up the `.env` file automatically.

### 3.2 Session Management (`auth.py`)

```python
class Session:
    jsessionid: str | None       # JSESSIONID cookie from server
    device_auth_token: str | None # Device auth token after LOGIN
    is_authenticated: bool
    expires_at: datetime | None

    def auth_headers(self, mode: str = "device-auth") -> dict[str, str]
```

The server uses `JSESSIONID` cookies (toolbox.md §4.1). After LOGIN, subsequent market calls use `device-auth` mode with the session cookie.

### 3.3 Login Flow

```
1. Boot:  GET /rest/2/boot → service URLs + JSESSIONID cookie
2. Login: POST {index_url}/login
          Body: igo-binary encoded {username, password, device_id, brand}
          Auth mode: full-auth
          → Session token + device auth
3. Subsequent calls use device-auth mode with JSESSIONID
```

### 3.4 Auth in the HTTP Client

```python
class NaviExtrasClient:
    def __init__(self, config: Config, credentials: Credentials | None = None): ...

    def boot(self) -> ServiceEndpoints
    def login(self, device: DeviceInfo) -> Session
    def request(self, method: str, path: str, auth_mode: str = "device-auth", **kwargs) -> Response
```

The client automatically:
- Attaches JSESSIONID cookie to all requests after boot
- Adds auth headers based on mode (full-auth for login, device-auth for market calls)
- Re-authenticates on 401/403 responses
- Sets `User-Agent: WinHTTP ToolBox/1.0` (toolbox.md §4.1)

## 4. Configuration (`config.py`)

> Ref: toolbox.md §2.2 (plugin.dll config tree)

All defaults extracted from plugin.dll decompilation:

```python
@dataclass
class Config:
    # API endpoints (toolbox.md §2.2, line 486)
    api_base: str = "https://zippy.naviextras.com/services/index/rest"
    selfie_url: str = "https://zippy.naviextras.com/services/selfie/rest/1/update"

    # Brand identity (toolbox.md §2.2, line 630-672)
    brand: str = "DaciaAutomotive"
    device_type: str = "DaciaToolbox"
    legacy_brand: str = "Dacia"
    model_filter: str = "Dacia_ULC"

    # App identity (toolbox.md §2.2, line 770-800)
    display_version: str = "5.28.2026041167"
    user_agent: str = "WinHTTP ToolBox/1.0"

    # Timeouts (toolbox.md §2.2, line ~700)
    timeout_idle: int = 30000
    http_timeout: int = 30

    # Local paths
    cache_dir: Path = Path.home() / ".medianav-toolbox" / "download_cache"
    config_path: Path = Path.home() / ".medianav-toolbox" / "config.toml"

    # Download settings
    max_concurrent_downloads: int = 2
    max_retries: int = 3
```

## 5. Device Module (`device.py`)

> Ref: toolbox.md §7 (device recognition), §21 (XOR tables), §22 (XOR decode)

### 5.1 device.nng Parsing

```python
@dataclass
class DeviceInfo:
    appcid: int              # At offset 0x5C LE (toolbox.md §7.6 step 3)
    brand_md5: str           # XOR-decoded from offset 0x40 (toolbox.md §7.6 step 5)
    sku_ids: list[int]       # Extracted via filter_factory_sku (toolbox.md §7.6 step 4)
    device_id: int | None    # Resolved after model matching
    device_name: str | None  # Resolved after model matching
    drive_path: Path
    raw_data: bytes          # Raw device.nng for pass-through to API

def parse_device_nng(path: Path) -> DeviceInfo
def xor_decode(data: bytes, table: bytes, offset: int = 0) -> bytes
```

XOR decode uses the 4096-byte table extracted from nngine.dll (toolbox.md §22.3):
```python
def xor_decode(data: bytes, table: bytes, offset: int = 0) -> bytes:
    """Decode using NNG XOR algorithm (toolbox.md line 453922)."""
    # Operates on 32-bit words: decoded = (table[i & 0x3ff] ^ word[i]) - iVar7
```

### 5.2 USB Drive Validation

```python
def detect_drive(usb_path: Path) -> DeviceInfo | None
def validate_drive(usb_path: Path) -> list[str]  # returns list of errors
def read_device_status(usb_path: Path) -> dict    # parse device_status.ini
def read_installed_content(usb_path: Path) -> list[InstalledContent]  # parse .stm files
```

### 5.3 .stm File Parsing

```python
@dataclass
class InstalledContent:
    content_id: int
    header_id: int
    size: int
    timestamp: int
    purpose: str       # "shadow"
    file_path: Path    # relative path on USB
    content_type: ContentType  # inferred from directory (map/poi/speedcam/voice/etc)
```

## 6. API Modules

> Ref: toolbox.md §5 (boot), §6 (market calls), §8 (register), §16 (call mapping), §23 (igo-binary)

### 6.1 igo-binary Codec (`api/igo_binary.py`)

```python
def encode_request(path: str, args: dict) -> bytes
def decode_response(data: bytes) -> dict
def encode_varint(value: int) -> bytes
def decode_varint(data: bytes, offset: int) -> tuple[int, int]
```

### 6.2 Boot Service (`api/boot.py`)

```python
@dataclass
class ServiceEndpoints:
    index_v2: str    # JSON API
    index_v3: str    # igo-binary API
    register: str    # Device registration
    selfie: str      # Self-update
    mobile: str      # Mobile service

def boot(client: NaviExtrasClient) -> ServiceEndpoints
```

### 6.3 Register Service (`api/register.py`)

> Ref: toolbox.md §16 complete path list

```python
def get_device_model_list(client, endpoints) -> list[DeviceModel]
def get_device_descriptor_list(client, endpoints, device: DeviceInfo) -> list[DeviceDescriptor]
def get_device_info(client, endpoints, serial_id: int) -> DeviceInfoResponse
def register_device(client, endpoints, device: DeviceInfo) -> RegisterResult
def register_device_unbind(client, endpoints, device: DeviceInfo) -> RegisterResult
```

### 6.4 Market API (`api/market.py`)

> Ref: toolbox.md §6.1 (call sequence), §16 (function→path→arg mapping)

```python
class MarketAPI:
    def __init__(self, client: NaviExtrasClient, session: Session, endpoints: ServiceEndpoints): ...

    # Core flow (toolbox.md §6.1 order)
    def login(self, credentials: Credentials, device: DeviceInfo) -> Session
    def send_drives(self, drives: list[DriveInfo]) -> dict
    def send_fingerprint(self, fp: Fingerprint) -> dict
    def send_md5(self, checksums: dict[str, str]) -> dict
    def send_sgn_file_validity(self, validity: dict) -> dict
    def send_device_status(self, status: dict) -> dict
    def get_process(self) -> ProcessInfo
    def send_process_status(self, status: ProcessStatus) -> dict
    def send_backups(self, backups: list) -> dict
    def send_error(self, code: int, message: str) -> dict
    def send_replacement_drives(self, drives: list[DriveInfo]) -> dict
    def send_file_content(self, content: bytes) -> dict
    def get_settings(self) -> dict
```

Each method maps to an API path (toolbox.md §16):

| Method | Path | Arg Size | Ref |
|--------|------|----------|-----|
| `login` | `/login` | 76 bytes | line 155845 |
| `send_drives` | `/senddrives` | 32 bytes | line 156243 |
| `send_fingerprint` | `/sendfingerprint` | 76 bytes | line 156646 |
| `get_process` | `/getprocess` | 8 bytes | line 155713 |
| `send_process_status` | `/sendprocessstatus` | 80 bytes | line 156911 |
| `send_backups` | `/sendbackups` | 32 bytes | line 155977 |
| `send_error` | `/senderror` | 32 bytes | line 156375 |
| `send_device_status` | `/senddevicestatus` | 240 bytes | line 156111 |
| `send_md5` | `/sendmd5` | 40 bytes | line 156779 |
| `send_sgn_file_validity` | `/sendsgnfilevalidity` | 36 bytes | line 157175 |
| `send_replacement_drives` | `/sendreplacementdrives` | 40 bytes | line 157043 |
| `send_file_content` | `/sendfilecontent` | 80 bytes | line 156507 |
| `get_settings` | `/settings` | — | line 157319 |

## 7. Download & Install

> Ref: toolbox.md §9 (download manager), §20 (content installation)

### 7.1 Download Manager (`download.py`)

```python
class DownloadManager:
    def __init__(self, config: Config, client: NaviExtrasClient): ...

    def download_all(self, items: list[DownloadItem], progress_cb=None) -> list[Path]
    def download_one(self, item: DownloadItem) -> Path
    def verify_md5(self, path: Path, expected: str) -> bool
    def clear_cache(self) -> None
```

Cache path: `{config.cache_dir}/` (toolbox.md §9.1, line 108986: `%app%/download_cache`)

### 7.2 Content Installer (`installer.py`)

```python
class ContentInstaller:
    def __init__(self, usb_path: Path): ...

    def install(self, content: list[ContentItem], files: list[Path], progress_cb=None) -> None
    def check_space(self, required_bytes: int) -> bool
    def write_stm_files(self, content: list[ContentItem]) -> None
    def update_checksums(self) -> None
    def update_fingerprint(self, fp: Fingerprint) -> None
    def write_update_checksum(self) -> None  # triggers head unit sync
```

USB layout (toolbox.md §20):
- `NaviSync/content/{type}/*.stm` — shadow metadata files
- `NaviSync/content/{type}/*.md5` — checksum files
- `update_checksum.md5` — signals head unit to process updates

## 8. Public API (`__init__.py`)

```python
class Toolbox:
    """Main entry point for the medianav_toolbox library."""

    def __init__(self, usb_path: Path, username: str | None = None, password: str | None = None,
                 config: Config | None = None): ...

    # Step-by-step API
    def boot(self) -> ServiceEndpoints
    def login(self) -> Session
    def detect_device(self) -> DeviceInfo
    def register(self) -> RegisterResult
    def catalog(self) -> list[ContentItem]
    def download(self, items: list[ContentItem] | None = None, progress_cb=None) -> list[Path]
    def install(self, files: list[Path], progress_cb=None) -> InstallResult

    # All-in-one
    def sync(self, progress_cb=None) -> SyncResult
```

Usage:
```python
from medianav_toolbox import Toolbox

tb = Toolbox(usb_path="/media/usb", username="<email>", password="<password>")
tb.boot()
tb.login()
device = tb.detect_device()
catalog = tb.catalog()
files = tb.download(catalog)
tb.install(files)
```

## 9. Complete Sequence Diagram

> Ref: toolbox.md §19.1 (app lifecycle)

```
User        Toolbox       Device       Boot       Register     Market       Download    Installer
 │            │             │            │            │            │            │            │
 │──sync()───▶│             │            │            │            │            │            │
 │            │──detect()──▶│            │            │            │            │            │
 │            │  read device.nng         │            │            │            │            │
 │            │  XOR decode (§22)        │            │            │            │            │
 │            │  extract APPCID/SKU/MD5  │            │            │            │            │
 │            │◀─DeviceInfo─│            │            │            │            │            │
 │            │                          │            │            │            │            │
 │            │──GET /rest/2/boot───────▶│            │            │            │            │
 │            │◀─ServiceEndpoints────────│            │            │            │            │
 │            │                          │            │            │            │            │
 │            │──/get_device_model_list──────────────▶│            │            │            │
 │            │◀─model list──────────────────────────│            │            │            │
 │            │──/devinfo (serial_id)────────────────▶│            │            │            │
 │            │◀─device info─────────────────────────│            │            │            │
 │            │──/device (if not registered)─────────▶│            │            │            │
 │            │◀─RegisterResult──────────────────────│            │            │            │
 │            │                          │            │            │            │            │
 │            │──/login (user+pass+device)───────────────────────▶│            │            │
 │            │◀─Session (JSESSIONID + device-auth)──────────────│            │            │
 │            │──/senddrives─────────────────────────────────────▶│            │            │
 │            │──/sendfingerprint────────────────────────────────▶│            │            │
 │            │──/sendmd5────────────────────────────────────────▶│            │            │
 │            │──/senddevicestatus───────────────────────────────▶│            │            │
 │            │──/getprocess─────────────────────────────────────▶│            │            │
 │            │◀─ProcessInfo (download URLs)─────────────────────│            │            │
 │            │                          │            │            │            │            │
 │◀─catalog──│                          │            │            │            │            │
 │─confirm──▶│                          │            │            │            │            │
 │            │──download(items)────────────────────────────────────────────▶│            │
 │◀─progress─│                          │            │            │            │            │
 │            │◀─files──────────────────────────────────────────────────────│            │
 │            │──install(files)──────────────────────────────────────────────────────────▶│
 │            │  write .stm + .md5 + update_checksum.md5                                 │
 │            │◀─done────────────────────────────────────────────────────────────────────│
 │            │──/sendprocessstatus──────────────────────────────▶│            │            │
 │            │──/sendbackups────────────────────────────────────▶│            │            │
 │◀─SyncResult│             │            │            │            │            │            │
```

## 10. Error Handling

| Error | Handling | Ref |
|-------|----------|-----|
| Network timeout | Retry 3× with backoff (1s, 2s, 4s) | toolbox.md §17.2 |
| HTTP 401/403 | Re-login with full-auth, then retry | toolbox.md §17.1 |
| HTTP 412 | Missing device data — fail with clear message | API probing |
| HTTP 417 | Wrong field values — fail with field details | API probing |
| HTTP 5xx | Retry 3×, then `/senderror` + fail | toolbox.md §6.1 |
| MD5 mismatch | Delete cached file, re-download once | toolbox.md §9.5 |
| USB disconnected | Abort, preserve download cache | toolbox.md §10.1 |
| Disk full | Pre-check space before install | toolbox.md §9.3 |
| Invalid device.nng | Fail: "not a valid MediaNav drive" | toolbox.md §7.3 |
| Login failed | Raise `AuthenticationError` with server message | toolbox.md §6.2 |
| Device not recognized | Raise `DeviceNotFoundError` | toolbox.md §7.3 |
| Multiple device matches | Raise `AmbiguousDeviceError` | toolbox.md §7.3 |

Market call errors use `MainError` + `SubError` codes (toolbox.md §6.2, line 26217).

## 11. Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| HTTP client | `httpx` | Sync + async, HTTP/2, streaming, cookie jar |
| CLI | `click` | Clean commands, built-in help |
| Config | TOML | Python 3.11+ `tomllib`, human-readable |
| Env/secrets | `python-dotenv` | Load `.env` file for credentials |
| Progress | `rich` | Progress bars, tables, logging |
| Data classes | `dataclasses` | Lightweight, no deps |
| Testing | `pytest` | Fixtures, parametrize, mocking |
| Mocking HTTP | `respx` | httpx-native mock library |
| Test fixtures | `tmp_path` | pytest built-in temp directories |

## 12. Unit Tests

All tests in `tests/` directory. Run with `pytest tests/ -v`.

### 12.1 `tests/test_config.py`

| Test | Description |
|------|-------------|
| `test_default_config` | Config() has correct defaults from plugin.dll |
| `test_config_from_toml` | Loads overrides from TOML file |
| `test_config_env_override` | Environment variables override TOML |
| `test_config_missing_file` | Falls back to defaults if no config file |

### 12.2 `tests/test_device.py`

| Test | Description |
|------|-------------|
| `test_parse_device_nng` | Parses real device.nng, extracts APPCID=0x42000B53 |
| `test_parse_device_nng_appcid` | Verifies APPCID at offset 0x5C (LE) |
| `test_xor_decode_normal_table` | XOR decode with normal table produces expected output |
| `test_xor_decode_china_table` | XOR decode with China table produces different output |
| `test_xor_decode_word_aligned` | Verifies 32-bit word operation (not byte-by-byte) |
| `test_validate_drive_valid` | Valid USB layout passes validation |
| `test_validate_drive_missing_device_nng` | Missing device.nng fails |
| `test_validate_drive_missing_navisync` | Missing NaviSync/ dir fails |
| `test_read_device_status` | Parses device_status.ini correctly |
| `test_read_device_status_fields` | Extracts freesize, totalsize, os_version |
| `test_parse_stm_file` | Parses .stm shadow file (content_id, size, timestamp) |
| `test_read_installed_content` | Scans all .stm files, infers content types from dirs |
| `test_detect_drive_not_found` | Returns None for non-MediaNav USB |
| `test_brand_mapping` | Brand index 0=dacia, 1=renault, etc. |

### 12.3 `tests/test_fingerprint.py`

| Test | Description |
|------|-------------|
| `test_read_fingerprint` | Reads fingerprint from USB |
| `test_save_fingerprint` | Writes fingerprint to USB |
| `test_encode_fingerprint` | Encodes for API transmission |
| `test_validate_fingerprint_valid` | Valid fingerprint passes |
| `test_validate_fingerprint_missing_checksum` | Missing checksum file fails |
| `test_validate_fingerprint_md5_mismatch` | MD5 mismatch fails |

### 12.4 `tests/test_auth.py`

| Test | Description |
|------|-------------|
| `test_credentials_from_args` | Credentials from constructor |
| `test_credentials_from_dotenv` | Credentials loaded from .env file |
| `test_credentials_from_env` | Credentials from NAVIEXTRAS_USER/PASS |
| `test_credentials_priority` | Constructor args override .env override env vars |
| `test_credentials_missing` | Raises error if no credentials |
| `test_session_headers_full_auth` | full-auth mode includes user+pass |
| `test_session_headers_device_auth` | device-auth mode uses session token |
| `test_session_expired` | Expired session triggers re-login |
| `test_jsessionid_cookie` | JSESSIONID extracted from response |

### 12.5 `tests/test_igo_binary.py`

| Test | Description |
|------|-------------|
| `test_decode_boot_response` | Decodes real v3 boot response into service list |
| `test_decode_boot_entry_count` | Boot response has 6 entries |
| `test_decode_boot_entry_fields` | Each entry has version, name, url |
| `test_encode_empty_request` | Encodes minimal request |
| `test_encode_login_request` | Encodes login with credentials + device |
| `test_decode_model_list_response` | Decodes /get_device_model_list response |
| `test_varint_encode_decode` | Round-trip varint encoding |
| `test_magic_header` | Encoded messages start with 0x80 0x80 |

### 12.6 `tests/test_boot.py`

| Test | Description |
|------|-------------|
| `test_boot_success` | Mocked boot returns ServiceEndpoints |
| `test_boot_parses_all_services` | Extracts index, register, selfie, mobile |
| `test_boot_network_error` | Retries on timeout, raises after 3 |
| `test_boot_server_error` | Handles 500 response |

### 12.7 `tests/test_register.py`

| Test | Description |
|------|-------------|
| `test_get_device_model_list` | Returns model list (mocked) |
| `test_get_device_descriptor_list` | Returns descriptors for device |
| `test_get_device_info` | Returns info for serial ID |
| `test_register_device` | Registers new device |
| `test_register_device_already_registered` | Handles already-registered |
| `test_register_device_unbind` | Unbinds + re-registers |

### 12.8 `tests/test_market.py`

| Test | Description |
|------|-------------|
| `test_login_success` | Login returns session with JSESSIONID |
| `test_login_bad_credentials` | Wrong password raises AuthenticationError |
| `test_login_sets_device_auth` | After login, subsequent calls use device-auth |
| `test_send_drives` | Sends drive info, gets 200 |
| `test_send_fingerprint` | Sends fingerprint data |
| `test_get_process` | Returns ProcessInfo with download URLs |
| `test_get_process_no_updates` | Returns empty list when up to date |
| `test_send_process_status` | Reports progress |
| `test_send_backups` | Reports backup info |
| `test_send_error` | Reports error to server |
| `test_market_call_sequence` | Calls happen in correct order |
| `test_market_call_retry_on_401` | Re-authenticates on 401 |

### 12.9 `tests/test_download.py`

| Test | Description |
|------|-------------|
| `test_download_one` | Downloads single file to cache |
| `test_download_md5_verify` | Verifies MD5 after download |
| `test_download_md5_mismatch` | Re-downloads on MD5 mismatch |
| `test_download_resume` | Resumes partial download via Range header |
| `test_download_cache_hit` | Skips download if cached + MD5 matches |
| `test_download_concurrent` | Downloads 2 files concurrently |
| `test_download_progress_callback` | Progress callback receives bytes/total |
| `test_clear_cache` | Removes all cached files |

### 12.10 `tests/test_installer.py`

| Test | Description |
|------|-------------|
| `test_install_writes_stm` | Creates .stm shadow files |
| `test_install_writes_md5` | Creates .md5 checksum files |
| `test_install_update_checksum` | Writes update_checksum.md5 |
| `test_install_check_space` | Fails if insufficient space |
| `test_install_preserves_existing` | Doesn't overwrite unrelated files |
| `test_install_content_type_dirs` | Files go to correct type directories |

### 12.11 `tests/test_cli.py`

| Test | Description |
|------|-------------|
| `test_cli_detect` | `detect` command shows device info |
| `test_cli_catalog` | `catalog` command lists available content |
| `test_cli_sync` | `sync` command runs full pipeline |
| `test_cli_login_prompt` | Prompts for password if not provided |
| `test_cli_no_usb` | Error message when no USB found |

## 13. Integration Tests

Integration tests in `tests/integration/`. Run with `pytest tests/integration/ -v --integration`.
These hit the real API (rate-limited, require credentials).

### 13.1 `tests/integration/test_boot_live.py`

| Test | Description |
|------|-------------|
| `test_boot_live` | GET /rest/2/boot returns valid JSON with all services |
| `test_boot_v3_live` | POST /rest/3/boot returns valid igo-binary |
| `test_boot_response_has_index` | Response contains index service URL |
| `test_boot_response_has_register` | Response contains register service URL |

### 13.2 `tests/integration/test_register_live.py`

| Test | Description |
|------|-------------|
| `test_get_device_model_list_live` | Returns model list version (already confirmed working) |
| `test_get_device_descriptor_list_live` | With real device.nng data |
| `test_devinfo_live` | With real device serial |

### 13.3 `tests/integration/test_login_live.py`

| Test | Description |
|------|-------------|
| `test_login_live` | Full login with real credentials + device |
| `test_login_bad_password_live` | Correct error on wrong password |
| `test_session_persists_live` | JSESSIONID works for subsequent calls |

### 13.4 `tests/integration/test_market_live.py`

| Test | Description |
|------|-------------|
| `test_full_market_sequence_live` | login → send_drives → send_fingerprint → get_process |
| `test_get_process_live` | Returns real download URLs |
| `test_send_drives_live` | Server accepts drive info |

### 13.5 `tests/integration/test_device_live.py`

| Test | Description |
|------|-------------|
| `test_parse_real_device_nng` | Parses the real device.nng from disk.zip |
| `test_read_real_usb_structure` | Reads all .stm files from real USB |
| `test_device_recognition_live` | Full recognition: APPCID → model list → match |

### 13.6 `tests/integration/test_end_to_end.py`

| Test | Description |
|------|-------------|
| `test_full_sync_dry_run` | boot → login → detect → catalog → (no download) |
| `test_download_single_item` | Downloads one real content item |

### 13.7 Integration Test Fixtures

```python
# tests/conftest.py
@pytest.fixture
def real_usb_path():
    """Path to extracted USB drive data."""
    return Path("analysis/usb_drive/disk")

@pytest.fixture
def real_device_nng(real_usb_path):
    """Real device.nng bytes."""
    return (real_usb_path / "NaviSync/license/device.nng").read_bytes()

@pytest.fixture
def xor_table_normal():
    """Normal XOR table extracted from nngine.dll."""
    return Path("analysis/xor_table_normal.bin").read_bytes()

@pytest.fixture
def credentials():
    """Real credentials from environment."""
    return Credentials(
        username=os.environ.get("NAVIEXTRAS_USER", ""),
        password=os.environ.get("NAVIEXTRAS_PASS", ""),
    )

@pytest.fixture
def live_client(credentials):
    """Client connected to real API."""
    pytest.importorskip("NAVIEXTRAS_USER" in os.environ, reason="No credentials")
    return NaviExtrasClient(Config(), credentials)
```

## 14. Test Data

Test fixtures use real data extracted during reverse engineering:

| File | Source | Purpose |
|------|--------|---------|
| `tests/data/device.nng` | USB drive | Real device identity file (268 bytes) |
| `tests/data/xor_table_normal.bin` | nngine.dll | XOR decode table (4096 bytes) |
| `tests/data/xor_table_china.bin` | nngine.dll | China XOR decode table (4096 bytes) |
| `tests/data/boot_response_v2.json` | Live API | Real boot response (JSON) |
| `tests/data/boot_response_v3.bin` | Live API | Real boot response (igo-binary, 350 bytes) |
| `tests/data/device_status.ini` | USB drive | Real device status |
| `tests/data/UnitedKingdom.fbl.stm` | USB drive | Real .stm shadow file |
| `tests/data/model_list_response.bin` | Live API | /get_device_model_list response |
